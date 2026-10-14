// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! A TCP stack inside the tunnel, so the relay can dial through it.
//!
//! `wg_tunnel` turns IP packets into encrypted datagrams. What nothing yet does
//! is produce those IP packets — because a WireGuard tunnel is a NETWORK, and
//! the relay wants a STREAM. Between the two sits a TCP implementation, and
//! there is no borrowing the operating system's: the kernel's stack is attached
//! to the kernel's interfaces, and the whole point of a userspace tunnel is
//! that there is no interface.
//!
//! So `smoltcp` runs here, over a device whose wire is the tunnel:
//!
//! ```text
//!   relay dials  ->  smoltcp TCP socket  ->  IP packet
//!                                             |
//!                                        wg_tunnel::send_packet
//!                                             |
//!                                        encrypted UDP to the peer
//! ```
//!
//! ## One task owns everything
//!
//! smoltcp's `Interface` and `SocketSet` are not `Sync` and are not meant to be
//! shared. Rather than wrap them in a mutex — which would serialise every
//! packet behind every dial anyway — all of it lives in one task, and callers
//! talk to it over channels. `dial` sends a request and gets back one half of a
//! `tokio::io::duplex` pair; the task pumps the other half.
//!
//! That also settles the shutdown question by construction: drop the handle,
//! the channel closes, the task ends, and the tunnel's socket goes with it.
//! A profile that closes takes its tunnel with it and leaves nothing running.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Context, Result};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Inside a WireGuard tunnel the usable MTU is 1420: 1500 less 60 for the outer
/// IPv6 header, 8 for UDP and 32 for WireGuard's own framing. Providers publish
/// this number and getting it wrong shows up as large responses hanging rather
/// than as an error.
const MTU: usize = 1420;

/// Buffers per connection. A browser opens many, so this is per-socket cost.
const RX_BUF: usize = 64 * 1024;
const TX_BUF: usize = 64 * 1024;

/// The device smoltcp writes to: two queues, drained by the task that owns it.
#[derive(Default)]
struct Wire {
    /// Packets that arrived from the peer, waiting to be given to smoltcp.
    inbound: std::collections::VecDeque<Vec<u8>>,
    /// Packets smoltcp produced, waiting to go into the tunnel.
    outbound: std::collections::VecDeque<Vec<u8>>,
}

impl Device for Wire {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        // Both tokens borrow the device in smoltcp's model; the rx one owns its
        // bytes so the outbound queue stays mutably borrowed by the tx token.
        Some((RxTok(packet), TxTok(&mut self.outbound)))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.outbound))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // IP rather than Ethernet: there are no frames in a tunnel and no ARP.
        // Choosing Ethernet here would have smoltcp emit frames the peer does
        // not expect, and the symptom is a tunnel that establishes and carries
        // nothing.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct RxTok(Vec<u8>);
impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxTok<'a>(&'a mut std::collections::VecDeque<Vec<u8>>);
impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let out = f(&mut buf);
        self.0.push_back(buf);
        out
    }
}

/// A name to resolve, inside the tunnel.
struct Resolve {
    name: String,
    answer: tokio::sync::oneshot::Sender<Result<IpAddr>>,
}

/// What a caller sends to the task that owns the stack.
struct Dial {
    to: SocketAddr,
    /// The persona's OS: the packets this connection is made of are the
    /// site's whole view of the machine's TCP (`syn_shape`).
    os: crate::syn_shape::Os,
    /// The task's end of the duplex pair; the caller keeps the other.
    stream: DuplexStream,
    /// Answered once the connection is up or has failed, so `dial` can report
    /// a refusal rather than handing back a stream that silently never works.
    ready: tokio::sync::oneshot::Sender<Result<()>>,
}

/// A running tunnel with a TCP stack on it.
pub struct Stack {
    /// Set once the peer has answered a handshake (`Tunnel::handshaken`).
    answered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    dials: tokio::sync::mpsc::Sender<Dial>,
    resolves: tokio::sync::mpsc::Sender<Resolve>,
    task: tokio::task::JoinHandle<()>,
}

impl Stack {
    /// Brings the tunnel up and starts the stack.
    pub async fn start(config: &crate::wireguard::Config) -> Result<Stack> {
        let tunnel = crate::wg_tunnel::Tunnel::connect(config).await?;

        // The address the peer assigned. `Address = 10.2.0.2/32` in the config;
        // the prefix is theirs to decide and taking the first is right because
        // a WireGuard client has exactly one.
        let cidr = config
            .addresses
            .first()
            .context("[Interface] has no Address, so there is nothing to be inside the tunnel")?;
        let (addr, prefix) = parse_cidr(cidr)?;

        // The resolvers the peer gave us. A tunnel with no DNS line is a
        // tunnel whose provider expects you to use theirs and did not say so;
        // falling back to the machine's resolver would send every name the
        // profile visits out of the operator's own connection, which is the
        // exact leak this is built to close. So: refuse instead.
        if config.dns.is_empty() {
            bail!(
                "the config has no DNS line, so names could only be resolved \
                 outside the tunnel — which would send every site the profile \
                 visits to this machine's resolver. Ask the provider for their \
                 DNS, or add one to the config."
            );
        }
        let servers: Vec<IpAddress> = config
            .dns
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(IpAddress::from)
            .collect();
        if servers.is_empty() {
            bail!("none of the DNS entries {:?} is an address", config.dns);
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<Dial>(32);
        let (rtx, rrx) = tokio::sync::mpsc::channel::<Resolve>(32);
        let answered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task = tokio::spawn(run(tunnel, addr, prefix, servers, answered.clone(), rx, rrx));
        Ok(Stack { answered, dials: tx, resolves: rtx, task })
    }

    /// Resolves a name using the peer's resolvers, inside the tunnel.
    ///
    /// The whole reason `dial` refuses names: doing this outside would ask the
    /// operator's own resolver what the profile is about to visit.
    pub async fn resolve(&self, name: &str) -> Result<IpAddr> {
        // An address needs no lookup, and asking anyway would be a query that
        // tells the resolver something for no answer in return.
        if let Ok(addr) = name.parse::<IpAddr>() {
            return Ok(addr);
        }
        let (answer, got) = tokio::sync::oneshot::channel();
        self.resolves
            .send(Resolve { name: name.to_string(), answer })
            .await
            .map_err(|_| anyhow::anyhow!("the tunnel is no longer running"))?;
        got.await
            .map_err(|_| anyhow::anyhow!("the tunnel stopped while resolving"))?
    }

    /// Opens a TCP connection through the tunnel.
    ///
    /// Takes an address rather than a name: DNS inside the tunnel is a separate
    /// problem and pretending otherwise here would make a resolver appear by
    /// accident, resolving through the machine rather than through the exit —
    /// which is the leak the whole tunnel exists to prevent.
    pub async fn dial(&self, to: SocketAddr, os: crate::syn_shape::Os) -> Result<DuplexStream> {
        let (mine, theirs) = tokio::io::duplex(RX_BUF);
        let (ready, done) = tokio::sync::oneshot::channel();
        self.dials
            .send(Dial { to, os, stream: theirs, ready })
            .await
            .map_err(|_| anyhow::anyhow!("the tunnel is no longer running"))?;
        done.await
            .map_err(|_| anyhow::anyhow!("the tunnel stopped while connecting"))??;
        Ok(mine)
    }
}

/// Deliberately says nothing.
///
/// `Upstream` derives Debug and is logged on every launch, and the reason that
/// derive is safe at all is a custom Debug one type over that keeps proxy
/// passwords out of the log line. A tunnel is reached through keys rather than
/// a password, and a Debug that grew fields later would put them somewhere
/// nobody thought to look.
impl std::fmt::Debug for Stack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wireguard tunnel")
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // Dropping the sender would end the task on its own; aborting makes it
        // immediate. A tunnel outliving the profile that opened it is a live
        // exit nobody is using — the same leak `relay` had with its JoinHandle.
        self.task.abort();
    }
}

/// The tunnel for one config, shared by everything in this process that uses
/// that config, and started the first time something dials through it.
///
/// Shared because a WireGuard key cannot be in two tunnels at once: the peer
/// answers whichever endpoint handshook last, so a second tunnel with the same
/// key — a proxy check while the profile is open, the exit lookup a launch
/// does right after starting its relay — would take the first one's traffic
/// away from it mid-page. Weak, so the tunnel ends when its last user does.
///
/// Lazy because `parse_upstream` is not async and every caller already has a
/// URL rather than a config; and a tunnel that is never dialled never sends a
/// handshake, which is the right amount of traffic for a profile that was
/// opened and closed.
pub struct Shared {
    config: crate::wireguard::Config,
    stack: tokio::sync::OnceCell<Stack>,
}

impl Shared {
    pub fn for_config(config: crate::wireguard::Config) -> std::sync::Arc<Shared> {
        use std::sync::{Arc, Mutex, OnceLock, Weak};
        static LIVE: OnceLock<Mutex<Vec<Weak<Shared>>>> = OnceLock::new();
        let mut live = LIVE.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|w| w.strong_count() > 0);
        if let Some(same) = live.iter().filter_map(Weak::upgrade).find(|s| s.config == config) {
            return same;
        }
        let shared = Arc::new(Shared { config, stack: tokio::sync::OnceCell::new() });
        live.push(Arc::downgrade(&shared));
        shared
    }

    async fn stack(&self) -> Result<&Stack> {
        self.stack.get_or_try_init(|| Stack::start(&self.config)).await
    }

    pub async fn resolve(&self, name: &str) -> Result<IpAddr> {
        self.stack().await?.resolve(name).await
    }

    /// Whether the peer has ever answered this tunnel's handshake. False for a
    /// tunnel nothing has dialled yet.
    pub fn answered(&self) -> bool {
        self.stack.get().is_some_and(|s| s.answered.load(std::sync::atomic::Ordering::Relaxed))
    }

    pub async fn dial(&self, to: SocketAddr, os: crate::syn_shape::Os) -> Result<DuplexStream> {
        self.stack().await?.dial(to, os).await
    }
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wireguard tunnel")
    }
}

/// A local port no live socket in the set is using, at random in `range`.
fn free_port(sockets: &SocketSet<'_>, range: std::ops::RangeInclusive<u16>) -> u16 {
    let used: std::collections::HashSet<u16> = sockets
        .iter()
        .filter_map(|(_, s)| match s {
            smoltcp::socket::Socket::Tcp(t) => t.local_endpoint().map(|e| e.port),
            _ => None,
        })
        .collect();
    loop {
        let port = rand::Rng::gen_range(&mut rand::thread_rng(), range.clone());
        if !used.contains(&port) {
            return port;
        }
    }
}

async fn run(
    mut tunnel: crate::wg_tunnel::Tunnel,
    addr: IpAddr,
    prefix: u8,
    servers: Vec<IpAddress>,
    answered: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut dials: tokio::sync::mpsc::Receiver<Dial>,
    mut resolves: tokio::sync::mpsc::Receiver<Resolve>,
) {
    let mut wire = Wire::default();
    let mut iface = Interface::new(
        Config::new(smoltcp::wire::HardwareAddress::Ip),
        &mut wire,
        Instant::now(),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::from(addr), prefix));
    });
    // Everything goes to the peer. The config's AllowedIPs was already checked
    // to be a default route (`wireguard::Config::parse` refuses a split
    // tunnel), so there is exactly one place for a packet to go.
    let _ = iface.routes_mut().add_default_ipv4_route(
        match addr {
            IpAddr::V4(v4) => v4.into(),
            IpAddr::V6(_) => {
                tracing::error!("IPv6-only tunnels are not supported yet");
                return;
            }
        },
    );

    let mut sockets = SocketSet::new(Vec::new());
    let dns = sockets.add(smoltcp::socket::dns::Socket::new(&servers, Vec::new()));
    let mut queries: Vec<(smoltcp::socket::dns::QueryHandle, String, tokio::sync::oneshot::Sender<Result<IpAddr>>)> =
        Vec::new();
    let mut pumps: HashMap<smoltcp::iface::SocketHandle, Pump> = HashMap::new();
    let mut shaper = crate::syn_shape::Shaper::new();
    let mut packet = Vec::new();

    loop {
        tokio::select! {
            // A new connection wanted.
            Some(dial) = dials.recv() => {
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0u8; RX_BUF]),
                    tcp::SocketBuffer::new(vec![0u8; TX_BUF]),
                );
                // The scale and the timestamps are promises about every
                // segment after the SYN, so smoltcp has to make them itself;
                // the shaper only rearranges what it sends.
                let os = dial.os;
                socket.set_window_shift(Some(os.window_shift()));
                if os.timestamps() {
                    socket.set_tsval_generator(Some(crate::syn_shape::tsval));
                }
                // Random within the OS's own range, like the OS: ports handed
                // out in order would let a site count our connections.
                let port = free_port(&sockets, os.ephemeral_ports());
                shaper.expect(port, os);
                let handle = sockets.add(socket);
                let s = sockets.get_mut::<tcp::Socket>(handle);
                let endpoint = (IpAddress::from(dial.to.ip()), dial.to.port());
                match s.connect(iface.context(), endpoint, port) {
                    Ok(()) => {
                        pumps.insert(handle, Pump { stream: dial.stream, ready: Some(dial.ready), out: Vec::new() });
                    }
                    Err(e) => {
                        let _ = dial.ready.send(Err(anyhow::anyhow!("{e:?}")));
                        sockets.remove(handle);
                    }
                }
            }

            // A name to look up.
            Some(req) = resolves.recv() => {
                let socket = sockets.get_mut::<smoltcp::socket::dns::Socket>(dns);
                match socket.start_query(iface.context(), &req.name, smoltcp::wire::DnsQueryType::A) {
                    Ok(handle) => queries.push((handle, req.name, req.answer)),
                    Err(e) => {
                        let _ = req.answer.send(Err(anyhow::anyhow!("{e:?}")));
                    }
                }
            }

            // A datagram from the peer.
            got = tunnel.recv_packet(&mut packet) => {
                if tunnel.handshaken() {
                    answered.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                match got {
                    Ok(true) => {
                        shaper.inbound(&mut packet);
                        wire.inbound.push_back(std::mem::take(&mut packet));
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "the tunnel failed");
                        return;
                    }
                }
            }

            // smoltcp's timers: retransmits, delayed ACKs, keepalives.
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }

        iface.poll(Instant::now(), &mut wire, &mut sockets);

        // Everything smoltcp produced goes into the tunnel.
        while let Some(mut out) = wire.outbound.pop_front() {
            shaper.outbound(&mut out);
            if let Err(e) = tunnel.send_packet(&out).await {
                tracing::warn!(error = %e, "could not send through the tunnel");
                return;
            }
        }
        if let Err(e) = tunnel.tick().await {
            tracing::warn!(error = %e, "the tunnel's timers failed");
            return;
        }

        // Answers that have arrived.
        //
        // Walked backwards with swap_remove rather than retain_mut: a oneshot
        // sender has to be MOVED to be used, and retain_mut only lends it. The
        // first version tried to work around that and was nonsense.
        {
            let socket = sockets.get_mut::<smoltcp::socket::dns::Socket>(dns);
            let mut i = queries.len();
            while i > 0 {
                i -= 1;
                use smoltcp::socket::dns::GetQueryResultError as E;
                let outcome = match socket.get_query_result(queries[i].0) {
                    Err(E::Pending) => continue,
                    Ok(addrs) => match addrs.first() {
                        Some(IpAddress::Ipv4(v4)) => Ok(IpAddr::from(std::net::Ipv4Addr::from(*v4))),
                        Some(IpAddress::Ipv6(v6)) => Ok(IpAddr::from(std::net::Ipv6Addr::from(*v6))),
                        // A successful query with no address is NXDOMAIN's
                        // quieter cousin, and it has to read as "no such host"
                        // rather than as a lookup that is still running.
                        None => Err(anyhow::anyhow!("{} has no address", queries[i].1)),
                    },
                    Err(e) => Err(anyhow::anyhow!("resolving {}: {e:?}", queries[i].1)),
                };
                let (_, _, answer) = queries.swap_remove(i);
                let _ = answer.send(outcome);
            }
        }

        // Move bytes between each socket and its caller.
        let mut finished = Vec::new();
        for (handle, pump) in pumps.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(*handle);

            if let Some(ready) = pump.ready.take() {
                if socket.may_send() {
                    let _ = ready.send(Ok(()));
                } else if !socket.is_open() {
                    let _ = ready.send(Err(anyhow::anyhow!("the peer refused the connection")));
                    finished.push(*handle);
                    continue;
                } else {
                    // Still connecting; put it back.
                    pump.ready = Some(ready);
                }
            }

            // Tunnel -> caller.
            if socket.can_recv() {
                let mut buf = [0u8; 8192];
                if let Ok(n) = socket.recv_slice(&mut buf) {
                    if n > 0 && pump.stream.write_all(&buf[..n]).await.is_err() {
                        finished.push(*handle);
                        continue;
                    }
                }
            }

            // Caller -> tunnel. Read without blocking the loop: a socket with
            // nothing to say must not stall every other connection.
            if socket.can_send() {
                let mut buf = [0u8; 8192];
                match tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    pump.stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(0)) => {
                        socket.close();
                        finished.push(*handle);
                    }
                    Ok(Ok(n)) => {
                        let _ = socket.send_slice(&buf[..n]);
                    }
                    Ok(Err(_)) => finished.push(*handle),
                    Err(_) => {}
                }
            }

            if !socket.is_active() && pump.ready.is_none() {
                finished.push(*handle);
            }
        }
        for handle in finished {
            pumps.remove(&handle);
            sockets.remove(handle);
        }
    }
}

struct Pump {
    stream: DuplexStream,
    ready: Option<tokio::sync::oneshot::Sender<Result<()>>>,
    #[allow(dead_code)]
    out: Vec<u8>,
}

/// `10.2.0.2/32` into an address and a prefix.
fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().context("the prefix is not a number")?),
        // A bare address means "just me", which is what /32 says.
        None => (s, 32),
    };
    let addr: IpAddr = addr.trim().parse().with_context(|| format!("{s} is not an address"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("/{prefix} is not a prefix an address of that family can have");
    }
    Ok((addr, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_and_its_prefix_are_read_the_way_a_provider_writes_them() {
        assert_eq!(
            parse_cidr("10.2.0.2/32").unwrap(),
            ("10.2.0.2".parse::<IpAddr>().unwrap(), 32)
        );
        // Some providers omit the prefix. A client has one address, so the
        // absence means /32 rather than "unknown".
        assert_eq!(
            parse_cidr("10.2.0.2").unwrap(),
            ("10.2.0.2".parse::<IpAddr>().unwrap(), 32)
        );
        assert_eq!(parse_cidr("fd00::2/128").unwrap().1, 128);

        assert!(parse_cidr("10.2.0.2/33").is_err());
        assert!(parse_cidr("not-an-address/32").is_err());
        assert!(parse_cidr("10.2.0.2/abc").is_err());
    }

    /// A config with no DNS must be REFUSED rather than quietly falling back
    /// to this machine's resolver.
    ///
    /// The fallback is the tempting thing to write and it is the whole leak:
    /// every site the profile opens would be announced to the operator's own
    /// resolver, from the operator's own address, before a single byte went
    /// through the tunnel. The bytes would be private and the intent would not.
    #[tokio::test]
    async fn a_tunnel_with_no_resolver_is_refused_rather_than_leaking_to_the_machine() {
        const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let text = format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.2.0.2/32\n\n\
             [Peer]\nPublicKey = {KEY}\nEndpoint = 127.0.0.1:51820\n\
             AllowedIPs = 0.0.0.0/0\n"
        );
        let config = crate::wireguard::Config::parse(&text).expect("a valid config");
        assert!(config.dns.is_empty(), "the fixture must have no DNS line");

        let err = Stack::start(&config).await.unwrap_err().to_string();
        assert!(err.contains("DNS"), "{err}");
        assert!(
            err.contains("resolver"),
            "the message has to say what would leak: {err}"
        );
    }

    /// The device is where a wrong medium turns into a tunnel that establishes
    /// and carries nothing, so the choice is asserted rather than assumed.
    #[test]
    fn the_device_speaks_ip_rather_than_ethernet() {
        let caps = Wire::default().capabilities();
        assert_eq!(caps.medium, Medium::Ip, "a tunnel has no frames and no ARP");
        assert_eq!(caps.max_transmission_unit, 1420);
    }

    /// Packets handed to the device come back out of it in order and intact —
    /// the smallest claim the stack rests on.
    #[test]
    fn the_wire_carries_packets_in_order() {
        let mut wire = Wire::default();
        wire.inbound.push_back(vec![1, 2, 3]);
        wire.inbound.push_back(vec![4, 5]);

        let (rx, _tx) = wire.receive(Instant::now()).expect("a packet was queued");
        assert_eq!(rx.consume(|b| b.to_vec()), vec![1, 2, 3]);
        let (rx, _tx) = wire.receive(Instant::now()).expect("and the second");
        assert_eq!(rx.consume(|b| b.to_vec()), vec![4, 5]);
        assert!(wire.receive(Instant::now()).is_none());

        // And what smoltcp transmits lands in the outbound queue for the
        // tunnel, which is the other half of the contract.
        let tx = wire.transmit(Instant::now()).unwrap();
        tx.consume(4, |b| b.copy_from_slice(&[9, 9, 9, 9]));
        assert_eq!(wire.outbound.pop_front().unwrap(), vec![9, 9, 9, 9]);
    }

    /// The SYN a site receives through a WireGuard profile, end to end: a
    /// proxy URL as the desktop builds it, `parse_upstream`, the shared
    /// tunnel, a real handshake with a peer on this machine, and the packet
    /// as that peer decrypts it — which is what it forwards to the site.
    ///
    /// This is how the shapes in `syn_shape` were first seen to be needed
    /// (14.10.2026: `ttl 64, win 65535, [mss 1380, wscale 1, sackOK, eol]`).
    #[tokio::test]
    async fn a_windows_profile_sends_a_windows_syn_through_the_tunnel() {
        use base64::Engine;
        use boringtun::noise::{Tunn, TunnResult};
        use boringtun::x25519::{PublicKey, StaticSecret};
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

        let client = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let mut peer = Tunn::new(server.clone(), PublicKey::from(&client), None, None, 7, None);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n\
             [Peer]\nPublicKey = {}\nEndpoint = 127.0.0.1:{port}\nAllowedIPs = 0.0.0.0/0\n",
            b64(&client.to_bytes()),
            b64(PublicKey::from(&server).as_bytes())
        );

        let url = crate::wireguard::url(&conf, "127.0.0.1", port);
        let upstream = crate::parse_upstream(&url).unwrap().for_os(crate::syn_shape::Os::Windows);
        let crate::relay::Upstream::WireGuard(shared, os) = upstream else { panic!("not WireGuard") };
        // A second parse while the first is alive is the same tunnel.
        let crate::relay::Upstream::WireGuard(again, _) = crate::parse_upstream(&url).unwrap() else { panic!() };
        assert!(std::sync::Arc::ptr_eq(&shared, &again), "two tunnels with one key");

        assert!(!shared.answered(), "nothing has dialled yet");
        let watched = shared.clone();
        tokio::spawn(async move {
            let _ = shared.dial("1.1.1.1:443".parse().unwrap(), os).await;
            std::future::pending::<()>().await
        });

        let mut dgram = vec![0u8; 65536];
        let mut out = vec![0u8; 65536];
        let syn = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                let (n, from) = socket.recv_from(&mut dgram).await.unwrap();
                let mut input = &dgram[..n];
                loop {
                    match peer.decapsulate(Some(from.ip()), input, &mut out) {
                        TunnResult::WriteToNetwork(d) => socket.send_to(d, from).await.unwrap(),
                        TunnResult::WriteToTunnelV4(p, _) if p[9] == 6 && p[33] & 0x02 != 0 => return p.to_vec(),
                        _ => break,
                    };
                    input = &[];
                }
            }
        })
        .await
        .expect("no SYN came through the tunnel");

        assert_eq!(syn[8], 128, "TTL");
        assert_ne!(u16::from_be_bytes([syn[4], syn[5]]), 0, "IP ID");
        assert_eq!(u16::from_be_bytes([syn[34], syn[35]]), 65535, "window");
        // mss 1380, nop, wscale 8, nop, nop, sackOK
        assert_eq!(&syn[40..], &[2, 4, 0x05, 0x64, 1, 3, 3, 8, 1, 1, 4, 2]);
        let local_port = u16::from_be_bytes([syn[20], syn[21]]);
        assert!(local_port >= 49152, "Windows' ephemeral range, got {local_port}");

        // The peer answered the handshake, and the tunnel knows it: this is
        // what tells a wrong key ("wgSilent") from a working tunnel.
        assert!(watched.answered(), "the handshake completed but the tunnel did not notice");
    }

    /// A peer that never answers — a wrong key looks exactly like this — is
    /// a tunnel that has not been answered, however long the dial waits.
    #[tokio::test]
    async fn a_silent_peer_leaves_the_tunnel_unanswered() {
        const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let conf = format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n\
             [Peer]\nPublicKey = {KEY}\nEndpoint = 127.0.0.1:{port}\nAllowedIPs = 0.0.0.0/0\n"
        );
        let shared = Shared::for_config(crate::wireguard::Config::parse(&conf).unwrap());
        let dial = shared.dial("1.1.1.1:443".parse().unwrap(), crate::syn_shape::Os::Linux);
        assert!(tokio::time::timeout(std::time::Duration::from_secs(2), dial).await.is_err());
        let mut buf = [0u8; 256];
        assert_eq!(silent.recv(&mut buf).await.unwrap(), 148, "a handshake initiation went out");
        assert!(!shared.answered());
    }
}
