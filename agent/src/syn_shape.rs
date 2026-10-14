// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! What a WireGuard profile's TCP looks like from the far side.
//!
//! Through a proxy the site's TCP peer is the proxy server, and nothing the
//! browser does reaches the SYN p0f reads. Through WireGuard it is different:
//! `wg_stack` builds every packet itself, the peer only forwards them, and so
//! the SYN the site sees is smoltcp's. Left alone that SYN is
//!
//! ```text
//!   ttl 64, id 0, win 65535, options [mss 1380, wscale 1, sackOK, eol]
//! ```
//!
//! which is no operating system at all — scale 1 and an option list without a
//! single NOP are a userspace stack's signature — and under a Windows persona
//! the TTL contradicts the User-Agent outright.
//!
//! So every packet the stack produces passes through a [`Shaper`] first, which
//! makes it the persona's OS. The numbers below were captured on the wire on
//! 14.10.2026, at srv.furybrowser.dev, from real machines:
//!
//! ```text
//!   Windows 11 26200  ttl 128  id+  win 65535  mss,nop,ws 8,nop,nop,sok
//!   macOS (Darwin 27) ttl 64   id 0 win 65535  mss,nop,ws 6,nop,nop,ts,sok,eol
//!   Linux 6.8         ttl 64   id+  win 64240  mss,sok,ts,nop,ws 7
//! ```
//!
//! Linux's window is the largest multiple of the MSS under 65536, not a
//! constant: a host route with `advmss 1380` on the same server gave 64860,
//! which is 47 × 1380 — and 1380 is exactly the MSS inside a tunnel.
//!
//! Two of these cannot be done by rewriting alone. The window scale is a
//! promise about every window that follows, so smoltcp has to keep it: that is
//! the one change in `vendor/smoltcp` (`set_window_shift`). Timestamps have to
//! be answered on every segment once offered, so smoltcp generates them and
//! this only moves them by a per-connection offset, the way Linux and macOS
//! randomise theirs.
//!
//! The MSS is left as it is. 1380 says "tunnel" to anyone who looks, but it is
//! what a real machine on the same tunnel would send too, and lying about it
//! would make the peer send segments that do not fit.

use std::collections::HashMap;

use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket};

/// The operating systems a persona can claim, as far as TCP is concerned.
/// Android is Linux here: same kernel, same option layout. Its window scale
/// varies with the phone's buffers and was not measured; Linux's 7 is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
}

impl Os {
    /// From a persona's `os.name`: "Windows", "macOS" or "Android".
    pub fn from_persona(name: &str) -> Os {
        let n = name.to_ascii_lowercase();
        if n.starts_with("win") {
            Os::Windows
        } else if n.starts_with("mac") {
            Os::MacOs
        } else {
            Os::Linux
        }
    }

    fn shape(self) -> &'static Shape {
        match self {
            Os::Windows => &WINDOWS,
            Os::MacOs => &MACOS,
            Os::Linux => &LINUX,
        }
    }

    /// The window scale the SYN advertises; smoltcp has to be told before it
    /// connects, because it keeps scaling every window by it afterwards.
    pub fn window_shift(self) -> u8 {
        self.shape().window_shift
    }

    /// Whether the OS offers TCP timestamps. When it does, smoltcp needs a
    /// generator before it connects.
    pub fn timestamps(self) -> bool {
        self.shape().layout.contains(&Opt::Ts)
    }

    /// Where the OS takes ephemeral ports from. A stack that hands them out in
    /// order is visible to a site across connections; real ones pick at random
    /// in their own range.
    pub fn ephemeral_ports(self) -> std::ops::RangeInclusive<u16> {
        self.shape().ports.clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opt {
    Mss,
    Nop,
    Ws,
    Sok,
    Ts,
    /// End of list, then zeros to the next multiple of four.
    Eol,
}

#[derive(Clone, Copy, Debug)]
enum SynWindow {
    Fixed(u16),
    /// The largest multiple of the MSS that fits in 16 bits.
    MssMultiple,
}

#[derive(Clone, Copy, Debug)]
enum IpId {
    /// Always zero on a DF packet: macOS.
    Zero,
    /// One counter for the whole host, from a random start: Windows.
    Global,
    /// A counter per connection, each from its own random start: Linux.
    PerFlow,
}

struct Shape {
    ttl: u8,
    window_shift: u8,
    syn_window: SynWindow,
    layout: &'static [Opt],
    ip_id: IpId,
    ports: std::ops::RangeInclusive<u16>,
}

const WINDOWS: Shape = Shape {
    ttl: 128,
    window_shift: 8,
    syn_window: SynWindow::Fixed(65535),
    layout: &[Opt::Mss, Opt::Nop, Opt::Ws, Opt::Nop, Opt::Nop, Opt::Sok],
    ip_id: IpId::Global,
    ports: 49152..=65535,
};

const MACOS: Shape = Shape {
    ttl: 64,
    window_shift: 6,
    syn_window: SynWindow::Fixed(65535),
    layout: &[Opt::Mss, Opt::Nop, Opt::Ws, Opt::Nop, Opt::Nop, Opt::Ts, Opt::Sok, Opt::Eol],
    ip_id: IpId::Zero,
    ports: 49152..=65535,
};

const LINUX: Shape = Shape {
    ttl: 64,
    window_shift: 7,
    syn_window: SynWindow::MssMultiple,
    layout: &[Opt::Mss, Opt::Sok, Opt::Ts, Opt::Nop, Opt::Ws],
    ip_id: IpId::PerFlow,
    // net.ipv4.ip_local_port_range's default.
    ports: 32768..=60999,
};

/// The clock smoltcp stamps segments with: milliseconds, like Linux and macOS.
/// Not the machine's uptime — that would be a fingerprint of its own — but
/// the time since this process first needed it; each connection then adds its
/// own random offset on the way out.
pub fn tsval() -> u32 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u32
}

/// What one connection needs remembered: where its IP IDs and its timestamps
/// start. Keyed by local port, which is unique among a stack's live sockets.
struct Flow {
    os: Os,
    next_id: u16,
    ts_offset: u32,
}

/// Rewrites a stack's packets on their way in and out of the tunnel.
///
/// Per connection rather than per stack: one tunnel can carry two profiles
/// (a WireGuard key cannot be in two tunnels at once, so two profiles with
/// the same config share one), and each connection looks like its own
/// persona's OS. What is not TCP — the DNS queries to the provider's own
/// resolver, which no site sees — goes out as Linux.
pub struct Shaper {
    /// The OS each local port was dialled for, until its SYN goes out.
    expected: HashMap<u16, Os>,
    flows: HashMap<u16, Flow>,
    global_id: u16,
}

const TCP: u8 = 6;

impl Shaper {
    pub fn new() -> Shaper {
        Shaper { expected: HashMap::new(), flows: HashMap::new(), global_id: rand::random() }
    }

    /// The connection about to be opened from `port` is to look like `os`.
    pub fn expect(&mut self, port: u16, os: Os) {
        self.expected.insert(port, os);
    }

    /// A packet smoltcp produced, about to be encrypted.
    pub fn outbound(&mut self, packet: &mut Vec<u8>) {
        let mut shape = Os::Linux.shape();
        let Ok(ip) = Ipv4Packet::new_checked(&packet[..]) else { return };
        let header_len = ip.header_len() as usize;
        let total = (ip.total_len() as usize).min(packet.len());
        let is_tcp = u8::from(ip.next_header()) == TCP;
        let (src, dst) = (ip.src_addr(), ip.dst_addr());
        packet.truncate(total);

        let mut ip_id = None;
        if is_tcp && total >= header_len + 20 {
            let tcp = &packet[header_len..];
            let port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let flags = tcp[13];
            let (syn, ack) = (flags & 0x02 != 0, flags & 0x10 != 0);

            if syn && !ack {
                // A retransmitted SYN keeps the flow it already has: the
                // site may have seen the first one, and a second with other
                // numbers would be two machines at once.
                if let Some(os) = self.expected.remove(&port) {
                    self.flows.insert(port, Flow { os, next_id: rand::random(), ts_offset: rand::random() });
                }
            }
            let os = self.flows.get(&port).map(|f| f.os).unwrap_or(Os::Linux);
            shape = os.shape();

            if syn && !ack {
                let rebuilt = rebuild_syn(&packet[header_len..], shape);
                packet.truncate(header_len);
                packet.extend_from_slice(&rebuilt);
                let len = packet.len() as u16;
                packet[2..4].copy_from_slice(&len.to_be_bytes());
            } else if os.timestamps() {
                nop_align_lone_timestamp(&mut packet[header_len..]);
            }

            if let Some(flow) = self.flows.get_mut(&port) {
                if os.timestamps() {
                    shift_timestamp(&mut packet[header_len..], flow.ts_offset, 0);
                }
                if let IpId::PerFlow = shape.ip_id {
                    ip_id = Some(flow.next_id);
                    flow.next_id = flow.next_id.wrapping_add(1);
                }
            }
        }

        let ident = match shape.ip_id {
            IpId::Zero => 0,
            IpId::Global => {
                self.global_id = self.global_id.wrapping_add(1);
                self.global_id
            }
            IpId::PerFlow => ip_id.unwrap_or_else(rand::random),
        };

        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
        ip.set_hop_limit(shape.ttl);
        ip.set_ident(ident);
        ip.fill_checksum();
        if is_tcp {
            if let Ok(mut tcp) = TcpPacket::new_checked(&mut packet[header_len..]) {
                tcp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
            }
        }
    }

    /// A packet from the peer, about to be given to smoltcp. The site echoes
    /// our shifted timestamps back, and smoltcp has to see its own.
    pub fn inbound(&mut self, packet: &mut [u8]) {
        let Ok(ip) = Ipv4Packet::new_checked(&packet[..]) else { return };
        if u8::from(ip.next_header()) != TCP {
            return;
        }
        let header_len = ip.header_len() as usize;
        let total = (ip.total_len() as usize).min(packet.len());
        let (src, dst) = (ip.src_addr(), ip.dst_addr());
        if total < header_len + 20 {
            return;
        }
        let tcp = &mut packet[header_len..total];
        let port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let Some(flow) = self.flows.get(&port) else { return };
        if flow.ts_offset == 0 || !shift_timestamp(tcp, 0, flow.ts_offset.wrapping_neg()) {
            return;
        }
        if let Ok(mut tcp) = TcpPacket::new_checked(tcp) {
            tcp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
        }
    }
}

/// The TCP options of a segment, as (kind, body) in the order they came.
fn options(tcp: &[u8]) -> Vec<(u8, &[u8])> {
    let data_offset = ((tcp[12] >> 4) as usize * 4).clamp(20, tcp.len());
    let mut opts = Vec::new();
    let mut i = 20;
    while i < data_offset {
        match tcp[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = tcp.get(i + 1) else { break };
                let len = len as usize;
                if len < 2 || i + len > data_offset {
                    break;
                }
                opts.push((kind, &tcp[i + 2..i + len]));
                i += len;
            }
        }
    }
    opts
}

/// The SYN's TCP header and options laid out as the OS lays them out.
fn rebuild_syn(tcp: &[u8], shape: &Shape) -> Vec<u8> {
    let opts = options(tcp);
    let find = |kind: u8| opts.iter().find(|(k, _)| *k == kind).map(|(_, b)| *b);
    let mss = find(2).filter(|b| b.len() == 2).map(|b| u16::from_be_bytes([b[0], b[1]]));

    let mut out = tcp[..20].to_vec();
    for opt in shape.layout {
        match opt {
            Opt::Mss => {
                if let Some(mss) = mss {
                    out.extend_from_slice(&[2, 4]);
                    out.extend_from_slice(&mss.to_be_bytes());
                }
            }
            Opt::Nop => out.push(1),
            // The value smoltcp put there, which is the one it was told to
            // use and will scale by. Not shape.window_shift: if the two ever
            // disagreed the peer would misread every window that follows.
            Opt::Ws => {
                if let Some(ws) = find(3) {
                    out.extend_from_slice(&[3, 3]);
                    out.extend_from_slice(ws);
                }
            }
            Opt::Sok => {
                if find(4).is_some() {
                    out.extend_from_slice(&[4, 2]);
                }
            }
            Opt::Ts => {
                if let Some(ts) = find(8).filter(|b| b.len() == 8) {
                    out.extend_from_slice(&[8, 10]);
                    out.extend_from_slice(ts);
                }
            }
            Opt::Eol => {
                out.push(0);
                while out.len() % 4 != 0 {
                    out.push(0);
                }
            }
        }
    }
    // A layout whose option went missing could leave the length off by a
    // byte or two; a header that is not a whole number of words is no header.
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out[12] = ((out.len() / 4) as u8) << 4 | (out[12] & 0x0f);

    // Only ever lower than what smoltcp offered, so the peer never thinks
    // there is room that is not there.
    let offered = u16::from_be_bytes([tcp[14], tcp[15]]);
    let window = match shape.syn_window {
        SynWindow::Fixed(w) => w,
        SynWindow::MssMultiple => match mss {
            Some(m) if m > 0 => (u16::MAX / m) * m,
            _ => offered,
        },
    }
    .min(offered);
    out[14..16].copy_from_slice(&window.to_be_bytes());
    // The checksum is filled by the caller once the IP header is final.
    out[16..18].copy_from_slice(&[0, 0]);
    out
}

/// smoltcp ends a timestamp-only option list with EOL padding; every real OS
/// puts two NOPs in front instead. Same twelve bytes, so the segment's size
/// does not move — which matters, because a full segment has no room to grow.
fn nop_align_lone_timestamp(tcp: &mut [u8]) {
    let data_offset = (tcp[12] >> 4) as usize * 4;
    if data_offset == 32 && tcp.len() >= 32 && tcp[20] == 8 && tcp[21] == 10 && tcp[30] == 0 && tcp[31] == 0 {
        tcp.copy_within(20..30, 22);
        tcp[20] = 1;
        tcp[21] = 1;
    }
}

/// Adds `to_val` to the timestamp option's TSval and `to_ecr` to its TSecr.
/// Returns whether there was one.
fn shift_timestamp(tcp: &mut [u8], to_val: u32, to_ecr: u32) -> bool {
    let data_offset = ((tcp[12] >> 4) as usize * 4).clamp(20, tcp.len());
    let mut i = 20;
    while i < data_offset {
        match tcp[i] {
            0 => return false,
            1 => i += 1,
            kind => {
                let Some(&len) = tcp.get(i + 1) else { return false };
                let len = len as usize;
                if len < 2 || i + len > data_offset {
                    return false;
                }
                if kind == 8 && len == 10 {
                    let at = |o: usize, t: &[u8]| u32::from_be_bytes([t[o], t[o + 1], t[o + 2], t[o + 3]]);
                    let val = at(i + 2, tcp).wrapping_add(to_val);
                    // A TSecr of zero means "nothing to echo yet" and has to
                    // stay zero, or the SYN would carry a nonsense echo.
                    let ecr = match at(i + 6, tcp) {
                        0 => 0,
                        e => e.wrapping_add(to_ecr),
                    };
                    tcp[i + 2..i + 6].copy_from_slice(&val.to_be_bytes());
                    tcp[i + 6..i + 10].copy_from_slice(&ecr.to_be_bytes());
                    return true;
                }
                i += len;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SYN smoltcp produced through a real tunnel on 14.10.2026, timestamps
    /// on, before shaping: mss 1380, wscale 8, sackOK, TS, EOL padding.
    fn smoltcp_syn(ws: u8, ts: bool) -> Vec<u8> {
        let mut tcp = vec![
            0xc0, 0x01, 0x01, 0xbb, 0xfd, 0xec, 0xf8, 0xa2, 0, 0, 0, 0, 0x00, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ];
        tcp.extend_from_slice(&[2, 4, 0x05, 0x64, 3, 3, ws, 4, 2]);
        if ts {
            tcp.extend_from_slice(&[8, 10, 0, 0, 0, 100, 0, 0, 0, 0]);
        }
        while tcp.len() % 4 != 0 {
            tcp.push(0);
        }
        tcp[12] = ((tcp.len() / 4) as u8) << 4;
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 2, 0, 2, 1, 1, 1, 1];
        let len = (ip.len() + tcp.len()) as u16;
        ip[2..4].copy_from_slice(&len.to_be_bytes());
        ip.extend_from_slice(&tcp);
        ip
    }

    /// What tcpdump would print for the option list, in its words.
    fn layout(packet: &[u8]) -> Vec<&'static str> {
        let tcp = &packet[20..];
        let end = (tcp[12] >> 4) as usize * 4;
        let mut out = Vec::new();
        let mut i = 20;
        while i < end {
            let (name, len) = match tcp[i] {
                0 => ("eol", end - i),
                1 => ("nop", 1),
                2 => ("mss", 4),
                3 => ("ws", 3),
                4 => ("sok", 2),
                8 => ("ts", 10),
                _ => ("?", tcp[i + 1] as usize),
            };
            out.push(name);
            i += len;
        }
        out
    }

    fn shaped(os: Os) -> Vec<u8> {
        let mut p = smoltcp_syn(os.window_shift(), os.timestamps());
        let mut shaper = Shaper::new();
        shaper.expect(0xc001, os);
        shaper.outbound(&mut p);
        p
    }

    fn checksums_hold(p: &[u8]) -> bool {
        let ip = Ipv4Packet::new_checked(p).unwrap();
        let tcp = TcpPacket::new_checked(&p[20..]).unwrap();
        ip.verify_checksum()
            && tcp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr()))
    }

    #[test]
    fn a_windows_syn_is_the_one_windows_11_sent() {
        let p = shaped(Os::Windows);
        assert_eq!(layout(&p), ["mss", "nop", "ws", "nop", "nop", "sok"]);
        assert_eq!(p[8], 128, "ttl");
        assert_eq!(p.len(), 52, "the captured Windows SYN is 52 bytes");
        assert_eq!(u16::from_be_bytes([p[34], p[35]]), 65535);
        assert_eq!(p[20 + 20 + 7], 8, "wscale");
        assert_ne!(u16::from_be_bytes([p[4], p[5]]), 0, "Windows numbers its packets");
        assert!(checksums_hold(&p));
    }

    #[test]
    fn a_macos_syn_is_the_one_macos_sent() {
        let p = shaped(Os::MacOs);
        assert_eq!(layout(&p), ["mss", "nop", "ws", "nop", "nop", "ts", "sok", "eol"]);
        assert_eq!(p[8], 64);
        assert_eq!(p.len(), 64, "the captured macOS SYN is 64 bytes");
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 0, "macOS leaves the id at 0 under DF");
        assert_eq!(u16::from_be_bytes([p[34], p[35]]), 65535);
        assert!(checksums_hold(&p));
    }

    #[test]
    fn a_linux_syn_is_the_one_linux_sent_through_the_same_mss() {
        let p = shaped(Os::Linux);
        assert_eq!(layout(&p), ["mss", "sok", "ts", "nop", "ws"]);
        assert_eq!(p[8], 64);
        assert_eq!(p.len(), 60);
        // Measured: Linux 6.8 with advmss 1380 offered 64860.
        assert_eq!(u16::from_be_bytes([p[34], p[35]]), 64860);
        assert!(checksums_hold(&p));
    }

    /// The timestamp leaves with a per-connection offset and comes back
    /// without it, or smoltcp would compute nonsense round-trip times — or,
    /// worse, drop the segments as too old (PAWS).
    #[test]
    fn a_timestamp_goes_out_shifted_and_comes_back_as_it_was() {
        // Where the TS option's TSval starts, in a whole IPv4 packet.
        let ts_at = |p: &[u8]| 20 + p[20..].windows(2).position(|w| w == [8, 10]).unwrap() + 2;
        let word = |p: &[u8], at: usize| u32::from_be_bytes(p[at..at + 4].try_into().unwrap());

        let mut shaper = Shaper::new();
        shaper.expect(0xc001, Os::Linux);
        let mut syn = smoltcp_syn(7, true);
        shaper.outbound(&mut syn);
        let offset = shaper.flows[&0xc001].ts_offset;
        let sent = word(&syn, ts_at(&syn));
        assert_eq!(sent, 100u32.wrapping_add(offset));
        assert_eq!(word(&syn, ts_at(&syn) + 4), 0, "a SYN echoes nothing");

        // The SYN-ACK from 1.1.1.1:443 echoing what it saw.
        let mut reply = smoltcp_syn(7, true);
        reply[12..16].copy_from_slice(&[1, 1, 1, 1]);
        reply[16..20].copy_from_slice(&[10, 2, 0, 2]);
        reply[20..24].copy_from_slice(&[0x01, 0xbb, 0xc0, 0x01]);
        reply[20 + 13] = 0x12;
        let at = ts_at(&reply) + 4;
        reply[at..at + 4].copy_from_slice(&sent.to_be_bytes());
        shaper.inbound(&mut reply);
        assert_eq!(word(&reply, at), 100, "smoltcp has to get its own clock back");
        let tcp = TcpPacket::new_checked(&reply[20..]).unwrap();
        assert!(tcp.verify_checksum(&IpAddress::Ipv4([1, 1, 1, 1].into()), &IpAddress::Ipv4([10, 2, 0, 2].into())));
    }

    /// Two profiles on one tunnel: each connection is its own persona's.
    #[test]
    fn connections_on_one_tunnel_each_look_like_their_own_os() {
        let mut shaper = Shaper::new();
        let mut win = smoltcp_syn(8, false);
        let mut mac = smoltcp_syn(6, true);
        mac[20..22].copy_from_slice(&[0xd0, 0x00]);
        shaper.expect(0xc001, Os::Windows);
        shaper.expect(0xd000, Os::MacOs);
        shaper.outbound(&mut win);
        shaper.outbound(&mut mac);
        assert_eq!((win[8], layout(&win).len()), (128, 6));
        assert_eq!((mac[8], layout(&mac).len()), (64, 8));

        // The retransmission of the Windows SYN is still Windows'.
        let mut again = smoltcp_syn(8, false);
        shaper.outbound(&mut again);
        assert_eq!(again[8], 128);
        assert_eq!(layout(&again), layout(&win));
    }

    #[test]
    fn a_lone_timestamp_gets_nops_in_front_and_keeps_its_size() {
        let mut tcp = vec![0u8; 32];
        tcp[12] = 8 << 4;
        tcp[20..30].copy_from_slice(&[8, 10, 1, 2, 3, 4, 5, 6, 7, 8]);
        nop_align_lone_timestamp(&mut tcp);
        assert_eq!(&tcp[20..32], &[1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_persona_picks_its_os() {
        assert_eq!(Os::from_persona("Windows"), Os::Windows);
        assert_eq!(Os::from_persona("macOS"), Os::MacOs);
        assert_eq!(Os::from_persona("Android"), Os::Linux);
    }
}
