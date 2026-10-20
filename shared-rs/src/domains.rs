// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! Refusing connections to hosts a profile does not want to talk to.
//!
//! In shared-rs since 12.09.2026: the server stores the organisation's lists
//! and needs to count and classify them, and two parsers of one format would
//! drift the first time one learned a new line shape. The agent re-exports
//! this as `blocklist`.
//!
//! Donut Browser calls its equivalent a per-profile DNS blocker. This is not
//! one, and the difference is worth stating because it is in our favour rather
//! than a shortfall.
//!
//! A DNS blocker answers a name lookup with nothing. Chromium can be told to
//! stop asking it: DNS-over-HTTPS is on by default for many resolvers, and a
//! browser doing DoH resolves through an encrypted channel the blocker never
//! sees. So a DNS-level blocker is bypassed by a setting inside the thing it is
//! meant to be filtering.
//!
//! Our relay never resolves anything. SOCKS5 is used with SOCKS5h semantics —
//! the hostname travels to the upstream, which resolves it (`relay.rs` says why:
//! resolving locally would leak the operator's resolver). Which means the relay
//! is handed a NAME, in the CONNECT, before any connection exists.
//!
//! That is a better place to decide. Every byte the profile sends goes through
//! the relay by construction — `--proxy-bypass-list=<-loopback>` and no
//! exceptions — so a refusal here cannot be routed around by a browser setting,
//! by DoH, or by a hardcoded resolver.
//!
//! What it cannot do, and what a DNS blocker also cannot do: a connection made
//! to a literal IP address carries no name to match. Nothing here pretends
//! otherwise.
//!
//! ## Matching
//!
//! Blocking `doubleclick.net` blocks `ad.doubleclick.net`, because a tracker
//! that moved to a subdomain is the same tracker. It does NOT block
//! `notdoubleclick.net`, which is what a substring match would do and is the
//! classic way a blocklist takes down a site nobody meant to touch.
//!
//! So: exact match on the name, then on each parent label in turn. A name has
//! at most a handful of labels, so this is a handful of hash lookups rather
//! than a walk over a hundred thousand patterns.

//!
//! ## The other direction
//!
//! A list that begins with the line `@allow-only` is read inside out: the
//! domains in it are the ONLY ones the profile may reach, and everything else
//! is refused. This is what a team wants for a member who should open the one
//! platform their profile exists for and nothing beside it — AdsPower sells it
//! as "site management" per member group (docs/12, audit of 12.09.2026). Same
//! matcher, same place in the relay, one flag.
//!
//! A profile can carry both kinds. Then the union of its allow-only lists is
//! the whitelist and the union of its ordinary lists is still subtracted from
//! it: allowed AND not blocked.
//!
//! ## The local network
//!
//! A list that begins with `@local` names hosts on this machine's own network
//! (a tailnet, an office LAN) which a profile reaches FROM THIS MACHINE rather
//! than through its proxy. The case that asked for it (20.10.2026): a
//! self-hosted Bitwarden that answers only inside the operator's tailnet, so
//! the extension in a profile could not reach it through any proxy at all.
//!
//! This is the one exception to "everything through the upstream", and it is
//! shaped so that it cannot become a real-IP leak:
//!
//! - an entry is a name, an address or a network, and an address or network
//!   outside private space ([`is_private_network`]) is dropped when the list
//!   is read;
//! - a name is matched exactly, never its subdomains: one wrong line on a list
//!   of exceptions should open one host, not a CDN;
//! - a name is resolved by this machine's resolver (MagicDNS on a tailnet) and
//!   dialled only if EVERY address it resolves to is private. A name that
//!   resolves anywhere public is refused, not proxied: it is somebody's
//!   internal name, and the proxy provider has no business seeing it either;
//! - it says nothing about names it does not list. A visited site's name is
//!   never resolved here to find out whether it happens to be local.
//!
//! On a machine that is not inside that network the name does not resolve, or
//! not to a private address, and the connection simply fails. So a team list
//! cannot send a colleague's traffic out of their own address.
//!
//! The agent applies a machine's `@local` lists to every profile it launches,
//! team profiles included (`load_local_lists` in ipc.rs): what the local
//! network holds is a fact about the machine. Which is why a `@local` entry
//! is NOT exempt from a whitelist or a blocklist: a list on the operator's own
//! machine must never loosen the organisation's. A member kept on one
//! platform reaches the vault when the whitelist names the vault too.

use std::collections::HashSet;
use std::net::IpAddr;

/// The line that turns a list into a whitelist. Written with a character no
/// hosts file, Adblock rule or domain can begin with, so no existing list is
/// reinterpreted by accident.
pub const ALLOW_ONLY: &str = "@allow-only";

/// The line that makes a list a set of hosts on the local network. See the
/// module documentation for what it may name and why.
pub const LOCAL: &str = "@local";

/// A set of domains, and everything below them.
#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    domains: HashSet<String>,
    /// `Some` once any allow-only list has been merged in: the domains a
    /// profile may reach. `None` means no restriction beyond `domains`.
    allowed: Option<HashSet<String>>,
    /// Names from `@local` lists, matched exactly.
    local_names: HashSet<String>,
    /// Addresses and networks from `@local` lists, all inside private space.
    local_nets: Vec<(IpAddr, u8)>,
}

impl Blocklist {
    /// Reads the formats a published list actually comes in.
    ///
    /// Three of them, because the lists people already have are written three
    /// ways and asking somebody to convert theirs is asking them not to bother:
    ///
    /// ```text
    ///   0.0.0.0 ads.example       hosts file — the address is ignored
    ///   127.0.0.1 ads.example     the same, older style
    ///   ||ads.example^            Adblock Plus, the domain-anchored form
    ///   ads.example               one per line
    /// ```
    ///
    /// Anything else on a line is skipped rather than guessed at. An Adblock
    /// rule with a path, an element selector or an option is not a domain and
    /// pretending it is would block more than it says.
    pub fn parse(text: &str) -> Blocklist {
        let lines = || {
            text.lines()
                .map(|raw| raw.split('#').next().unwrap_or("").trim())
                .filter(|l| !l.is_empty() && !l.starts_with('!'))
        };
        // A list is one kind. `@local` wins over `@allow-only` in the same
        // file: read as a whitelist, a set of internal hosts would refuse the
        // whole internet, which nobody writing `@local` meant.
        if lines().any(|l| l.eq_ignore_ascii_case(LOCAL)) {
            return Self::parse_local(lines());
        }

        let mut domains = HashSet::new();
        let mut allow_only = false;
        for line in lines() {
            if line.eq_ignore_ascii_case(ALLOW_ONLY) {
                allow_only = true;
                continue;
            }

            let candidate = if let Some(rest) = line.strip_prefix("||") {
                // ||domain^ or ||domain^$options — anything after the anchor is
                // a rule this does not implement, so the rule is skipped rather
                // than approximated.
                match rest.split_once('^') {
                    Some((domain, tail)) if tail.is_empty() => domain,
                    _ => continue,
                }
            } else {
                let mut fields = line.split_whitespace();
                let first = fields.next().unwrap_or("");
                match fields.next() {
                    // A hosts line: an address and then names.
                    Some(name) if is_address(first) => name,
                    // Two fields and the first is not an address: not a shape
                    // this understands.
                    Some(_) => continue,
                    None => first,
                }
            };

            if let Some(d) = normalise(candidate) {
                domains.insert(d);
            }
        }
        if allow_only {
            Blocklist { allowed: Some(domains), ..Default::default() }
        } else {
            Blocklist { domains, ..Default::default() }
        }
    }

    /// One entry per line: a name, an address, or a network in CIDR form.
    /// Anything public is dropped here, so nothing later has to ask.
    fn parse_local<'a>(lines: impl Iterator<Item = &'a str>) -> Blocklist {
        let mut list = Blocklist::default();
        for line in lines {
            if line.eq_ignore_ascii_case(LOCAL) || line.eq_ignore_ascii_case(ALLOW_ONLY) {
                continue;
            }
            let entry = line.split_whitespace().next().unwrap_or("");
            if let Some(net) = parse_net(entry) {
                list.local_nets.push(net);
            } else if !looks_like_address(entry) {
                if let Some(name) = normalise(entry) {
                    list.local_names.insert(name);
                }
            }
        }
        list
    }

    /// Fold another list into this one: blocked domains union, allowed
    /// domains union. A profile's lists are read one file at a time so that
    /// an `@allow-only` in one of them cannot turn a neighbouring blocklist's
    /// domains into permissions, which concatenating the texts would do.
    pub fn merge(&mut self, other: Blocklist) {
        self.domains.extend(other.domains);
        if let Some(theirs) = other.allowed {
            self.allowed.get_or_insert_with(HashSet::new).extend(theirs);
        }
        self.local_names.extend(other.local_names);
        self.local_nets.extend(other.local_nets);
    }

    /// How many entries are named, whichever way they are read.
    pub fn len(&self) -> usize {
        self.domains.len()
            + self.allowed.as_ref().map_or(0, HashSet::len)
            + self.local_names.len()
            + self.local_nets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refuses_nothing() && !self.is_local()
    }

    /// No blocklist and no whitelist: `blocks` can answer without looking.
    fn refuses_nothing(&self) -> bool {
        self.domains.is_empty() && self.allowed.is_none()
    }

    /// Does this list read as a whitelist?
    pub fn is_allow_only(&self) -> bool {
        self.allowed.is_some()
    }

    /// Does this list name anything on the local network?
    pub fn is_local(&self) -> bool {
        !self.local_names.is_empty() || !self.local_nets.is_empty()
    }

    /// Is this host — a name or an address, as the browser asked for it —
    /// named by a `@local` list? The relay then dials it from this machine,
    /// after checking what the name resolves to (`is_private_network`).
    pub fn reached_locally(&self, host: &str) -> bool {
        if !self.is_local() {
            return false;
        }
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return self.local_nets.iter().any(|&(net, bits)| in_net(ip, net, bits));
        }
        normalise(host).is_some_and(|n| self.local_names.contains(&n))
    }

    /// Is this host refused — named in a blocklist, or absent from a whitelist
    /// the profile carries?
    pub fn blocks(&self, host: &str) -> bool {
        if self.refuses_nothing() {
            return false;
        }
        let Some(name) = normalise(host) else {
            // Not a name this can match: an IP literal, a single label. A
            // whitelist refuses it — "only these domains" cannot admit what
            // it cannot name — and a blocklist lets it through, as before.
            return self.allowed.is_some();
        };
        if let Some(allowed) = &self.allowed {
            if !matches_or_parent(allowed, &name) {
                return true;
            }
        }
        matches_or_parent(&self.domains, &name)
    }
}

/// The name, then each parent. `a.b.example.com` asks for `a.b.example.com`,
/// `b.example.com`, `example.com`, `com` — four lookups, not a hundred
/// thousand comparisons.
fn matches_or_parent(set: &HashSet<String>, host: &str) -> bool {
    if set.is_empty() {
        return false;
    }
    let mut rest: &str = host;
    loop {
        if set.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, parent)) if !parent.is_empty() => rest = parent,
            _ => return false,
        }
    }
}

fn is_address(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Lowercased, with a trailing dot and any port removed. `None` for something
/// that is not a hostname at all.
fn normalise(raw: &str) -> Option<String> {
    let s = raw.trim().trim_end_matches('.');
    let s = s.split(':').next().unwrap_or(s);
    if s.is_empty() || !s.contains('.') {
        // A single label is either localhost or a typo, and blocking every
        // name that ends in it would be a wide net for no benefit.
        return None;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        // "0.0.0.0" as the whole entry is a malformed hosts line, not a domain.
        return None;
    }
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_') {
        return None;
    }
    Some(s.to_ascii_lowercase())
}


/// What a screen shows beside a list's name, without keeping the parsed set
/// around: how many entries it names and which way it reads.
pub struct Summary {
    pub entries: usize,
    pub allow_only: bool,
    pub local: bool,
}

pub fn summarise(body: &str) -> Summary {
    let l = Blocklist::parse(body);
    Summary { entries: l.len(), allow_only: l.is_allow_only(), local: l.is_local() }
}

/// An address on a private network: RFC 1918, the RFC 6598 shared space that
/// Tailscale and Headscale number tailnets from (100.64.0.0/10), or an IPv6
/// unique-local address.
///
/// NOT loopback: the agent's own API listens there, and a profile that could
/// reach it could drive the agent. NOT link-local: 169.254.169.254 is the
/// metadata service on every cloud machine. Neither is a network anybody
/// means by "my local network".
pub fn is_private_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_private_network(IpAddr::V4(v4)),
            None => (v6.segments()[0] & 0xfe00) == 0xfc00,
        },
    }
}

/// `10.1.2.3` or `100.64.0.0/10`, kept only if the whole of it is private.
fn parse_net(entry: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = match entry.split_once('/') {
        Some((a, b)) => (a, b.parse::<u8>().ok()?),
        None => (entry, if entry.contains(':') { 128 } else { 32 }),
    };
    let ip: IpAddr = addr.trim_start_matches('[').trim_end_matches(']').parse().ok()?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    if bits > width {
        return None;
    }
    let (first, last) = net_bounds(ip, bits);
    // Both ends: CIDR blocks are aligned, so a block whose first and last
    // addresses are private lies inside one private range. `10.0.0.0/7`
    // ends at 11.255.255.255 and is refused.
    (is_private_network(first) && is_private_network(last)).then_some((first, bits))
}

fn net_bounds(ip: IpAddr, bits: u8) -> (IpAddr, IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let n = u32::from(v4) & mask;
            (IpAddr::V4(n.into()), IpAddr::V4((n | !mask).into()))
        }
        IpAddr::V6(v6) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            let n = u128::from(v6) & mask;
            (IpAddr::V6(n.into()), IpAddr::V6((n | !mask).into()))
        }
    }
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    // An IPv4 address asked for as ::ffff:a.b.c.d is the same host.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    ip.is_ipv4() == net.is_ipv4() && net_bounds(ip, bits).0 == net
}

/// An entry that tried to be an address or a network and was not a private
/// one. It must not be read as a name instead.
fn looks_like_address(entry: &str) -> bool {
    entry.contains('/') || entry.contains(':') || entry.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_only_reads_the_list_inside_out() {
        let list = Blocklist::parse("@allow-only\nfacebook.com\n||fbcdn.net^\n");
        assert!(list.is_allow_only());
        assert_eq!(list.len(), 2);
        for ok in ["facebook.com", "www.facebook.com", "static.xx.fbcdn.net"] {
            assert!(!list.blocks(ok), "{ok} is the platform and must open");
        }
        for no in ["google.com", "notfacebook.com", "facebook.com.evil.example", "10.0.0.1"] {
            assert!(list.blocks(no), "{no} is not on the list and must be refused");
        }
    }

    #[test]
    fn a_whitelist_and_a_blocklist_on_one_profile_compose() {
        let mut list = Blocklist::parse("@allow-only\nfacebook.com\n");
        list.merge(Blocklist::parse("pixel.facebook.com\n"));
        assert!(!list.blocks("www.facebook.com"));
        assert!(list.blocks("pixel.facebook.com"), "allowed by the whitelist, then subtracted");
        assert!(list.blocks("example.com"));
        // Merging two whitelists widens, never narrows.
        list.merge(Blocklist::parse("@allow-only\ninstagram.com\n"));
        assert!(!list.blocks("instagram.com"));
        assert!(!list.blocks("www.facebook.com"));
    }

    #[test]
    fn the_directive_is_not_a_domain_and_is_case_insensitive() {
        let list = Blocklist::parse("@ALLOW-ONLY\nexample.com\n");
        assert!(list.is_allow_only());
        assert_eq!(list.len(), 1);
        // No directive: an ordinary list, as every existing file is.
        assert!(!Blocklist::parse("example.com\n").is_allow_only());
    }

    #[test]
    fn the_three_formats_a_published_list_comes_in() {
        let list = Blocklist::parse(
            "\
# a comment
0.0.0.0 ads.example.com
127.0.0.1  trackers.example.net
||beacon.example.org^
plain.example.io

! an adblock comment
",
        );
        assert_eq!(list.len(), 4, "{:?}", list.domains);
        for host in ["ads.example.com", "trackers.example.net", "beacon.example.org", "plain.example.io"] {
            assert!(list.blocks(host), "{host}");
        }
    }

    /// The behaviour that makes it useful, and the one that makes it safe.
    #[test]
    fn a_subdomain_is_blocked_and_a_lookalike_is_not() {
        let list = Blocklist::parse("doubleclick.net");
        assert!(list.blocks("doubleclick.net"));
        assert!(list.blocks("ad.doubleclick.net"));
        assert!(list.blocks("a.b.c.doubleclick.net"));

        // What a substring match would get wrong, and it is how a blocklist
        // takes down a site nobody meant to touch.
        assert!(!list.blocks("notdoubleclick.net"));
        assert!(!list.blocks("doubleclick.net.example.com"));
        assert!(!list.blocks("net"));
    }

    #[test]
    fn a_host_with_a_port_or_a_trailing_dot_still_matches() {
        let list = Blocklist::parse("ads.example.com");
        assert!(list.blocks("ads.example.com:443"));
        assert!(list.blocks("ADS.EXAMPLE.COM"));
        assert!(list.blocks("ads.example.com."));
    }

    /// Adblock rules that are not plain domains are skipped rather than
    /// approximated — an option or a path changes what the rule means.
    #[test]
    fn adblock_rules_that_are_not_domains_are_left_alone() {
        let list = Blocklist::parse(
            "\
||ads.example.com^
||tracker.example.com^$third-party
||example.com/ads/*
##.ad-banner
@@||allowed.example.com^
",
        );
        assert_eq!(list.len(), 1, "{:?}", list.domains);
        assert!(list.blocks("ads.example.com"));
        assert!(!list.blocks("tracker.example.com"), "an option changes the rule");
        assert!(!list.blocks("allowed.example.com"), "an exception is not a block");
    }

    #[test]
    fn an_empty_list_blocks_nothing_and_costs_nothing() {
        let list = Blocklist::default();
        assert!(list.is_empty());
        assert!(!list.blocks("anything.example.com"));
    }

    /// A literal address carries no name. Stated as a test so the limit is
    /// recorded rather than discovered.
    #[test]
    fn an_ip_literal_is_not_matched_by_any_domain_rule() {
        let list = Blocklist::parse("0.0.0.0 ads.example.com\nexample.com");
        assert!(!list.blocks("93.184.216.34"));
        // And a malformed hosts line whose only field is an address does not
        // become a domain entry.
        assert!(!list.blocks("0.0.0.0"));
    }

    /// The case it was built for: a vault on a tailnet, named by MagicDNS.
    #[test]
    fn a_local_list_names_hosts_and_private_networks() {
        let list = Blocklist::parse("@local\nvault.example.com\n100.64.0.0/10\n10.1.2.3\nfd00::/8\n");
        assert!(list.is_local());
        assert!(!list.is_allow_only());
        assert_eq!(list.len(), 4);
        for yes in ["vault.example.com", "VAULT.example.com.", "100.64.0.1", "100.127.255.254", "10.1.2.3", "fd00::1", "::ffff:100.64.0.1"] {
            assert!(list.reached_locally(yes), "{yes}");
        }
        for no in ["www.vault.example.com", "example.com", "10.1.2.4", "100.128.0.1", "8.8.8.8", "fe80::1"] {
            assert!(!list.reached_locally(no), "{no}");
        }
        // It blocks nothing on its own.
        assert!(!list.blocks("example.com"));
        assert!(!list.blocks("vault.example.com"));
    }

    /// What keeps it from being a real-IP leak: nothing public gets in, not
    /// even as a network that merely starts in private space.
    #[test]
    fn a_local_list_drops_everything_public() {
        let list = Blocklist::parse(
            "@local\n8.8.8.8\n0.0.0.0/0\n10.0.0.0/7\n127.0.0.1\n169.254.169.254\n::1\n2001:db8::/32\n::/0\n10.0.0.0/33\n",
        );
        assert!(!list.is_local(), "{:?}", list.local_nets);
        assert_eq!(list.len(), 0);
        assert!(!list.reached_locally("8.8.8.8"));
        assert!(!list.reached_locally("127.0.0.1"));
    }

    #[test]
    fn private_means_rfc1918_tailnets_and_ula_and_nothing_else() {
        for yes in ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "100.100.100.100", "fd12::1", "::ffff:192.168.0.1"] {
            assert!(is_private_network(yes.parse().unwrap()), "{yes}");
        }
        for no in ["127.0.0.1", "169.254.169.254", "0.0.0.0", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.32.0.1", "::1", "fe80::1", "2001:db8::1"] {
            assert!(!is_private_network(no.parse().unwrap()), "{no}");
        }
    }

    /// A `@local` entry loosens nothing: the agent merges this machine's
    /// local lists into every launch, team profiles included, and the
    /// organisation's whitelist and blocklist must still hold.
    #[test]
    fn a_local_entry_loosens_no_whitelist_and_no_blocklist() {
        let mut list = Blocklist::parse("@allow-only\nfacebook.com\n");
        list.merge(Blocklist::parse("@local\nvault.example.com\n100.64.0.0/10\n"));
        assert!(list.blocks("vault.example.com"), "not on the whitelist");
        assert!(list.blocks("100.64.0.1"));
        list.merge(Blocklist::parse("@allow-only\nvault.example.com\n"));
        assert!(!list.blocks("vault.example.com"), "named by the whitelist too");
        list.merge(Blocklist::parse("vault.example.com\n"));
        assert!(list.blocks("vault.example.com"));
    }

    /// `@local` and `@allow-only` in one file: local, or the internal hosts
    /// would become the only sites the profile may open.
    #[test]
    fn local_wins_over_allow_only_in_one_file() {
        let list = Blocklist::parse("@allow-only\n@local\nvault.example.com\n");
        assert!(list.is_local());
        assert!(!list.is_allow_only());
        assert!(!list.blocks("example.com"));
    }

    #[test]
    fn a_hundred_thousand_entries_is_a_handful_of_lookups() {
        let text: String = (0..100_000).map(|i| format!("0.0.0.0 host{i}.example.com\n")).collect();
        let list = Blocklist::parse(&text);
        assert_eq!(list.len(), 100_000);

        let start = std::time::Instant::now();
        for i in 0..10_000 {
            assert!(list.blocks(&format!("sub.host{}.example.com", i % 100_000)));
        }
        // Not a benchmark — a guard against somebody replacing the label walk
        // with a scan over the set, which would be a hundred thousand string
        // comparisons per connection on the path every request takes.
        assert!(start.elapsed().as_secs() < 2, "took {:?}", start.elapsed());
    }
}
