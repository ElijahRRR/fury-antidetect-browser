// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! Room for the sockets a relay holds.
//!
//! Every tunnel through a relay is two descriptors, the browser's end and the
//! site's, and every open profile is a relay. An application started from the
//! Finder gets launchd's soft limit of 256 (`launchctl limit maxfiles`), which
//! a terminal never shows: there `ulimit -n` is in the hundreds of thousands,
//! so the agent run by hand never runs out.
//!
//! Run out it did. A tester's log (18.10.2026, macOS 26.2, three to five
//! no-proxy profiles with web.telegram.org and ad-heavy pages, behind Mullvad
//! multihop) had 1100 lines of "failed to lookup address information:
//! nodename nor servname provided" and 39 agent restarts in a day. It read as
//! DNS and was not: at the limit macOS's getaddrinfo cannot open its socket to
//! mDNSResponder and answers EAI_NONAME, the same words as a name that does not
//! exist. Measured here with a Python process held at 256: the lookup fails
//! with exactly that message and succeeds again once three descriptors are
//! freed. The next accept() on the IPC socket then failed with EMFILE, the
//! agent exited, and every profile lost its relay.
//!
//! Windows has no per-process descriptor limit that sockets count against, so
//! there is nothing to do there.

/// What the agent asks for. 10240 is macOS's `OPEN_MAX`: a soft limit above
/// it is refused by `setrlimit` even when the hard limit is "unlimited", and
/// forty times the old ceiling is far more than any number of profiles a
/// person keeps open.
#[cfg(unix)]
const WANT: u64 = 10240;

/// Raise this process's soft descriptor limit towards [`WANT`], never past the
/// hard limit. Returns `(before, after)` for the log, or `None` where there is
/// no such limit or it could not be read.
///
/// Children inherit it. That is harmless for Chromium, which sets its own limit
/// at startup on macOS, and it is what a browser started from a terminal would
/// have anyway.
pub fn raise_fd_limit() -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: a valid pointer to an rlimit this function owns.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
            return None;
        }
        let before = lim.rlim_cur as u64;
        let target = WANT.min(lim.rlim_max as u64);
        if before >= target {
            return Some((before, before));
        }
        let raised = libc::rlimit { rlim_cur: target as libc::rlim_t, rlim_max: lim.rlim_max };
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
            return Some((before, before));
        }
        Some((before, target))
    }
    #[cfg(windows)]
    {
        None
    }
}

/// An accept() that failed because this process or the machine is out of
/// descriptors. Worth waiting out rather than stopping for: one connection
/// closing is enough to make the next accept succeed.
pub fn is_out_of_descriptors(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
    }
    #[cfg(windows)]
    {
        let _ = e;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_limit_ends_at_least_where_it_started() {
        let (before, after) = raise_fd_limit().expect("RLIMIT_NOFILE is readable on Unix");
        assert!(after >= before);
    }

    #[test]
    fn emfile_is_recognised_and_a_refusal_is_not() {
        assert!(is_out_of_descriptors(&std::io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(is_out_of_descriptors(&std::io::Error::from_raw_os_error(libc::ENFILE)));
        assert!(!is_out_of_descriptors(&std::io::Error::from_raw_os_error(libc::ECONNREFUSED)));
    }
}
