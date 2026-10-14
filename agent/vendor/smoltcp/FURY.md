# smoltcp 0.12.0, vendored

Taken unchanged from crates.io (`smoltcp-0.12.0`, 0BSD, see `LICENSE-0BSD.txt`)
and wired in with `[patch.crates-io]` in the workspace `Cargo.toml`. The
`[[example]]` and `[[bench]]` sections and the files they name were dropped
from the manifest; nothing else in the tree was.

The one change, marked `FURY:` in `src/socket/tcp.rs`:

- `Socket::set_window_shift` lets the caller choose the window scale a SYN
  advertises. Upstream derives it from the receive buffer's size, which gives
  64 KiB buffers a scale of 1 that no real OS sends; WireGuard profiles need
  Windows' 8, Linux's 7 or macOS's 6 to match the persona (`agent/src/syn_shape.rs`).

To move to a newer smoltcp: copy the release in, drop the examples again, and
re-apply that one hunk. `grep -rn FURY: src` finds it.
