// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

/** The server offered to somebody who has not got one.
 *
 *  Fury is self-hosted and the first screen said so, with two buttons that both
 *  needed an address: connect to a server, or make an account on one. A person
 *  with neither read that as "so where do I get a server?" -- which is a fair
 *  question and had no answer in the application.
 *
 *  There are two answers now and they are for different people. Somebody
 *  working alone needs no server and no account at all: that is the
 *  "work without an account" button, it is the default the README describes,
 *  and the browser spoofs exactly the same either way. Somebody who wants their
 *  profiles on a server, or a team, needs one of these -- and this address is
 *  offered so that not having a machine of your own is not the end of the road.
 *
 *  WHAT SIGNING UP HERE MEANS, because a default that hides this would be worse
 *  than no default. Every sign-up creates its own organisation with the caller
 *  as owner, and an organisation is the boundary every query on that server
 *  already filters on -- so a stranger who signs up cannot address anything of
 *  anyone else's. That is structural rather than a check. The vault is still
 *  wrapped with a key derived from the account password, which the server never
 *  sees; what it holds is ciphertext it cannot open.
 *
 *  It is still somebody else's machine. Anyone who would rather that not be
 *  true can clear the field and type their own, which is why this is a
 *  PREFILLED VALUE and not a hidden default -- the address is visible, editable,
 *  and deleting it costs one keystroke.
 *
 *  Until 0.1.5 this was `204-168-178-23.sslip.io` -- the machine had no domain,
 *  and sslip.io resolving a hostname to the address written inside it was what
 *  made a certificate possible at all. The server still answers on that name so
 *  installs that saved it keep working; new installs get the domain. If the
 *  server ever moves, this is the only line in the desktop to change.
 */
export const DEFAULT_SERVER = "srv.furybrowser.dev";

/** Servers this project runs, under every name they answer to. Their owners
 *  are not the people using them, so a "your server is behind" notice is not
 *  shown for them: nobody there could act on it. */
export const OUR_SERVERS = [DEFAULT_SERVER, "204-168-178-23.sslip.io"];

/** `a` is a newer dotted version than `b`. Numeric, so 0.10.0 beats 0.9.0;
 *  a leading v and a pre-release suffix are ignored, as in src-tauri/update.rs. */
export function versionNewer(a: string, b: string): boolean {
  const parts = (v: string) =>
    v.replace(/^[vV]/, "").split(/[-+]/)[0].split(".").map((p) => parseInt(p, 10) || 0);
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return false;
}
