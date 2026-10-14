// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

/** The proxy URL the agent's `parse_upstream` reads, built from form fields.
 *
 *  As typed, not percent-encoded: that parser does not decode, and a login
 *  like "id__cr.us;sessttl.60" encoded to "id__cr.us%3Bsessttl.60" was turned
 *  away by the proxy (13.10.2026).
 *
 *  A WireGuard proxy has no login: its secret is the whole .conf, kept where a
 *  password goes, and the URL carries it there as unpadded base64url —
 *  `wireguard://wg:<conf>@<endpoint>`. The agent (`wireguard::url`) and the
 *  shell (`commands.rs::proxy_url`) build the same string. */
export function proxyUrl(kind: string, host: string, port: number | string, user?: string | null, pass?: string | null): string {
  if (kind === "wireguard") {
    return `wireguard://wg:${base64url(pass ?? "")}@${host.trim()}:${Number(port)}`;
  }
  const auth = user ? `${user}:${pass ?? ""}@` : "";
  return `${kind}://${auth}${host.trim()}:${Number(port)}`;
}

function base64url(text: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(text)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The `Endpoint = host:port` of a WireGuard config, which is what the proxy
 *  is shown and matched by. `null` until the pasted text has one. */
export function wgEndpoint(conf: string): { host: string; port: number } | null {
  const line = conf.split(/\r?\n/).find((l) => /^\s*endpoint\s*=/i.test(l));
  const value = line?.split("=").slice(1).join("=").trim();
  const m = value?.match(/^\[?([^\]]+?)\]?:(\d{1,5})$/);
  if (!m) return null;
  const port = Number(m[2]);
  return port > 0 && port < 65536 ? { host: m[1], port } : null;
}
