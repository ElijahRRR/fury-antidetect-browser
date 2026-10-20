// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import { useI18n } from "../i18n";
import { wgEndpoint } from "../proxyUrl";

/** A WireGuard proxy's .conf, pasted whole. The same in the proxy dialog and
 *  in the profile editor's inline form.
 *
 *  The whole file rather than its fields: providers hand out a file, and the
 *  agent parses it the way `wg-quick` does and says what it refuses (a split
 *  tunnel, no DNS line) on Check. The endpoint is shown back so the paste
 *  visibly took. */
export function WireGuardConf({ id, value, onChange, readOnly = false }: { id?: string; value: string; onChange: (v: string) => void; readOnly?: boolean }) {
  const { t } = useI18n();
  const endpoint = wgEndpoint(value);
  return (
    <>
      <textarea
        id={id}
        value={value}
        readOnly={readOnly}
        autoFocus={!readOnly}
        spellCheck={false}
        autoComplete="off"
        rows={9}
        style={{ fontFamily: "var(--mono)", fontSize: 12 }}
        placeholder={"[Interface]\nPrivateKey = …\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.provider.net:51820\nAllowedIPs = 0.0.0.0/0"}
        onChange={(e) => onChange(e.target.value)}
      />
      <p className="hint">
        {value.trim() && !endpoint
          ? t("px.wgNoEndpoint")
          : endpoint
            ? t("px.wgEndpoint", { endpoint: `${endpoint.host}:${endpoint.port}` })
            : t("px.wgHint")}
      </p>
    </>
  );
}
