// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import { useCallback, useEffect, useState } from "react";
import { api, type LoginEvent, type SecurityPolicy, type SessionRow } from "../api";
import { useI18n } from "../i18n";
import { withStepUp } from "../stepUp";
import { useAsk } from "./Ask";
import { Select } from "./Select";

/** The organisation's sign-in policy, its login journal, and everyone's
 *  sessions. Owners and admins; the policy itself is the owner's to change.
 *
 *  What the leaders on team features sell under "account security"
 *  (docs/08 §4) and what the server grew on 12.09.2026 (server/src/security.rs).
 *  The screen is deliberately plain: three questions an agency owner asks —
 *  who must use a code, from where may people sign in, who is signed in right
 *  now — and one list nobody reads until the day they have to. */
export function Security({ isOwner }: { isOwner: boolean }) {
  const { t, say } = useI18n();
  const { ask, dialog } = useAsk();
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null);
  const [members, setMembers] = useState<{ user_id: string; email: string; totp_enabled_at: string | null }[]>([]);
  const [allowText, setAllowText] = useState("");
  const [logins, setLogins] = useState<LoginEvent[]>([]);
  const [outcome, setOutcome] = useState("");
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await api.orgSecurity();
      setPolicy(s.policy);
      setMembers(s.members);
      setAllowText(s.policy.ip_allowlist.join("\n"));
      setLogins(await api.loginEvents(null, outcome || null, null));
      setSessions(await api.sessions(true));
      setError(null);
    } catch (e) {
      setError(say(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [outcome]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) return <div className="notice warnBar">{error}</div>;
  if (!policy) return <p className="hint">{t("ext.loading")}</p>;

  const notEnrolled = members.filter((m) => !m.totp_enabled_at);

  return (
    <div>
      {dialog}
      <h2 className="sectionTitle" style={{ marginTop: "var(--s-6)" }}>{t("sec.policy")}</h2>
      <div className="field">
        <label>{t("sec.secondFactor")}</label>
        <div>
          <Select
            value={policy.second_factor}
            disabled={!isOwner}
            onChange={(e) => setPolicy({ ...policy, second_factor: e.target.value as SecurityPolicy["second_factor"] })}
          >
            <option value="off">{t("sec.sfOff")}</option>
            <option value="new_device">{t("sec.sfNewDevice")}</option>
            <option value="always">{t("sec.sfAlways")}</option>
          </Select>
          <p className="hint">{t("sec.secondFactorHint")}</p>
          {policy.second_factor !== "off" && notEnrolled.length > 0 && (
            <p className="hint warn">
              {t("sec.notEnrolled", { n: notEnrolled.length })} {notEnrolled.map((m) => m.email).join(", ")}
            </p>
          )}
        </div>
      </div>
      <div className="field">
        <label>{t("sec.allowlist")}</label>
        <div>
          <textarea
            rows={4}
            value={allowText}
            disabled={!isOwner}
            spellCheck={false}
            placeholder={"203.0.113.0/24\n198.51.100.7"}
            style={{ width: "100%", maxWidth: 420, fontFamily: "var(--mono)", fontSize: 12 }}
            onChange={(e) => setAllowText(e.target.value)}
          />
          <p className="hint">{t("sec.allowlistHint")}</p>
          <label className="row" style={{ gap: 6, marginTop: "var(--s-1)" }}>
            <input
              type="checkbox"
              style={{ width: 14, height: 14, accentColor: "var(--accent)" }}
              checked={policy.owner_exempt_from_allowlist}
              disabled={!isOwner}
              onChange={(e) => setPolicy({ ...policy, owner_exempt_from_allowlist: e.target.checked })}
            />
            <span>{t("sec.ownerExempt")}</span>
          </label>
        </div>
      </div>
      <div className="field">
        <label>{t("sec.sensitive")}</label>
        <div>
          <label className="row" style={{ gap: 6 }}>
            <input
              type="checkbox"
              style={{ width: 14, height: 14, accentColor: "var(--accent)" }}
              checked={policy.sensitive_actions_2fa}
              disabled={!isOwner}
              onChange={(e) => setPolicy({ ...policy, sensitive_actions_2fa: e.target.checked })}
            />
            <span>{t("sec.sensitive")}</span>
          </label>
          <p className="hint">{t("sec.sensitiveHint")}</p>
          {policy.sensitive_actions_2fa && notEnrolled.length > 0 && (
            <p className="hint warn">
              {t("sec.notEnrolled", { n: notEnrolled.length })} {notEnrolled.map((m) => m.email).join(", ")}
            </p>
          )}
        </div>
      </div>
      {isOwner && (
        <div className="row" style={{ marginBottom: "var(--s-4)" }}>
          <button
            className="primary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setNote(null);
              setError(null);
              try {
                // Changing the policy is itself one of the guarded actions.
                const r = await withStepUp(ask, t, () =>
                  api.setOrgSecurity({
                    ...policy,
                    ip_allowlist: allowText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
                  }),
                );
                if (r === null) return;
                setPolicy(r.policy);
                setNote(t("sec.saved"));
              } catch (e) {
                setError(say(e));
              } finally {
                setBusy(false);
              }
            }}
          >
            {t("sec.save")}
          </button>
          {note && <span className="muted">{note}</span>}
        </div>
      )}

      <h2 className="sectionTitle" style={{ marginTop: "var(--s-6)" }}>{t("sec.sessions")}</h2>
      <p className="hint">{t("sec.sessionsHint")}</p>
      {sessions.length === 0 ? (
        <p className="empty pad">{t("sec.noSessions")}</p>
      ) : (
        <table className="grid">
          <thead>
            <tr>
              <th>{t("sec.who")}</th>
              <th>{t("sec.machine")}</th>
              <th>{t("net.ip")}</th>
              <th>{t("sec.lastSeen")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td>
                  {s.email}
                  {s.current && <span className="muted small"> · {t("sec.thisSession")}</span>}
                </td>
                <td>{s.machine_name || "—"}</td>
                <td className="mono small">{s.ip ?? "—"}</td>
                <td className="muted small">{new Date(s.last_seen_at).toLocaleString()}</td>
                <td className="actions">
                  {!s.current && (
                    <button
                      className="ghost danger"
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true);
                        try {
                          await api.revokeSession(s.id);
                          await load();
                        } catch (e) {
                          setError(say(e));
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      {t("sec.endSession")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2 className="sectionTitle" style={{ marginTop: "var(--s-6)" }}>{t("sec.logins")}</h2>
      <div className="row" style={{ marginBottom: "var(--s-2)" }}>
        <Select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">{t("sec.allOutcomes")}</option>
          {["ok", "bad_password", "ip_refused", "totp_required", "totp_failed"].map((o) => (
            <option key={o} value={o}>{t(`sec.outcome.${o}` as never)}</option>
          ))}
        </Select>
      </div>
      {logins.length === 0 ? (
        <p className="empty pad">{t("sec.noLogins")}</p>
      ) : (
        <div className="tableWrap">
          <table className="grid">
            <thead>
              <tr>
                <th>{t("sec.when")}</th>
                <th>{t("sec.who")}</th>
                <th>{t("sec.outcomeCol")}</th>
                <th>{t("net.ip")}</th>
                <th>{t("sec.machine")}</th>
              </tr>
            </thead>
            <tbody>
              {logins.map((l) => (
                <tr key={l.id}>
                  <td className="mono small">{l.at.replace("T", " ").slice(0, 19)}</td>
                  <td>{l.email}</td>
                  <td className={l.outcome === "ok" ? "ok" : "warn"}>{t(`sec.outcome.${l.outcome}` as never)}</td>
                  <td className="mono small">{l.ip ?? "—"}</td>
                  <td className="muted small">{l.machine_name || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
