// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import { useCallback, useEffect, useState } from "react";
import { useI18n } from "../i18n";
import { api } from "../api";

type Entry = Awaited<ReturnType<typeof api.audit>>[number];

/** Who did what, and when.
 *
 *  The table has been written to since the first migration and until now there
 *  was nowhere to read it, which made it a table rather than an audit. For the
 *  agencies this product is for, "who opened that profile on Tuesday" is the
 *  question asked after somebody leaves, and it is the reason a team pays for
 *  anything.
 *
 *  Owners and admins only, and the server is what decides that — this screen
 *  shows what it is given. A member seeing every action of every colleague is
 *  surveillance rather than accountability.
 *
 *  Paged by id rather than by page number. Rows arrive while somebody is
 *  reading, and OFFSET would show them one twice or skip it. */
export function Audit() {
  const { t } = useI18n();
  const [rows, setRows] = useState<Entry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  // Filters. An action prefix rather than a fixed list: actions are dotted
  // (`profile.launch`, `login.new_device`) so a family is a prefix, and a new
  // action is filterable the day it is written without touching this file.
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");

  const load = useCallback(async (before?: number) => {
    setBusy(true);
    try {
      const page = await api.audit(before, {
        action,
        actor,
        since: since ? new Date(since).toISOString() : "",
        until: until ? new Date(until + "T23:59:59").toISOString() : "",
      });
      // Fewer than asked for means the end. Asking again would be a request
      // that can only return nothing.
      if (page.length < 200) setDone(true);
      setRows((prev) => (before === undefined ? page : [...prev, ...page]));
      setError(null);
    } catch (e) {
      // An empty log and an unreachable server look identical unless the
      // failure is shown, and "no events" is the more reassuring of the two —
      // which is exactly why it must not be shown for the wrong reason.
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [action, actor, since, until]);

  useEffect(() => {
    setDone(false);
    void load();
  }, [load]);

  const filters = (
    <div className="row" style={{ flexWrap: "wrap", gap: "var(--s-2)", marginBottom: "var(--s-2)" }}>
      <select value={action} onChange={(e) => setAction(e.target.value)} style={{ minWidth: 150 }}>
        <option value="">{t("aud.all")}</option>
        <option value="login.">{t("aud.logins")}</option>
        <option value="profile.">{t("aud.profiles")}</option>
        <option value="proxy.">{t("aud.proxies")}</option>
        <option value="project.">{t("aud.projects")}</option>
        <option value="org.">{t("aud.org")}</option>
        <option value="session.">{t("aud.sessions")}</option>
        <option value="user.">{t("aud.users")}</option>
      </select>
      <input placeholder={t("aud.who")} value={actor} onChange={(e) => setActor(e.target.value)} style={{ width: 200 }} />
      <input type="date" value={since} onChange={(e) => setSince(e.target.value)} style={{ width: 150 }} />
      <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} style={{ width: 150 }} />
    </div>
  );

  if (error) {
    return (
      <div className="notice warnBar" role="status">
        {error}
      </div>
    );
  }

  if (rows.length === 0 && !busy) {
    return (
      <div className="empty pad">
        {filters}
        <p>{t("aud.empty")}</p>
        <p className="muted">{t("aud.emptyHint")}</p>
      </div>
    );
  }

  return (
    <div className="tableWrap">
      {filters}
      <table className="grid">
        <thead>
          <tr>
            <th>{t("aud.when")}</th>
            <th>{t("aud.whoCol")}</th>
            <th>{t("aud.what")}</th>
            <th>{t("aud.detail")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="mono">{r.at.replace("T", " ").slice(0, 19)}</td>
              <td>{r.actor}</td>
              <td className="mono">{r.action}</td>
              <td className="muted">
                {/* The detail is whatever the action recorded, so it is shown
                    as it was stored rather than interpreted. A renderer that
                    understood some actions and not others would show a blank
                    cell for the ones it did not, which reads as "nothing
                    happened". */}
                {r.detail && Object.keys(r.detail as object).length > 0
                  ? JSON.stringify(r.detail)
                  : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {!done && (
        <button
          className="ghost"
          disabled={busy}
          onClick={() => void load(rows[rows.length - 1]?.id)}
        >
          {busy ? t("aud.loading") : t("aud.older")}
        </button>
      )}
    </div>
  );
}
