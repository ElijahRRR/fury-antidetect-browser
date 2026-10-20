// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import { useCallback, useEffect, useState } from "react";
import { api, type OrgDomainList } from "../api";
import { useI18n } from "../i18n";

/** The organisation's domain lists: the owner decides that a freelancer's
 *  profiles open the one platform they exist for and nothing beside it, and
 *  the freelancer's machine does not get a vote. Lists are written here and
 *  attached to a member through their grant in the People table above. The
 *  format is the agent's own (docs/16 5.26): a hosts file, an Adblock list,
 *  one domain per line; `@allow-only` on the first line for a whitelist. */
export function TeamDomainLists({ canEdit }: { canEdit: boolean }) {
  const { t, say } = useI18n();
  const [lists, setLists] = useState<OrgDomainList[]>([]);
  const [editing, setEditing] = useState<{ id: string | null; name: string; body: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setLists(await api.orgDomainLists());
      setError(null);
    } catch (e) {
      setError(say(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div>
      <h2 className="sectionTitle" style={{ marginTop: "var(--s-6)" }}>{t("tdl.title")}</h2>
      <p className="hint" style={{ maxWidth: 620 }}>{t("tdl.hint")}</p>
      {error && <p className="error">{error}</p>}
      {lists.length > 0 && (
        <table className="grid" style={{ maxWidth: 720 }}>
          <tbody>
            {lists.map((l) => (
              <tr key={l.id}>
                <td>
                  <div className="name">{l.name}</div>
                  <div className="muted small">
                    {l.local ? t("pd.listLocal", { n: l.domains }) : l.allow_only ? t("pd.listAllowOnly", { n: l.domains }) : t("pd.listBlocks", { n: l.domains })}
                  </div>
                </td>
                <td className="actions">
                  {canEdit && (
                    <>
                      <button className="ghost" disabled={busy} onClick={() => setEditing({ id: l.id, name: l.name, body: l.body })}>
                        {t("row.edit")}
                      </button>
                      <button
                        className="ghost danger"
                        disabled={busy}
                        onClick={async () => {
                          setBusy(true);
                          try {
                            await api.deleteOrgDomainList(l.id);
                            await load();
                          } catch (e) {
                            setError(say(e));
                          } finally {
                            setBusy(false);
                          }
                        }}
                      >
                        {t("row.delete")}
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {canEdit && !editing && (
        <button style={{ marginTop: "var(--s-2)" }} onClick={() => setEditing({ id: null, name: "", body: "" })}>
          {t("tdl.new")}
        </button>
      )}
      {editing && (
        <div style={{ maxWidth: 620, marginTop: "var(--s-3)" }}>
          <div className="field">
            <label htmlFor="tdl-name">{t("set.listName")}</label>
            <div>
              <input id="tdl-name" value={editing.name} placeholder="facebook-only" onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
            </div>
          </div>
          <div className="field">
            <label htmlFor="tdl-body">{t("set.listText")}</label>
            <div>
              <textarea
                id="tdl-body"
                rows={7}
                value={editing.body}
                spellCheck={false}
                style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 12 }}
                placeholder={"@allow-only\nfacebook.com\n||fbcdn.net^"}
                onChange={(e) => setEditing({ ...editing, body: e.target.value })}
              />
              <div className="row" style={{ marginTop: "var(--s-2)" }}>
                <button
                  className="primary"
                  disabled={busy || !editing.name.trim() || !editing.body.trim()}
                  onClick={async () => {
                    setBusy(true);
                    setError(null);
                    try {
                      await api.saveOrgDomainList(editing.id, editing.name.trim(), editing.body);
                      setEditing(null);
                      await load();
                    } catch (e) {
                      setError(say(e));
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  {t("set.listSave")}
                </button>
                <button className="ghost" onClick={() => setEditing(null)}>{t("ui.cancel")}</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
