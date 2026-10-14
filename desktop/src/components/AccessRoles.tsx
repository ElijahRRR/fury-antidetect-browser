// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

import { useState } from "react";
import { api, type AccessRole, type Perm } from "../api";
import { useI18n, type Key } from "../i18n";
import { useAsk } from "./Ask";

/** Roles the organisation names itself (server 0017): a set of the ten
 *  project rights under a name, given to people project by project in the
 *  table above. A grant on a role follows it — the server rewrites everyone's
 *  rights when the boxes here change — which is the point of having roles
 *  rather than ticking the same three boxes for twenty operators.
 *
 *  The list is loaded by Users, which also needs it for the pickers, and
 *  reloaded through `onChanged` because saving rewrites grants it shows. */
export function AccessRoles({
  roles,
  allPerms,
  onChanged,
}: {
  roles: AccessRole[];
  allPerms: Perm[];
  onChanged: () => Promise<void>;
}) {
  const { t, say } = useI18n();
  const { ask, dialog } = useAsk();
  const [editing, setEditing] = useState<{ id: string | null; name: string; perms: Set<Perm> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await onChanged();
      return true;
    } catch (e) {
      setError(say(e));
      return false;
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      {dialog}
      <h2 className="sectionTitle" style={{ marginTop: "var(--s-6)" }}>{t("ar.title")}</h2>
      <p className="hint" style={{ maxWidth: 620 }}>{t("ar.hint")}</p>
      {error && <p className="error">{error}</p>}
      {roles.length > 0 && (
        <table className="grid" style={{ maxWidth: 720 }}>
          <tbody>
            {roles.map((r) => (
              <tr key={r.id}>
                <td>
                  <div className="name">{r.name}</div>
                  <div className="muted small">
                    {r.permissions.map((p) => t(("perm." + p) as Key)).join(" · ")}
                  </div>
                </td>
                <td className="muted small" style={{ whiteSpace: "nowrap" }}>
                  {t("ar.holders", { n: r.grants })}
                </td>
                <td className="actions">
                  <button
                    className="ghost"
                    disabled={busy}
                    onClick={() => setEditing({ id: r.id, name: r.name, perms: new Set(r.permissions) })}
                  >
                    {t("row.edit")}
                  </button>
                  <button
                    className="ghost danger"
                    disabled={busy}
                    onClick={async () => {
                      const go = await ask({
                        title: t("ar.delete", { name: r.name }),
                        detail: t("ar.confirmDelete", { n: r.grants }),
                        confirmLabel: t("row.delete"),
                        danger: true,
                      });
                      if (go === null) return;
                      await run(() => api.deleteAccessRole(r.id));
                    }}
                  >
                    {t("row.delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!editing && (
        <button
          style={{ marginTop: "var(--s-2)" }}
          onClick={() => setEditing({ id: null, name: "", perms: new Set<Perm>(["view", "launch"]) })}
        >
          {t("ar.new")}
        </button>
      )}
      {editing && (
        <div style={{ maxWidth: 720, marginTop: "var(--s-3)" }}>
          <div className="field">
            <label htmlFor="ar-name">{t("ar.name")}</label>
            <div>
              <input
                id="ar-name"
                value={editing.name}
                maxLength={64}
                placeholder={t("ar.namePlaceholder")}
                autoFocus
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </div>
          </div>
          {/* `view` is always on, as in the row editor: the server adds it
              anyway, and a box that unticks and comes back is a lie. */}
          <div className="permsGrid" style={{ marginTop: "var(--s-2)" }}>
            {allPerms.map((p) => (
              <label key={p} className="row" style={{ gap: 6, alignItems: "flex-start" }}>
                <input
                  type="checkbox"
                  style={{ width: 13, height: 13, marginTop: 2, accentColor: "var(--accent)" }}
                  checked={p === "view" || editing.perms.has(p)}
                  disabled={busy || p === "view"}
                  onChange={(e) => {
                    const perms = new Set(editing.perms);
                    if (e.target.checked) perms.add(p);
                    else perms.delete(p);
                    setEditing({ ...editing, perms });
                  }}
                />
                <span className="small">{t(("perm." + p) as Key)}</span>
              </label>
            ))}
          </div>
          <p className="hint small" style={{ marginTop: "var(--s-2)" }}>
            {t("ar.ceiling")}
            {editing.id && roles.find((r) => r.id === editing.id)?.grants
              ? " " + t("ar.rewrites", { n: roles.find((r) => r.id === editing.id)?.grants ?? 0 })
              : ""}
          </p>
          <div className="row" style={{ marginTop: "var(--s-2)" }}>
            <button
              className="primary"
              disabled={busy || !editing.name.trim()}
              onClick={async () => {
                const ok = await run(() =>
                  api.saveAccessRole(
                    editing.id,
                    editing.name.trim(),
                    allPerms.filter((p) => p === "view" || editing.perms.has(p)),
                  ),
                );
                if (ok) setEditing(null);
              }}
            >
              {t("ar.save")}
            </button>
            <button className="ghost" onClick={() => setEditing(null)}>
              {t("ui.cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
