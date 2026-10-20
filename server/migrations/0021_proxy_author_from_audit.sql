-- Who added a proxy, for the proxies added before 0015 recorded it.
--
-- 0015 left created_by NULL on every older proxy and said those stay with the
-- owners and admins who added them. A person whose role was lowered since is
-- then refused their own proxies: a tester met "this proxy was added by a
-- colleague" on one he had added himself (20.10.2026), and the form only said
-- so at Save, after he had typed every field in again.
--
-- The audit log has known all along: every create writes "proxy.create" with
-- the actor and the proxy's id (since 31.07.2026). Proxies older than that, or
-- whose author is gone from the log, stay NULL and stay with owners and admins.
--
-- Both tables FORCE row-level security (0006), and a migration runs with no
-- app.user_id, so under their policies this UPDATE would see no rows and
-- report success. The owner's exemption is restored for this one transaction.

ALTER TABLE proxies      NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events NO FORCE ROW LEVEL SECURITY;

UPDATE proxies x
   SET created_by = a.actor_user_id
  FROM (SELECT DISTINCT ON (target_id) target_id, org_id, actor_user_id
          FROM audit_events
         WHERE action = 'proxy.create' AND actor_user_id IS NOT NULL
         ORDER BY target_id, at) a
 WHERE x.created_by IS NULL
   AND a.target_id = x.id
   AND a.org_id = x.org_id;

ALTER TABLE proxies      FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
