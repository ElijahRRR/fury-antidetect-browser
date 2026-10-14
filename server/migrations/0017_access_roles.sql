-- Roles an organisation names itself: a set of the ten project rights under a
-- name ("operator", "farmer"), given to people project by project.
--
-- Until now the ten boxes were ticked per person per project, and a team of
-- twenty operators meant ticking the same three boxes twenty times, then
-- un-ticking one of them twenty times when the policy changed (the request,
-- 14.10.2026). Competitors sell the same thing as member groups.
--
-- A grant that carries a role is LINKED to it: changing the role's boxes
-- rewrites `permissions` on every grant that points at it, in the same
-- transaction (api.rs, relink_role). `permissions` therefore stays the one
-- column every check reads -- rbac_guard, the listings, holds_somewhere -- and
-- none of them had to learn about roles. The org role (owner, admin, manager,
-- member) is untouched: it is still the ceiling, and a linked grant is capped
-- by it when it is written, exactly as a hand-ticked one is.
--
-- Deleting a role leaves the grants with the boxes they had, unlinked. Taking
-- access away from twenty people is what revoking is for, not a side effect of
-- tidying the list of roles.

CREATE TABLE org_access_roles (
    id           UUID        PRIMARY KEY,
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    -- The same bits as project_grants.permissions (0001).
    permissions  BIGINT      NOT NULL,
    created_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

ALTER TABLE org_access_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_access_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON org_access_roles USING (user_in_org(org_id));

ALTER TABLE project_grants
    ADD COLUMN access_role UUID REFERENCES org_access_roles(id) ON DELETE SET NULL;
CREATE INDEX project_grants_access_role ON project_grants (access_role) WHERE access_role IS NOT NULL;
