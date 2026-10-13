-- Machines that belong to the organisation: personas captured from a real
-- computer and shared with the team.
--
-- A server accepted only the catalogue it was built with, so a machine a
-- member captured ("Snapshot this machine", agent/src/capture.rs) could be
-- used for profiles on that member's computer and for no team profile at all:
-- create_profile refused it as "the client and the server ship different
-- catalogues" (tester, 13.10.2026). The persona is stored whole, as the agent
-- reads it, and validated with the same code before it is stored; every
-- computer that opens a team profile on it is handed it by its shell.
--
-- The text is a persona and nothing else. It describes a machine -- screen,
-- GPU, fonts, voices -- and no network or account fields, which is what the
-- capture's own conversion guarantees (fury-detect persona, personas-check).

CREATE TABLE org_personas (
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    id          TEXT        NOT NULL,
    persona     JSONB       NOT NULL,
    created_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id)
);

ALTER TABLE org_personas ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_personas FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON org_personas USING (user_in_org(org_id));
