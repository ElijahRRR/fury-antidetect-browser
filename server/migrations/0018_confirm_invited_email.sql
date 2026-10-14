-- Confirming that whoever redeems an invitation reads the inbox it was issued
-- for (mail.rs, api.rs enroll_email_*).
--
-- A code pasted into a group chat enrolled whoever typed it first, under the
-- invited address and with their own password; nothing told the owner it was
-- not the person they invited (14.10.2026). With mail configured the server
-- sends six digits to the address, and only the answer to them -- a one-time
-- proof -- lets the enrolment through.
--
-- Hashes only, like code_hash: a database dump should not yield a working
-- code or proof. The counters are what keep six digits from being guessed
-- (five wrong answers spend the code) and the address from being flooded
-- (five letters per invitation, a minute apart).

ALTER TABLE enrollments
    ADD COLUMN email_code_hash       BYTEA,
    ADD COLUMN email_code_expires_at TIMESTAMPTZ,
    ADD COLUMN email_code_attempts   INT NOT NULL DEFAULT 0,
    ADD COLUMN email_code_sent_at    TIMESTAMPTZ,
    ADD COLUMN email_codes_sent      INT NOT NULL DEFAULT 0,
    ADD COLUMN email_proof_hash      BYTEA;
