-- WireGuard as a kind of proxy (agent/src/wg_stack.rs, syn_shape.rs).
--
-- The whole .conf is the secret, and it travels where a password does: inside
-- credentials_enc, sealed on the client under the proxy's data key. So this
-- server stores nothing new and can read nothing new: host and port are the
-- config's Endpoint, kept for display and matching like any proxy's.
--
-- ADD VALUE commits with the migration's transaction and is not used inside
-- it, which is the one restriction Postgres puts on it.

ALTER TYPE proxy_kind ADD VALUE IF NOT EXISTS 'wireguard';
