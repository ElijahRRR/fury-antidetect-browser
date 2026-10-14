-- The key a profile's cookies are encrypted with, kept so a rotation can carry
-- it over instead of replacing it.
--
-- WHY. The core encrypts cookies under a key derived from the profile key
-- (patch 0110, shared-rs/src/keys.rs `os_crypt_key`), and the profile key is
-- derived from the organisation key. So replacing the organisation key -- which
-- removing a member does -- replaced every profile's cookie key too, while the
-- cookies on disk and inside every bundle stayed encrypted under the old one.
-- The agent then refused to launch each such profile rather than let Chromium
-- delete the rows it could not read (agent/src/ipc.rs, `Fury Key Id`). Met on
-- 14.10.2026: a member removed on the 13th, and a profile last opened on the
-- 12th would not open again.
--
-- WHAT. The cookie key, wrapped under the profile's CURRENT key. A rotation
-- unwraps it under the old profile key and wraps it under the new one, the way
-- a proxy's data key is moved -- 32 bytes per profile, and not one cookie row
-- touched. NULL means "never rotated since this existed": the key is still the
-- one derived from the profile key, and a client derives it as before.
--
-- WHY THAT IS NOT A LEAK. Somebody removed keeps the cookie key they could
-- always derive. It decrypts cookie values inside a profile directory, and the
-- directory reaches anyone only inside a bundle sealed under a fresh data key
-- that the new profile key wraps -- which they no longer have.

ALTER TABLE profiles ADD COLUMN wrapped_cookie_key BYTEA;

COMMENT ON COLUMN profiles.wrapped_cookie_key IS
    'The cookie encryption key, wrapped under the profile key of the current organisation key generation. NULL: derived from the profile key, as before any rotation.';
