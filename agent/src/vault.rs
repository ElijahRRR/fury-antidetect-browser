// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! The vault — one key on this machine, and what it seals.
//!
//! # What it protects and what it cannot
//!
//! The local database holds proxy passwords and rotation links, and a rotation
//! link usually embeds an API key. Those were stored as typed. The file is mode
//! 0600 under a 0700 directory, which stops other users but not backup
//! software, sync clients, crash reporters or anything else running as this
//! user that copies a directory wholesale.
//!
//! So the secret columns are sealed with a key that lives in the OS keychain
//! rather than beside them. What that buys is real but bounded, and worth
//! stating plainly: a copied `fury.db` is now useless on its own. It is not a
//! defence against a process running as this user, which can ask the keychain
//! for the key exactly as the agent does.
//!
//! # Why this shape
//!
//! One machine key sealing individual values, rather than an encrypted
//! database. It is the same construction the bundle format needs
//! (docs/06-profile-sync.md): a key that never leaves the client, sealing
//! payloads a server only ever stores. Building it here first means the sync
//! layer inherits something already in use rather than something written the
//! week it is needed.
//!
//! Values carry a version prefix, so a database written before the vault
//! existed still reads — and is sealed the next time it is saved. A migration
//! that must run before the app starts is a migration that fails on somebody's
//! laptop at the worst moment.

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

const SERVICE: &str = "dev.fury.agent";
const ACCOUNT: &str = "vault-key";
const PREFIX: &str = "fury:v1:";
const NONCE_LEN: usize = 24;

/// The machine key, created on first use.
///
/// Read once and cached for the process: a keychain read is a round trip to a
/// daemon, and the profile list seals and opens a handful of values every time
/// it refreshes.
///
/// The read is deliberately *lazy*. macOS ties keychain permission to the
/// signature of the binary asking, so a rebuilt agent — a development build, or
/// any user the day after an update — gets a modal dialog, and the read blocks
/// inside the Security framework until somebody clicks it. Doing that at
/// startup meant the agent hung before it had logged a single line and before
/// the socket existed: from the application, an agent that simply never came
/// up. Loading on first use costs nothing when the answer is cached and keeps
/// the failure where it can be explained.
///
/// A failed read is remembered too, so a refused keychain does not put its
/// dialog up again at every list refresh -- but only until `retry`. It used to
/// be remembered for the life of the process: one dismissed dialog after an
/// update and every sealed proxy password read back as empty until Fury was
/// restarted, with nothing on screen to say so (tester, 15.10.2026).
pub struct Vault {
    key: std::sync::Mutex<Key>,
}

#[derive(Clone, Copy)]
enum Key {
    Unread,
    Have([u8; 32]),
    Failed,
}

impl Vault {
    pub fn open() -> Self {
        Self { key: std::sync::Mutex::new(Key::Unread) }
    }

    /// The key, read from the keychain the first time anything needs it.
    /// Held across the read, as the OnceLock before it was: two callers must
    /// not put up two dialogs.
    fn key(&self) -> Option<[u8; 32]> {
        let mut k = self.key.lock().unwrap_or_else(|e| e.into_inner());
        if let Key::Unread = *k {
            *k = match load_or_create() {
                Some(key) => Key::Have(key),
                None => Key::Failed,
            };
        }
        match *k {
            Key::Have(key) => Some(key),
            _ => None,
        }
    }

    /// Ask the keychain again after a failed read; the operator's "try again"
    /// once they have seen why their passwords are blank.
    pub fn retry(&self) -> bool {
        {
            let mut k = self.key.lock().unwrap_or_else(|e| e.into_inner());
            if let Key::Failed = *k {
                *k = Key::Unread;
            }
        }
        self.available()
    }

    /// Read the key now, off the caller's thread.
    ///
    /// Called once at startup so the usual case — a granted keychain, a few
    /// milliseconds — is over before the first profile is listed, and the
    /// unusual one puts its dialog on screen next to a running application
    /// rather than in place of one.
    pub fn prime(self: &std::sync::Arc<Self>) {
        let vault = std::sync::Arc::clone(self);
        std::thread::spawn(move || {
            let _ = vault.key();
        });
    }

    /// Seal a value for storage. Returns it unchanged when there is no key —
    /// an unavailable keychain must not stop someone using the application,
    /// and refusing to save a proxy would do exactly that.
    pub fn seal(&self, plain: &str) -> String {
        let Some(key) = self.key() else {
            return plain.to_string();
        };
        let nonce: [u8; NONCE_LEN] = rand::random();
        let cipher = XChaCha20Poly1305::new((&key).into());
        match cipher.encrypt(XNonce::from_slice(&nonce), plain.as_bytes()) {
            Ok(sealed) => {
                let mut blob = nonce.to_vec();
                blob.extend_from_slice(&sealed);
                format!("{PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(blob))
            }
            Err(_) => plain.to_string(),
        }
    }

    /// Open a stored value.
    ///
    /// A value without the prefix was written before the vault existed and is
    /// returned as it is. That is what makes this migration-free: nothing has
    /// to be rewritten before the app will start.
    pub fn open_value(&self, stored: &str) -> String {
        // An empty string rather than the ciphertext: a password that fails
        // to open must not be handed to a proxy as if it were the password.
        self.try_open(stored).unwrap_or_default()
    }

    /// Whether a stored value reads back as what was sealed. False for one
    /// sealed under a key this machine cannot get at right now -- which a save
    /// must then leave alone rather than overwrite with the blank it showed.
    pub fn opens(&self, stored: &str) -> bool {
        self.try_open(stored).is_some()
    }

    fn try_open(&self, stored: &str) -> Option<String> {
        let Some(rest) = stored.strip_prefix(PREFIX) else {
            return Some(stored.to_string());
        };
        let key = self.key()?;
        let blob = base64::engine::general_purpose::STANDARD.decode(rest).ok()?;
        if blob.len() <= NONCE_LEN {
            return None;
        }
        let cipher = XChaCha20Poly1305::new((&key).into());
        cipher
            .decrypt(XNonce::from_slice(&blob[..NONCE_LEN]), &blob[NONCE_LEN..])
            .ok()
            .and_then(|v| String::from_utf8(v).ok())
    }

    pub fn available(&self) -> bool {
        self.key().is_some()
    }

    /// A vault with a known key, so tests never touch the real keychain — and
    /// never leave an entry behind on the machine that ran them.
    #[cfg(test)]
    pub fn for_tests(key: [u8; 32]) -> Self {
        Self { key: std::sync::Mutex::new(Key::Have(key)) }
    }

    #[cfg(test)]
    pub fn for_tests_without_key() -> Self {
        Self { key: std::sync::Mutex::new(Key::Failed) }
    }
}

fn load_or_create() -> Option<[u8; 32]> {
    // Logged before the call, not after: on a signature the keychain does not
    // recognise this blocks until a dialog is answered, and the log is the only
    // place that says why.
    tracing::info!("reading the vault key — the OS may ask for permission");

    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .inspect_err(|e| tracing::warn!(error = %e, "no credential store — secrets stay as typed"))
        .ok()?;

    match entry.get_password() {
        Ok(existing) => base64::engine::general_purpose::STANDARD
            .decode(existing)
            .ok()
            .and_then(|v| v.try_into().ok()),
        Err(keyring::Error::NoEntry) => {
            let key: [u8; 32] = rand::random();
            let encoded = base64::engine::general_purpose::STANDARD.encode(key);
            match entry.set_password(&encoded) {
                Ok(()) => Some(key),
                Err(e) => {
                    // Refusing to run would be worse. Losing the ability to
                    // seal is a downgrade; losing the application is a failure.
                    tracing::warn!(error = %e, "could not store the vault key");
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not read the vault key");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault with a known key, so the tests do not touch the real keychain.
    fn fixed() -> Vault {
        Vault::for_tests([7u8; 32])
    }

    #[test]
    fn a_sealed_value_does_not_contain_the_secret() {
        let v = fixed();
        let sealed = v.seal("s3cr3t-proxy-password");
        assert!(sealed.starts_with(PREFIX));
        assert!(!sealed.contains("s3cr3t"), "the plaintext survived: {sealed}");
        assert_eq!(v.open_value(&sealed), "s3cr3t-proxy-password");
    }

    #[test]
    fn sealing_twice_gives_different_bytes() {
        // A per-value nonce. Without it, two profiles sharing a password would
        // be visibly the same row in a stolen database.
        let v = fixed();
        assert_ne!(v.seal("same"), v.seal("same"));
    }

    #[test]
    fn a_value_written_before_the_vault_still_reads() {
        // No migration step: an old database opens, and its values are sealed
        // the next time they are saved.
        let v = fixed();
        assert_eq!(v.open_value("plain-old-password"), "plain-old-password");
    }

    #[test]
    fn a_value_from_another_machine_opens_as_empty_not_as_ciphertext() {
        let sealed = fixed().seal("theirs");
        let other = Vault::for_tests([9u8; 32]);
        // Handing a proxy the base64 of somebody else's ciphertext, as if it
        // were a password, would be worse than failing.
        assert_eq!(other.open_value(&sealed), "");
    }

    #[test]
    fn without_a_keychain_values_pass_through_rather_than_breaking() {
        let none = Vault::for_tests_without_key();
        assert_eq!(none.seal("as typed"), "as typed");
        assert_eq!(none.open_value("as typed"), "as typed");
        assert!(!none.available());
    }
}
