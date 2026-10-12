// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! The profile's name under its icon in the macOS Dock.
//!
//! Every profile is the same signed core, so every one of them said "Fury"
//! in the Dock, and with five open the only way to find an account was to
//! click through them (tester, 12.10.2026).
//!
//! What the Dock shows is the application bundle's DIRECTORY name, not
//! CFBundleName and not anything the running process says about itself.
//! Measured on a two-line Cocoa program: CFBundleName "Fury" in a bundle named
//! DockName.app showed "DockName"; the same bundle copied to "console1 TR.app"
//! showed "console1 TR"; renaming the running process through LaunchServices
//! (_LSSetApplicationInformationItem, kLSDisplayNameKey) changed what lsappinfo
//! reported and left the Dock as it was.
//!
//! So each launch runs a copy of the core named after the profile. A clone,
//! not a copy (clonefile: 0.12 s, no blocks written), in dock.noindex so that
//! Spotlight does not list it as an application (paths::dock_dir). What was
//! checked on the notarised core before relying on it:
//!
//!   - the signature survives: a bundle's directory name is not part of what
//!     is signed (`codesign --verify --deep --strict`, and `spctl` still says
//!     "Notarized Developer ID");
//!   - the keychain does not ask: the Safe Storage entry trusts the core by
//!     its designated requirement (identifier dev.fury.core, team JKN8WHX7FS),
//!     not by path, so a clone anywhere opens it like the original;
//!   - the menu bar still says Fury: that one is CFBundleName.
//!
//! Remade on every launch -- the core may have been updated since the last
//! one, and a profile is never launched twice at once, so its clone is never
//! replaced under a running browser. Any failure here is not a failed launch:
//! the original core runs, and the Dock says Fury, as before.

use std::path::{Path, PathBuf};

/// The name as the Dock will show it, or None to leave it "Fury".
///
/// A directory name, so the two characters a macOS path cannot hold in a
/// component -- `/`, and `:` which Finder shows as `/` -- become `-`, control
/// characters go, a leading dot (a hidden directory) goes, and it is kept to
/// a length the Dock can show anyway.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn display_name(name: &str) -> Option<String> {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '/' || c == ':' { '-' } else { c })
        .take(80)
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').trim().to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The executable of this profile's named copy of the core, made now.
///
/// `core_binary` is `<X>.app/Contents/MacOS/<exe>`; the copy is
/// `dock.noindex/<profile id>/<name>.app` with the same path inside.
#[cfg(target_os = "macos")]
pub fn named_core(core_binary: &Path, profile_id: &str, name: &str) -> std::io::Result<PathBuf> {
    named_core_in(&crate::paths::dock_dir(), core_binary, profile_id, name)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn named_core_in(dock_dir: &Path, core_binary: &Path, profile_id: &str, name: &str) -> std::io::Result<PathBuf> {
    let invalid = |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, what.to_string());
    let name = display_name(name).ok_or_else(|| invalid("the profile has no name to show"))?;
    // A directory component, so it has to be one.
    if profile_id.is_empty() || !profile_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(invalid("not a profile id"));
    }
    let exe = core_binary.file_name().ok_or_else(|| invalid("no executable"))?;
    let app = core_binary
        .parent()
        .filter(|p| p.ends_with("Contents/MacOS"))
        .and_then(Path::parent)
        .and_then(Path::parent)
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
        .ok_or_else(|| invalid("the core is not inside an application bundle"))?;

    let dir = dock_dir.join(profile_id);
    // Whatever the last launch left, including a clone under another name.
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    let named = dir.join(format!("{name}.app"));
    clone(app, &named)?;
    Ok(named.join("Contents/MacOS").join(exe))
}

#[cfg(target_os = "macos")]
fn clone(src: &Path, dst: &Path) -> std::io::Result<()> {
    fury_platform::tree::clone_tree(src, dst)
}

#[cfg(not(target_os = "macos"))]
fn clone(_src: &Path, _dst: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("the Dock is a macOS thing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_becomes_one_directory_component() {
        assert_eq!(display_name("console1.access@gmail.com | TR").as_deref(), Some("console1.access@gmail.com | TR"));
        assert_eq!(display_name("a/b:c").as_deref(), Some("a-b-c"));
        assert_eq!(display_name("  .hidden ").as_deref(), Some("hidden"));
        assert_eq!(display_name("tab\there\n").as_deref(), Some("tabhere"));
        assert_eq!(display_name("   "), None);
        assert_eq!(display_name("..."), None);
        assert_eq!(display_name(&"x".repeat(300)).map(|s| s.chars().count()), Some(80));
        assert_eq!(display_name("Профиль 1").as_deref(), Some("Профиль 1"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_copy_is_named_after_the_profile_and_remade_each_time() {
        let root = std::env::temp_dir().join(format!("fury-dock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let core = root.join("core.bundle/Fury.app/Contents/MacOS");
        std::fs::create_dir_all(&core).unwrap();
        std::fs::write(core.join("Fury"), b"v1").unwrap();
        let dock = root.join("dock.noindex");

        let exe = named_core_in(&dock, &core.join("Fury"), "p-1", "kg-seo 1").unwrap();
        assert_eq!(exe, dock.join("p-1/kg-seo 1.app/Contents/MacOS/Fury"));
        assert_eq!(std::fs::read(&exe).unwrap(), b"v1");

        // A new core and a renamed profile: the old clone goes, the new one
        // carries the new core.
        std::fs::write(core.join("Fury"), b"v2").unwrap();
        let exe = named_core_in(&dock, &core.join("Fury"), "p-1", "kg-seo 2").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"v2");
        assert!(!dock.join("p-1/kg-seo 1.app").exists());

        assert!(named_core_in(&dock, &core.join("Fury"), "../x", "n").is_err());
        assert!(named_core_in(&dock, Path::new("/usr/bin/true"), "p-2", "n").is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
