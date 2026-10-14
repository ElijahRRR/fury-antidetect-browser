// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Bogdan Shapovalov and the Fury authors

//! Fetching a `.crx` from the Chrome Web Store by id, the way the browser
//! itself would — and from where the browser would.
//!
//! The update endpoint hands out the current package for any id. What matters
//! here is not the URL but the route: the download goes **through the proxy
//! of the profile it is being installed into**, so Google sees the exit that
//! profile always shows it, and never the operator's own address beside an
//! extension id that says what the operator is up to. That was the objection
//! in `install_core.rs` to fetching anything automatically, and the decision
//! recorded in docs/12 (B, 12.09.2026) is this compromise: fetch, but only
//! along the profile's own path. A profile with no proxy fetches directly,
//! because directly *is* its path.
//!
//! What comes back is checked, not trusted: `ext::parse` recovers the signing
//! key and derives the id from it, and the caller refuses a package whose key
//! does not derive the id that was asked for. The endpoint is Google's, over
//! TLS, but the check costs nothing and is what "installed by id" means.

use anyhow::{bail, Context, Result};

/// A package larger than this is not an extension somebody would put in a
/// profile; it is a mistake or a redirect to somewhere else.
const MAX_BYTES: usize = 128 * 1024 * 1024;

/// The same request Chromium makes when it installs from the store.
pub fn crx_url(id: &str) -> String {
    format!(
        "https://clients2.google.com/service/update2/crx?response=redirect&prodversion={}&acceptformat=crx3&x=id%3D{id}%26uc",
        crate::CHROME_FULL_VERSION
    )
}

/// Download the package for `id`, through `proxy_url` when there is one.
pub async fn fetch(id: &str, proxy_url: Option<&str>) -> Result<Vec<u8>> {
    if !fury_shared::extensions::is_id(id) {
        bail!("{id:?} is not an extension id");
    }
    let mut b = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(format!(
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Safari/537.36",
            crate::CHROME_FULL_VERSION
        ));
    // Held until the download is done: a WireGuard profile's route is a relay
    // of our own, and it stops when this goes.
    let mut _relay = None;
    if let Some(p) = proxy_url {
        let p = if p.starts_with("wireguard://") {
            let (addr, guard) = crate::relay::loopback(crate::parse_upstream(p)?).await?;
            _relay = Some(guard);
            addr
        } else {
            p.to_string()
        };
        b = b.proxy(reqwest::Proxy::all(&p).context("the profile's proxy address")?);
    }
    let res = b.build()?.get(crx_url(id)).send().await.context("reaching the Web Store")?;
    if !res.status().is_success() {
        // 204 is what the endpoint says for an id it has never heard of.
        bail!("the Web Store answered {} for {id}", res.status());
    }
    if let Some(len) = res.content_length() {
        if len as usize > MAX_BYTES {
            bail!("the package is {len} bytes, which is not an extension");
        }
    }
    let bytes = res.bytes().await.context("downloading the package")?;
    if bytes.len() > MAX_BYTES {
        bail!("the package is {} bytes, which is not an extension", bytes.len());
    }
    if bytes.len() < 16 || &bytes[..4] != b"Cr24" {
        bail!("the Web Store did not return a CRX for {id}");
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_url_carries_the_id_and_our_version() {
        let u = super::crx_url("ddkjiahejlhfcafbddmgiahcphecmpfh");
        assert!(u.contains("x=id%3Dddkjiahejlhfcafbddmgiahcphecmpfh%26uc"));
        assert!(u.contains(&format!("prodversion={}", crate::CHROME_FULL_VERSION)));
        assert!(u.starts_with("https://clients2.google.com/"));
    }
}
