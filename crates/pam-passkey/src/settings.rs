//! The settings `setup` writes to the user's login keychain (`config`) and the helper reads as
//! PAM_USER (DESIGN 状態と設定).

use crate::store::StoreConfig;
use pam_passkey::keychain::{Keychain, KeychainError, SystemItem};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub const DEFAULT_PAGE_URL: &str = "https://pam-passkey.github.io/";

/// The login keychain item `config`: one user's settings, as setup checked them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub page_url: String,
    pub store: StoreConfig,
    /// Empty: show the URLs on the terminal.
    pub send_command: String,
}

/// `page_url` and what is derived from it: the origin the assertion must come from and the
/// RP ID the passkey belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub url: String,
    pub origin: String,
    pub rp_id: String,
}

impl Page {
    pub fn parse(text: &str) -> Result<Self, String> {
        let url = Url::parse(text).map_err(|error| format!("page_url: {error}"))?;
        if url.scheme() != "https" {
            return Err("page_url must be an https URL".into());
        }
        // The approval URL is <page_url>#<presigned GET>; a fragment of its own would be lost.
        if url.fragment().is_some() {
            return Err("page_url must not have a fragment".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("page_url must not carry credentials".into());
        }
        // An RP ID is a domain; WebAuthn does not accept IP addresses.
        let Some(Host::Domain(host)) = url.host() else {
            return Err("page_url must name its host by domain".into());
        };
        Ok(Self {
            rp_id: host.to_owned(),
            origin: url.origin().ascii_serialization(),
            url: url.as_str().to_owned(),
        })
    }
}

/// An item that may be absent: `Ok(None)` only for "not found".
pub fn read_optional(
    keychain: &Keychain,
    item: SystemItem,
) -> Result<Option<String>, KeychainError> {
    match keychain.read_system(item) {
        Ok(value) => Ok(Some(value)),
        Err(KeychainError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The default page gives the default RP ID and an origin without a path or port.
    #[test]
    fn default_page_derives_origin_and_rp_id() {
        let page = Page::parse(DEFAULT_PAGE_URL).unwrap();
        assert_eq!(page.url, "https://pam-passkey.github.io/");
        assert_eq!(page.origin, "https://pam-passkey.github.io");
        assert_eq!(page.rp_id, "pam-passkey.github.io");
        // A fork on another host and port keeps both in its origin.
        let fork = Page::parse("https://example.com:8443/approve/").unwrap();
        assert_eq!(fork.origin, "https://example.com:8443");
        assert_eq!(fork.rp_id, "example.com");
        // The default port is not part of the origin, as browsers serialize it.
        let explicit = Page::parse("https://pam-passkey.github.io:443/").unwrap();
        assert_eq!(explicit.origin, "https://pam-passkey.github.io");
    }

    // Pages that could not be a WebAuthn origin, or that would break the approval URL, are refused.
    #[test]
    fn rejects_unusable_pages() {
        for text in [
            "http://pam-passkey.github.io/",
            "https://pam-passkey.github.io/#x",
            "https://user:pass@pam-passkey.github.io/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "pam-passkey.github.io",
            "",
        ] {
            assert!(Page::parse(text).is_err(), "{text}");
        }
    }
}
