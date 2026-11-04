use core_foundation::base::TCFType;
use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::base::{SecKeychainRef, errSecItemNotFound, errSecSuccess};
use std::ffi::CString;
use std::fmt;
use std::path::Path;

// SecBase.h defines these macOS-only legacy Keychain statuses; security-framework-sys
// exposes only part of this family. Distinguish a locked keychain by checking its status.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_INTERACTION_REQUIRED: i32 = -25315;
const ERR_SEC_AUTH_FAILED: i32 = -25293;

const SERVICE: &str = "pam-passkey";
const PROBE_SERVICE: &str = "pam-passkey-probe";
const SYSTEM_PATH: &str = "/Library/Keychains/System.keychain";

unsafe extern "C" {
    fn passkey_write_restricted(
        keychain: SecKeychainRef,
        self_path: *const std::ffi::c_char,
        service: *const std::ffi::c_char,
        account: *const std::ffi::c_char,
        value: *const u8,
        value_len: usize,
    ) -> i32;
    fn passkey_keychain_is_locked(keychain: SecKeychainRef) -> i32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemItem {
    PageUrl,
    Store,
    SendCommand,
    SigningKey,
    VerificationKey,
}

impl SystemItem {
    fn account(self) -> &'static str {
        match self {
            Self::PageUrl => "page_url",
            Self::Store => "store",
            Self::SendCommand => "send_command",
            Self::SigningKey => "signing_key",
            Self::VerificationKey => "verification_key",
        }
    }
}

#[derive(Debug)]
pub enum KeychainError {
    InvalidInput(&'static str),
    Open(security_framework::base::Error),
    Operation(security_framework::base::Error),
    AccessDenied(i32),
    Locked(i32),
    NotFound,
    UnexpectedResult,
    Utf8(std::string::FromUtf8Error),
    CurrentExe(std::io::Error),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(out, "invalid {field}: empty or contains NUL"),
            Self::Open(error) => write!(out, "open keychain: {error} (OSStatus {})", error.code()),
            Self::Operation(error) => write!(
                out,
                "keychain operation: {error} (OSStatus {})",
                error.code()
            ),
            Self::AccessDenied(status) => write!(out, "keychain access denied (OSStatus {status})"),
            Self::Locked(status) => write!(out, "keychain locked (OSStatus {status})"),
            Self::NotFound => write!(out, "keychain item not found"),
            Self::UnexpectedResult => write!(out, "keychain returned an unexpected item type"),
            Self::Utf8(error) => write!(out, "keychain item is not UTF-8: {error}"),
            Self::CurrentExe(error) => write!(out, "find current executable: {error}"),
        }
    }
}

impl std::error::Error for KeychainError {}

pub struct Keychain {
    handle: SecKeychain,
}

impl Keychain {
    pub fn system() -> Result<Self, KeychainError> {
        Ok(Self {
            handle: SecKeychain::open(SYSTEM_PATH).map_err(KeychainError::Open)?,
        })
    }

    /// Open the login keychain explicitly, not the caller's (possibly root) default keychain.
    /// The caller must already have permanently dropped to the target user's uid.
    pub fn login(home: &Path) -> Result<Self, KeychainError> {
        Ok(Self {
            handle: SecKeychain::open(home.join("Library/Keychains/login.keychain-db"))
                .map_err(KeychainError::Open)?,
        })
    }

    fn query(&self, service: &str, account: &str) -> ItemSearchOptions {
        let mut query = ItemSearchOptions::new();
        query
            .keychains(std::slice::from_ref(&self.handle))
            .class(ItemClass::generic_password())
            .service(service)
            .account(account);
        query
    }

    fn classify(&self, error: security_framework::base::Error) -> KeychainError {
        let status = error.code();
        // Security.framework can report item-not-found even while the Keychain is locked.
        // SAFETY: the handle stays alive while Security.framework checks its unlock state.
        let locked = unsafe { passkey_keychain_is_locked(self.handle.as_concrete_TypeRef()) };
        if locked == 1 {
            return KeychainError::Locked(status);
        }
        if status == errSecItemNotFound {
            return KeychainError::NotFound;
        }
        if matches!(
            status,
            ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_INTERACTION_REQUIRED | ERR_SEC_AUTH_FAILED
        ) {
            return KeychainError::AccessDenied(status);
        }
        KeychainError::Operation(error)
    }

    fn read(&self, service: &str, account: &str) -> Result<String, KeychainError> {
        let mut query = self.query(service, account);
        query.load_data(true);
        let result = query.search().map_err(|error| self.classify(error))?;
        match result.into_iter().next() {
            Some(SearchResult::Data(value)) => {
                String::from_utf8(value).map_err(KeychainError::Utf8)
            }
            Some(_) => Err(KeychainError::UnexpectedResult),
            None => Err(KeychainError::NotFound),
        }
    }

    fn write(&self, service: &str, account: &str, value: &str) -> Result<(), KeychainError> {
        let executable = std::env::current_exe().map_err(KeychainError::CurrentExe)?;
        let executable = CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
            executable.as_os_str(),
        ))
        .map_err(|_| KeychainError::InvalidInput("executable path"))?;
        let service = CString::new(service).map_err(|_| KeychainError::InvalidInput("service"))?;
        let account = CString::new(account).map_err(|_| KeychainError::InvalidInput("account"))?;
        // SAFETY: SecKeychain and all CString/byte buffers remain alive throughout this call.
        let status = unsafe {
            passkey_write_restricted(
                self.handle.as_concrete_TypeRef(),
                executable.as_ptr(),
                service.as_ptr(),
                account.as_ptr(),
                value.as_ptr(),
                value.len(),
            )
        };
        if status == errSecSuccess {
            Ok(())
        } else {
            Err(self.classify(security_framework::base::Error::from_code(status)))
        }
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        self.query(service, account)
            .delete()
            .map_err(|error| self.classify(error))
    }

    pub fn read_system(&self, item: SystemItem) -> Result<String, KeychainError> {
        self.read(SERVICE, item.account())
    }

    pub fn write_system(&self, item: SystemItem, value: &str) -> Result<(), KeychainError> {
        self.write(SERVICE, item.account(), value)
    }

    pub fn delete_system(&self, item: SystemItem) -> Result<(), KeychainError> {
        self.delete(SERVICE, item.account())
    }

    pub fn read_probe_system(&self, item: SystemItem) -> Result<String, KeychainError> {
        self.read(PROBE_SERVICE, item.account())
    }

    pub fn write_probe_system(&self, item: SystemItem, value: &str) -> Result<(), KeychainError> {
        self.write(PROBE_SERVICE, item.account(), value)
    }

    pub fn delete_probe_system(&self, item: SystemItem) -> Result<(), KeychainError> {
        self.delete(PROBE_SERVICE, item.account())
    }

    fn user_account(user: &str) -> Result<String, KeychainError> {
        if user.is_empty() || user.contains(['\0', '/']) || user == "." || user == ".." {
            return Err(KeychainError::InvalidInput("user"));
        }
        Ok(format!("users/{user}"))
    }

    pub fn read_user(&self, user: &str) -> Result<String, KeychainError> {
        self.read(SERVICE, &Self::user_account(user)?)
    }

    pub fn write_user(&self, user: &str, jsonl: &str) -> Result<(), KeychainError> {
        self.write(SERVICE, &Self::user_account(user)?, jsonl)
    }

    pub fn delete_user(&self, user: &str) -> Result<(), KeychainError> {
        self.delete(SERVICE, &Self::user_account(user)?)
    }

    pub fn read_probe_user(&self, user: &str) -> Result<String, KeychainError> {
        self.read(PROBE_SERVICE, &Self::user_account(user)?)
    }

    pub fn write_probe_user(&self, user: &str, value: &str) -> Result<(), KeychainError> {
        self.write(PROBE_SERVICE, &Self::user_account(user)?, value)
    }

    pub fn delete_probe_user(&self, user: &str) -> Result<(), KeychainError> {
        self.delete(PROBE_SERVICE, &Self::user_account(user)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Accounts must stay within one users/<OS user> namespace; never permit another item or path.
    #[test]
    fn user_account_rejects_invalid_names() {
        for user in ["", "a/b", "a\0b", ".", ".."] {
            assert!(matches!(
                Keychain::user_account(user),
                Err(KeychainError::InvalidInput("user"))
            ));
        }
        assert_eq!(Keychain::user_account("kawaz").unwrap(), "users/kawaz");
    }

    // System secrets must be addressed through a fixed enum, not a caller-controlled account.
    #[test]
    fn system_item_accounts_are_fixed() {
        assert_eq!(SystemItem::PageUrl.account(), "page_url");
        assert_eq!(SystemItem::Store.account(), "store");
        assert_eq!(SystemItem::SendCommand.account(), "send_command");
        assert_eq!(SystemItem::SigningKey.account(), "signing_key");
        assert_eq!(SystemItem::VerificationKey.account(), "verification_key");
    }
}
