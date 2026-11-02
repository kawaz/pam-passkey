use core_foundation::base::TCFType;
use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::base::{SecKeychainRef, errSecItemNotFound, errSecSuccess};
use std::ffi::CString;
use std::fmt;

const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

unsafe extern "C" {
    fn kcpoc_write_all_apps(
        keychain: SecKeychainRef,
        service: *const std::ffi::c_char,
        account: *const std::ffi::c_char,
        value: *const u8,
        value_len: usize,
    ) -> i32;
}

#[derive(Debug)]
pub enum KeychainError {
    InvalidInput(&'static str),
    Open(security_framework::base::Error),
    Operation(security_framework::base::Error),
    NotFound,
    UnexpectedResult,
    InvalidUtf8(std::string::FromUtf8Error),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "{field} contains a NUL byte"),
            Self::Open(error) => write!(
                formatter,
                "open System Keychain: {error} (OSStatus {})",
                error.code()
            ),
            Self::Operation(error) => write!(
                formatter,
                "System Keychain operation: {error} (OSStatus {})",
                error.code()
            ),
            Self::NotFound => write!(formatter, "item not found in System Keychain"),
            Self::UnexpectedResult => write!(
                formatter,
                "System Keychain returned an unexpected item type"
            ),
            Self::InvalidUtf8(error) => write!(formatter, "item data is not UTF-8: {error}"),
        }
    }
}

impl std::error::Error for KeychainError {}

fn keychain() -> Result<SecKeychain, KeychainError> {
    SecKeychain::open(SYSTEM_KEYCHAIN).map_err(KeychainError::Open)
}

fn search<'a>(keychain: &'a SecKeychain, service: &str, account: &str) -> ItemSearchOptions {
    let mut query = ItemSearchOptions::new();
    query
        .keychains(std::slice::from_ref(keychain))
        .class(ItemClass::generic_password())
        .service(service)
        .account(account);
    query
}

pub fn read(service: &str, account: &str) -> Result<String, KeychainError> {
    let keychain = keychain()?;
    let mut query = search(&keychain, service, account);
    query.load_data(true);
    let results = query.search().map_err(|error| {
        if error.code() == errSecItemNotFound {
            KeychainError::NotFound
        } else {
            KeychainError::Operation(error)
        }
    })?;
    match results.into_iter().next() {
        Some(SearchResult::Data(value)) => {
            String::from_utf8(value).map_err(KeychainError::InvalidUtf8)
        }
        Some(_) => Err(KeychainError::UnexpectedResult),
        None => Err(KeychainError::NotFound),
    }
}

pub fn delete(service: &str, account: &str) -> Result<(), KeychainError> {
    let keychain = keychain()?;
    search(&keychain, service, account)
        .delete()
        .map_err(KeychainError::Operation)
}

pub fn write(service: &str, account: &str, value: &str) -> Result<(), KeychainError> {
    let service = CString::new(service).map_err(|_| KeychainError::InvalidInput("service"))?;
    let account = CString::new(account).map_err(|_| KeychainError::InvalidInput("account"))?;
    let keychain = keychain()?;
    // SAFETY: the keychain reference and all buffers remain valid for the duration of the C call.
    let status = unsafe {
        kcpoc_write_all_apps(
            keychain.as_concrete_TypeRef(),
            service.as_ptr(),
            account.as_ptr(),
            value.as_ptr(),
            value.len(),
        )
    };
    if status == errSecSuccess {
        Ok(())
    } else {
        Err(KeychainError::Operation(
            security_framework::base::Error::from_code(status),
        ))
    }
}
