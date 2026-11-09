//! The language of the system dialogs this binary shows (Touch ID / password): English, or
//! Japanese for a user whose first preferred language is Japanese. CLI messages stay English.

use std::ffi::{CString, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

unsafe extern "C" {
    // The module's shim (pam_passkey/src/touch_id.m), linked here as well.
    fn passkey_prefers_japanese(home: *const c_char) -> c_int;
}

pub fn prefers_japanese(home: &Path) -> bool {
    let Ok(home) = CString::new(home.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: the path is NUL-terminated and outlives the call.
    unsafe { passkey_prefers_japanese(home.as_ptr()) == 1 }
}
