//! Unified logging (category `helper`) for diagnosing a request after the fact, through the
//! module's shim (pam_passkey/src/log.c). Messages never carry secrets: no store keys, no
//! URLs, no assertion contents.

#[cfg(not(test))]
unsafe extern "C" {
    fn passkey_log(
        helper: std::ffi::c_int,
        error: std::ffi::c_int,
        message: *const std::ffi::c_char,
    );
}

/// Tests do not write to the system's log.
#[cfg(test)]
fn write(_: bool, _: &str) {}

#[cfg(not(test))]
fn write(error: bool, message: &str) {
    let Ok(message) = std::ffi::CString::new(message.replace('\0', "\\0")) else {
        return;
    };
    // SAFETY: the message is NUL-terminated and outlives the call.
    unsafe { passkey_log(1, std::ffi::c_int::from(error), message.as_ptr()) }
}

pub fn step(message: &str) {
    write(false, message);
}

pub fn failure(message: &str) {
    write(true, message);
}
