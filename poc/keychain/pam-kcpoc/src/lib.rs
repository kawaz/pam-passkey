use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::ptr;

// OpenPAM constants and layouts match the macOS SDK security/pam_*.h headers.
const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_TEXT_INFO: c_int = 4;
const PAM_CONV: c_int = 5;
const PAM_MAX_MSG_SIZE: usize = 512;
const SERVICE: &str = "pam-passkey-poc";

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *mut c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            c_int,
            *const *const PamMessage,
            *mut *mut PamResponse,
            *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

unsafe fn inform(conv: &PamConv, text: &str) -> Option<()> {
    let message = CString::new(text).ok()?;
    if message.as_bytes_with_nul().len() > PAM_MAX_MSG_SIZE {
        return None;
    }
    let item = PamMessage {
        msg_style: PAM_TEXT_INFO,
        msg: message.as_ptr().cast_mut(),
    };
    let items = [&item as *const PamMessage];
    let mut response: *mut PamResponse = ptr::null_mut();
    let send = conv.conv?;
    // SAFETY: message and item pointers remain valid until the conversation returns.
    let status = unsafe { send(1, items.as_ptr(), &mut response, conv.appdata_ptr) };
    if !response.is_null() {
        // SAFETY: OpenPAM's conversation returns free-compatible response allocations.
        unsafe {
            libc::free((*response).resp.cast());
            libc::free(response.cast());
        }
    }
    (status == PAM_SUCCESS).then_some(())
}

unsafe fn authenticate(pamh: *mut PamHandle) {
    if pamh.is_null() {
        return;
    }
    let mut item: *const c_void = ptr::null();
    // SAFETY: pamh is the OpenPAM-owned handle, and item is writable out storage.
    if unsafe { pam_get_item(pamh, PAM_CONV, &mut item) } != PAM_SUCCESS || item.is_null() {
        return;
    }
    // SAFETY: the PAM_CONV item is a conversation object owned by OpenPAM.
    let conv = unsafe { &*item.cast::<PamConv>() };
    let mut user: *const c_char = ptr::null();
    // SAFETY: pamh is valid and pam_get_user fills in the borrowed C string.
    if unsafe { pam_get_user(pamh, &mut user, ptr::null()) } != PAM_SUCCESS || user.is_null() {
        // SAFETY: inform uses the borrowed conversation only for this synchronous call.
        let _ = unsafe { inform(conv, "pam_kcpoc: pam_get_user failed") };
        return;
    }
    // SAFETY: the user's string remains owned by OpenPAM during this call.
    let user = unsafe { CStr::from_ptr(user) }.to_string_lossy();
    let result = match poc_keychain::read(SERVICE, &user) {
        Ok(value) => format!("pam_kcpoc: {user} = {value}"),
        Err(error) => format!("pam_kcpoc: {user}: {error}"),
    };
    // Large values or embedded NULs cannot be displayed in one OpenPAM message.
    // SAFETY: inform keeps the C message allocated until the conversation returns.
    if unsafe { inform(conv, &result) }.is_none() {
        // SAFETY: the fallback is a short literal with no embedded NUL bytes.
        let _ = unsafe {
            inform(
                conv,
                "pam_kcpoc: result cannot be displayed (too long or contains NUL)",
            )
        };
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // SAFETY: malformed handles are ignored, and this module never grants authentication.
    unsafe { authenticate(pamh) };
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
