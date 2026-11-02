use libc::{c_char, c_int, c_void, pid_t};
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;

// Values and layouts from the macOS SDK's security/pam_{appl,constants,types}.h.
const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 9;
const PAM_IGNORE: c_int = 25;
const PAM_TEXT_INFO: c_int = 4;
const PAM_CONV: c_int = 5;
const PAM_MAX_MSG_SIZE: usize = 512;

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
extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
        -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

extern "C" {
    fn pam_poc_parent_pid(pid: pid_t, parent: *mut pid_t) -> c_int;
    fn pam_poc_touch_id(
        reason: *const c_char,
        errbuf: *mut c_char,
        errlen: usize,
    ) -> c_int;
}

fn touch_id_reason(args: &[String]) -> String {
    // Limit the displayed argument text in bytes without splitting a UTF-8 character.
    let command = args[args.len().min(1)..].join(" ");
    let reason = if command.is_empty() {
        "sudo".to_string()
    } else {
        format!("sudo {command}")
    };
    let end = reason
        .char_indices()
        .map(|(index, ch)| index + ch.len_utf8())
        .take_while(|&end| end <= 120)
        .last()
        .unwrap_or(0);
    if reason.len() <= 120 {
        reason
    } else {
        format!("{}…", &reason[..end])
    }
}

fn inform_chunks(conv: &PamConv, text: &str) -> Option<()> {
    let max = PAM_MAX_MSG_SIZE - 1 - "pam_poc: ".len();
    let mut remaining = text;
    while !remaining.is_empty() {
        let mut end = remaining.len().min(max);
        while !remaining.is_char_boundary(end) {
            end -= 1;
        }
        // SAFETY: OpenPAM's conversation is called with a valid, bounded UTF-8 string.
        unsafe { inform(conv, &format!("pam_poc: {}", &remaining[..end])) }?;
        remaining = &remaining[end..];
    }
    Some(())
}

fn argv_for(pid: pid_t) -> Option<Vec<String>> {
    let mut argmax: c_int = 0;
    let mut size = mem::size_of_val(&argmax);
    let mut limit = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: sysctl receives writable storage with its exact byte length.
    if unsafe {
        libc::sysctl(
            limit.as_mut_ptr(),
            limit.len() as u32,
            (&mut argmax as *mut c_int).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
        || size != mem::size_of::<c_int>()
        || argmax <= 0
    {
        return None;
    }

    let mut bytes = vec![0u8; usize::try_from(argmax).ok()?];
    let mut size = bytes.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: sysctl's writable buffer is `bytes`, and `size` states its capacity.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
        || size > bytes.len()
    {
        return None;
    }
    parse_argv(&bytes[..size])
}

fn parse_argv(bytes: &[u8]) -> Option<Vec<String>> {
    let count = i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
    if count <= 0 {
        return None;
    }
    let mut cursor = 4;
    let executable_end = bytes.get(cursor..)?.iter().position(|&byte| byte == 0)? + cursor;
    cursor = executable_end + 1;
    while bytes.get(cursor) == Some(&0) {
        cursor += 1;
    }
    let mut args = Vec::new();
    for _ in 0..count {
        let end = bytes.get(cursor..)?.iter().position(|&byte| byte == 0)? + cursor;
        args.push(String::from_utf8_lossy(&bytes[cursor..end]).into_owned());
        cursor = end + 1;
    }
    Some(args)
}

fn executable_path(pid: pid_t) -> Option<String> {
    let mut bytes = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most the supplied buffer length.
    let len = unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if len <= 0 || len as usize > bytes.len() {
        return None;
    }
    // proc_pidpath returns the path length excluding the terminating NUL.
    Some(String::from_utf8_lossy(&bytes[..len as usize]).into_owned())
}

/// Walks from the current process to launchd. On failure returns the ancestors
/// collected so far plus the reason, so the caller can show where the walk stopped.
fn ancestry() -> Result<Vec<(pid_t, String)>, (Vec<(pid_t, String)>, String)> {
    // SAFETY: getpid has no pointer arguments or preconditions.
    let mut current = unsafe { libc::getpid() };
    let mut ancestors = Vec::new();
    loop {
        if current <= 0 || ancestors.iter().any(|(pid, _)| *pid == current) {
            return Err((ancestors, format!("pid {current} でループ or 不正")));
        }
        let path = executable_path(current).unwrap_or_else(|| "(proc_pidpath 失敗)".to_string());
        ancestors.push((current, path));
        if current == 1 {
            return Ok(ancestors);
        }
        let mut parent = 0;
        // SAFETY: the C shim checks the result size and writes one valid pid_t.
        if unsafe { pam_poc_parent_pid(current, &mut parent) } != 0 {
            return Err((
                ancestors,
                format!("pid {current} の ppid 取得に失敗 (sysctl KERN_PROC_PID)"),
            ));
        }
        current = parent;
    }
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
    // SAFETY: the message and pointer array remain alive until the callback returns.
    let status = unsafe { send(1, items.as_ptr(), &mut response, conv.appdata_ptr) };
    if !response.is_null() {
        // SAFETY: OpenPAM's conversation contract allocates responses with free-compatible memory.
        unsafe {
            libc::free((*response).resp.cast());
            libc::free(response.cast());
        }
    }
    (status == PAM_SUCCESS).then_some(())
}

unsafe fn authenticate(pamh: *mut PamHandle) -> Option<c_int> {
    if pamh.is_null() {
        return None;
    }
    let mut user: *const c_char = ptr::null();
    // SAFETY: pamh is a non-null handle supplied by OpenPAM.
    if unsafe { pam_get_user(pamh, &mut user, ptr::null()) } != PAM_SUCCESS || user.is_null() {
        return None;
    }
    // SAFETY: pam_get_user returns a NUL-terminated string owned by OpenPAM.
    let user = unsafe { CStr::from_ptr(user) }.to_string_lossy();
    let mut item: *const c_void = ptr::null();
    // SAFETY: item is the out pointer specified by pam_get_item.
    if unsafe { pam_get_item(pamh, PAM_CONV, &mut item) } != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: PAM_CONV identifies an OpenPAM-owned pam_conv lasting for this call.
    let conv = unsafe { &*item.cast::<PamConv>() };
    unsafe { inform(conv, &format!("pam_poc: {user} の承認待ち")) }?;

    let pid = unsafe { libc::getpid() };
    let args = argv_for(pid)?;
    // PAM_MAX_MSG_SIZE limits each display message; refuse rather than hide argv bytes.
    unsafe { inform(conv, &format!("pam_poc: sudo argv: {args:?}")) }?;
    let (ancestors, failure) = match ancestry() {
        Ok(list) => (list, None),
        Err((list, reason)) => (list, Some(reason)),
    };
    for (pid, path) in ancestors {
        unsafe { inform(conv, &format!("pam_poc: pid {pid}: {path}")) }?;
    }
    if let Some(reason) = failure {
        unsafe { inform(conv, &format!("pam_poc: ツリー取得中断: {reason}")) }?;
        return None;
    }
    let reason = CString::new(touch_id_reason(&args)).ok()?;
    let mut diagnostics = vec![0 as c_char; 4096];
    // SAFETY: the reason is NUL-terminated, and the shim writes within diagnostics.
    let result = unsafe {
        pam_poc_touch_id(
            reason.as_ptr(),
            diagnostics.as_mut_ptr(),
            diagnostics.len(),
        )
    };
    // SAFETY: the Objective-C shim NUL-terminates the provided diagnostics buffer.
    let details = unsafe { CStr::from_ptr(diagnostics.as_ptr()) }.to_string_lossy();
    if !details.is_empty() && inform_chunks(conv, &details).is_none() {
        return Some(PAM_AUTH_ERR);
    }
    if result == -3
        && unsafe {
            inform(
                conv,
                "pam_poc: 詳細を確認が押された (ここで承認 URL を open する想定)",
            )
        }
        .is_none()
    {
        return Some(PAM_AUTH_ERR);
    }
    Some(if result == 0 {
        PAM_SUCCESS
    } else {
        PAM_AUTH_ERR
    })
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // SAFETY: a valid OpenPAM handle is required; malformed handles return PAM_IGNORE.
    unsafe { authenticate(pamh) }.unwrap_or(PAM_IGNORE)
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{parse_argv, touch_id_reason};

    // The prompt names the requested command without duplicating argv[0], and remains short.
    #[test]
    fn touch_id_reason_joins_command_arguments() {
        assert_eq!(
            touch_id_reason(&["sudo".into(), "-k".into(), "true".into()]),
            "sudo -k true"
        );
        assert_eq!(touch_id_reason(&[]), "sudo");
    }

    // A multibyte argument crossing the limit must remain valid UTF-8 when shortened.
    #[test]
    fn touch_id_reason_truncates_at_character_boundary() {
        let reason = touch_id_reason(&["sudo".into(), "あ".repeat(50)]);
        assert!(reason.ends_with('…'));
        assert!(reason.len() <= 123);
        assert!(reason.starts_with("sudo あ"));
    }

    #[test]
    fn reads_argument_count_without_reaching_environment() {
        let mut bytes = 2i32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"/usr/bin/sudo\0\0\0sudo\0true\0SECRET=not-displayed\0");
        assert_eq!(parse_argv(&bytes), Some(vec!["sudo".into(), "true".into()]));
    }

    #[test]
    fn rejects_missing_arguments() {
        let mut bytes = 2i32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"/usr/bin/sudo\0sudo\0");
        assert_eq!(parse_argv(&bytes), None);
    }
}
