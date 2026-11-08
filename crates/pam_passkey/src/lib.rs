use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_TEXT_INFO: c_int = 4;
const PAM_CONV: c_int = 5;
const PAM_MAX_MSG_SIZE: usize = 512;
const DEFAULT_HELPER: &str = "/usr/local/libexec/pam-passkey";

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn passkey_verify_pid(pid: c_int) -> c_int;
}

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

fn secure_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = Some(path);
    while let Some(part) = current {
        let Ok(metadata) = part.symlink_metadata() else {
            return false;
        };
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return false;
        }
        if part == path && !metadata.is_file() || part != path && !metadata.is_dir() {
            return false;
        }
        current = part.parent();
    }
    true
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
    // SAFETY: the message and pointer array remain alive throughout the synchronous callback.
    let status = unsafe { send(1, items.as_ptr(), &mut response, conv.appdata_ptr) };
    if !response.is_null() {
        // SAFETY: OpenPAM's response allocations are free-compatible.
        unsafe {
            libc::free((*response).resp.cast());
            libc::free(response.cast());
        }
    }
    (status == PAM_SUCCESS).then_some(())
}

fn helper_path(argc: c_int, argv: *const *const c_char) -> Option<String> {
    if argc < 0 || argc > 32 {
        return None;
    }
    let mut path = DEFAULT_HELPER.to_owned();
    if argc == 0 {
        return Some(path);
    }
    if argv.is_null() {
        return None;
    }
    for index in 0..argc as isize {
        // SAFETY: OpenPAM supplies `argc` pointers in `argv` during the call.
        let argument = unsafe { *argv.offset(index) };
        if argument.is_null() {
            return None;
        }
        // SAFETY: OpenPAM supplies NUL-terminated argument strings.
        let value = unsafe { CStr::from_ptr(argument) }.to_str().ok()?;
        if let Some(selected) = value.strip_prefix("helper=") {
            if selected.is_empty() {
                return None;
            }
            path = selected.to_owned();
        } else {
            return None;
        }
    }
    Some(path)
}

unsafe fn authenticate(
    pamh: *mut PamHandle,
    argc: c_int,
    argv: *const *const c_char,
) -> Option<()> {
    if pamh.is_null() {
        return None;
    }
    let mut item: *const c_void = ptr::null();
    // SAFETY: PAM owns this conversation object throughout the call.
    if unsafe { pam_get_item(pamh, PAM_CONV, &mut item) } != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: PAM_CONV denotes an OpenPAM-owned conversation object.
    let conv = unsafe { &*item.cast::<PamConv>() };
    let message = match unsafe { probe(pamh, argc, argv) } {
        Ok(message) => message,
        Err(stage) => format!("pam-passkey probe: failed at {stage}"),
    };
    // SAFETY: OpenPAM conversation is live for the duration of the callback.
    unsafe { inform(conv, &message) }
}

unsafe fn probe(
    pamh: *mut PamHandle,
    argc: c_int,
    argv: *const *const c_char,
) -> Result<String, &'static str> {
    let mut user: *const c_char = ptr::null();
    // SAFETY: PAM owns the handle and returned C string for this call.
    if unsafe { pam_get_user(pamh, &mut user, ptr::null()) } != PAM_SUCCESS || user.is_null() {
        return Err("pam_get_user");
    }
    // SAFETY: PAM retains `user` until the authenticate callback returns.
    let user = unsafe { CStr::from_ptr(user) }
        .to_str()
        .map_err(|_| "user utf8")?;
    if user.contains('/') || user.is_empty() {
        return Err("user name");
    }
    let path = helper_path(argc, argv).ok_or("helper_path")?;
    if !secure_path(Path::new(&path)) {
        return Err("secure_path");
    }
    let mut command = Command::new(path);
    command
        .arg("_probe-auth")
        .arg(user)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the callback calls only async-signal-safe functions between fork and exec.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| "spawn")?;
    // SAFETY: the PID belongs to our freshly spawned child, checked before releasing the handshake byte.
    let verify = unsafe { passkey_verify_pid(child.id() as c_int) };
    if verify != 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(format!(
            "pam-passkey probe: failed at verify_pid (status {verify})"
        ));
    }
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .ok_or("stdin")?
        .write_all(&[1])
        .map_err(|_| "handshake")?;
    child.stdin.take();
    let output = child.wait_with_output().map_err(|_| "wait")?;
    Ok(if output.status.success() {
        format!(
            "pam-passkey probe: {} bytes of user Keychain data",
            output.stdout.len()
        )
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr: String = stderr
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect();
        format!(
            "pam-passkey probe: user Keychain child returned {:?}: {stderr}",
            output.status.code()
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Verification-only module: a probe must never authenticate a caller.
    let _ = std::panic::catch_unwind(|| unsafe { authenticate(pamh, argc, argv) });
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

#[cfg(test)]
mod tests {
    use super::*;

    // A helper path is trusted only if every component, including / and the binary, is root-owned and non-writable by others; symlinks cannot bypass this check.
    #[test]
    fn rejects_relative_paths() {
        assert!(!secure_path(Path::new("target/release/pam-passkey")));
    }
}
