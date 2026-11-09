//! `pam_passkey.so`: Touch ID and remote approval in parallel (DR-0002), decided by the
//! DR-0012 state table. Remote approval itself lives in the helper (DR-0003).

mod helper;
mod interrupt;
mod machine;
mod process;
mod touch_id;

use libc::{c_char, c_int, c_void, uid_t};
use machine::{Action, Input, Machine, Outcome};
use protocol::encoding::{base64url, format_utc};
use protocol::{HelperCommand, HelperEvent, HelperInput, RequestDetails};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use touch_id::{LA_USER_CANCEL, LA_USER_FALLBACK, Report as TouchReport, Round};

// Values and layouts from the macOS SDK's security/pam_{appl,constants,types}.h.
const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 9;
const PAM_IGNORE: c_int = 25;
const PAM_SILENT: c_int = i32::MIN;
const PAM_TEXT_INFO: c_int = 4;
const PAM_SERVICE: c_int = 1;
const PAM_TTY: c_int = 3;
const PAM_CONV: c_int = 5;
const PAM_MAX_MSG_SIZE: usize = 512;

const DEFAULT_HELPER: &str = "/usr/local/libexec/pam-passkey";
/// Request lifetime (DESIGN 未決事項: 60–120 s, provisional default 90 s).
const REQUEST_LIFETIME: Duration = Duration::from_secs(90);
/// How long a cancelled dialog may take to close before the driver stops waiting for it.
const DIALOG_CLOSE_GRACE: Duration = Duration::from_secs(5);

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

unsafe extern "C" {
    fn passkey_gui_session_of(uid: uid_t) -> c_int;
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

enum Event {
    Touch(TouchReport),
    Helper(helper::Report),
    Interrupted,
}

/// Sends one `PAM_TEXT_INFO` message, split into messages of at most `PAM_MAX_MSG_SIZE` bytes.
fn inform(conv: &PamConv, text: &str) {
    let Some(send) = conv.conv else {
        return;
    };
    let mut remaining = text;
    while !remaining.is_empty() {
        let mut end = remaining.len().min(PAM_MAX_MSG_SIZE - 1);
        while !remaining.is_char_boundary(end) {
            end -= 1;
        }
        let Ok(message) = CString::new(&remaining[..end]) else {
            return;
        };
        remaining = &remaining[end..];
        let item = PamMessage {
            msg_style: PAM_TEXT_INFO,
            msg: message.as_ptr().cast_mut(),
        };
        let items = [&item as *const PamMessage];
        let mut response: *mut PamResponse = std::ptr::null_mut();
        // SAFETY: the message and pointer array remain alive throughout the synchronous callback.
        let status = unsafe { send(1, items.as_ptr(), &mut response, conv.appdata_ptr) };
        if !response.is_null() {
            // SAFETY: OpenPAM's response allocations are free-compatible.
            unsafe {
                libc::free((*response).resp.cast());
                libc::free(response.cast());
            }
        }
        if status != PAM_SUCCESS {
            return;
        }
    }
}

/// The helper path from the module arguments: only `helper=<absolute path>` is accepted.
/// `None` means the arguments are not understood, so remote cannot be used.
fn helper_path(arguments: &[&str]) -> Option<String> {
    let mut path = DEFAULT_HELPER.to_owned();
    for argument in arguments {
        let selected = argument.strip_prefix("helper=")?;
        if !selected.starts_with('/') {
            return None;
        }
        path = selected.to_owned();
    }
    Some(path)
}

fn module_arguments<'a>(argc: c_int, argv: *const *const c_char) -> Option<Vec<&'a str>> {
    let count = usize::try_from(argc).ok().filter(|count| *count <= 32)?;
    if count == 0 {
        return Some(Vec::new());
    }
    if argv.is_null() {
        return None;
    }
    (0..count)
        .map(|index| {
            // SAFETY: OpenPAM supplies `argc` pointers in `argv` for the duration of the call.
            let argument = unsafe { *argv.add(index) };
            if argument.is_null() {
                return None;
            }
            // SAFETY: OpenPAM supplies NUL-terminated argument strings.
            unsafe { CStr::from_ptr(argument) }.to_str().ok()
        })
        .collect()
}

fn pam_string(pamh: *mut PamHandle, item_type: c_int) -> Option<String> {
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: PAM owns the handle and the returned string for this call.
    if unsafe { pam_get_item(pamh, item_type, &mut item) } != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: string items are NUL-terminated C strings owned by PAM.
    let text = unsafe { CStr::from_ptr(item.cast::<c_char>()) };
    text.to_str().ok().map(str::to_owned)
}

/// uid and home directory of a user name from the user database.
fn user_of(user: &str) -> Option<(uid_t, PathBuf)> {
    let name = CString::new(user).ok()?;
    // SAFETY: getpwnam_r writes into the provided struct and buffer only.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut storage = vec![0u8; 16384];
        let mut result = std::ptr::null_mut();
        let rc = libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        let home = std::ffi::OsStr::from_bytes(CStr::from_ptr(pwd.pw_dir).to_bytes());
        Some((pwd.pw_uid, PathBuf::from(home)))
    }
}

fn host_name() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most the buffer length.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return String::new();
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

fn request_id() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: arc4random_buf fills exactly the given length.
    unsafe { libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
    base64url(&bytes)
}

/// How Touch ID runs for this request (DR-0012): `None` if it cannot be used,
/// `Some(Some(uid))` to evaluate with the euid dropped to PAM_USER, `Some(None)` to evaluate as is.
fn touch_plan(pam_uid: uid_t) -> Option<Option<uid_t>> {
    // SAFETY: the session shim only reads the caller's own security and audit session.
    if unsafe { passkey_gui_session_of(pam_uid) } != 1 {
        return None;
    }
    // SAFETY: getuid / geteuid have no preconditions.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if euid == 0 {
        // A root PAM_USER has no enrolled biometry; canEvaluatePolicy reports that.
        Some((pam_uid != 0).then_some(pam_uid))
    } else if euid == pam_uid && uid == pam_uid {
        Some(None)
    } else {
        None
    }
}

fn touch_input(answer: Option<libc::c_long>, restored: bool) -> Input {
    if !restored {
        return Input::EuidNotRestored;
    }
    match answer {
        None => Input::TouchUnavailable,
        Some(0) => Input::TouchSucceeded,
        Some(LA_USER_FALLBACK) => Input::TouchFallback,
        Some(LA_USER_CANCEL) => Input::TouchCancelled,
        Some(_) => Input::TouchFailed,
    }
}

fn helper_input(id: &str, event: helper::Report) -> Option<Input> {
    use helper::Report;
    Some(match event {
        Report::Event(HelperEvent::Unavailable { .. }) => Input::RemoteUnavailable,
        Report::Event(HelperEvent::Result { id: answered, pass }) => {
            if pass && answered == id {
                Input::RemotePassed
            } else {
                Input::RemoteFailed
            }
        }
        Report::Event(HelperEvent::Url { .. }) => return None,
        Report::Malformed | Report::Closed => Input::RemoteFailed,
        Report::WriteFailed {
            command: Some(HelperCommand::Open | HelperCommand::Reactivate),
        } => Input::OpenFailed,
        Report::WriteFailed { .. } => Input::RemoteFailed,
    })
}

struct Driver {
    events: Receiver<Event>,
    sender: Sender<Event>,
    machine: Machine,
    round: Option<Round>,
    /// A round has started and its `Ended` report has not arrived yet.
    round_live: bool,
    /// `open` / `reactivate` are due once the re-shown dialog is up.
    open_due: bool,
    helper: Option<helper::Helper>,
    plan: Option<Option<uid_t>>,
    /// The dialog's buttons in Japanese (PAM_USER prefers it) or English.
    japanese: bool,
    reason: CString,
    id: String,
    deadline: Instant,
    conv: Option<*const PamConv>,
}

impl Driver {
    fn start_round(&mut self) {
        let Some(plan) = self.plan else {
            return;
        };
        let sender = self.sender.clone();
        self.round = Some(Round::start(
            plan,
            self.japanese,
            self.reason.clone(),
            move |report| {
                let _ = sender.send(Event::Touch(report));
            },
        ));
        self.round_live = true;
    }

    fn run(mut self) -> c_int {
        let sender = self.sender.clone();
        // Held until finish returns, so Ctrl-C also counts while the dialog is being closed.
        // Without the watch (no pipe / sigaction failed) the wait still ends at the deadline.
        let _interrupts = interrupt::Watch::start(move || {
            let _ = sender.send(Event::Interrupted);
        });
        let mut action = self.machine.initial();
        let outcome = loop {
            match action {
                Action::Finish(outcome) => break outcome,
                Action::Reshow => {
                    self.start_round();
                    self.open_due = true;
                }
                Action::Wait => {}
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            action = match self.events.recv_timeout(remaining) {
                Ok(event) => match self.input(event) {
                    Some(input) => self.machine.on(input),
                    None => Action::Wait,
                },
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    self.machine.on(Input::Expired)
                }
            };
        };
        self.finish(outcome)
    }

    fn input(&mut self, event: Event) -> Option<Input> {
        match event {
            Event::Touch(TouchReport::Started) => {
                if std::mem::take(&mut self.open_due)
                    && let Some(helper) = &self.helper
                {
                    helper.send(HelperCommand::Open);
                    helper.send(HelperCommand::Reactivate);
                }
                None
            }
            Event::Touch(TouchReport::Ended { answer, restored }) => {
                self.round_live = false;
                Some(touch_input(answer, restored))
            }
            Event::Helper(helper::Report::Event(HelperEvent::Url { url })) => {
                if let Some(conv) = self.conv {
                    // SAFETY: the conversation belongs to the ongoing pam_sm_authenticate call.
                    inform(unsafe { &*conv }, &format!("pam-passkey: 承認 URL: {url}"));
                }
                None
            }
            Event::Helper(report) => helper_input(&self.id, report),
            Event::Interrupted => Some(Input::Interrupted),
        }
    }

    /// Stops the dialog, tells the helper the conclusion and returns the PAM result.
    fn finish(self, outcome: Outcome) -> c_int {
        let mut outcome = outcome;
        if self.round_live
            && let Some(round) = &self.round
        {
            round.cancel();
            let until = Instant::now() + DIALOG_CLOSE_GRACE;
            let mut ended = None;
            while let Ok(event) = self
                .events
                .recv_timeout(until.saturating_duration_since(Instant::now()))
            {
                if let Event::Touch(TouchReport::Ended { restored, .. }) = event {
                    ended = Some(restored);
                    break;
                }
            }
            match ended {
                Some(true) => {}
                Some(false) => outcome = Outcome::AuthErr,
                None => {
                    // The round may still hold the dropped euid. pam_sm_authenticate takes it
                    // back; the abandoned round must not touch the euid after we return.
                    round.abandon();
                    outcome = Outcome::AuthErr;
                }
            }
        }
        // The helper's input is closed when `self` (and the helper in it) drops on return, after
        // the queued lines: `finish` for a Touch ID success, otherwise the close means cancel.
        if outcome == Outcome::TouchSuccess
            && let Some(helper) = &self.helper
        {
            helper.send(HelperCommand::Finish { pass: true });
        }
        match outcome {
            Outcome::TouchSuccess | Outcome::RemoteSuccess => PAM_SUCCESS,
            Outcome::AuthErr => PAM_AUTH_ERR,
            Outcome::Ignore => PAM_IGNORE,
        }
    }
}

/// # Safety
/// `pamh` must be the handle OpenPAM passed to `pam_sm_authenticate`.
unsafe fn authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return PAM_IGNORE;
    }
    // 1. PAM_USER, its uid and whether it has the GUI session.
    let mut user: *const c_char = std::ptr::null();
    // SAFETY: PAM owns the handle and the returned string for this call.
    if unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) } != PAM_SUCCESS || user.is_null() {
        return PAM_IGNORE;
    }
    // SAFETY: PAM keeps `user` alive until the authenticate callback returns.
    let Ok(user) = unsafe { CStr::from_ptr(user) }.to_str() else {
        return PAM_IGNORE;
    };
    if user.is_empty() || user.contains('/') {
        return PAM_IGNORE;
    }
    let user = user.to_owned();
    let Some((pam_uid, pam_home)) = user_of(&user) else {
        return PAM_IGNORE;
    };
    let plan = touch_plan(pam_uid);
    // Read as the caller (root) before any drop; only a dialog needs it.
    let japanese = plan.is_some() && touch_id::prefers_japanese(&pam_home);

    // 2. Process information, while the euid is still the caller's.
    let processes = process::ancestry();
    let argv_text = processes
        .first()
        .and_then(|own| own.argv.clone())
        .unwrap_or_default();
    let service = pam_string(pamh, PAM_SERVICE).unwrap_or_else(|| "pam-passkey".to_owned());
    let tty = pam_string(pamh, PAM_TTY);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let id = request_id();
    // SAFETY: getuid has no preconditions.
    let caller_uid = unsafe { libc::getuid() };
    let input = HelperInput {
        user: user.clone(),
        caller_uid,
        id: id.clone(),
        expires: format_utc(now + REQUEST_LIFETIME.as_secs() as i64),
        tty: tty.clone(),
        details: RequestDetails {
            host: host_name(),
            user,
            caller_uid,
            tty,
            time: format_utc(now),
            argv: argv_text.clone(),
            processes,
        },
    };
    let deadline = Instant::now() + REQUEST_LIFETIME;

    // 3. Helper: placement check, spawn, signature check, input line.
    let (sender, events) = channel();
    let helper = module_arguments(argc, argv)
        .and_then(|arguments| helper_path(&arguments))
        .and_then(|path| {
            let sender = sender.clone();
            helper::spawn(Path::new(&path), &input, deadline, move |report| {
                let _ = sender.send(Event::Helper(report));
            })
            .ok()
        });

    // 4. Touch ID, with the euid dropped only after the spawn above.
    let mut conv: *const c_void = std::ptr::null();
    // SAFETY: PAM owns the conversation object throughout the call.
    let conv = (unsafe { pam_get_item(pamh, PAM_CONV, &mut conv) } == PAM_SUCCESS
        && !conv.is_null()
        && flags & PAM_SILENT == 0)
        .then_some(conv.cast::<PamConv>());
    let reason = CString::new(touch_id::reason(&argv_text, &service))
        .unwrap_or_else(|_| c"pam-passkey".to_owned());
    let mut driver = Driver {
        events,
        sender,
        machine: Machine::new(plan.is_some(), helper.is_some()),
        round: None,
        round_live: false,
        open_due: false,
        helper,
        plan,
        japanese,
        reason,
        id,
        deadline,
        conv,
    };
    driver.start_round();
    // 5. One loop over both paths until the state table concludes.
    driver.run()
}

/// PAM auth entry point. Panics are caught and become `PAM_AUTH_ERR`; every failure is
/// `PAM_AUTH_ERR` or `PAM_IGNORE`, which fall through to the next module (password).
///
/// # Safety
/// Called by OpenPAM with its handle and the module arguments from the policy line.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: geteuid has no preconditions.
    let caller_euid = unsafe { libc::geteuid() };
    let result = std::panic::catch_unwind(|| unsafe { authenticate(pamh, flags, argc, argv) })
        .unwrap_or(PAM_AUTH_ERR);
    // A dialog that did not close in time (or a panic) can leave the euid dropped. Take it back,
    // and since the evaluation did not end cleanly, do not authenticate (DR-0012 seteuid の順序).
    // SAFETY: geteuid / seteuid have no memory preconditions.
    if unsafe { libc::geteuid() } != caller_euid {
        let _ = unsafe { libc::seteuid(caller_euid) };
        return PAM_AUTH_ERR;
    }
    result
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

    // Only `helper=<absolute path>` is understood; anything else must not silently pick a binary.
    #[test]
    fn module_arguments_select_only_absolute_helpers() {
        assert_eq!(helper_path(&[]).as_deref(), Some(DEFAULT_HELPER));
        assert_eq!(
            helper_path(&["helper=/nix/store/x/bin/pam-passkey"]).as_deref(),
            Some("/nix/store/x/bin/pam-passkey")
        );
        assert_eq!(helper_path(&["helper=pam-passkey"]), None);
        assert_eq!(helper_path(&["helper="]), None);
        assert_eq!(helper_path(&["debug"]), None);
    }

    // DR-0012 helper の成功判定: only `pass: true` for our own request ID is success.
    #[test]
    fn only_matching_pass_result_is_remote_success() {
        let result = |id: &str, pass| {
            helper_input(
                "ours",
                helper::Report::Event(HelperEvent::Result {
                    id: id.into(),
                    pass,
                }),
            )
        };
        assert_eq!(result("ours", true), Some(Input::RemotePassed));
        assert_eq!(result("ours", false), Some(Input::RemoteFailed));
        assert_eq!(result("other", true), Some(Input::RemoteFailed));
        assert_eq!(
            helper_input("ours", helper::Report::Malformed),
            Some(Input::RemoteFailed)
        );
        assert_eq!(
            helper_input("ours", helper::Report::Closed),
            Some(Input::RemoteFailed)
        );
    }

    // The helper failing to take `open` is the "remote cannot open the page" case of DR-0012.
    #[test]
    fn failed_open_write_is_open_failure() {
        assert_eq!(
            helper_input(
                "ours",
                helper::Report::WriteFailed {
                    command: Some(HelperCommand::Open)
                }
            ),
            Some(Input::OpenFailed)
        );
        assert_eq!(
            helper_input("ours", helper::Report::WriteFailed { command: None }),
            Some(Input::RemoteFailed)
        );
    }

    // LAError codes map onto the state table inputs; an unrestored euid overrides any answer.
    #[test]
    fn touch_answers_map_to_inputs() {
        assert_eq!(touch_input(Some(0), true), Input::TouchSucceeded);
        assert_eq!(touch_input(Some(-3), true), Input::TouchFallback);
        assert_eq!(touch_input(Some(-2), true), Input::TouchCancelled);
        assert_eq!(touch_input(Some(-1), true), Input::TouchFailed);
        assert_eq!(touch_input(Some(-8), true), Input::TouchFailed);
        assert_eq!(touch_input(None, true), Input::TouchUnavailable);
        assert_eq!(touch_input(Some(0), false), Input::EuidNotRestored);
    }
}
