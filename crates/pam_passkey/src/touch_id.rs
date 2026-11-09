//! Touch ID (LAContext) rounds. One round is one dialog evaluated on its own thread,
//! with the euid dropped to PAM_USER for the whole evaluation (DR-0012 seteuid の順序).

use libc::{c_char, c_int, c_long, c_void, uid_t};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

unsafe extern "C" {
    fn passkey_touch_id_create(japanese: c_int) -> *mut c_void;
    fn passkey_prefers_japanese(home: *const c_char) -> c_int;
    fn passkey_touch_id_can_evaluate(handle: *mut c_void) -> c_long;
    fn passkey_touch_id_begin(handle: *mut c_void, reason: *const c_char) -> c_int;
    fn passkey_touch_id_wait(handle: *mut c_void) -> c_long;
    fn passkey_touch_id_cancel(handle: *mut c_void);
    fn passkey_touch_id_release(handle: *mut c_void);
}

/// LAError codes the driver distinguishes (LocalAuthentication/LAError.h).
pub const LA_USER_CANCEL: c_long = -2;
pub const LA_USER_FALLBACK: c_long = -3;
/// Too many failed attempts; biometry stays locked until the user's password is entered once.
pub const LA_BIOMETRY_LOCKOUT: c_long = -8;
pub const LA_APP_CANCEL: c_long = -9;

struct Dialog(*mut c_void);

// SAFETY: the Objective-C object is reference counted; `cancel` (LAContext invalidate) is
// called from another thread while `wait` blocks on a dispatch semaphore, which the shim supports.
unsafe impl Send for Dialog {}
unsafe impl Sync for Dialog {}

impl Dialog {
    fn create(japanese: bool) -> Option<Self> {
        // SAFETY: the shim returns a retained object or NULL.
        let handle = unsafe { passkey_touch_id_create(c_int::from(japanese)) };
        (!handle.is_null()).then_some(Self(handle))
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        // SAFETY: the handle was retained by create and is released exactly once.
        unsafe { passkey_touch_id_release(self.0) }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Report {
    /// The dialog is up (evaluatePolicy was called).
    Started,
    /// The round is over. `answer` is the dialog's LAError code (0 for a match), or `Err` when
    /// no dialog could be shown, with `canEvaluatePolicy`'s LAError code if it gave one;
    /// `restored` is false when the euid could not be returned to root.
    Ended {
        answer: Result<c_long, Option<c_long>>,
        restored: bool,
    },
}

#[derive(Default)]
struct RoundState {
    dialog: Option<Arc<Dialog>>,
    cancelled: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<RoundState>,
    /// Set when the driver stopped waiting for this round and restored the euid itself;
    /// the round must then leave the euid alone.
    abandoned: AtomicBool,
}

pub struct Round {
    shared: Arc<Shared>,
}

/// Drops the euid for the evaluation and returns it on `restore` or when dropped (panic path).
struct Euid {
    dropped: bool,
    shared: Arc<Shared>,
}

impl Euid {
    fn restore(&mut self) -> bool {
        if !std::mem::take(&mut self.dropped) || self.shared.abandoned.load(Ordering::SeqCst) {
            return true;
        }
        // SAFETY: seteuid has no memory preconditions; the saved uid is 0 when we dropped.
        unsafe { libc::seteuid(0) == 0 && libc::geteuid() == 0 }
    }
}

impl Drop for Euid {
    fn drop(&mut self) {
        self.restore();
    }
}

impl Round {
    /// Starts a round. `drop_to` is the uid to evaluate as (PAM_USER) when the caller runs with
    /// euid 0, `None` to evaluate with the caller's own credentials.
    pub fn start(
        drop_to: Option<uid_t>,
        japanese: bool,
        reason: CString,
        report: impl Fn(Report) + Send + 'static,
    ) -> Self {
        let shared = Arc::new(Shared::default());
        let round = Arc::clone(&shared);
        std::thread::spawn(move || {
            let mut euid = Euid {
                dropped: false,
                shared: Arc::clone(&round),
            };
            if let Some(uid) = drop_to {
                // SAFETY: seteuid has no memory preconditions.
                if unsafe { libc::seteuid(uid) } != 0 {
                    report(Report::Ended {
                        answer: Err(None),
                        restored: unsafe { libc::geteuid() } == 0,
                    });
                    return;
                }
                euid.dropped = true;
            }
            let answer = evaluate(&round, japanese, &reason, &report);
            let restored = euid.restore();
            report(Report::Ended { answer, restored });
        });
        Self { shared }
    }

    /// Closes the dialog. A round that has not shown its dialog yet will not show it.
    pub fn cancel(&self) {
        let mut state = lock(&self.shared.state);
        state.cancelled = true;
        if let Some(dialog) = &state.dialog {
            // SAFETY: the handle is alive while the Arc is held.
            unsafe { passkey_touch_id_cancel(dialog.0) }
        }
    }

    /// The driver gave up on this round and restored the euid itself.
    pub fn abandon(&self) {
        self.shared.abandoned.store(true, Ordering::SeqCst);
        self.cancel();
    }
}

fn lock(state: &Mutex<RoundState>) -> std::sync::MutexGuard<'_, RoundState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn evaluate(
    shared: &Shared,
    japanese: bool,
    reason: &CString,
    report: &impl Fn(Report),
) -> Result<c_long, Option<c_long>> {
    let dialog = Arc::new(Dialog::create(japanese).ok_or(None)?);
    // SAFETY: the handle is alive for the whole function.
    let can = unsafe { passkey_touch_id_can_evaluate(dialog.0) };
    if can != 0 {
        return Err(Some(can));
    }
    {
        let mut state = lock(&shared.state);
        if state.cancelled {
            return Ok(LA_APP_CANCEL);
        }
        // SAFETY: the reason is NUL-terminated and outlives the call; the shim copies it.
        if unsafe { passkey_touch_id_begin(dialog.0, reason.as_ptr()) } != 0 {
            return Err(None);
        }
        state.dialog = Some(Arc::clone(&dialog));
    }
    report(Report::Started);
    // SAFETY: the evaluation was started above, so the semaphore is signalled exactly once.
    Ok(unsafe { passkey_touch_id_wait(dialog.0) })
}

/// Whether the dialog's buttons are shown in Japanese: the first of the preferred languages of
/// the user whose home is `home` (falling back to the system's) is Japanese. English otherwise.
pub fn prefers_japanese(home: &Path) -> bool {
    let Ok(home) = CString::new(home.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: the path is NUL-terminated and outlives the call.
    unsafe { passkey_prefers_japanese(home.as_ptr()) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home_with_languages(languages: &str) -> std::path::PathBuf {
        let template = CString::new(
            std::env::temp_dir()
                .join("pam-passkey-languages.XXXXXX")
                .as_os_str()
                .as_bytes(),
        )
        .unwrap();
        let raw = template.into_raw();
        // SAFETY: mkdtemp rewrites the NUL-terminated template in place; `raw` is reclaimed once.
        let made = unsafe { libc::mkdtemp(raw) };
        let home = unsafe { CString::from_raw(raw) };
        assert!(!made.is_null());
        let home = std::path::PathBuf::from(home.into_string().unwrap());
        let preferences = home.join("Library/Preferences");
        std::fs::create_dir_all(&preferences).unwrap();
        std::fs::write(
            preferences.join(".GlobalPreferences.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>AppleLanguages</key><array>{languages}</array></dict></plist>"#
            ),
        )
        .unwrap();
        home
    }

    // The buttons follow the first preferred language of PAM_USER, not the process's own.
    #[test]
    fn language_is_the_users_first_preference() {
        for (languages, japanese) in [
            ("<string>ja-JP</string><string>en-US</string>", true),
            ("<string>ja</string>", true),
            ("<string>en-US</string><string>ja-JP</string>", false),
            ("<string>fr-FR</string>", false),
        ] {
            let home = home_with_languages(languages);
            assert_eq!(prefers_japanese(&home), japanese, "{languages}");
            std::fs::remove_dir_all(home).unwrap();
        }
        // Without the user's setting the system's applies.
        let system = prefers_japanese(Path::new("/nonexistent"));
        let home = home_with_languages("");
        assert_eq!(prefers_japanese(&home), system);
        std::fs::remove_dir_all(home).unwrap();
    }
}
