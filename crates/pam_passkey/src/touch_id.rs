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
pub const LA_APP_CANCEL: c_long = -9;

/// Longest `localizedReason` shown, in characters. The dialog cuts longer text at the end.
const MAX_REASON_CHARS: usize = 120;

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

fn is_bidi_control(ch: char) -> bool {
    matches!(ch, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The dialog text. The OS puts its own lead-in (「<プロセス名> で次の操作を実行しようとしています:」)
/// before it, so the command follows an empty line as a paragraph of its own.
pub fn reason(argv: &[String], fallback: &str) -> String {
    format!("\n\n{}", command_line(argv, fallback))
}

/// The caller's command line with control and bidi characters escaped, shortened in the middle
/// so that both the command and its last arguments stay visible.
fn command_line(argv: &[String], fallback: &str) -> String {
    let program = argv
        .first()
        .map(|first| first.rsplit('/').next().unwrap_or(first).to_owned())
        .filter(|program| !program.is_empty());
    let text = match program {
        Some(program) => std::iter::once(program.as_str())
            .chain(argv[1..].iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        None => fallback.to_owned(),
    };
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() || is_bidi_control(ch) {
            escaped.push_str(&format!("\\u{{{:04X}}}", u32::from(ch)));
        } else {
            escaped.push(ch);
        }
    }
    shorten_middle(&escaped, MAX_REASON_CHARS)
}

fn shorten_middle(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_owned();
    }
    let keep = max - 1;
    let head = keep.div_ceil(2);
    let tail = keep / 2;
    chars[..head]
        .iter()
        .chain(std::iter::once(&'…'))
        .chain(&chars[chars.len() - tail..])
        .collect()
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

    // The command is its own paragraph after the OS lead-in: one empty line, then the command.
    #[test]
    fn reason_puts_the_command_after_an_empty_line() {
        assert_eq!(
            reason(
                &["/usr/bin/sudo".into(), "-k".into(), "true".into()],
                "sudo"
            ),
            "\n\nsudo -k true"
        );
    }

    // The command is named by its basename followed by the arguments, as the user typed them.
    #[test]
    fn command_line_is_basename_and_arguments() {
        assert_eq!(
            command_line(
                &["/usr/bin/sudo".into(), "-k".into(), "true".into()],
                "sudo"
            ),
            "sudo -k true"
        );
        assert_eq!(command_line(&[], "sudo"), "sudo");
        assert_eq!(command_line(&["".into()], "login"), "login");
    }

    // Long command lines keep their head and tail; the cut is marked so the user sees text is missing.
    // The limit applies to the command itself, not to the separating empty line.
    #[test]
    fn long_command_line_is_shortened_in_the_middle() {
        let argv: Vec<String> = ["sudo".to_owned(), "a".repeat(200), "--last".to_owned()].into();
        let text = command_line(&argv, "sudo");
        assert_eq!(text.chars().count(), MAX_REASON_CHARS);
        assert!(text.starts_with("sudo aaa"));
        assert!(text.ends_with("aaa --last"));
        assert_eq!(text.matches('…').count(), 1);
        assert_eq!(reason(&argv, "sudo"), format!("\n\n{text}"));
        // Multibyte characters are counted as characters and never split.
        let wide = command_line(&["sudo".into(), "あ".repeat(300)], "sudo");
        assert_eq!(wide.chars().count(), MAX_REASON_CHARS);
    }

    // Control and bidi characters in argv cannot reorder or hide what the dialog shows, and a
    // newline in an argument cannot fake the paragraph layout.
    #[test]
    fn control_and_bidi_characters_are_escaped() {
        assert_eq!(
            command_line(&["sudo".into(), "a\nb".into(), "x\u{202E}y".into()], "sudo"),
            "sudo a\\u{000A}b x\\u{202E}y"
        );
    }
}
