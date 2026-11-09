mod add;
mod auth;
mod cbor;
mod child;
mod language;
mod passkeys;
mod records;
mod settings;
mod setup;
mod store;
#[cfg(test)]
mod test_support;
mod webauthn;

use child::{RunAs, current_user};
use pam_passkey::keychain::{Keychain, KeychainError, SystemItem};
use std::error::Error;
use std::ffi::{CString, c_char};
use std::io::BufRead;
use std::path::Path;

const HELP: &str = "pam-passkey — passkey approval for PAM (sudo) from a phone or this Mac

Commands:
  setup [--edit|--stdin|--dump] [--module <path>] [page_url]
                                     Configure the approval page, the store and send_command as a
                                     JSON document in your login keychain (the first run creates
                                     the signing key through sudo; see setup --help)
  add [label]                        Register a passkey for yourself (asks for Touch ID or your
                                     password, then shows or sends a registration URL; the label
                                     defaults to the registration time)
  list                               List your passkeys: label, credential id, registration time
  del <label|id>                     Delete one of your passkeys by credential id or by label

Commands (internal, started by pam_passkey.so, the helper itself or setup):
  _setup-write                       Create the System Keychain signing key (as root)
  _auth                              Serve one authentication request (helper-protocol on stdin/stdout)
  _read-user <user>                  For the root helper only: print the user's settings and signed
                                     passkey records from the login keychain (exit 3: locked)
  _open-page                         Open the URL read from stdin in the default browser
  _activate-browser                  Bring the default browser for the URL read from stdin to the front

Commands (verification):
  _probe-open <user>                 Open a dummy approval URL as <user>, then activate the browser again
  _probe-dialog [--seteuid <user> | --drop <user>] <reason>
                                     Show the module's Touch ID dialog with <reason> verbatim (e.g.
                                     $'line 1\\nline 2') and print the ids, the GUI session check,
                                     canEvaluatePolicy and the answer. Without a flag: as the current
                                     user, not root. Through sudo: --seteuid evaluates as root with
                                     the euid set to <user>, --drop in a child permanently dropped
                                     to <user>
  _probe-system <write|read|delete> <page_url|store|send_command|signing_key|verification_key>
                                     Inspect isolated, fixed-value System Keychain items
  _probe-login <write|read|delete>   Inspect an isolated, fixed-value login keychain item

Global options:
  --help                             Show this help

Environment: ignored by Keychain item selection; spawned children inherit none of it, except
send_command, which gets PATH LANG LC_* TMPDIR SSH_AUTH_SOCK and its user's HOME USER LOGNAME.
";
const PROBE_VALUE: &str = "pam-passkey-keychain-probe-2026";

unsafe extern "C" {
    fn passkey_open_url(url: *const c_char) -> i32;
    fn passkey_activate_handler(url: *const c_char) -> i32;
    fn passkey_touch_id_create(japanese: std::ffi::c_int) -> *mut std::ffi::c_void;
    fn passkey_touch_id_can_evaluate(handle: *mut std::ffi::c_void) -> std::ffi::c_long;
    fn passkey_touch_id_begin(handle: *mut std::ffi::c_void, reason: *const c_char) -> i32;
    fn passkey_touch_id_wait(handle: *mut std::ffi::c_void) -> std::ffi::c_long;
    fn passkey_touch_id_release(handle: *mut std::ffi::c_void);
}

unsafe extern "C" {
    // The module's session check (pam_passkey/src/process.c), linked here for the probe.
    fn passkey_gui_session_of(uid: libc::uid_t) -> std::ffi::c_int;
}

/// How `_probe-dialog` evaluates, for comparing the ways the module could show its dialog.
enum DialogAs {
    /// As the user running the probe, without sudo (as `add` does).
    Caller,
    /// As root with the euid set to the user for the evaluation and back (the module inside
    /// sudo does this, though its real uid is the user's rather than root's).
    Seteuid(child::Identity),
    /// In a child permanently dropped to the user, as the helper's children run.
    Dropped(String),
}

/// `_probe-dialog`: the module's dialog with an unmodified reason, to see how the dialog
/// renders it and whether it can be shown at all. Prints the process's ids, whether it is in
/// the user's graphical session, `canEvaluatePolicy` and the LAError code of the answer.
fn probe_dialog(how: DialogAs, reason: &str) -> Result<(), Box<dyn Error>> {
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    let uid = match &how {
        DialogAs::Caller if root => {
            return Err("run as the user whose Touch ID is evaluated, without sudo (or use --seteuid / --drop <user> through sudo)".into());
        }
        DialogAs::Seteuid(_) | DialogAs::Dropped(_) if !root => {
            return Err("--seteuid and --drop need root (run through sudo)".into());
        }
        DialogAs::Dropped(user) => {
            let status = RunAs::for_user(user)?
                .command("_probe-dialog")?
                .arg(reason)
                .status()?;
            if !status.success() {
                return Err(format!("the dropped child ended with {status}").into());
            }
            return Ok(());
        }
        DialogAs::Seteuid(identity) => identity.uid,
        // SAFETY: getuid has no preconditions.
        DialogAs::Caller => unsafe { libc::getuid() },
    };
    let japanese = match &how {
        DialogAs::Seteuid(identity) => language::prefers_japanese(identity.home()),
        _ => language::prefers_japanese(&current_user()?.1),
    };
    let reason = CString::new(reason)?;
    if let DialogAs::Seteuid(_) = how
        // SAFETY: seteuid has no memory preconditions.
        && unsafe { libc::seteuid(uid) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the ids are read, the session shim reads the process's own session; the handle
    // is created, used and released here and the reason outlives begin.
    let (can, answer, ids, session) = unsafe {
        let ids = (libc::getuid(), libc::geteuid());
        let session = passkey_gui_session_of(uid);
        let handle = passkey_touch_id_create(std::ffi::c_int::from(japanese));
        if handle.is_null() {
            (None, None, ids, session)
        } else {
            let can = passkey_touch_id_can_evaluate(handle);
            let answer = (can == 0 && passkey_touch_id_begin(handle, reason.as_ptr()) == 0)
                .then(|| passkey_touch_id_wait(handle));
            passkey_touch_id_release(handle);
            (Some(can), answer, ids, session)
        }
    };
    // SAFETY: seteuid has no memory preconditions; the saved uid is root's.
    if let DialogAs::Seteuid(_) = how
        && unsafe { libc::seteuid(0) } != 0
    {
        return Err("could not return the euid to root".into());
    }
    println!(
        "ruid: {} euid: {} gui-session-of({uid}): {session}",
        ids.0, ids.1
    );
    match can {
        None => println!("canEvaluatePolicy: (no LAContext)"),
        Some(can) => println!("canEvaluatePolicy: {can}"),
    }
    if let Some(answer) = answer {
        let meaning = match answer {
            0 => "success",
            -1 => "authentication failed",
            -2 => "cancel",
            -3 => "fallback (Show details)",
            -4 => "system cancel",
            -6 => "biometry not available",
            -7 => "biometry not enrolled",
            -8 => "biometry lockout",
            -1004 => "not interactive",
            _ => "other LAError",
        };
        println!("answer: {answer} ({meaning})");
    }
    Ok(())
}

fn probe_dialog_args(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [reason] => probe_dialog(DialogAs::Caller, reason),
        [flag, user, reason] if flag == "--seteuid" => {
            probe_dialog(DialogAs::Seteuid(child::identity(user)?), reason)
        }
        [flag, user, reason] if flag == "--drop" => {
            probe_dialog(DialogAs::Dropped(user.clone()), reason)
        }
        _ => Err("usage: _probe-dialog [--seteuid <user> | --drop <user>] <reason>".into()),
    }
}

/// `_read-user`: started by the root helper as the user whose login keychain it reads; prints
/// its `config` and `users/<user>` items as one JSON line (an absent item is null). Started any
/// other way it prints nothing: the settings carry the store's secret.
fn read_user(user: &str) -> i32 {
    if !auth::started_by_root_helper() {
        eprintln!("pam-passkey: _read-user answers only to the root helper");
        return 1;
    }
    let result = current_user().and_then(|(current, home)| {
        if user != current {
            return Err("read requested for another OS user".into());
        }
        Ok(auth::read_own_items(user, Path::new(&home)))
    });
    match result {
        Ok(Ok(items)) => match serde_json::to_string(&items) {
            Ok(line) => {
                println!("{line}");
                0
            }
            Err(error) => {
                eprintln!("pam-passkey: {error}");
                1
            }
        },
        Ok(Err(error @ (KeychainError::Locked(_) | KeychainError::AccessDenied(_)))) => {
            eprintln!("pam-passkey: {error}");
            auth::EXIT_LOCKED
        }
        Ok(Err(error)) => {
            eprintln!("pam-passkey: {error}");
            1
        }
        Err(error) => {
            eprintln!("pam-passkey: {error}");
            1
        }
    }
}

/// `_open-page` / `_activate-browser`: the URL comes on stdin so it never appears in argv.
fn browser(activate: bool) -> Result<(), Box<dyn Error>> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let url = CString::new(line.trim_end_matches('\n'))?;
    if url.is_empty() {
        return Err("no URL on standard input".into());
    }
    // SAFETY: the URL is NUL-terminated and outlives the call.
    let status = unsafe {
        if activate {
            passkey_activate_handler(url.as_ptr())
        } else {
            passkey_open_url(url.as_ptr())
        }
    };
    if status != 0 {
        return Err(format!("LaunchServices returned OSStatus {status}").into());
    }
    Ok(())
}

fn probe_open(user: &str) -> Result<(), Box<dyn Error>> {
    let run_as = RunAs::for_user(user)?;
    if let RunAs::Inherited = run_as
        && current_user()?.0 != user
    {
        return Err("not root: run as <user> itself or through sudo".into());
    }
    auth::open_page(&run_as, auth::DUMMY_APPROVAL_URL)?;
    println!("opened {}", auth::DUMMY_APPROVAL_URL);
    auth::activate_browser(&run_as, auth::DUMMY_APPROVAL_URL)?;
    println!("activated the default browser again");
    Ok(())
}

fn probe_system(operation: &str, account: &str) -> Result<(), Box<dyn Error>> {
    let item = match account {
        "page_url" => SystemItem::PageUrl,
        "store" => SystemItem::Store,
        "send_command" => SystemItem::SendCommand,
        "signing_key" => SystemItem::SigningKey,
        "verification_key" => SystemItem::VerificationKey,
        _ => return Err("unknown probe item".into()),
    };
    let keychain = Keychain::system()?;
    match operation {
        "write" => keychain.write_probe_system(item, PROBE_VALUE)?,
        "read" => {
            let value = keychain.read_probe_system(item)?;
            if value != PROBE_VALUE {
                return Err("probe value differs from fixed test value".into());
            }
            println!("{value}");
        }
        "delete" => keychain.delete_probe_system(item)?,
        _ => return Err("unknown probe operation".into()),
    }
    Ok(())
}

fn probe_login(operation: &str) -> Result<(), Box<dyn Error>> {
    let (user, home) = current_user()?;
    let keychain = Keychain::login(Path::new(&home))?;
    match operation {
        "write" => keychain.write_probe_user(&user, PROBE_VALUE)?,
        "read" => {
            let value = keychain.read_probe_user(&user)?;
            if value != PROBE_VALUE {
                return Err("probe value differs from fixed test value".into());
            }
            println!("{value}");
        }
        "delete" => keychain.delete_probe_user(&user)?,
        _ => return Err("unknown probe operation".into()),
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [] => print!("{HELP}"),
        [command, ..] if command == "setup" && args.iter().any(|arg| arg == "--help") => {
            print!("{}", setup::HELP)
        }
        _ if args.iter().any(|arg| arg == "--help") => print!("{HELP}"),
        [command, rest @ ..] if command == "setup" => setup::run(rest)?,
        [command] if command == "add" => add::run(None)?,
        [command, label] if command == "add" => add::run(Some(label))?,
        [command] if command == "list" => passkeys::list()?,
        [command, target] if command == "del" => passkeys::del(target)?,
        [command] if command == "_auth" => auth::run()?,
        [command] if command == "_setup-write" => setup::write_from_stdin()?,
        [command] if command == "_open-page" => browser(false)?,
        [command] if command == "_activate-browser" => browser(true)?,
        [command, user] if command == "_probe-open" => probe_open(user)?,
        [command, rest @ ..] if command == "_probe-dialog" => probe_dialog_args(rest)?,
        [command, operation, item] if command == "_probe-system" => probe_system(operation, item)?,
        [command, operation] if command == "_probe-login" => probe_login(operation)?,
        _ => return Err("invalid arguments; run pam-passkey --help".into()),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [command, user] = args.as_slice()
        && command == "_read-user"
    {
        std::process::exit(read_user(user));
    }
    if let Err(error) = run(&args) {
        eprintln!("pam-passkey: {error}");
        std::process::exit(1);
    }
}
