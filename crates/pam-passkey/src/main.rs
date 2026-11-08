mod auth;
mod child;
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
  setup [--module <path>] [page_url] Configure the approval page, the store and send_command
                                     (writes the System Keychain through sudo; see setup --help)

Commands (internal, started by pam_passkey.so, the helper itself or setup):
  setup --stdin                      Write the settings checked by setup (as root)
  _auth                              Serve one authentication request (helper-protocol on stdin/stdout)
  _read-user-keys <user>             Print the user's signed public-key records (exit 2: none, 3: locked)
  _open-page                         Open the URL read from stdin in the default browser
  _activate-browser                  Bring the default browser for the URL read from stdin to the front

Commands (verification):
  _probe-open <user>                 Open a dummy approval URL as <user>, then activate the browser again
  _probe-dialog <reason>             Show the module's Touch ID dialog with <reason> verbatim (as the
                                     current user, not root; e.g. $'line 1\\nline 2') and print the answer
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
    fn passkey_touch_id_create() -> *mut std::ffi::c_void;
    fn passkey_touch_id_can_evaluate(handle: *mut std::ffi::c_void) -> std::ffi::c_long;
    fn passkey_touch_id_begin(handle: *mut std::ffi::c_void, reason: *const c_char) -> i32;
    fn passkey_touch_id_wait(handle: *mut std::ffi::c_void) -> std::ffi::c_long;
    fn passkey_touch_id_release(handle: *mut std::ffi::c_void);
}

/// `_probe-dialog`: the module's dialog with an unmodified reason, to see how the dialog
/// renders it (line breaks, length). Prints the LAError code of the answer.
fn probe_dialog(reason: &str) -> Result<(), Box<dyn Error>> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Err("run as the user whose Touch ID is evaluated, without sudo".into());
    }
    let reason = CString::new(reason)?;
    // SAFETY: the handle is created, used and released here; the reason outlives begin.
    unsafe {
        let handle = passkey_touch_id_create();
        if handle.is_null() {
            return Err("could not create an LAContext".into());
        }
        let can = passkey_touch_id_can_evaluate(handle);
        println!("canEvaluatePolicy: {can}");
        let answer = if can != 0 {
            None
        } else if passkey_touch_id_begin(handle, reason.as_ptr()) != 0 {
            passkey_touch_id_release(handle);
            return Err("the reason was rejected (empty or not UTF-8)".into());
        } else {
            Some(passkey_touch_id_wait(handle))
        };
        passkey_touch_id_release(handle);
        if let Some(answer) = answer {
            let meaning = match answer {
                0 => "success",
                -1 => "authentication failed",
                -2 => "cancel",
                -3 => "fallback (詳細を確認)",
                -4 => "system cancel",
                -8 => "biometry lockout",
                _ => "other LAError",
            };
            println!("answer: {answer} ({meaning})");
        }
    }
    Ok(())
}

/// `_read-user-keys`: runs as the user whose login keychain it reads.
fn read_user_keys(user: &str) -> i32 {
    let result = current_user().and_then(|(current, home)| {
        if user != current {
            return Err("read requested for another OS user".into());
        }
        Ok(Keychain::login(Path::new(&home))?.read_user(user))
    });
    match result {
        Ok(Ok(keys)) => {
            print!("{keys}");
            0
        }
        Ok(Err(KeychainError::NotFound)) => auth::EXIT_NOT_FOUND,
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
        [command] if command == "_auth" => auth::run()?,
        [command] if command == "_open-page" => browser(false)?,
        [command] if command == "_activate-browser" => browser(true)?,
        [command, user] if command == "_probe-open" => probe_open(user)?,
        [command, reason] if command == "_probe-dialog" => probe_dialog(reason)?,
        [command, operation, item] if command == "_probe-system" => probe_system(operation, item)?,
        [command, operation] if command == "_probe-login" => probe_login(operation)?,
        _ => return Err("invalid arguments; run pam-passkey --help".into()),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [command, user] = args.as_slice()
        && command == "_read-user-keys"
    {
        std::process::exit(read_user_keys(user));
    }
    if let Err(error) = run(&args) {
        eprintln!("pam-passkey: {error}");
        std::process::exit(1);
    }
}
