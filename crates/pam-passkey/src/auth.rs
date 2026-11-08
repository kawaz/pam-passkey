//! `_auth`: the helper's side of helper-protocol, spawned by `pam_passkey.so`.

use crate::child::{RunAs, current_user};
use protocol::encoding::parse_utc;
use protocol::{HelperCommand, HelperEvent, HelperInput, UnavailableReason};
use std::error::Error;
use std::io::{BufRead, Read, Write};
use std::process::Stdio;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Exit statuses of `_read-user-keys` other than success, so the helper can tell why it read nothing.
pub const EXIT_NOT_FOUND: i32 = 2;
pub const EXIT_LOCKED: i32 = 3;

/// Stand-in for the approval URL until requests are put to the store.
pub const DUMMY_APPROVAL_URL: &str = "https://pam-passkey.github.io/#pam-passkey-dummy-request";

/// The input line carries the process chain; its request object is capped at 64 KiB.
const MAX_LINE: u64 = 1024 * 1024;

enum Records {
    Found(String),
    Unavailable(UnavailableReason),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
    Finished {
        pass: bool,
    },
    /// Standard input was closed: the PAM side cancelled or gave up.
    Cancelled,
    Expired,
}

fn emit(event: &HelperEvent) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", serde_json::to_string(event)?)?;
    stdout.flush()
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    if reader
        .by_ref()
        .take(MAX_LINE)
        .read_until(b'\n', &mut line)?
        == 0
    {
        return Ok(None);
    }
    if line.pop() != Some(b'\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "line too long or not terminated",
        ));
    }
    Ok(Some(line))
}

fn valid_request_id(id: &str) -> bool {
    id.len() == 22
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_user(user: &str) -> bool {
    !user.is_empty() && !user.contains(['/', '\0']) && user != "." && user != ".."
}

/// Reads `users/<PAM_USER>` from PAM_USER's login keychain in a child running as PAM_USER.
fn read_records(user: &str, run_as: &RunAs) -> Result<Records, Box<dyn Error>> {
    match run_as {
        // root has no passkeys and no biometry (DR-0012); its login keychain is never read.
        RunAs::Dropped(identity) if identity.uid == 0 => {
            return Ok(Records::Unavailable(UnavailableReason::NoCredentials));
        }
        RunAs::Dropped(_) => {}
        RunAs::Inherited => {
            if current_user()?.0 != user {
                return Err(
                    "not root and PAM_USER is another user; cannot read its keychain".into(),
                );
            }
        }
    }
    let output = run_as
        .command("_read-user-keys")?
        .arg(user)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()?;
    match output.status.code() {
        Some(0) => Ok(Records::Found(String::from_utf8(output.stdout)?)),
        Some(EXIT_NOT_FOUND) => Ok(Records::Unavailable(UnavailableReason::NoCredentials)),
        Some(EXIT_LOCKED) => Ok(Records::Unavailable(UnavailableReason::KeychainLocked)),
        status => Err(format!("user Keychain child failed: {status:?}").into()),
    }
}

/// Credential ids from the records whose JWS verifies (DR-0011).
/// Design rationale: the JWS verifier and the System Keychain public key arrive with the store
/// integration; until then no record can be verified, and unverified records are ignored.
fn trusted_credentials(_records: &str) -> Vec<String> {
    Vec::new()
}

/// Runs `pam-passkey <subcommand>` as PAM_USER with `url` on its standard input.
fn browser(run_as: &RunAs, subcommand: &str, url: &str) -> Result<(), Box<dyn Error>> {
    let mut child = run_as
        .command(subcommand)?
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{url}")?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("{subcommand} failed: {status}").into());
    }
    Ok(())
}

pub fn open_page(run_as: &RunAs, url: &str) -> Result<(), Box<dyn Error>> {
    browser(run_as, "_open-page", url)
}

pub fn activate_browser(run_as: &RunAs, url: &str) -> Result<(), Box<dyn Error>> {
    browser(run_as, "_activate-browser", url)
}

/// Serves PAM's commands until `finish`, the close of standard input, or the deadline.
/// `lines` yields each later input line, then `None` at end of input.
pub fn serve(
    lines: &Receiver<Option<Vec<u8>>>,
    deadline: Instant,
    mut act: impl FnMut(HelperCommand),
) -> Ending {
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Some(line)) => match serde_json::from_slice::<HelperCommand>(&line) {
                Ok(HelperCommand::Finish { pass }) => return Ending::Finished { pass },
                Ok(command) => act(command),
                Err(_) => eprintln!("pam-passkey: ignored an unknown command line"),
            },
            Ok(None) | Err(RecvTimeoutError::Disconnected) => return Ending::Cancelled,
            Err(RecvTimeoutError::Timeout) => return Ending::Expired,
        }
    }
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let input = read_line(&mut std::io::stdin().lock())?.ok_or("no input line")?;
    let input: HelperInput = serde_json::from_slice(&input)?;
    if !valid_user(&input.user) || !valid_request_id(&input.id) {
        return Err("invalid user or request ID in the input line".into());
    }
    let expires = parse_utc(&input.expires).ok_or("expires is not RFC 3339 UTC")?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let remaining = u64::try_from(expires - now)
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or("the request has already expired")?;
    let deadline = Instant::now() + Duration::from_secs(remaining);

    let run_as = RunAs::for_user(&input.user)?;
    let records = match read_records(&input.user, &run_as)? {
        Records::Found(records) => records,
        Records::Unavailable(reason) => {
            emit(&HelperEvent::Unavailable { reason })?;
            return Ok(());
        }
    };
    if trusted_credentials(&records).is_empty() {
        emit(&HelperEvent::Unavailable {
            reason: UnavailableReason::NoCredentials,
        })?;
        return Ok(());
    }

    // The store integration goes here: PUT the request, deliver the approval URL
    // (send_command, or a `url` event), and poll for the assertion alongside the commands.
    let (sender, lines) = channel();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        while let Ok(Some(line)) = read_line(&mut stdin) {
            if sender.send(Some(line)).is_err() {
                return;
            }
        }
        let _ = sender.send(None);
    });
    let ending = serve(&lines, deadline, |command| {
        let result = match command {
            HelperCommand::Open => open_page(&run_as, DUMMY_APPROVAL_URL),
            HelperCommand::Reactivate => activate_browser(&run_as, DUMMY_APPROVAL_URL),
            HelperCommand::Finish { .. } => Ok(()),
        };
        if let Err(error) = result {
            eprintln!("pam-passkey: {error}");
        }
    });
    // The result PUT (pass only for Finished { pass: true }) and the DELETE of the request and
    // assertion belong to the store integration as well.
    eprintln!("pam-passkey: request ended: {ending:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Sender;

    fn feed(lines: &[Option<&str>]) -> Receiver<Option<Vec<u8>>> {
        let (sender, receiver): (Sender<Option<Vec<u8>>>, _) = channel();
        for line in lines {
            sender
                .send(line.map(|text| text.as_bytes().to_vec()))
                .unwrap();
        }
        receiver
    }

    // helper-protocol コマンド: open / reactivate are served in order, and finish ends the request
    // without serving anything queued after it.
    #[test]
    fn serves_commands_until_finish() {
        let lines = feed(&[
            Some(r#"{"cmd":"open"}"#),
            Some(r#"{"cmd":"reactivate"}"#),
            Some(r#"{"cmd":"finish","pass":true}"#),
            Some(r#"{"cmd":"open"}"#),
        ]);
        let mut served = Vec::new();
        let ending = serve(&lines, Instant::now() + Duration::from_secs(5), |command| {
            served.push(command)
        });
        assert_eq!(ending, Ending::Finished { pass: true });
        assert_eq!(served, [HelperCommand::Open, HelperCommand::Reactivate]);
    }

    // Closing standard input is the cancel command; unknown lines do not end the request.
    #[test]
    fn closed_input_is_cancel() {
        let lines = feed(&[Some("garbage"), Some(r#"{"cmd":"open"}"#), None]);
        let mut served = Vec::new();
        let ending = serve(&lines, Instant::now() + Duration::from_secs(5), |command| {
            served.push(command)
        });
        assert_eq!(ending, Ending::Cancelled);
        assert_eq!(served, [HelperCommand::Open]);
    }

    // The helper stops at the same deadline as PAM even if PAM never closes its input.
    #[test]
    fn deadline_ends_the_request() {
        let (_sender, lines) = channel::<Option<Vec<u8>>>();
        let started = Instant::now();
        let ending = serve(&lines, started + Duration::from_millis(100), |_| {});
        assert_eq!(ending, Ending::Expired);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    // Lines are bounded and must be complete; a truncated or oversized line is an error, not input.
    #[test]
    fn read_line_requires_terminated_bounded_lines() {
        let mut ok = &b"one\ntwo\n"[..];
        assert_eq!(read_line(&mut ok).unwrap(), Some(b"one".to_vec()));
        assert_eq!(read_line(&mut ok).unwrap(), Some(b"two".to_vec()));
        assert_eq!(read_line(&mut ok).unwrap(), None);
        let mut unterminated = &b"tail"[..];
        assert!(read_line(&mut unterminated).is_err());
        let long = vec![b'a'; MAX_LINE as usize + 1];
        assert!(read_line(&mut long.as_slice()).is_err());
    }

    // The request ID is the PAM module's 16 random bytes in base64url; nothing else names a request.
    #[test]
    fn request_id_shape() {
        assert!(valid_request_id(&protocol::encoding::base64url(
            &[0xff; 16]
        )));
        assert!(!valid_request_id("short"));
        assert!(!valid_request_id("aaaaaaaaaaaaaaaaaaaaa="));
        assert!(!valid_user("a/b"));
        assert!(!valid_user(".."));
        assert!(valid_user("kawaz"));
    }
}
