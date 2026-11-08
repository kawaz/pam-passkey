//! `_auth`: the helper's side of helper-protocol, spawned by `pam_passkey.so`.
//!
//! One request: PUT the request to the store, deliver the approval URL, poll for the assertion
//! while serving PAM's commands, verify it, PUT the result, and DELETE the request and the
//! assertion (DR-0006).

use crate::child::{RunAs, current_user};
use crate::records::{parse_verification_jwk, trusted_credentials};
use crate::settings::{DEFAULT_PAGE_URL, Page, read_optional};
use crate::store::{Fetched, MAX_ASSERTION, MAX_REQUEST, Store, StoreConfig};
use crate::webauthn::{CredentialSet, Expectation, Rejection, verify_assertion};
use pam_passkey::keychain::{Keychain, SystemItem};
use protocol::encoding::parse_utc;
use protocol::{ExchangeRequest, HelperCommand, HelperEvent, HelperInput, UnavailableReason};
use std::error::Error;
use std::io::{BufRead, Read, Write};
use std::process::{Child, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Exit statuses of `_read-user-keys` other than success, so the helper can tell why it read nothing.
pub const EXIT_NOT_FOUND: i32 = 2;
pub const EXIT_LOCKED: i32 = 3;

/// What `_probe-open` opens: the default page with a fragment that names no request.
pub const DUMMY_APPROVAL_URL: &str = "https://pam-passkey.github.io/#pam-passkey-dummy-request";

/// The input line carries the process chain; its request object is capped at 64 KiB.
const MAX_LINE: u64 = 1024 * 1024;

/// How often the assertion is polled (DESIGN 未決事項: 仮の既定は 1 秒).
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Longest single store request while waiting, so a hung request cannot hold the wait open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The result PUT and the DELETEs after the request ended share this budget: PAM signals the
/// helper 5 seconds after the deadline.
const CLEANUP_BUDGET: Duration = Duration::from_secs(4);

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
    /// The first assertion found in the store, and its verdict.
    Judged(Result<(), Rejection>),
}

impl Ending {
    /// The result object (DR-0006 終了経路ごとの result).
    fn pass(&self) -> bool {
        matches!(self, Self::Finished { pass: true } | Self::Judged(Ok(())))
    }

    /// Whether PAM still waits for a `result` event: not after `finish` or the close of its input.
    fn reported(&self) -> bool {
        matches!(self, Self::Judged(_) | Self::Expired)
    }
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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
        Some(status) => Err(format!(
            "cannot read the login keychain of user {user} (exit status {status})"
        )
        .into()),
        None => {
            Err(format!("reading the login keychain of user {user} was killed by a signal").into())
        }
    }
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

/// Serves PAM's commands until `finish`, the close of standard input, the deadline, or a poll
/// that concludes the request. `lines` yields each later input line, then `None` at end of
/// input; `poll` runs every `interval` (first right away) and is given the time left.
pub fn serve(
    lines: &Receiver<Option<Vec<u8>>>,
    deadline: Instant,
    interval: Duration,
    mut act: impl FnMut(HelperCommand),
    mut poll: impl FnMut(Duration) -> Option<Ending>,
) -> Ending {
    let mut next_poll = Instant::now();
    loop {
        let wake = next_poll.min(deadline);
        match lines.recv_timeout(wake.saturating_duration_since(Instant::now())) {
            Ok(Some(line)) => match serde_json::from_slice::<HelperCommand>(&line) {
                Ok(HelperCommand::Finish { pass }) => return Ending::Finished { pass },
                Ok(command) => act(command),
                Err(_) => eprintln!("pam-passkey: ignored an unknown command line"),
            },
            Ok(None) | Err(RecvTimeoutError::Disconnected) => return Ending::Cancelled,
            Err(RecvTimeoutError::Timeout) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ending::Expired;
                }
                if Instant::now() >= next_poll {
                    if let Some(ending) = poll(left) {
                        return ending;
                    }
                    next_poll = Instant::now() + interval;
                }
            }
        }
    }
}

/// The side effects of a request, apart from the store.
pub trait Effects {
    fn emit(&mut self, event: &HelperEvent);
    /// Run `send_command` with `url` on its standard input.
    fn send(&mut self, command: &str, url: &str);
    fn open(&mut self, url: &str);
    fn reactivate(&mut self, url: &str);
}

/// One request against the store, after PAM_USER's credentials have been established.
pub struct Remote<'a> {
    pub input: &'a HelperInput,
    pub page: &'a Page,
    pub store: &'a Store,
    pub credentials: &'a CredentialSet,
    /// `None` delivers the approval URL as a `url` event (DR-0008).
    pub send_command: Option<&'a str>,
    /// The request's `expires` in Unix seconds, and the same instant on the monotonic clock.
    pub expires: i64,
    pub deadline: Instant,
}

impl Remote<'_> {
    /// Runs the request to its end. `Err` means the store could not take the request, which
    /// the caller reports as `unavailable store-unreachable`.
    pub fn run(
        &self,
        lines: &Receiver<Option<Vec<u8>>>,
        effects: &mut impl Effects,
    ) -> Result<Ending, UnavailableReason> {
        let id = &self.input.id;
        let request_key = self.store.key(id, "request");
        let assertion_key = self.store.key(id, "assertion");
        let result_key = self.store.key(id, "result");
        // Presigned URLs last exactly as long as the request (DR-0005).
        let valid_for =
            Duration::from_secs(u64::try_from(self.expires - unix_now()).unwrap_or(0).max(1));
        let request = ExchangeRequest::Approve {
            details: self.input.details.clone(),
            nonce: id.clone(),
            expires: self.input.expires.clone(),
            allow_credentials: self.credentials.ids(),
            assertion_put_url: self.store.presign_put(&assertion_key, valid_for).into(),
            result_get_url: self.store.presign_get(&result_key, valid_for).into(),
        };
        // These bytes are what the page fetches and what the challenge is the hash of.
        let request =
            serde_json::to_vec(&request).map_err(|_| UnavailableReason::StoreUnreachable)?;
        if request.len() > MAX_REQUEST {
            eprintln!(
                "pam-passkey: the request is {} bytes, over the {MAX_REQUEST}-byte limit",
                request.len()
            );
            return Err(UnavailableReason::StoreUnreachable);
        }
        let timeout = REQUEST_TIMEOUT.min(self.deadline.saturating_duration_since(Instant::now()));
        match self.store.put(&request_key, &request, false, timeout) {
            Ok(200) => {}
            Ok(status) => {
                eprintln!("pam-passkey: PUT of the request answered HTTP {status}");
                return Err(UnavailableReason::StoreUnreachable);
            }
            Err(error) => {
                eprintln!("pam-passkey: PUT of the request: {error}");
                return Err(UnavailableReason::StoreUnreachable);
            }
        }

        let approval_url = format!(
            "{}#{}",
            self.page.url,
            self.store.presign_get(&request_key, valid_for)
        );
        match self.send_command {
            Some(command) => effects.send(command, &approval_url),
            None => effects.emit(&HelperEvent::Url {
                url: approval_url.clone(),
            }),
        }

        let mut act = |command| match command {
            HelperCommand::Open => effects.open(&approval_url),
            HelperCommand::Reactivate => effects.reactivate(&approval_url),
            HelperCommand::Finish { .. } => {}
        };
        let poll = |left: Duration| {
            match self
                .store
                .get(&assertion_key, MAX_ASSERTION, REQUEST_TIMEOUT.min(left))
            {
                Ok(Fetched::Missing) => None,
                // The first object found decides; later overwrites are never read (DR-0006).
                Ok(Fetched::Found(body)) => Some(Ending::Judged(verify_assertion(
                    &body,
                    &Expectation {
                        request: &request,
                        page: self.page,
                        credentials: self.credentials,
                        expires: self.expires,
                        now: unix_now(),
                    },
                ))),
                Ok(Fetched::TooLarge) => Some(Ending::Judged(Err(Rejection::TooLarge))),
                Err(error) => {
                    eprintln!("pam-passkey: polling for the assertion: {error}");
                    None
                }
            }
        };
        let ending = serve(lines, self.deadline, POLL_INTERVAL, &mut act, poll);
        eprintln!("pam-passkey: request ended: {ending:?}");
        self.conclude(
            &ending,
            effects,
            [&request_key, &assertion_key],
            &result_key,
        );
        Ok(ending)
    }

    /// result PUT, the `result` event if PAM still waits for one, then the DELETEs.
    fn conclude(
        &self,
        ending: &Ending,
        effects: &mut impl Effects,
        deleted: [&str; 2],
        result_key: &str,
    ) {
        let until = Instant::now() + CLEANUP_BUDGET;
        let left = || until.saturating_duration_since(Instant::now());
        let pass = ending.pass();
        let body: &[u8] = if pass { b"pass" } else { b"fail" };
        match self.store.put(result_key, body, false, left()) {
            Ok(200) => {}
            Ok(status) => eprintln!("pam-passkey: PUT of the result answered HTTP {status}"),
            Err(error) => eprintln!("pam-passkey: PUT of the result: {error}"),
        }
        if ending.reported() {
            effects.emit(&HelperEvent::Result {
                id: self.input.id.clone(),
                pass,
            });
        }
        for key in deleted {
            if left().is_zero() {
                eprintln!("pam-passkey: no time left to delete {key}");
                continue;
            }
            if let Err(error) = self.store.delete(key, left()) {
                eprintln!("pam-passkey: DELETE of {key}: {error}");
            }
        }
    }
}

/// The real side effects: events on standard output, children as PAM_USER.
struct Helper<'a> {
    run_as: &'a RunAs,
    sent: Option<Child>,
}

impl Effects for Helper<'_> {
    fn emit(&mut self, event: &HelperEvent) {
        if let Err(error) = emit(event) {
            eprintln!("pam-passkey: writing an event: {error}");
        }
    }

    /// Failures are warnings only (DR-0008). The command runs alongside the wait and is
    /// stopped if it is still running when the request ends.
    fn send(&mut self, command: &str, url: &str) {
        let spawned = self.run_as.shell(command).and_then(|mut shell| {
            let mut child = shell
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take()
                && let Err(error) = writeln!(stdin, "{url}")
            {
                eprintln!("pam-passkey: writing the URL to send_command: {error}");
            }
            Ok(child)
        });
        match spawned {
            Ok(child) => self.sent = Some(child),
            Err(error) => eprintln!("pam-passkey: warning: send_command could not start: {error}"),
        }
    }

    fn open(&mut self, url: &str) {
        if let Err(error) = open_page(self.run_as, url) {
            eprintln!("pam-passkey: {error}");
        }
    }

    fn reactivate(&mut self, url: &str) {
        if let Err(error) = activate_browser(self.run_as, url) {
            eprintln!("pam-passkey: {error}");
        }
    }
}

impl Drop for Helper<'_> {
    fn drop(&mut self) {
        let Some(mut child) = self.sent.take() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => {
                eprintln!("pam-passkey: warning: send_command exited with {status}");
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                eprintln!("pam-passkey: warning: send_command was still running; stopped it");
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// The System Keychain settings a remote approval needs.
struct Settings {
    page: Page,
    store: StoreConfig,
    send_command: Option<String>,
    verification_key: ed25519_dalek::VerifyingKey,
}

/// The settings, or why their absence makes remote unavailable. `Err` is a Keychain failure.
fn load_settings() -> Result<Result<Settings, UnavailableReason>, Box<dyn Error>> {
    let keychain = Keychain::system()?;
    // Without the verification key no record can be trusted: nothing is registered.
    let Some(verification_key) = read_optional(&keychain, SystemItem::VerificationKey)?
        .as_deref()
        .and_then(parse_verification_jwk)
    else {
        eprintln!("pam-passkey: no usable verification key in the System Keychain (run setup)");
        return Ok(Err(UnavailableReason::NoCredentials));
    };
    let store = match read_optional(&keychain, SystemItem::Store)? {
        Some(text) => match serde_json::from_str::<StoreConfig>(&text) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("pam-passkey: the store setting is not valid: {error}");
                return Ok(Err(UnavailableReason::StoreUnreachable));
            }
        },
        None => {
            eprintln!("pam-passkey: no store setting in the System Keychain (run setup)");
            return Ok(Err(UnavailableReason::StoreUnreachable));
        }
    };
    let page = Page::parse(
        read_optional(&keychain, SystemItem::PageUrl)?
            .as_deref()
            .unwrap_or(DEFAULT_PAGE_URL),
    )?;
    let send_command =
        read_optional(&keychain, SystemItem::SendCommand)?.filter(|command| !command.is_empty());
    Ok(Ok(Settings {
        page,
        store,
        send_command,
        verification_key,
    }))
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let input = read_line(&mut std::io::stdin().lock())?.ok_or("no input line")?;
    let input: HelperInput = serde_json::from_slice(&input)?;
    if !valid_user(&input.user) || !valid_request_id(&input.id) {
        return Err("invalid user or request ID in the input line".into());
    }
    let expires = parse_utc(&input.expires).ok_or("expires is not RFC 3339 UTC")?;
    let remaining = u64::try_from(expires - unix_now())
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or("the request has already expired")?;
    let deadline = Instant::now() + Duration::from_secs(remaining);

    let unavailable = |reason| emit(&HelperEvent::Unavailable { reason });
    let run_as = RunAs::for_user(&input.user)?;
    let records = match read_records(&input.user, &run_as)? {
        Records::Found(records) => records,
        Records::Unavailable(reason) => return Ok(unavailable(reason)?),
    };
    let Settings {
        page,
        store,
        send_command,
        verification_key,
    } = match load_settings()? {
        Ok(settings) => settings,
        Err(reason) => return Ok(unavailable(reason)?),
    };
    let credentials = trusted_credentials(&records, &verification_key, &input.user);
    if credentials.is_empty() {
        return Ok(unavailable(UnavailableReason::NoCredentials)?);
    }
    let store = match Store::new(&store) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("pam-passkey: {error}");
            return Ok(unavailable(UnavailableReason::StoreUnreachable)?);
        }
    };

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
    let remote = Remote {
        input: &input,
        page: &page,
        store: &store,
        credentials: &credentials,
        send_command: send_command.as_deref(),
        expires,
        deadline,
    };
    let mut effects = Helper {
        run_as: &run_as,
        sent: None,
    };
    if let Err(reason) = remote.run(&lines, &mut effects) {
        unavailable(reason)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::minio::Minio;
    use crate::test_support::{Authenticator, Draft};
    use protocol::RequestDetails;
    use protocol::encoding::{base64url, format_utc};
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

    fn never(_: Duration) -> Option<Ending> {
        None
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
        let ending = serve(
            &lines,
            Instant::now() + Duration::from_secs(5),
            Duration::from_secs(1),
            |command| served.push(command),
            never,
        );
        assert_eq!(ending, Ending::Finished { pass: true });
        assert_eq!(served, [HelperCommand::Open, HelperCommand::Reactivate]);
    }

    // Closing standard input is the cancel command; unknown lines do not end the request.
    #[test]
    fn closed_input_is_cancel() {
        let lines = feed(&[Some("garbage"), Some(r#"{"cmd":"open"}"#), None]);
        let mut served = Vec::new();
        let ending = serve(
            &lines,
            Instant::now() + Duration::from_secs(5),
            Duration::from_secs(1),
            |command| served.push(command),
            never,
        );
        assert_eq!(ending, Ending::Cancelled);
        assert_eq!(served, [HelperCommand::Open]);
    }

    // The helper stops at the same deadline as PAM even if PAM never closes its input.
    #[test]
    fn deadline_ends_the_request() {
        let (_sender, lines) = channel::<Option<Vec<u8>>>();
        let started = Instant::now();
        let ending = serve(
            &lines,
            started + Duration::from_millis(100),
            Duration::from_secs(1),
            |_| {},
            never,
        );
        assert_eq!(ending, Ending::Expired);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    // The store is polled right away and then once per interval, commands keep being served in
    // between, and the first poll that finds the assertion ends the request with its verdict.
    #[test]
    fn polls_until_the_assertion_arrives() {
        let (sender, lines) = channel::<Option<Vec<u8>>>();
        let started = Instant::now();
        let mut polls = Vec::new();
        let mut served = Vec::new();
        let ending = serve(
            &lines,
            started + Duration::from_secs(5),
            Duration::from_millis(100),
            |command| served.push(command),
            |_| {
                polls.push(started.elapsed());
                if polls.len() == 1 {
                    sender.send(Some(br#"{"cmd":"open"}"#.to_vec())).unwrap();
                }
                (polls.len() == 3).then_some(Ending::Judged(Err(Rejection::Signature)))
            },
        );
        assert_eq!(ending, Ending::Judged(Err(Rejection::Signature)));
        assert_eq!(served, [HelperCommand::Open]);
        assert!(polls[0] < Duration::from_millis(50), "{polls:?}");
        // The command between polls does not reset the cadence.
        assert!(polls[1] >= Duration::from_millis(100), "{polls:?}");
        assert!(polls[2] >= Duration::from_millis(200), "{polls:?}");
        assert!(polls[2] < Duration::from_millis(400), "{polls:?}");
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

    // DR-0006 終了経路ごとの result, and which endings PAM still waits a result event for.
    #[test]
    fn endings_map_to_results() {
        for (ending, pass, reported) in [
            (Ending::Judged(Ok(())), true, true),
            (Ending::Judged(Err(Rejection::Signature)), false, true),
            (Ending::Finished { pass: true }, true, false),
            (Ending::Finished { pass: false }, false, false),
            (Ending::Cancelled, false, false),
            (Ending::Expired, false, true),
        ] {
            assert_eq!(ending.pass(), pass, "{ending:?}");
            assert_eq!(ending.reported(), reported, "{ending:?}");
        }
    }

    /// What a request did, as seen from outside the store.
    #[derive(Default)]
    struct Recorded {
        events: Vec<HelperEvent>,
        sent: Vec<(String, String)>,
        opened: Vec<String>,
    }

    /// Effects that hand the approval URL to a test "page" through a channel.
    struct Recorder {
        recorded: Recorded,
        urls: Sender<String>,
    }

    impl Effects for Recorder {
        fn emit(&mut self, event: &HelperEvent) {
            if let HelperEvent::Url { url } = event {
                let _ = self.urls.send(url.clone());
            }
            self.recorded.events.push(event.clone());
        }
        fn send(&mut self, command: &str, url: &str) {
            let _ = self.urls.send(url.to_owned());
            self.recorded
                .sent
                .push((command.to_owned(), url.to_owned()));
        }
        fn open(&mut self, url: &str) {
            self.recorded.opened.push(url.to_owned());
        }
        fn reactivate(&mut self, _: &str) {}
    }

    fn input(id: &str, lifetime: i64) -> HelperInput {
        let now = unix_now();
        HelperInput {
            user: "kawaz".into(),
            caller_uid: 501,
            id: id.into(),
            expires: format_utc(now + lifetime),
            tty: Some("/dev/ttys001".into()),
            details: RequestDetails {
                host: "mac".into(),
                user: "kawaz".into(),
                caller_uid: 501,
                tty: Some("/dev/ttys001".into()),
                time: format_utc(now),
                argv: vec!["sudo".into(), "true".into()],
                processes: Vec::new(),
            },
        }
    }

    /// What the test page does with the request it fetched.
    enum PageAction {
        /// Sign the request; `change` breaks one acceptance condition first.
        Sign(Box<dyn FnOnce(&mut Draft) + Send>),
        /// Put unsigned content in the assertion's place (a refusal).
        Refuse,
        /// Do nothing; PAM ends the request with these input lines.
        Leave(Vec<Option<&'static str>>),
    }

    struct Outcome {
        ending: Ending,
        recorded: Recorded,
        result: Option<Vec<u8>>,
        request_left: u16,
        assertion_left: u16,
    }

    /// One request against MinIO from PUT to DELETE, with a page that fetches the request
    /// through the approval URL and answers through the presigned URLs it contains.
    fn round(minio: &Minio, id: &str, send_command: Option<&str>, action: PageAction) -> Outcome {
        let store = Store::new(&minio.config(true)).unwrap();
        let page = Page::parse("https://pam-passkey.github.io/").unwrap();
        let authenticator = Authenticator::new(5, b"registered-credential");
        let mut credentials = CredentialSet::default();
        credentials.insert(
            authenticator.credential_id.clone(),
            authenticator.public_key(),
        );
        let input = input(id, 30);
        let expires = parse_utc(&input.expires).unwrap();
        let (url_sender, urls) = channel::<String>();
        let (line_sender, lines) = channel();
        // PAM keeps the helper's input open until it ends the request itself; the tester
        // thread's sender alone would close it when the thread returns.
        let _pam_input = line_sender.clone();
        let agent = minio.page_agent();
        let page_for_thread = page.clone();
        let tester = std::thread::spawn(move || {
            let approval = urls.recv().unwrap();
            let fetch = approval
                .strip_prefix("https://pam-passkey.github.io/#")
                .expect("approval URL is <page_url>#<presigned GET>")
                .to_owned();
            let request = agent
                .get(&fetch)
                .call()
                .unwrap()
                .body_mut()
                .read_to_vec()
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&request).unwrap();
            let assertion_put = parsed["assertion_put_url"].as_str().unwrap().to_owned();
            let result_get = parsed["result_get_url"].as_str().unwrap().to_owned();
            let put = |body: &[u8]| {
                agent
                    .put(&assertion_put)
                    .header("If-None-Match", "*")
                    .send(body)
                    .unwrap()
                    .status()
                    .as_u16()
            };
            match action {
                PageAction::Sign(change) => {
                    let mut draft = Draft::valid(&authenticator, &request, &page_for_thread);
                    change(&mut draft);
                    assert_eq!(put(&draft.finish(&authenticator)), 200);
                }
                PageAction::Refuse => assert_eq!(put(b"refused"), 200),
                PageAction::Leave(input) => {
                    for line in input {
                        let _ = line_sender.send(line.map(|text| text.as_bytes().to_vec()));
                    }
                }
            }
            (parsed, result_get)
        });
        let mut recorder = Recorder {
            recorded: Recorded::default(),
            urls: url_sender,
        };
        let remote = Remote {
            input: &input,
            page: &page,
            store: &store,
            credentials: &credentials,
            send_command,
            expires,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        let ending = remote.run(&lines, &mut recorder).unwrap();
        let (parsed, result_get) = tester.join().unwrap();
        // The request carries the documented fields and the registered credential ids.
        assert_eq!(parsed["kind"], "approve");
        assert_eq!(parsed["nonce"], id);
        assert_eq!(parsed["expires"], input.expires.as_str());
        assert_eq!(
            parsed["allow_credentials"],
            serde_json::json!([base64url(b"registered-credential")])
        );
        assert!(parsed.get("challenge").is_none());
        let agent = minio.page_agent();
        let mut response = agent.get(&result_get).call().unwrap();
        let result = (response.status() == 200).then(|| response.body_mut().read_to_vec().unwrap());
        let timeout = Duration::from_secs(5);
        let left = |name| match store.get(&store.key(id, name), 1 << 20, timeout).unwrap() {
            Fetched::Missing => 404,
            _ => 200,
        };
        Outcome {
            ending,
            recorded: recorder.recorded,
            result,
            request_left: left("request"),
            assertion_left: left("assertion"),
        }
    }

    fn id(index: usize) -> String {
        base64url(&[index as u8; 16])
    }

    // (2) A signed assertion passes; a refusal and each single broken condition fail. Every
    // ending PUTs its result, reports it, and leaves neither the request nor the assertion.
    #[test]
    #[ignore = "needs MinIO on PATH (brew install minio); run with: cargo test -- --ignored"]
    fn remote_round_trips_against_minio() {
        let minio = Minio::start();
        type Change = Box<dyn FnOnce(&mut Draft) + Send>;
        let cases: Vec<(&str, PageAction, Result<(), Rejection>)> = vec![
            ("signed", PageAction::Sign(Box::new(|_| {})), Ok(())),
            ("refused", PageAction::Refuse, Err(Rejection::Malformed)),
            (
                "type",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.client_data["type"] = "webauthn.create".into();
                }) as Change),
                Err(Rejection::Type),
            ),
            (
                "challenge",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.client_data["challenge"] = base64url(&[0; 32]).into();
                })),
                Err(Rejection::Challenge),
            ),
            (
                "origin",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.client_data["origin"] = "https://evil.example".into();
                })),
                Err(Rejection::Origin),
            ),
            (
                "crossOrigin",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.client_data["crossOrigin"] = true.into();
                })),
                Err(Rejection::CrossOrigin),
            ),
            (
                "topOrigin",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft
                        .client_data
                        .insert("topOrigin".into(), "https://evil.example".into());
                })),
                Err(Rejection::TopOrigin),
            ),
            (
                "rpIdHash",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.authenticator_data[0] ^= 1;
                })),
                Err(Rejection::RpIdHash),
            ),
            (
                "UP",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.authenticator_data[32] &= !0x01;
                })),
                Err(Rejection::UserPresent),
            ),
            (
                "UV",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.authenticator_data[32] &= !0x04;
                })),
                Err(Rejection::UserVerified),
            ),
            (
                "authenticatorData length",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.authenticator_data.resize(2048, 0);
                })),
                Err(Rejection::AuthenticatorDataLength),
            ),
            (
                "credential id",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.credential_id = b"unregistered".to_vec();
                })),
                Err(Rejection::UnknownCredential),
            ),
            (
                "signature",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft.corrupt_signature = true;
                })),
                Err(Rejection::Signature),
            ),
            (
                "size",
                PageAction::Sign(Box::new(|draft: &mut Draft| {
                    draft
                        .client_data
                        .insert("pad".into(), "x".repeat(20_000).into());
                })),
                Err(Rejection::TooLarge),
            ),
        ];
        for (index, (name, action, verdict)) in cases.into_iter().enumerate() {
            let id = id(index);
            let outcome = round(&minio, &id, None, action);
            let pass = verdict.is_ok();
            assert_eq!(outcome.ending, Ending::Judged(verdict), "{name}");
            assert_eq!(
                outcome.result.as_deref(),
                Some(if pass { &b"pass"[..] } else { &b"fail"[..] }),
                "{name}"
            );
            // Without send_command the URL goes to PAM, and the result follows it.
            assert!(
                matches!(&outcome.recorded.events[..], [HelperEvent::Url { .. }, HelperEvent::Result { id: answered, pass: reported }] if *answered == id && *reported == pass),
                "{name}: {:?}",
                outcome.recorded.events
            );
            assert_eq!(
                (outcome.request_left, outcome.assertion_left),
                (404, 404),
                "{name}"
            );
        }
    }

    // (2) PAM's endings without an assertion: finish after Touch ID PUTs pass, the close of
    // the input PUTs fail; neither sends a result event, and both clean up. With send_command
    // the URL goes there instead of an event, and `open` opens the same approval URL.
    #[test]
    #[ignore = "needs MinIO on PATH (brew install minio); run with: cargo test -- --ignored"]
    fn pam_endings_against_minio() {
        let minio = Minio::start();
        let finished = round(
            &minio,
            &id(100),
            Some("notify"),
            PageAction::Leave(vec![
                Some(r#"{"cmd":"open"}"#),
                Some(r#"{"cmd":"finish","pass":true}"#),
            ]),
        );
        assert_eq!(finished.ending, Ending::Finished { pass: true });
        assert_eq!(finished.result.as_deref(), Some(&b"pass"[..]));
        assert!(
            finished.recorded.events.is_empty(),
            "{:?}",
            finished.recorded.events
        );
        let [(command, url)] = &finished.recorded.sent[..] else {
            panic!("{:?}", finished.recorded.sent);
        };
        assert_eq!(command, "notify");
        assert_eq!(finished.recorded.opened, std::slice::from_ref(url));
        assert_eq!((finished.request_left, finished.assertion_left), (404, 404));

        let cancelled = round(&minio, &id(101), None, PageAction::Leave(vec![None]));
        assert_eq!(cancelled.ending, Ending::Cancelled);
        assert_eq!(cancelled.result.as_deref(), Some(&b"fail"[..]));
        assert!(
            matches!(&cancelled.recorded.events[..], [HelperEvent::Url { .. }]),
            "{:?}",
            cancelled.recorded.events
        );
        assert_eq!(
            (cancelled.request_left, cancelled.assertion_left),
            (404, 404)
        );
    }

    // A store that does not take the request makes remote unavailable before any URL is sent.
    #[test]
    fn unreachable_store_is_unavailable() {
        // Nothing listens on the discard port, so the PUT is refused at once.
        let store = Store::new(&crate::test_support::unreachable_store()).unwrap();
        let page = Page::parse("https://pam-passkey.github.io/").unwrap();
        let input = input(&id(1), 30);
        let (urls, _receiver) = channel();
        let mut recorder = Recorder {
            recorded: Recorded::default(),
            urls,
        };
        let (_sender, lines) = channel();
        let remote = Remote {
            input: &input,
            page: &page,
            store: &store,
            credentials: &CredentialSet::default(),
            send_command: None,
            expires: parse_utc(&input.expires).unwrap(),
            deadline: Instant::now() + Duration::from_secs(30),
        };
        assert_eq!(
            remote.run(&lines, &mut recorder),
            Err(UnavailableReason::StoreUnreachable)
        );
        assert!(recorder.recorded.events.is_empty());
    }
}
