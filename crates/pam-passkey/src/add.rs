//! `add [label]` (DR-0011): the user's identity check, the registration through the store and
//! the page, the credential's acceptance, and the signed record in the login keychain.

use crate::child::{RunAs, current_user};
use crate::language::prefers_japanese;
use crate::passkeys::{self, own_keychain};
use crate::records::{
    EcPublicJwk, PasskeyRecord, parse_signing_jwk, parse_verification_jwk, sign_record,
};
use crate::settings::{Config, Page};
use crate::store::{Fetched, MAX_CREDENTIAL, Store, StoreConfig};
use crate::webauthn::{Registered, RegistrationExpectation, Rejection, verify_registration};
use pam_passkey::keychain::{Keychain, KeychainError, SystemItem};
use protocol::ExchangeRequest;
use protocol::encoding::{base64url, format_utc};
use std::error::Error;
use std::ffi::{CString, c_char, c_long};
use std::fmt;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long the registration URL stays usable (DESIGN 未決事項: 要求の期限の仮の既定 90 秒).
const LIFETIME: i64 = 90;
/// How often the credential is polled (the helper's interval for the assertion).
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Longest single store request while waiting.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Each DELETE after the registration ended.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the wait reports its progress (the spinner's frame rate).
const TICK: Duration = Duration::from_millis(100);
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// What the wait for the credential reports to the terminal.
pub enum Progress {
    /// Still waiting; the registration expires after this long.
    Waiting(Duration),
    /// A poll failed; the wait goes on.
    Warning(String),
}

unsafe extern "C" {
    fn passkey_owner_authenticate(reason: *const c_char) -> c_long;
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn random<const N: usize>() -> Result<[u8; N], Box<dyn Error>> {
    let mut bytes = [0u8; N];
    security_framework::random::SecRandom::default().copy_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Why a registration ended without a credential to record.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollError {
    /// The store did not take the registration payload.
    Store(String),
    /// No credential arrived before `expires`.
    Expired,
    /// The first credential found did not meet a registration condition.
    Rejected(Rejection),
}

impl fmt::Display for EnrollError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(message) => {
                write!(out, "the store did not take the registration: {message}")
            }
            Self::Expired => write!(out, "no passkey was registered before the URL expired"),
            Self::Rejected(rejection) => write!(
                out,
                "the registration page sent a credential that is not accepted ({rejection:?})"
            ),
        }
    }
}

impl Error for EnrollError {}

/// One registration against the store (DR-0011 手順 2–4 と 7).
pub struct Enrollment<'a> {
    pub page: &'a Page,
    pub store: &'a Store,
    /// Names the objects: `<prefix><id>/registration` and `.../credential`.
    pub id: &'a str,
    pub user_name: &'a str,
    pub user_id: &'a [u8],
    /// Unix seconds.
    pub expires: i64,
}

impl Enrollment<'_> {
    /// PUTs the registration payload, hands `<page_url>#<presigned GET>` to `deliver`, polls
    /// for the credential until `expires`, judges the first one found, and DELETEs both
    /// objects whatever the ending. `progress` hears about the wait every [`TICK`].
    pub fn run(
        &self,
        deliver: impl FnOnce(&str),
        progress: impl FnMut(Progress),
    ) -> Result<Registered, EnrollError> {
        let registration_key = self.store.key(self.id, "registration");
        let credential_key = self.store.key(self.id, "credential");
        let ending = self.exchange(&registration_key, &credential_key, deliver, progress);
        for key in [&registration_key, &credential_key] {
            if let Err(error) = self.store.delete(key, CLEANUP_TIMEOUT) {
                eprintln!("pam-passkey: DELETE of {key}: {error}");
            }
        }
        ending
    }

    fn exchange(
        &self,
        registration_key: &str,
        credential_key: &str,
        deliver: impl FnOnce(&str),
        mut progress: impl FnMut(Progress),
    ) -> Result<Registered, EnrollError> {
        // Presigned URLs last exactly as long as the registration.
        let valid_for =
            Duration::from_secs(u64::try_from(self.expires - unix_now()).unwrap_or(0).max(1));
        let payload = ExchangeRequest::Register {
            rp_id: self.page.rp_id.clone(),
            user_name: self.user_name.to_owned(),
            user_id: base64url(self.user_id),
            expires: format_utc(self.expires),
            credential_put_url: self.store.presign_put(credential_key, valid_for).into(),
        };
        // These bytes are what the page fetches and what the challenge is the hash of.
        let payload =
            serde_json::to_vec(&payload).map_err(|error| EnrollError::Store(error.to_string()))?;
        match self
            .store
            .put(registration_key, &payload, false, REQUEST_TIMEOUT)
        {
            Ok(200) => {}
            Ok(status) => return Err(EnrollError::Store(format!("HTTP {status}"))),
            Err(error) => return Err(EnrollError::Store(error.to_string())),
        }
        deliver(&format!(
            "{}#{}",
            self.page.url,
            self.store.presign_get(registration_key, valid_for)
        ));
        let mut next_poll = Instant::now();
        loop {
            let left = self.expires - unix_now();
            if left <= 0 {
                return Err(EnrollError::Expired);
            }
            let left = Duration::from_secs(left.unsigned_abs());
            progress(Progress::Waiting(left));
            if Instant::now() < next_poll {
                std::thread::sleep(TICK.min(left));
                continue;
            }
            next_poll = Instant::now() + POLL_INTERVAL;
            match self
                .store
                .poll(credential_key, MAX_CREDENTIAL, REQUEST_TIMEOUT.min(left))
            {
                Ok(Fetched::Missing) => {}
                // The first object found decides; the registration is not waited for again.
                Ok(Fetched::Found(body)) => {
                    return verify_registration(
                        &body,
                        &RegistrationExpectation {
                            registration: &payload,
                            page: self.page,
                            expires: self.expires,
                            now: unix_now(),
                        },
                    )
                    .map_err(EnrollError::Rejected);
                }
                Ok(Fetched::TooLarge) => return Err(EnrollError::Rejected(Rejection::TooLarge)),
                Err(error) => progress(Progress::Warning(format!(
                    "pam-passkey: polling for the credential: {error}"
                ))),
            }
            // Design rationale: an S3-compatible store has no change notification, so the
            // credential's object is polled every POLL_INTERVAL, as the helper polls for the
            // assertion; the TICK sleeps in between only pace the progress display.
            std::thread::sleep(TICK.min(left));
        }
    }
}

/// The JWS payload for an accepted credential (DR-0011 手順 5).
pub fn record(
    user: &str,
    label: &str,
    user_id: &[u8],
    registered: &Registered,
    now: i64,
) -> PasskeyRecord {
    PasskeyRecord {
        user: user.to_owned(),
        credential_id: base64url(&registered.credential_id),
        user_id: base64url(user_id),
        public_key: EcPublicJwk::from_key(&registered.public_key),
        label: label.to_owned(),
        registered: format_utc(now),
        backup_eligible: registered.backup_eligible,
        backup_state: registered.backup_state,
    }
}

/// The default label: the local registration time (DR-0010: `YYYY-MM-DD HH:MM`).
fn local_label(unix_seconds: i64) -> String {
    let time = unix_seconds as libc::time_t;
    // SAFETY: localtime_r writes only into the provided struct.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
        return format_utc(unix_seconds);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    )
}

/// The identity check's text, after the OS lead-in ("<app> is trying to ...").
fn owner_reason(user: &str, japanese: bool) -> String {
    if japanese {
        format!("{user} の passkey を登録します (スマホやこの Mac からの sudo の承認用)")
    } else {
        format!("register a passkey for {user} (sudo approvals from a phone or this Mac)")
    }
}

/// DR-0011 手順 1: Touch ID, or the login password on a Mac without it.
fn confirm_owner(user: &str, home: &Path) -> Result<(), Box<dyn Error>> {
    let reason = CString::new(owner_reason(user, prefers_japanese(home)))?;
    // SAFETY: the reason is NUL-terminated and outlives the call.
    match unsafe { passkey_owner_authenticate(reason.as_ptr()) } {
        0 => Ok(()),
        -2 | -4 => Err("the identity check was cancelled".into()),
        code => Err(format!("the identity check did not succeed (LAError {code})").into()),
    }
}

/// The settings `add` needs before the identity check, from the login keychain. The signing key is
/// only checked for presence here; its value is read once the credential has been accepted.
struct Settings {
    page: Page,
    store: StoreConfig,
    send_command: Option<String>,
}

fn load_settings(system: &Keychain, login: &Keychain) -> Result<Settings, Box<dyn Error>> {
    let config = match login.read_config() {
        Ok(text) => text,
        Err(KeychainError::NotFound) => {
            return Err("no settings in your login keychain (run pam-passkey setup)".into());
        }
        Err(error) => return Err(error.into()),
    };
    let config: Config = serde_json::from_str(&config)
        .map_err(|error| format!("your settings are not valid (run pam-passkey setup): {error}"))?;
    if !(system.exists_system(SystemItem::SigningKey)?
        && system.exists_system(SystemItem::VerificationKey)?)
    {
        return Err("no signing key in the System Keychain (run pam-passkey setup)".into());
    }
    Ok(Settings {
        page: Page::parse(&config.page_url)?,
        store: config.store,
        send_command: Some(config.send_command).filter(|command| !command.is_empty()),
    })
}

/// The registration URL goes to send_command or to the terminal, nowhere else (DR-0011).
/// send_command runs alongside the wait and is stopped if it outlives it.
fn deliver(send_command: Option<&str>, url: &str) -> Option<Child> {
    let Some(command) = send_command else {
        eprintln!(
            "add: open this URL in a browser that can create your passkey (valid for {LIFETIME} seconds):\n\n  {url}\n"
        );
        return None;
    };
    let spawned = RunAs::Inherited.shell(command).and_then(|mut shell| {
        let mut child = shell
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "{url}")?;
        }
        Ok(child)
    });
    match spawned {
        Ok(child) => {
            eprintln!(
                "add: sent the registration URL with send_command (valid for {LIFETIME} seconds)"
            );
            Some(child)
        }
        Err(error) => {
            eprintln!("pam-passkey: warning: send_command could not start: {error}");
            None
        }
    }
}

fn stop(sent: Option<Child>) {
    let Some(mut child) = sent else {
        return;
    };
    match child.try_wait() {
        Ok(Some(status)) if !status.success() => {
            eprintln!("pam-passkey: warning: send_command exited with {status}");
        }
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn run(label: Option<&str>) -> Result<(), Box<dyn Error>> {
    let label = match label {
        Some("") => return Err("the label must not be empty".into()),
        Some(option) if option.starts_with('-') => {
            return Err(format!("unknown option {option}; run pam-passkey --help").into());
        }
        Some(label) => label.to_owned(),
        None => local_label(unix_now()),
    };
    let (user, login) = own_keychain()?;
    let system = Keychain::system()?;
    let settings = load_settings(&system, &login)?;
    // The record is written to the login keychain at the end; fail before a passkey is
    // created if it cannot be (locked, denied).
    passkeys::read(&login, &user)?;
    let store = Store::new(&settings.store)?;
    confirm_owner(&user, &current_user()?.1)?;

    let id = base64url(&random::<16>()?);
    let user_id = random::<16>()?;
    let enrollment = Enrollment {
        page: &settings.page,
        store: &store,
        id: &id,
        user_name: &user,
        user_id: &user_id,
        expires: unix_now() + LIFETIME,
    };
    let terminal = std::io::stderr().is_terminal();
    let mut sent = None;
    let mut frame = 0;
    let registered = enrollment.run(
        |url| {
            sent = deliver(settings.send_command.as_deref(), url);
            if !terminal {
                eprintln!("add: waiting for the passkey...");
            }
        },
        // On a terminal one line is rewritten in place: a spinner and the seconds left.
        |progress| match progress {
            Progress::Waiting(left) if terminal => {
                eprint!(
                    "\r\x1b[K{} waiting for the passkey… {}s",
                    SPINNER[frame % SPINNER.len()],
                    left.as_secs()
                );
                frame += 1;
            }
            Progress::Waiting(_) => {}
            Progress::Warning(message) if terminal => eprintln!("\r\x1b[K{message}"),
            Progress::Warning(message) => eprintln!("{message}"),
        },
    );
    if terminal {
        eprint!("\r\x1b[K");
    }
    stop(sent);
    let registered = registered?;

    // DR-0011: the signing key is read here alone, after the identity check, in this process.
    let signing_key = parse_signing_jwk(&system.read_system(SystemItem::SigningKey)?)
        .ok_or("the signing key in the System Keychain is not usable (run pam-passkey setup)")?;
    let verification_key = parse_verification_jwk(
        &system.read_system(SystemItem::VerificationKey)?,
    )
    .ok_or("the verification key in the System Keychain is not usable (run pam-passkey setup)")?;
    if signing_key.verifying_key() != verification_key {
        return Err(
            "the System Keychain's signing and verification keys do not match (run pam-passkey setup)"
                .into(),
        );
    }
    let record = record(&user, &label, &user_id, &registered, unix_now());
    let line = sign_record(&signing_key, &record);
    drop(signing_key);
    let jsonl = passkeys::append(
        &passkeys::read(&login, &user)?,
        &line,
        &record.credential_id,
    )?;
    login.write_user(&user, &jsonl)?;
    println!(
        "added {}\t{}",
        passkeys::printable(&record.label),
        record.credential_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{trusted_credentials, unverified_record};
    use crate::settings::DEFAULT_PAGE_URL;
    use crate::test_support::minio::Minio;
    use crate::test_support::{Authenticator, RegistrationDraft, record_signer};
    use protocol::encoding::{base64url_decode, parse_utc};
    use std::sync::mpsc::channel;

    // The identity check names the user in the dialog's language.
    #[test]
    fn owner_reason_follows_the_language() {
        assert!(owner_reason("kawaz", false).starts_with("register a passkey for kawaz"));
        assert!(owner_reason("kawaz", true).starts_with("kawaz の passkey を登録します"));
    }

    // The default label is the local time to the minute.
    #[test]
    fn default_label_is_local_minutes() {
        let label = local_label(unix_now());
        let bytes = label.as_bytes();
        assert_eq!(bytes.len(), 16, "{label}");
        assert_eq!(
            (bytes[4], bytes[7], bytes[10], bytes[13]),
            (b'-', b'-', b' ', b':')
        );
    }

    /// What the test page does with the registration payload it fetched.
    enum PageAction {
        /// Create the credential; `change` breaks one registration condition first.
        Create(Box<dyn FnOnce(&mut RegistrationDraft) + Send>),
        /// Put something that is not a credential.
        Junk,
        /// Never answer.
        Leave,
    }

    struct Outcome {
        result: Result<Registered, EnrollError>,
        payload: serde_json::Value,
        /// The status of a second PUT through the same credential URL.
        second_put: Option<u16>,
        registration_left: bool,
        credential_left: bool,
        /// Each `Waiting` report's seconds left, in order.
        waiting: Vec<u64>,
    }

    /// One registration against MinIO, with a page that fetches the payload through the
    /// registration URL and answers through the presigned PUT inside it.
    fn round(minio: &Minio, id: &str, lifetime: i64, action: PageAction) -> Outcome {
        let store = Store::new(&minio.config(true)).unwrap();
        let page = Page::parse(DEFAULT_PAGE_URL).unwrap();
        let authenticator = Authenticator::new(8, b"enrolled-credential");
        let (urls, received) = channel::<String>();
        let agent = minio.page_agent();
        let page_for_thread = page.clone();
        let tester = std::thread::spawn(move || {
            let url = received.recv().unwrap();
            let fetch = url
                .strip_prefix("https://pam-passkey.github.io/#")
                .expect("registration URL is <page_url>#<presigned GET>")
                .to_owned();
            let payload = agent
                .get(&fetch)
                .call()
                .unwrap()
                .body_mut()
                .read_to_vec()
                .unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            let put_url = parsed["credential_put_url"].as_str().unwrap().to_owned();
            let put = |body: &[u8]| {
                agent
                    .put(&put_url)
                    .header("If-None-Match", "*")
                    .send(body)
                    .unwrap()
                    .status()
                    .as_u16()
            };
            let second_put = match action {
                PageAction::Create(change) => {
                    let mut draft =
                        RegistrationDraft::valid(&authenticator, &payload, &page_for_thread);
                    change(&mut draft);
                    assert_eq!(put(&draft.finish()), 200);
                    Some(put(b"overwrite"))
                }
                PageAction::Junk => {
                    assert_eq!(put(br#"{"rejected":true}"#), 200);
                    None
                }
                PageAction::Leave => None,
            };
            (parsed, second_put)
        });
        let enrollment = Enrollment {
            page: &page,
            store: &store,
            id,
            user_name: "kawaz",
            user_id: &[3; 16],
            expires: unix_now() + lifetime,
        };
        let mut waiting = Vec::new();
        let result = enrollment.run(
            |url| urls.send(url.to_owned()).unwrap(),
            |progress| match progress {
                Progress::Waiting(left) => waiting.push(left.as_secs()),
                Progress::Warning(message) => panic!("{message}"),
            },
        );
        let (payload, second_put) = tester.join().unwrap();
        let left = |name| {
            !matches!(
                store
                    .get(&store.key(id, name), 1 << 20, Duration::from_secs(5))
                    .unwrap(),
                Fetched::Missing
            )
        };
        Outcome {
            result,
            payload,
            second_put,
            registration_left: left("registration"),
            credential_left: left("credential"),
            waiting,
        }
    }

    // (4) add against MinIO without a page: the payload has the exchange-format keys, an
    // accepted credential becomes a record the helper trusts, rejected / missing credentials
    // end the registration, and no ending leaves the objects behind.
    #[test]
    #[ignore = "needs MinIO on PATH (brew install minio); run with: cargo test -- --ignored"]
    fn add_round_trips_against_minio() {
        let minio = Minio::start();
        let accepted = round(
            &minio,
            "enroll-ok",
            30,
            PageAction::Create(Box::new(|_| {})),
        );
        let registered = accepted.result.unwrap();
        assert_eq!(registered.credential_id, b"enrolled-credential");
        assert_eq!(
            registered.public_key,
            Authenticator::new(8, b"").public_key()
        );
        // The credential URL writes once (put_once): the first credential cannot be replaced.
        assert_eq!(accepted.second_put, Some(412));
        assert!(!accepted.registration_left && !accepted.credential_left);
        let payload = accepted.payload.as_object().unwrap();
        let mut keys: Vec<&str> = payload.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "credential_put_url",
                "expires",
                "kind",
                "rp_id",
                "user_id",
                "user_name"
            ]
        );
        assert_eq!(payload["kind"], "register");
        assert_eq!(payload["rp_id"], "pam-passkey.github.io");
        assert_eq!(payload["user_name"], "kawaz");
        assert_eq!(
            base64url_decode(payload["user_id"].as_str().unwrap()).unwrap(),
            [3; 16]
        );
        assert!(parse_utc(payload["expires"].as_str().unwrap()).is_some());

        // The record add signs is one the helper accepts for that user, with the key and flags.
        let signer = record_signer(4);
        let line = sign_record(
            &signer,
            &record("kawaz", "phone", &[3; 16], &registered, unix_now()),
        );
        let credentials = trusted_credentials(&line, &signer.verifying_key(), "kawaz");
        assert_eq!(credentials.ids(), [base64url(b"enrolled-credential")]);
        let stored = unverified_record(&line).unwrap();
        assert_eq!(
            (stored.label.as_str(), stored.backup_eligible),
            ("phone", true)
        );
        assert_eq!(stored.user_id, base64url(&[3; 16]));

        let rejected = round(
            &minio,
            "enroll-type",
            30,
            PageAction::Create(Box::new(|draft: &mut RegistrationDraft| {
                draft.client_data["type"] = "webauthn.get".into();
            })),
        );
        assert_eq!(rejected.result, Err(EnrollError::Rejected(Rejection::Type)));
        assert!(!rejected.registration_left && !rejected.credential_left);

        let alg = round(
            &minio,
            "enroll-alg",
            30,
            PageAction::Create(Box::new(|draft: &mut RegistrationDraft| {
                draft.cose_key[1].1 = crate::cbor::Value::Integer(-257);
            })),
        );
        assert_eq!(alg.result, Err(EnrollError::Rejected(Rejection::Algorithm)));

        let junk = round(&minio, "enroll-junk", 30, PageAction::Junk);
        assert_eq!(
            junk.result,
            Err(EnrollError::Rejected(Rejection::Malformed))
        );
        assert!(!junk.registration_left && !junk.credential_left);

        let expired = round(&minio, "enroll-expired", 2, PageAction::Leave);
        assert_eq!(expired.result, Err(EnrollError::Expired));
        // The wait reports every tick (about ten a second) with a countdown that never rises,
        // and polls stay quiet: a missing credential is no warning.
        assert!(expired.waiting.len() >= 10, "{:?}", expired.waiting);
        assert!(expired.waiting.windows(2).all(|pair| pair[0] >= pair[1]));
        assert!(expired.waiting[0] <= 2);
        assert!(!expired.registration_left && !expired.credential_left);
    }

    // A store that does not take the payload ends the registration before any URL is shown.
    #[test]
    fn unreachable_store_delivers_nothing() {
        let store = Store::new(&crate::test_support::unreachable_store()).unwrap();
        let page = Page::parse(DEFAULT_PAGE_URL).unwrap();
        let enrollment = Enrollment {
            page: &page,
            store: &store,
            id: "unreachable",
            user_name: "kawaz",
            user_id: &[0; 16],
            expires: unix_now() + 30,
        };
        let mut delivered = false;
        let result = enrollment.run(|_| delivered = true, |_| {});
        assert!(matches!(result, Err(EnrollError::Store(_))), "{result:?}");
        assert!(!delivered);
    }
}
