//! `setup [--module <path>] [page_url]` (DR-0010): collect and check the settings as the user,
//! then write the System Keychain items as root (`sudo <self> setup --stdin`).

use crate::records::{signing_jwk, verification_jwk};
use crate::settings::{DEFAULT_PAGE_URL, Page};
use crate::store::{Fetched, Store, StoreConfig, StoreError};
use pam_passkey::keychain::{Keychain, SystemItem};
use protocol::encoding::base64url;
use protocol::placement::secure_path;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::ffi::{CStr, CString, c_char, c_int};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const HELP: &str = "pam-passkey setup — configure the approval page, the store and send_command

Usage:
  pam-passkey setup [--module <path>] [page_url]

  page_url            The approval / registration page (default: https://pam-passkey.github.io/)
  --module <path>     Also check the placement of pam_passkey.so at <path>

With a terminal on standard input, setup asks for the store (endpoint, bucket, region, prefix,
access key, secret) and send_command. Otherwise it reads one JSON line from standard input:

  {\"page_url\": \"https://...\", \"store\": {\"endpoint\": \"https://...\", \"bucket\": \"...\",
   \"region\": \"...\", \"prefix\": \"...\", \"access_key\": \"...\", \"secret\": \"...\"},
   \"send_command\": \"...\", \"regenerate_key\": false}

setup checks the store (and whether it can refuse a second write of the same object), sets the
bucket's CORS and lifecycle rules (replacing the bucket's existing ones), checks that pam-passkey
is installed in a root-owned location, and then writes the settings to the System Keychain
through sudo. An existing signing key is kept unless regenerate_key is true (asked
interactively); a new key invalidates every registered passkey.
";

/// Each store request during setup; setup is interactive, not on PAM's deadline.
const STORE_TIMEOUT: Duration = Duration::from_secs(15);
const SUDO: &str = "/usr/bin/sudo";

// readpassphrase(3): reads from /dev/tty with echo off and restores the terminal on signals.
const RPP_REQUIRE_TTY: c_int = 0x02;
unsafe extern "C" {
    fn readpassphrase(
        prompt: *const c_char,
        buf: *mut c_char,
        size: usize,
        flags: c_int,
    ) -> *mut c_char;
}

/// The store as the user gives it. `put_once` is setup's own finding, so a given value is
/// ignored (DR-0010).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreInput {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub prefix: String,
    pub access_key: String,
    pub secret: String,
    #[serde(default, rename = "put_once")]
    _ignored_put_once: Option<serde::de::IgnoredAny>,
}

/// The non-interactive input line (DR-0010 のキー).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInput {
    #[serde(default)]
    pub page_url: Option<String>,
    pub store: StoreInput,
    #[serde(default)]
    pub send_command: Option<String>,
    #[serde(default)]
    pub regenerate_key: bool,
}

/// The checked settings, as the root side writes them (`setup --stdin`).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checked {
    pub page_url: String,
    pub store: StoreConfig,
    /// Empty: show the URL on the terminal.
    pub send_command: String,
    pub regenerate_key: bool,
}

/// What the bucket needs when setup may not configure it itself.
fn required_configuration(page: &Page, store: &StoreConfig) -> String {
    format!(
        "Configure the bucket {bucket:?} yourself, or give the access key these permissions:\n\
         \x20 CORS: AllowedOrigins {origin}; AllowedMethods GET, PUT; AllowedHeaders If-None-Match, Content-Type\n\
         \x20 lifecycle: objects under {prefix:?} expire after 1 day\n\
         \x20 access key: GetObject / PutObject / DeleteObject on {prefix:?}*, PutBucketCors and PutLifecycleConfiguration on the bucket",
        bucket = store.bucket,
        origin = page.origin,
        prefix = store.prefix,
    )
}

/// Write, read back, write again with `If-None-Match: *`, delete. The store refuses the second
/// write with 412 exactly when presigned PUTs can be made write-once.
fn probe_put_once(store: &Store) -> Result<bool, String> {
    let mut nonce = [0u8; 16];
    security_framework::random::SecRandom::default()
        .copy_bytes(&mut nonce)
        .map_err(|error| format!("random: {error}"))?;
    let key = store.key(&format!("setup-{}", base64url(&nonce)), "probe");
    let body = b"pam-passkey setup probe";
    match store.put(&key, body, false, STORE_TIMEOUT) {
        Ok(200) => {}
        Ok(status) => return Err(format!("PUT answered HTTP {status}")),
        Err(error) => return Err(error.to_string()),
    }
    let checked = match store.get(&key, body.len(), STORE_TIMEOUT) {
        Ok(Fetched::Found(read)) if read == body => Ok(()),
        Ok(other) => Err(format!("GET did not return what was PUT ({other:?})")),
        Err(error) => Err(format!("GET: {error}")),
    };
    let put_once = checked.and_then(|()| match store.put(&key, body, true, STORE_TIMEOUT) {
        Ok(412) => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(format!("conditional PUT: {error}")),
    });
    let deleted = store
        .delete(&key, STORE_TIMEOUT)
        .map_err(|error| format!("DELETE: {error}"));
    let put_once = put_once?;
    deleted?;
    Ok(put_once)
}

/// Validates the input against the store and configures the bucket. Runs as the user.
/// Also returns the bucket settings the store does not implement (HTTP 501), which the user
/// has to provide by the store's own means.
pub fn check(
    input: SetupInput,
    page_argument: Option<&str>,
) -> Result<(Checked, Vec<&'static str>), String> {
    let page_url = match (page_argument, input.page_url.as_deref()) {
        (Some(argument), Some(given)) if argument != given => {
            return Err(format!(
                "page_url is given twice ({argument} on the command line, {given} on standard input)"
            ));
        }
        (Some(page), _) | (None, Some(page)) => page,
        (None, None) => DEFAULT_PAGE_URL,
    };
    let page = Page::parse(page_url)?;
    let mut config = StoreConfig {
        endpoint: input.store.endpoint,
        bucket: input.store.bucket,
        region: input.store.region,
        prefix: input.store.prefix,
        access_key: input.store.access_key,
        secret: input.store.secret,
        put_once: false,
    };
    let store = Store::new(&config).map_err(|error| error.to_string())?;
    config.put_once =
        probe_put_once(&store).map_err(|error| format!("the store is not usable: {error}"))?;
    // Design rationale: a store without the bucket API (MinIO answers PutBucketCors with 501;
    // it configures CORS server-wide) can still serve the pages, so "not implemented" is
    // reported for the user to handle, while a refusal (permissions) stops setup (DR-0010).
    let mut unsupported = Vec::new();
    for (name, result) in [
        ("CORS", store.put_cors(&page.origin, STORE_TIMEOUT)),
        ("lifecycle", store.put_lifecycle(STORE_TIMEOUT)),
    ] {
        match result {
            Ok(()) => {}
            Err(StoreError::Status(501)) => unsupported.push(name),
            Err(error) => {
                return Err(format!(
                    "could not set the bucket's {name} rules: {error}\n{}",
                    required_configuration(&page, &config)
                ));
            }
        }
    }
    Ok((
        Checked {
            page_url: page.url,
            store: config,
            send_command: input.send_command.unwrap_or_default(),
            regenerate_key: input.regenerate_key,
        },
        unsupported,
    ))
}

/// DR-0003 置き場: refuse to point the Keychain ACL at a binary others could replace.
fn check_placement(module: Option<&Path>) -> Result<PathBuf, Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    if !secure_path(&executable) {
        return Err(format!(
            "{} is not in a root-owned location that only root can write (install it first)",
            executable.display()
        )
        .into());
    }
    if let Some(module) = module
        && !secure_path(module)
    {
        return Err(format!(
            "{} is not in a root-owned location that only root can write",
            module.display()
        )
        .into());
    }
    Ok(executable)
}

fn signing_key_exists(keychain: &Keychain) -> Result<bool, Box<dyn Error>> {
    Ok(keychain.exists_system(SystemItem::SigningKey)?
        && keychain.exists_system(SystemItem::VerificationKey)?)
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// `setup --stdin`: write what the user side checked. Runs as root.
fn write(checked: &Checked) -> Result<(), Box<dyn Error>> {
    if !is_root() {
        return Err("setup --stdin writes the System Keychain and must run as root".into());
    }
    check_placement(None)?;
    let page = Page::parse(&checked.page_url)?;
    Store::new(&checked.store)?;
    let keychain = Keychain::system()?;
    keychain.write_system(SystemItem::PageUrl, &page.url)?;
    keychain.write_system(SystemItem::Store, &serde_json::to_string(&checked.store)?)?;
    keychain.write_system(SystemItem::SendCommand, &checked.send_command)?;
    if checked.regenerate_key || !signing_key_exists(&keychain)? {
        let mut secret = [0u8; 32];
        security_framework::random::SecRandom::default().copy_bytes(&mut secret)?;
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        keychain.write_system(SystemItem::SigningKey, &signing_jwk(&key))?;
        keychain.write_system(
            SystemItem::VerificationKey,
            &verification_jwk(&key.verifying_key()),
        )?;
        println!("setup: generated a new signing key (register passkeys with `pam-passkey add`)");
    } else {
        println!("setup: kept the existing signing key");
    }
    println!(
        "setup: wrote page_url, store and send_command ({})",
        if checked.send_command.is_empty() {
            "URLs are shown on the terminal"
        } else {
            "URLs go to send_command"
        }
    );
    Ok(())
}

fn prompt(label: &str, default: Option<&str>) -> Result<String, Box<dyn Error>> {
    let mut stderr = std::io::stderr().lock();
    match default {
        Some(default) => write!(stderr, "{label} [{default}]: ")?,
        None => write!(stderr, "{label}: ")?,
    }
    stderr.flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        return Err("input ended".into());
    }
    let value = line.trim_end_matches(['\n', '\r']).to_owned();
    Ok(match default {
        Some(default) if value.is_empty() => default.to_owned(),
        _ => value,
    })
}

/// The secret is read with the echo off and never printed.
fn prompt_secret(label: &str) -> Result<String, Box<dyn Error>> {
    let prompt = CString::new(format!("{label}: "))?;
    let mut buffer = vec![0 as c_char; 1024];
    // SAFETY: the prompt is NUL-terminated and the buffer size is passed with it.
    let read = unsafe {
        readpassphrase(
            prompt.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            RPP_REQUIRE_TTY,
        )
    };
    if read.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: readpassphrase NUL-terminates what it read within the buffer.
    let secret = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()?
        .to_owned();
    buffer.fill(0);
    Ok(secret)
}

fn interactive(page_argument: Option<&str>) -> Result<(SetupInput, String), Box<dyn Error>> {
    let page_url = prompt("page_url", Some(page_argument.unwrap_or(DEFAULT_PAGE_URL)))?;
    let store = StoreInput {
        endpoint: prompt("store endpoint (https://...)", None)?,
        bucket: prompt("bucket", None)?,
        region: prompt("region", None)?,
        prefix: prompt("prefix (may be empty)", Some(""))?,
        access_key: prompt("access key", None)?,
        secret: prompt_secret("secret (not shown)")?,
        _ignored_put_once: None,
    };
    let send_command = prompt("send_command (empty: show URLs on the terminal)", Some(""))?;
    Ok((
        SetupInput {
            page_url: None,
            store,
            send_command: Some(send_command),
            regenerate_key: false,
        },
        page_url,
    ))
}

fn confirm(question: &str) -> Result<bool, Box<dyn Error>> {
    let answer = prompt(&format!("{question} [y/N]"), None)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// One JSON line from a non-terminal standard input, or `None` if it is empty.
fn read_input_line() -> Result<Option<String>, Box<dyn Error>> {
    let mut text = String::new();
    std::io::stdin()
        .lock()
        .take(1024 * 1024)
        .read_to_string(&mut text)?;
    let text = text.trim_end_matches(['\n', '\r']);
    if text.is_empty() {
        return Ok(None);
    }
    if text.contains('\n') {
        return Err("standard input must be exactly one JSON line".into());
    }
    Ok(Some(text.to_owned()))
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    if let [flag] = args
        && flag == "--stdin"
    {
        let line = read_input_line()?.ok_or("setup --stdin: no settings on standard input")?;
        return write(&serde_json::from_str(&line)?);
    }
    let mut module = None;
    let mut page_argument = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--module" => {
                module = Some(PathBuf::from(rest.next().ok_or("--module needs a path")?));
            }
            option if option.starts_with('-') => {
                return Err(
                    format!("unknown option {option}; run pam-passkey setup --help").into(),
                );
            }
            page if page_argument.is_none() => page_argument = Some(page.to_owned()),
            _ => return Err("setup takes at most one page_url".into()),
        }
    }

    let terminal = std::io::stdin().is_terminal();
    let (input, page_url) = if terminal {
        let (input, page_url) = interactive(page_argument.as_deref())?;
        (input, Some(page_url))
    } else {
        let Some(line) = read_input_line()? else {
            if args.is_empty() {
                print!("{HELP}");
                return Ok(());
            }
            return Err("no settings on standard input (one JSON line, see setup --help)".into());
        };
        (serde_json::from_str::<SetupInput>(&line)?, page_argument)
    };
    let executable = check_placement(module.as_deref())?;
    let (mut checked, unsupported) = check(input, page_url.as_deref())?;
    eprintln!(
        "setup: the store works (write-once uploads: {})",
        if checked.store.put_once { "yes" } else { "no" }
    );
    if unsupported.is_empty() {
        eprintln!("setup: set the bucket's CORS and lifecycle rules");
    } else {
        eprintln!(
            "setup: warning: the store does not implement the bucket's {} API.\n{}",
            unsupported.join(" and "),
            required_configuration(&Page::parse(&checked.page_url)?, &checked.store)
        );
    }
    if terminal && signing_key_exists(&Keychain::system()?)? {
        checked.regenerate_key = confirm(
            "A signing key exists. A new one invalidates every registered passkey. Generate a new key?",
        )?;
    }
    if is_root() {
        return write(&checked);
    }
    let mut sudo = Command::new(SUDO)
        .arg(&executable)
        .arg("setup")
        .arg("--stdin")
        .stdin(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = sudo.stdin.take() {
        writeln!(stdin, "{}", serde_json::to_string(&checked)?)?;
    }
    let status = sudo.wait()?;
    if !status.success() {
        return Err(format!("writing the settings through sudo failed: {status}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::minio::Minio;

    fn input(json: &str) -> SetupInput {
        serde_json::from_str(json).unwrap()
    }

    const STORE: &str = r#"{"endpoint":"http://127.0.0.1:9","bucket":"b","region":"r","access_key":"k","secret":"s3cr3t-value"}"#;

    // The non-interactive line has exactly the DR-0010 keys; a given put_once is ignored, an
    // unknown key (a typo) is an error rather than a silently dropped setting.
    #[test]
    fn input_line_keys() {
        let parsed = input(&format!(r#"{{"store":{STORE}}}"#));
        assert_eq!(parsed.page_url, None);
        assert_eq!(parsed.store.prefix, "");
        assert!(!parsed.regenerate_key);
        let with_put_once = STORE.replace('}', r#","put_once":true}"#);
        assert!(
            serde_json::from_str::<SetupInput>(&format!(r#"{{"store":{with_put_once}}}"#)).is_ok()
        );
        assert!(
            serde_json::from_str::<SetupInput>(&format!(
                r#"{{"store":{STORE},"sendcommand":"x"}}"#
            ))
            .is_err()
        );
        assert!(serde_json::from_str::<SetupInput>(r#"{"page_url":"https://x/"}"#).is_err());
    }

    // Two different page URLs (argument and input line) are refused before the store is touched.
    #[test]
    fn page_url_given_twice_must_agree() {
        let line = format!(r#"{{"page_url":"https://a.example/","store":{STORE}}}"#);
        let error = check(input(&line), Some("https://b.example/")).unwrap_err();
        assert!(error.contains("given twice"), "{error}");
        let error =
            check(input(&format!(r#"{{"store":{STORE}}}"#)), Some("http://x/")).unwrap_err();
        assert!(error.contains("https"), "{error}");
    }

    // An unreachable store stops setup with an error that does not leak the secret.
    #[test]
    fn unreachable_store_stops_setup() {
        let error = check(input(&format!(r#"{{"store":{STORE}}}"#)), None).unwrap_err();
        assert!(error.starts_with("the store is not usable"), "{error}");
        assert!(!error.contains("s3cr3t-value"), "{error}");
    }

    // (3) The user-side part of setup against MinIO: the probe finds write-once uploads, the
    // bucket gets the lifecycle rule, and the probe leaves nothing.
    #[test]
    #[ignore = "needs MinIO on PATH (brew install minio); run with: cargo test -- --ignored"]
    fn checks_and_configures_minio() {
        let minio = Minio::start();
        let config = minio.config(false);
        let line = serde_json::json!({
            "store": {
                "endpoint": config.endpoint,
                "bucket": config.bucket,
                "region": config.region,
                "prefix": config.prefix,
                "access_key": config.access_key,
                "secret": config.secret,
                "put_once": false,
            },
            "send_command": "notify-me",
        })
        .to_string();
        let (checked, unsupported) =
            check(input(&line), Some("https://example.com:8443/approve/")).unwrap();
        // MinIO implements bucket lifecycle but answers PutBucketCors with 501 (its CORS is a
        // server-wide setting), which setup reports instead of failing.
        assert_eq!(unsupported, ["CORS"]);
        assert_eq!(
            checked,
            Checked {
                page_url: "https://example.com:8443/approve/".into(),
                store: StoreConfig {
                    put_once: true,
                    ..config.clone()
                },
                send_command: "notify-me".into(),
                regenerate_key: false,
            }
        );
        let (status, lifecycle) = minio.bucket_get(("lifecycle", ""));
        assert_eq!(status, 200, "{lifecycle}");
        assert!(lifecycle.contains("<Days>1</Days>"), "{lifecycle}");
        assert!(lifecycle.contains("pam-passkey/"), "{lifecycle}");
        let (status, listing) = minio.bucket_get(("list-type", "2"));
        assert_eq!(status, 200, "{listing}");
        assert!(!listing.contains("<Key>"), "{listing}");
        // What the root side receives round-trips through its JSON line.
        let line = serde_json::to_string(&checked).unwrap();
        assert_eq!(serde_json::from_str::<Checked>(&line).unwrap(), checked);
    }
}
