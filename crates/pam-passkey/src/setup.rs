//! `setup` (DR-0010): the settings as one JSON document. `--dump` prints the current ones,
//! `--stdin` takes a document, `--edit` (the default) opens the current one in `$EDITOR`. The
//! document is checked as the user; only the write runs as root (`sudo <self> _setup-write`).

use crate::records::{signing_jwk, verification_jwk};
use crate::settings::{DEFAULT_PAGE_URL, Page, read_optional};
use crate::store::{Fetched, Store, StoreConfig, StoreError};
use pam_passkey::keychain::{Keychain, KeychainError, SystemItem};
use protocol::encoding::base64url;
use protocol::placement::secure_path;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const HELP: &str = "pam-passkey setup — configure the approval page, the store and send_command

Usage:
  pam-passkey setup [--edit] [--module <path>] [page_url]
  pam-passkey setup --stdin [--module <path>] [page_url]
  pam-passkey setup --dump

  --edit              Open the current settings in $EDITOR (vi if unset) and apply them if they
                      changed (the default with a terminal on standard input)
  --stdin             Apply the settings document read from standard input
  --dump              Print the current settings document (the secret as \"***\")
  --module <path>     Where pam_passkey.so is, only if not at the default
                      /usr/local/lib/pam/pam_passkey.so (its placement is checked too)
  page_url            The approval / registration page; must agree with the document's page_url
                      if both are given (default: https://pam-passkey.github.io/)

The settings document (JSON, one line or formatted):

  {
    \"page_url\": \"https://pam-passkey.github.io/\",
    \"store\": {\"endpoint\": \"https://...\", \"bucket\": \"...\", \"region\": \"...\",
              \"prefix\": \"...\", \"access_key\": \"...\", \"secret\": \"...\"},
    \"send_command\": \"\",
    \"regenerate_key\": false
  }

  secret \"***\"       keeps the current secret
  prefix             may be empty or omitted
  send_command       receives each approval / registration URL on standard input; empty shows
                     the URLs on the terminal
  regenerate_key     true replaces the signing key, which invalidates every registered passkey
                     (default false: an existing key is kept)

setup checks the store (and whether it can refuse a second write of the same object), sets the
bucket's CORS and lifecycle rules (replacing the bucket's existing ones), checks that pam-passkey
is installed in a root-owned location, and then writes the settings to the System Keychain
through sudo.
";

/// Each store request during setup; setup is interactive, not on PAM's deadline.
const STORE_TIMEOUT: Duration = Duration::from_secs(15);
const SUDO: &str = "/usr/bin/sudo";
/// Where `just install` puts the module; checked when present and no `--module` is given.
const DEFAULT_MODULE: &str = "/usr/local/lib/pam/pam_passkey.so";
/// What `--dump` writes for the secret, and what keeps the current secret on input.
const SECRET_PLACEHOLDER: &str = "***";
/// The editor when `$EDITOR` is unset or empty.
const DEFAULT_EDITOR: &str = "vi";
/// Settings documents are small; anything longer is not one.
const MAX_DOCUMENT: u64 = 1024 * 1024;

/// The store as the user gives it. `put_once` is setup's own finding, so a given value is
/// ignored (DR-0010).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreInput {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub prefix: String,
    pub access_key: String,
    pub secret: String,
    #[serde(default, rename = "put_once", skip_serializing)]
    _ignored_put_once: Option<serde::de::IgnoredAny>,
}

/// The settings document (DR-0010 のキー). `--dump` writes it without `regenerate_key`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInput {
    #[serde(default)]
    pub page_url: Option<String>,
    pub store: StoreInput,
    #[serde(default)]
    pub send_command: Option<String>,
    #[serde(default, skip_serializing)]
    pub regenerate_key: bool,
}

/// The checked settings, as the root side writes them (`_setup-write`).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checked {
    pub page_url: String,
    pub store: StoreConfig,
    /// Empty: show the URL on the terminal.
    pub send_command: String,
    pub regenerate_key: bool,
}

/// The settings a previous setup wrote. `None` for an item that is not there.
#[derive(Default)]
pub struct Current {
    pub page_url: Option<String>,
    pub store: Option<StoreConfig>,
    pub send_command: Option<String>,
}

impl Current {
    /// Read as the user (the items' ACL names the pam-passkey binary).
    fn read() -> Result<Self, Box<dyn Error>> {
        let keychain = Keychain::system()?;
        let store = read_optional(&keychain, SystemItem::Store)?
            .map(|text| serde_json::from_str::<StoreConfig>(&text))
            .transpose()
            .map_err(|error| format!("the current store setting is not valid: {error}"))?;
        Ok(Self {
            page_url: read_optional(&keychain, SystemItem::PageUrl)?,
            store,
            send_command: read_optional(&keychain, SystemItem::SendCommand)?,
        })
    }
}

/// The document `--dump` prints and `--edit` opens: the current settings with the secret
/// replaced by `***`, or a template to fill in on the first run.
pub fn dump(current: &Current) -> String {
    let store = current.store.as_ref();
    let field = |pick: fn(&StoreConfig) -> &str| store.map(pick).unwrap_or_default().to_owned();
    let document = SetupInput {
        page_url: Some(
            current
                .page_url
                .clone()
                .unwrap_or_else(|| DEFAULT_PAGE_URL.into()),
        ),
        store: StoreInput {
            endpoint: field(|store| &store.endpoint),
            bucket: field(|store| &store.bucket),
            region: field(|store| &store.region),
            prefix: field(|store| &store.prefix),
            access_key: field(|store| &store.access_key),
            secret: if store.is_some() {
                SECRET_PLACEHOLDER.into()
            } else {
                String::new()
            },
            _ignored_put_once: None,
        },
        send_command: Some(current.send_command.clone().unwrap_or_default()),
        regenerate_key: false,
    };
    let mut text = serde_json::to_string_pretty(&document).unwrap_or_default();
    text.push('\n');
    text
}

/// A settings document; `"***"` as the secret stands for the current one.
pub fn parse(text: &str, current: &Current) -> Result<SetupInput, String> {
    let mut input: SetupInput = serde_json::from_str(text)
        .map_err(|error| format!("the settings are not valid: {error}"))?;
    if input.store.secret == SECRET_PLACEHOLDER {
        input.store.secret = current
            .store
            .as_ref()
            .map(|store| store.secret.clone())
            .ok_or(
                "the secret is \"***\" (keep the current one), but there is no current secret",
            )?;
    }
    Ok(input)
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
                "page_url is given twice ({argument} on the command line, {given} in the settings)"
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

/// Write what the user side checked. Runs as root.
fn write(checked: &Checked) -> Result<(), Box<dyn Error>> {
    if !is_root() {
        return Err("_setup-write writes the System Keychain and must run as root".into());
    }
    check_placement(None)?;
    let page = Page::parse(&checked.page_url)?;
    Store::new(&checked.store)?;
    let keychain = Keychain::system()?;
    // No Keychain dialog may appear behind setup's back: a write that would need one fails
    // and says so instead.
    let _no_dialogs =
        security_framework::os::macos::keychain::SecKeychain::disable_user_interaction()?;
    let put = |item: SystemItem, name: &str, value: &str| {
        keychain.write_system(item, value).map_err(|error| match error {
            KeychainError::AccessDenied(_) => format!(
                "writing {name} to the System Keychain needs an authorization that setup does not ask for ({error})"
            ),
            error => format!("writing {name} to the System Keychain: {error}"),
        })
    };
    put(SystemItem::PageUrl, "page_url", &page.url)?;
    put(
        SystemItem::Store,
        "store",
        &serde_json::to_string(&checked.store)?,
    )?;
    put(
        SystemItem::SendCommand,
        "send_command",
        &checked.send_command,
    )?;
    if checked.regenerate_key || !signing_key_exists(&keychain)? {
        let mut secret = [0u8; 32];
        security_framework::random::SecRandom::default().copy_bytes(&mut secret)?;
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        put(SystemItem::SigningKey, "signing_key", &signing_jwk(&key))?;
        put(
            SystemItem::VerificationKey,
            "verification_key",
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

/// `_setup-write`: the checked settings as one JSON line on standard input. Runs as root.
pub fn write_from_stdin() -> Result<(), Box<dyn Error>> {
    let text = read_document(std::io::stdin().lock())?;
    write(&serde_json::from_str(&text)?)
}

fn read_document(reader: impl Read) -> Result<String, Box<dyn Error>> {
    let mut text = String::new();
    reader.take(MAX_DOCUMENT).read_to_string(&mut text)?;
    if text.trim().is_empty() {
        return Err("no settings on standard input (see pam-passkey setup --help)".into());
    }
    Ok(text)
}

fn confirm(question: &str) -> Result<bool, Box<dyn Error>> {
    eprint!("{question} [y/N]: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// A file only this user can read, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn create(text: &str) -> Result<Self, Box<dyn Error>> {
        let mut random = [0u8; 9];
        security_framework::random::SecRandom::default().copy_bytes(&mut random)?;
        let path =
            std::env::temp_dir().join(format!("pam-passkey-setup-{}.json", base64url(&random)));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(text.as_bytes())?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `$EDITOR`, or vi.
fn editor() -> String {
    std::env::var("EDITOR")
        .ok()
        .filter(|editor| !editor.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_EDITOR.into())
}

/// `--edit`: the document in `editor`, in a file removed afterwards. `None` if it came back
/// unchanged.
fn edit(original: &str, editor: &str) -> Result<Option<String>, Box<dyn Error>> {
    let scratch = Scratch::create(original)?;
    // `$EDITOR` may carry arguments (`code --wait`), as a shell word list.
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(&scratch.0)
        .status()?;
    if !status.success() {
        return Err(format!("the editor exited with {status}; nothing was changed").into());
    }
    let edited = std::fs::read_to_string(&scratch.0)?;
    Ok((edited != original).then_some(edited))
}

#[derive(PartialEq, Eq)]
enum Mode {
    Edit,
    Stdin,
    Dump,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut mode = None;
    let mut module = None;
    let mut page_argument = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let chosen = match arg.as_str() {
            "--edit" => Mode::Edit,
            "--stdin" => Mode::Stdin,
            "--dump" => Mode::Dump,
            "--module" => {
                module = Some(PathBuf::from(rest.next().ok_or("--module needs a path")?));
                continue;
            }
            option if option.starts_with('-') => {
                return Err(
                    format!("unknown option {option}; run pam-passkey setup --help").into(),
                );
            }
            page if page_argument.is_none() => {
                page_argument = Some(page.to_owned());
                continue;
            }
            _ => return Err("setup takes at most one page_url".into()),
        };
        if mode.replace(chosen).is_some() {
            return Err("give one of --edit, --stdin and --dump".into());
        }
    }
    // --stdin needs the current settings only for a "***" secret; without them that is refused.
    let current = match Current::read() {
        Ok(current) => current,
        Err(error) if mode == Some(Mode::Stdin) => {
            eprintln!("setup: could not read the current settings ({error})");
            Current::default()
        }
        Err(error) => return Err(error),
    };
    let text = match mode {
        Some(Mode::Dump) => {
            if module.is_some() || page_argument.is_some() {
                return Err("--dump takes no other arguments".into());
            }
            print!("{}", dump(&current));
            return Ok(());
        }
        Some(Mode::Stdin) => read_document(std::io::stdin().lock())?,
        Some(Mode::Edit) | None => {
            if mode.is_none() && !std::io::stdin().is_terminal() {
                print!("{HELP}");
                return Ok(());
            }
            match edit(&dump(&current), &editor())? {
                Some(edited) => edited,
                None => {
                    eprintln!("setup: no changes");
                    return Ok(());
                }
            }
        }
    };
    let input = parse(&text, &current)?;
    let module = module.or_else(|| {
        let default = PathBuf::from(DEFAULT_MODULE);
        default.exists().then_some(default)
    });
    let executable = check_placement(module.as_deref())?;
    let (checked, unsupported) = check(input, page_argument.as_deref())?;
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
    // DR-0010: replacing an existing key invalidates every registration; with a terminal the
    // user confirms it, a document on standard input is taken as the decision.
    if checked.regenerate_key && signing_key_exists(&Keychain::system()?)? {
        if mode != Some(Mode::Stdin) && std::io::stdin().is_terminal() {
            if !confirm(
                "regenerate_key is true: a new signing key invalidates every registered passkey. Continue?",
            )? {
                return Err("nothing was written".into());
            }
        } else {
            eprintln!("setup: replacing the signing key; every registered passkey becomes invalid");
        }
    }
    if is_root() {
        return write(&checked);
    }
    let mut sudo = Command::new(SUDO)
        .arg(&executable)
        .arg("_setup-write")
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

    fn current() -> Current {
        Current {
            page_url: Some("https://pam-passkey.github.io/".into()),
            store: Some(StoreConfig {
                endpoint: "https://s3.ap-northeast-1.amazonaws.com".into(),
                bucket: "bucket".into(),
                region: "ap-northeast-1".into(),
                prefix: "kawaz-mbp/".into(),
                access_key: "AKIAEXAMPLE".into(),
                secret: "s3cr3t-value".into(),
                put_once: true,
            }),
            send_command: Some("notify".into()),
        }
    }

    // --dump hides the secret behind "***" and leaves out put_once (setup's own finding); the
    // same document read back keeps every value and the current secret.
    #[test]
    fn dump_then_stdin_keeps_the_settings() {
        let current = current();
        let text = dump(&current);
        assert!(!text.contains("s3cr3t-value"), "{text}");
        assert!(text.contains(r#""secret": "***""#), "{text}");
        assert!(
            !text.contains("put_once") && !text.contains("regenerate_key"),
            "{text}"
        );
        let input = parse(&text, &current).unwrap();
        assert_eq!(
            input.page_url.as_deref(),
            Some("https://pam-passkey.github.io/")
        );
        assert_eq!(input.store.secret, "s3cr3t-value");
        assert_eq!(input.store.prefix, "kawaz-mbp/");
        assert_eq!(input.store.access_key, "AKIAEXAMPLE");
        assert_eq!(input.send_command.as_deref(), Some("notify"));
        assert!(!input.regenerate_key);
        // One line works as well as the formatted document; a new secret replaces the current.
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["store"]["secret"] = "new-secret".into();
        value["regenerate_key"] = true.into();
        let input = parse(&value.to_string(), &current).unwrap();
        assert_eq!(input.store.secret, "new-secret");
        assert!(input.regenerate_key);
    }

    // The first run has nothing to keep: the template carries the default page and an empty
    // secret, and "***" is refused rather than written as the secret.
    #[test]
    fn first_run_template_and_placeholder() {
        let text = dump(&Current::default());
        assert!(
            text.contains(r#""page_url": "https://pam-passkey.github.io/""#),
            "{text}"
        );
        assert!(text.contains(r#""secret": """#), "{text}");
        let with_placeholder = dump(&current());
        let error = parse(&with_placeholder, &Current::default()).unwrap_err();
        assert!(error.contains("no current secret"), "{error}");
    }

    // The editor gets the document in a private file that is gone afterwards; only a changed,
    // successfully saved document is applied. `$EDITOR` may carry its own arguments.
    #[test]
    fn edit_applies_only_a_changed_document() {
        let original = dump(&current());
        let record = |editor: &str| {
            let seen =
                std::env::temp_dir().join(format!("pam-passkey-edit-seen-{}", std::process::id()));
            let editor = editor.replace("SEEN", &seen.display().to_string());
            let result = edit(&original, &editor);
            let path = std::fs::read_to_string(&seen).unwrap_or_default();
            let _ = std::fs::remove_file(&seen);
            (result, path.trim().to_owned())
        };
        let (unchanged, path) = record("ls -l \"$1\" > SEEN; :");
        assert_eq!(unchanged.unwrap(), None);
        assert!(path.starts_with("-rw-------"), "{path}");
        let file = path.split_whitespace().last().unwrap().to_owned();
        assert!(!Path::new(&file).exists(), "{file}");
        let (changed, _) = record("sed -i '' -e 's/notify/changed/'");
        let changed = changed.unwrap().unwrap();
        assert!(
            changed.contains(r#""send_command": "changed""#),
            "{changed}"
        );
        let (failed, _) = record("false");
        assert!(
            failed
                .unwrap_err()
                .to_string()
                .contains("nothing was changed")
        );
    }

    // A document that is not the settings is refused before anything else happens.
    #[test]
    fn invalid_documents_are_refused() {
        let current = current();
        for text in [
            "",
            "not json",
            r#"{"page_url":"https://x/"}"#,
            &dump(&current).replace("send_command", "sendcommand"),
            r#"{"store":{"endpoint":"https://e/","bucket":"b","region":"r","access_key":"k","secret":"***"},"regenerate_key":"yes"}"#,
        ] {
            let error = parse(text, &current).unwrap_err();
            assert!(
                error.starts_with("the settings are not valid"),
                "{text}: {error}"
            );
            assert!(!error.contains("s3cr3t-value"), "{error}");
        }
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
