//! `list` and `del` (DR-0010), and the line `add` appends: the user's `users/<os user>` item
//! in the login keychain, edited as JSONL without verifying the JWS of any line.

use crate::child::current_user;
use crate::records::{PasskeyRecord, unverified_record};
use pam_passkey::keychain::{Keychain, KeychainError};
use std::error::Error;
use std::fmt::Write as _;
use std::path::Path;

/// `list` / `add` / `del` act on the invoking user's own login keychain. root has no passkeys
/// (DR-0012: PAM_USER が root ならパスワードへ落ちる), so a run through sudo is a mistake.
pub fn own_keychain() -> Result<(String, Keychain), Box<dyn Error>> {
    // SAFETY: getuid / geteuid have no preconditions.
    if unsafe { libc::getuid() == 0 || libc::geteuid() == 0 } {
        return Err("run as the user whose passkeys these are, without sudo".into());
    }
    let (user, home) = current_user()?;
    let keychain = Keychain::login(Path::new(&home))?;
    Ok((user, keychain))
}

/// The item's text; an absent item has no lines.
pub fn read(keychain: &Keychain, user: &str) -> Result<String, KeychainError> {
    match keychain.read_user(user) {
        Ok(text) => Ok(text),
        Err(KeychainError::NotFound) => Ok(String::new()),
        Err(error) => Err(error),
    }
}

fn lines(jsonl: &str) -> impl Iterator<Item = &str> {
    jsonl.lines().filter(|line| !line.trim().is_empty())
}

fn join<'a>(lines: impl Iterator<Item = &'a str>) -> String {
    lines.fold(String::new(), |mut text, line| {
        text.push_str(line);
        text.push('\n');
        text
    })
}

/// `jsonl` with `line` (the record of `credential_id`) after the existing lines. A credential
/// id that is already there is refused rather than recorded twice.
pub fn append(jsonl: &str, line: &str, credential_id: &str) -> Result<String, String> {
    if lines(jsonl)
        .filter_map(unverified_record)
        .any(|record| record.credential_id == credential_id)
    {
        return Err(format!(
            "the credential {credential_id} is already registered"
        ));
    }
    Ok(join(lines(jsonl).chain([line])))
}

/// `jsonl` without the passkey `target` names, and the removed records. A credential id is
/// matched first (all its lines go); otherwise a label must name exactly one passkey. Lines
/// that cannot be read are kept as they are.
pub fn remove(jsonl: &str, target: &str) -> Result<(String, Vec<PasskeyRecord>), String> {
    let parsed: Vec<(&str, Option<PasskeyRecord>)> = lines(jsonl)
        .map(|line| (line, unverified_record(line)))
        .collect();
    let matching = |field: fn(&PasskeyRecord) -> &str| -> Vec<&PasskeyRecord> {
        parsed
            .iter()
            .filter_map(|(_, record)| record.as_ref())
            .filter(|record| field(record) == target)
            .collect()
    };
    let by_id: fn(&PasskeyRecord) -> &str = |record| &record.credential_id;
    let by_label: fn(&PasskeyRecord) -> &str = |record| &record.label;
    let field = if !matching(by_id).is_empty() {
        by_id
    } else {
        match matching(by_label)[..] {
            [] => {
                return Err(format!(
                    "no passkey has the credential id or label {target:?} (see pam-passkey list)"
                ));
            }
            [_] => by_label,
            ref candidates => {
                let mut message = format!(
                    "the label {target:?} names more than one passkey; delete one by its credential id:"
                );
                for record in candidates {
                    let _ = write!(
                        message,
                        "\n  {}  registered {}",
                        record.credential_id, record.registered
                    );
                }
                return Err(message);
            }
        }
    };
    let (removed, kept): (Vec<_>, Vec<_>) = parsed.into_iter().partition(|(_, record)| {
        record
            .as_ref()
            .is_some_and(|record| field(record) == target)
    });
    Ok((
        join(kept.into_iter().map(|(line, _)| line)),
        removed
            .into_iter()
            .filter_map(|(_, record)| record)
            .collect(),
    ))
}

/// A value from the item on one terminal line: control characters are shown escaped.
pub fn printable(text: &str) -> String {
    text.chars()
        .flat_map(|symbol| {
            if symbol.is_control() {
                symbol.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![symbol]
            }
        })
        .collect()
}

/// `list`: one line per passkey, `<label>\t<credential id>\t<registered>`.
pub fn list() -> Result<(), Box<dyn Error>> {
    let (user, keychain) = own_keychain()?;
    let jsonl = read(&keychain, &user)?;
    let mut shown = 0;
    for (number, line) in lines(&jsonl).enumerate() {
        match unverified_record(line) {
            Some(record) => {
                println!(
                    "{}\t{}\t{}",
                    printable(&record.label),
                    printable(&record.credential_id),
                    printable(&record.registered)
                );
                shown += 1;
            }
            None => eprintln!("pam-passkey: record {} cannot be read", number + 1),
        }
    }
    if shown == 0 {
        eprintln!("pam-passkey: no passkeys are registered for {user} (pam-passkey add)");
    }
    Ok(())
}

/// `del <label|id>`: rewrites the item without the passkey, or deletes the item once it has no
/// lines left (the helper then reports no credentials).
pub fn del(target: &str) -> Result<(), Box<dyn Error>> {
    let (user, keychain) = own_keychain()?;
    let (kept, removed) = remove(&read(&keychain, &user)?, target)?;
    if kept.is_empty() {
        keychain.delete_user(&user)?;
    } else {
        keychain.write_user(&user, &kept)?;
    }
    for record in removed {
        println!(
            "deleted {}\t{}",
            printable(&record.label),
            printable(&record.credential_id)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Authenticator, record_signer, signed_record};
    use protocol::encoding::base64url;

    fn record(seed: u8, label: &str) -> String {
        let authenticator = Authenticator::new(seed, format!("credential-{seed}").as_bytes());
        let line = signed_record(&record_signer(1), "kawaz", &authenticator);
        // signed_record labels every record "test"; relabel through the payload.
        let mut record = unverified_record(&line).unwrap();
        record.label = label.into();
        crate::records::sign_record(&record_signer(1), &record)
    }

    fn id(seed: u8) -> String {
        base64url(format!("credential-{seed}").as_bytes())
    }

    // A credential id wins over a label, and removes every line that carries it.
    #[test]
    fn removes_by_credential_id_first() {
        // The label of passkey 2 is passkey 1's id: the id is what is meant.
        let jsonl = [record(1, "phone"), record(2, &id(1)), record(1, "again")].join("\n");
        let (kept, removed) = remove(&jsonl, &id(1)).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(removed.iter().all(|record| record.credential_id == id(1)));
        assert_eq!(kept, format!("{}\n", record(2, &id(1))));
    }

    #[test]
    fn removes_by_a_unique_label() {
        let jsonl = format!("{}\n{}\n", record(1, "phone"), record(2, "mac"));
        let (kept, removed) = remove(&jsonl, "mac").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].credential_id, id(2));
        assert_eq!(kept, format!("{}\n", record(1, "phone")));
        // The last passkey leaves nothing, which del turns into deleting the item.
        let (kept, _) = remove(&kept, "phone").unwrap();
        assert_eq!(kept, "");
    }

    // A label shared by several passkeys is refused with the candidates' ids; an unknown
    // target is refused; neither changes anything.
    #[test]
    fn refuses_ambiguous_and_unknown_targets() {
        let jsonl = format!("{}\n{}\n", record(1, "same"), record(2, "same"));
        let error = remove(&jsonl, "same").unwrap_err();
        assert!(error.contains(&id(1)) && error.contains(&id(2)), "{error}");
        let error = remove(&jsonl, "other").unwrap_err();
        assert!(error.contains("no passkey"), "{error}");
    }

    // Lines that cannot be read are neither matched nor dropped.
    #[test]
    fn keeps_unreadable_lines() {
        let jsonl = format!("not json\n{}\n\n", record(1, "phone"));
        let (kept, removed) = remove(&jsonl, "phone").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(kept, "not json\n");
    }

    #[test]
    fn append_keeps_lines_and_refuses_a_known_id() {
        let first = record(1, "phone");
        let jsonl = append("", &first, &id(1)).unwrap();
        assert_eq!(jsonl, format!("{first}\n"));
        // An item without a final newline still gets one line per record.
        let second = record(2, "mac");
        let jsonl = append(jsonl.trim_end(), &second, &id(2)).unwrap();
        assert_eq!(jsonl, format!("{first}\n{second}\n"));
        assert!(append(&jsonl, &record(1, "dup"), &id(1)).is_err());
    }

    #[test]
    fn printable_escapes_control_characters() {
        assert_eq!(printable("a\tb\u{1b}[31m"), "a\\u{9}b\\u{1b}[31m");
        assert_eq!(printable("ラベル"), "ラベル");
    }
}
