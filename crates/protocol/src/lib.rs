use serde::{Deserialize, Serialize};

pub mod dialog;
pub mod encoding;
pub mod placement;

/// Process data collected in the PAM caller before the helper is spawned.
/// Values the caller could not obtain are `null` (docs/design/exchange-format.md, `processes`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessDetails {
    pub pid: u32,
    pub uid: u32,
    pub cwd: Option<String>,
    pub path: Option<String>,
    pub argv: Option<Vec<String>>,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestDetails {
    pub host: String,
    pub user: String,
    pub caller_uid: u32,
    pub tty: Option<String>,
    pub time: String,
    pub argv: Vec<String>,
    pub processes: Vec<ProcessDetails>,
}

/// The first line the PAM module writes to the helper's standard input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperInput {
    pub user: String,
    pub caller_uid: u32,
    pub id: String,
    pub expires: String,
    pub tty: Option<String>,
    pub details: RequestDetails,
}

/// One line on the helper's standard output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperEvent {
    Unavailable { reason: UnavailableReason },
    Url { url: String },
    Result { id: String, pass: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnavailableReason {
    NoCredentials,
    StoreUnreachable,
    KeychainLocked,
}

/// Lines after the first on the helper's standard input. Closing the input means cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperCommand {
    Open,
    Reactivate,
    /// Touch ID is locked out (`canEvaluatePolicy` -8) while PAM_USER has a GUI session.
    NotifyLockout,
    Finish {
        pass: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExchangeRequest {
    Approve {
        details: RequestDetails,
        nonce: String,
        expires: String,
        allow_credentials: Vec<String>,
        assertion_put_url: String,
        result_get_url: String,
    },
    Register {
        rp_id: String,
        user_name: String,
        user_id: String,
        expires: String,
        credential_put_url: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // An unavailable helper must carry one of the three documented reasons; arbitrary text is not an event.
    #[test]
    fn unavailable_reasons_have_stable_wire_names() {
        for (reason, wire) in [
            (UnavailableReason::NoCredentials, "no-credentials"),
            (UnavailableReason::StoreUnreachable, "store-unreachable"),
            (UnavailableReason::KeychainLocked, "keychain-locked"),
        ] {
            assert_eq!(
                serde_json::to_string(&HelperEvent::Unavailable { reason }).unwrap(),
                format!(r#"{{"event":"unavailable","reason":"{wire}"}}"#)
            );
        }
        assert!(
            serde_json::from_str::<HelperEvent>(r#"{"event":"unavailable","reason":"other"}"#)
                .is_err()
        );
    }

    // The PAM module accepts success only from a result event; its wire shape is fixed by helper-protocol.
    #[test]
    fn result_and_url_events_have_documented_shapes() {
        assert_eq!(
            serde_json::from_str::<HelperEvent>(r#"{"event":"result","id":"abc","pass":true}"#)
                .unwrap(),
            HelperEvent::Result {
                id: "abc".into(),
                pass: true
            }
        );
        assert_eq!(
            serde_json::to_string(&HelperEvent::Url {
                url: "https://example.invalid/#x".into()
            })
            .unwrap(),
            r#"{"event":"url","url":"https://example.invalid/#x"}"#
        );
        // An event with extra keys is not one of the documented events.
        assert!(
            serde_json::from_str::<HelperEvent>(
                r#"{"event":"result","id":"abc","pass":true,"extra":1}"#
            )
            .is_err()
        );
    }

    // A finish command is the only command with a boolean; the same boolean decides the result PUT.
    #[test]
    fn commands_have_documented_wire_shapes() {
        for (command, wire) in [
            (HelperCommand::Open, r#"{"cmd":"open"}"#),
            (HelperCommand::Reactivate, r#"{"cmd":"reactivate"}"#),
            (HelperCommand::NotifyLockout, r#"{"cmd":"notify_lockout"}"#),
            (
                HelperCommand::Finish { pass: true },
                r#"{"cmd":"finish","pass":true}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&command).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<HelperCommand>(wire).unwrap(),
                command
            );
        }
    }

    // Missing process values are written as null rather than omitted, as exchange-format requires.
    #[test]
    fn missing_process_values_serialize_as_null() {
        let process = ProcessDetails {
            pid: 1,
            uid: 0,
            cwd: None,
            path: None,
            argv: None,
            signing_id: None,
            team_id: None,
            signer: None,
        };
        assert_eq!(
            serde_json::to_string(&process).unwrap(),
            r#"{"pid":1,"uid":0,"cwd":null,"path":null,"argv":null,"signing_id":null,"team_id":null,"signer":null}"#
        );
    }
}
