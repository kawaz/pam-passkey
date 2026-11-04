use serde::{Deserialize, Serialize};

/// Process data collected in the PAM caller before the helper is spawned.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessDetails {
    pub pid: u32,
    pub uid: u32,
    pub cwd: Option<String>,
    pub path: Option<String>,
    pub argv: Vec<String>,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub signer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperInput {
    pub user: String,
    pub caller_uid: u32,
    pub id: String,
    pub expires: String,
    pub tty: Option<String>,
    pub details: RequestDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HelperEvent {
    Unavailable { reason: UnavailableReason },
    Url { url: String },
    Result { id: String, pass: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnavailableReason {
    NoCredentials,
    StoreUnreachable,
    KeychainLocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum HelperCommand {
    Open,
    Reactivate,
    Finish { pass: bool },
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
        let event = HelperEvent::Unavailable {
            reason: UnavailableReason::KeychainLocked,
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"event":"unavailable","reason":"keychain-locked"}"#
        );
    }

    // A finish command is the only command with a boolean; the same boolean decides the result PUT.
    #[test]
    fn finish_command_roundtrips() {
        let command: HelperCommand =
            serde_json::from_str(r#"{"cmd":"finish","pass":true}"#).unwrap();
        assert!(matches!(command, HelperCommand::Finish { pass: true }));
    }
}
