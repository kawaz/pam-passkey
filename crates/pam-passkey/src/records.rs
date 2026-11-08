//! The passkey records in the login keychain (`users/<os user>`, JSONL) and the Ed25519 keys
//! that sign them (DR-0011, exchange-format JWS).
//!
//! Each line is a JWS in the flattened JSON serialization (RFC 7515 §7.2.2), so that the item
//! stays one JSON value per line. The protected header is exactly `{"alg":"Ed25519"}`.

use crate::webauthn::CredentialSet;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::VerifyingKey as PasskeyKey;
use protocol::encoding::{base64url, base64url_decode};
use serde::{Deserialize, Serialize};

const PROTECTED_HEADER: &str = r#"{"alg":"Ed25519"}"#;

/// The JWS payload of one registered passkey.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRecord {
    /// The OS user the passkey was registered for; a record copied to another user is invalid.
    pub user: String,
    /// base64url credential id.
    pub credential_id: String,
    /// base64url WebAuthn user handle.
    pub user_id: String,
    pub public_key: EcPublicJwk,
    pub label: String,
    /// RFC 3339 UTC.
    pub registered: String,
    /// The BE / BS flags at registration.
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// A P-256 public key as a JWK (RFC 7518 §6.2.1), the passkey's ES256 key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl EcPublicJwk {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "add (実装 ③b) records the registered key")
    )]
    pub fn from_key(key: &PasskeyKey) -> Self {
        let point = key.to_sec1_point(false);
        let bytes = point.as_bytes();
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: base64url(&bytes[1..33]),
            y: base64url(&bytes[33..65]),
        }
    }

    pub fn to_key(&self) -> Option<PasskeyKey> {
        if self.kty != "EC" || self.crv != "P-256" {
            return None;
        }
        let (x, y) = (base64url_decode(&self.x)?, base64url_decode(&self.y)?);
        if x.len() != 32 || y.len() != 32 {
            return None;
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        PasskeyKey::from_sec1_bytes(&point).ok()
    }
}

/// An Ed25519 key as a JWK (RFC 8037): the signing key has `d`, the verification key does not.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OkpJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

pub fn signing_jwk(key: &SigningKey) -> String {
    let jwk = OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: base64url(key.verifying_key().as_bytes()),
        d: Some(base64url(key.as_bytes())),
    };
    serde_json::to_string(&jwk).unwrap_or_default()
}

pub fn verification_jwk(key: &VerifyingKey) -> String {
    let jwk = OkpJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: base64url(key.as_bytes()),
        d: None,
    };
    serde_json::to_string(&jwk).unwrap_or_default()
}

/// The System Keychain `verification_key` item. A JWK with a private part is not a
/// verification key.
pub fn parse_verification_jwk(text: &str) -> Option<VerifyingKey> {
    let jwk: OkpJwk = serde_json::from_str(text).ok()?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" || jwk.d.is_some() {
        return None;
    }
    let x: [u8; 32] = base64url_decode(&jwk.x)?.try_into().ok()?;
    VerifyingKey::from_bytes(&x).ok()
}

/// The System Keychain `signing_key` item; `x` must belong to `d`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "add (実装 ③b) reads the signing key")
)]
pub fn parse_signing_jwk(text: &str) -> Option<SigningKey> {
    let jwk: OkpJwk = serde_json::from_str(text).ok()?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return None;
    }
    let d: [u8; 32] = base64url_decode(jwk.d.as_deref()?)?.try_into().ok()?;
    let key = SigningKey::from_bytes(&d);
    (base64url(key.verifying_key().as_bytes()) == jwk.x).then_some(key)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlattenedJws {
    protected: String,
    payload: String,
    signature: String,
}

/// One JSONL line for `record`, signed with the System Keychain signing key.
#[cfg_attr(not(test), expect(dead_code, reason = "add (実装 ③b) signs records"))]
pub fn sign_record(key: &SigningKey, record: &PasskeyRecord) -> String {
    use ed25519_dalek::Signer;
    let protected = base64url(PROTECTED_HEADER.as_bytes());
    let payload = base64url(&serde_json::to_vec(record).unwrap_or_default());
    let signature = key.sign(format!("{protected}.{payload}").as_bytes());
    serde_json::to_string(&FlattenedJws {
        protected,
        payload,
        signature: base64url(&signature.to_bytes()),
    })
    .unwrap_or_default()
}

/// The payload of `line` if its JWS verifies under `key`.
pub fn verify_record(line: &str, key: &VerifyingKey) -> Option<PasskeyRecord> {
    let jws: FlattenedJws = serde_json::from_str(line).ok()?;
    // Only the header we write: no other algorithm, no `crit`, nothing to interpret.
    if base64url_decode(&jws.protected)? != PROTECTED_HEADER.as_bytes() {
        return None;
    }
    let signature = Signature::from_slice(&base64url_decode(&jws.signature)?).ok()?;
    key.verify_strict(
        format!("{}.{}", jws.protected, jws.payload).as_bytes(),
        &signature,
    )
    .ok()?;
    serde_json::from_slice(&base64url_decode(&jws.payload)?).ok()
}

/// The credentials of `user` among the records whose JWS verifies (DESIGN 状態と設定):
/// records that do not verify, belong to another OS user, or carry an unusable key are ignored.
pub fn trusted_credentials(jsonl: &str, key: &VerifyingKey, user: &str) -> CredentialSet {
    let mut set = CredentialSet::default();
    for (number, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some(record) = verify_record(line, key) else {
            eprintln!(
                "pam-passkey: ignored passkey record {} (signature does not verify)",
                number + 1
            );
            continue;
        };
        if record.user != user {
            eprintln!(
                "pam-passkey: ignored passkey record {} (registered for another user)",
                number + 1
            );
            continue;
        }
        let (Some(id), Some(public_key)) = (
            base64url_decode(&record.credential_id),
            record.public_key.to_key(),
        ) else {
            eprintln!(
                "pam-passkey: ignored passkey record {} (unusable credential id or key)",
                number + 1
            );
            continue;
        };
        set.insert(id, public_key);
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Authenticator, record_signer, signed_record};

    // A signed record verifies and round-trips its payload; the signing key's JWK yields the
    // same verification key that setup stores beside it.
    #[test]
    fn signed_records_verify() {
        let signer = record_signer(1);
        let verifier = parse_verification_jwk(&verification_jwk(&signer.verifying_key())).unwrap();
        let reparsed = parse_signing_jwk(&signing_jwk(&signer)).unwrap();
        assert_eq!(reparsed.as_bytes(), signer.as_bytes());
        let authenticator = Authenticator::new(7, b"credential-7");
        let line = signed_record(&signer, "kawaz", &authenticator);
        let record = verify_record(&line, &verifier).unwrap();
        assert_eq!(record.user, "kawaz");
        assert_eq!(
            record.public_key.to_key().unwrap(),
            authenticator.public_key()
        );
        let set = trusted_credentials(&line, &verifier, "kawaz");
        assert_eq!(set.ids(), [base64url(b"credential-7")]);
    }

    // Records that do not verify under the System Keychain key, or that name another OS user,
    // contribute nothing: a user-writable login keychain cannot add a credential (DR-0011).
    #[test]
    fn foreign_and_forged_records_are_ignored() {
        let signer = record_signer(1);
        let verifier = signer.verifying_key();
        let other_signer = record_signer(2);
        let authenticator = Authenticator::new(7, b"credential-7");
        let good = signed_record(&signer, "kawaz", &authenticator);
        let forged = signed_record(&other_signer, "kawaz", &authenticator);
        let for_other_user = signed_record(&signer, "someone", &authenticator);
        let jsonl = format!("{forged}\n{for_other_user}\nnot json\n\n");
        assert!(trusted_credentials(&jsonl, &verifier, "kawaz").is_empty());
        // A payload swapped under a valid signature does not verify.
        let mut jws: FlattenedJws = serde_json::from_str(&good).unwrap();
        let other: FlattenedJws = serde_json::from_str(&for_other_user).unwrap();
        jws.payload = other.payload;
        assert!(verify_record(&serde_json::to_string(&jws).unwrap(), &verifier).is_none());
        // Another protected header (here: another algorithm name) is not accepted, even signed.
        let mut jws: FlattenedJws = serde_json::from_str(&good).unwrap();
        jws.protected = base64url(br#"{"alg":"EdDSA"}"#);
        let input = format!("{}.{}", jws.protected, jws.payload);
        use ed25519_dalek::Signer;
        jws.signature = base64url(&signer.sign(input.as_bytes()).to_bytes());
        assert!(verify_record(&serde_json::to_string(&jws).unwrap(), &verifier).is_none());
        // The good line still counts when mixed with the rest.
        let jsonl = format!("{forged}\n{good}\n");
        assert_eq!(trusted_credentials(&jsonl, &verifier, "kawaz").len(), 1);
    }

    // Key items of the wrong shape are not keys: a verification key with `d`, a signing key
    // whose `x` is not its own, other curves.
    #[test]
    fn key_items_must_have_their_exact_shape() {
        let signer = record_signer(1);
        assert!(parse_verification_jwk(&signing_jwk(&signer)).is_none());
        let mut jwk: OkpJwk = serde_json::from_str(&signing_jwk(&signer)).unwrap();
        jwk.x = base64url(record_signer(2).verifying_key().as_bytes());
        assert!(parse_signing_jwk(&serde_json::to_string(&jwk).unwrap()).is_none());
        let public = verification_jwk(&signer.verifying_key()).replace("Ed25519", "X25519");
        assert!(parse_verification_jwk(&public).is_none());
        let point = EcPublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: base64url(&[0; 32]),
            y: base64url(&[0; 32]),
        };
        assert!(point.to_key().is_none());
    }
}
