//! The helper's acceptance of an assertion and `add`'s acceptance of a credential
//! (docs/design/webauthn-verification.md, 認証 / 登録).

use crate::cbor::{self, Value};
use crate::settings::Page;
use crate::store::{MAX_ASSERTION, MAX_CREDENTIAL};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use protocol::encoding::{base64url, base64url_decode};
use protocol::{Assertion, Credential};
use sha2::{Digest, Sha256};

/// rpIdHash (32) + flags (1) + signCount (4) is the shortest authenticatorData. Assertions
/// carry no attested credential data, so only extensions can add to it; this bounds them.
const MIN_AUTHENTICATOR_DATA: usize = 37;
pub const MAX_AUTHENTICATOR_DATA: usize = 1024;
/// WebAuthn Level 3 §6.5.1: credentialIdLength is at most 1023.
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// aaguid (16) + credentialIdLength (2) precede the credential id.
const ATTESTED_CREDENTIAL_HEADER: usize = 18;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const FLAG_ATTESTED: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;

/// COSE (RFC 9053): kty EC2, crv P-256, alg ES256, and the labels of a key's parameters.
const COSE_KTY: i128 = 1;
const COSE_ALG: i128 = 3;
const COSE_CRV: i128 = -1;
const COSE_X: i128 = -2;
const COSE_Y: i128 = -3;
const COSE_KTY_EC2: i128 = 2;
const COSE_CRV_P256: i128 = 1;
const COSE_ALG_ES256: i128 = -7;

/// The verified credentials of PAM_USER, by credential id.
#[derive(Default)]
pub struct CredentialSet {
    entries: Vec<(Vec<u8>, VerifyingKey)>,
}

impl CredentialSet {
    /// A credential id registered twice keeps its first key.
    pub fn insert(&mut self, id: Vec<u8>, key: VerifyingKey) {
        if self.key(&id).is_none() {
            self.entries.push((id, key));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The request's `allow_credentials`.
    pub fn ids(&self) -> Vec<String> {
        self.entries.iter().map(|(id, _)| base64url(id)).collect()
    }

    fn key(&self, id: &[u8]) -> Option<&VerifyingKey> {
        self.entries
            .iter()
            .find(|(known, _)| known.as_slice() == id)
            .map(|(_, key)| key)
    }
}

/// Why an assertion or a credential was not accepted, one per row of the acceptance tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    TooLarge,
    /// Not the assertion / credential object, or a value that is not base64url.
    Malformed,
    /// `clientDataJSON` is not a JSON object.
    ClientData,
    Type,
    Challenge,
    Origin,
    CrossOrigin,
    TopOrigin,
    AuthenticatorDataLength,
    RpIdHash,
    UserPresent,
    UserVerified,
    UnknownCredential,
    Signature,
    Expired,
    /// The attestation object is not a CBOR map with `authData` bytes.
    AttestationObject,
    /// The AT flag is clear, or the attested credential data does not parse to its end.
    AttestedCredentialData,
    CredentialIdLength,
    /// The credential object names another id than its authenticatorData.
    CredentialIdMismatch,
    /// The COSE key's alg is not ES256.
    Algorithm,
    /// Not a P-256 EC2 key, or not a point on the curve.
    PublicKey,
}

/// The client data checks both ceremonies share: `kind` is `webauthn.get` or `webauthn.create`,
/// and the challenge is the SHA-256 of the bytes PUT for the page.
fn check_client_data(
    client_data_json: &[u8],
    kind: &str,
    payload: &[u8],
    page: &Page,
) -> Result<(), Rejection> {
    let client_data: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(client_data_json).map_err(|_| Rejection::ClientData)?;
    if client_data.get("type").and_then(|value| value.as_str()) != Some(kind) {
        return Err(Rejection::Type);
    }
    let challenge = client_data
        .get("challenge")
        .and_then(|value| value.as_str())
        .and_then(base64url_decode);
    if challenge.as_deref() != Some(Sha256::digest(payload).as_slice()) {
        return Err(Rejection::Challenge);
    }
    if client_data.get("origin").and_then(|value| value.as_str()) != Some(page.origin.as_str()) {
        return Err(Rejection::Origin);
    }
    match client_data.get("crossOrigin") {
        None | Some(serde_json::Value::Bool(false)) => {}
        Some(_) => return Err(Rejection::CrossOrigin),
    }
    // Present at all, even as null, means the ceremony ran in an embedded context.
    if client_data.contains_key("topOrigin") {
        return Err(Rejection::TopOrigin);
    }
    Ok(())
}

/// rpIdHash, UP and UV; returns the flags.
fn check_authenticator_data(authenticator_data: &[u8], page: &Page) -> Result<u8, Rejection> {
    if authenticator_data.len() < MIN_AUTHENTICATOR_DATA {
        return Err(Rejection::AuthenticatorDataLength);
    }
    if authenticator_data[..32] != *Sha256::digest(page.rp_id.as_bytes()) {
        return Err(Rejection::RpIdHash);
    }
    let flags = authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(Rejection::UserPresent);
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(Rejection::UserVerified);
    }
    Ok(flags)
}

/// What the assertion must be bound to.
pub struct Expectation<'a> {
    /// The request bytes exactly as PUT; the challenge is their SHA-256.
    pub request: &'a [u8],
    pub page: &'a Page,
    pub credentials: &'a CredentialSet,
    /// The request's `expires` and the Mac's clock, in Unix seconds.
    pub expires: i64,
    pub now: i64,
}

pub fn verify_assertion(body: &[u8], expected: &Expectation) -> Result<(), Rejection> {
    if expected.now >= expected.expires {
        return Err(Rejection::Expired);
    }
    if body.len() > MAX_ASSERTION {
        return Err(Rejection::TooLarge);
    }
    let assertion: Assertion = serde_json::from_slice(body).map_err(|_| Rejection::Malformed)?;
    let decode = |text: &str| base64url_decode(text).ok_or(Rejection::Malformed);
    let credential_id = decode(&assertion.credential_id)?;
    let client_data_json = decode(&assertion.client_data_json)?;
    let authenticator_data = decode(&assertion.authenticator_data)?;
    let signature = decode(&assertion.signature)?;

    check_client_data(
        &client_data_json,
        "webauthn.get",
        expected.request,
        expected.page,
    )?;
    if authenticator_data.len() > MAX_AUTHENTICATOR_DATA {
        return Err(Rejection::AuthenticatorDataLength);
    }
    check_authenticator_data(&authenticator_data, expected.page)?;

    let key = expected
        .credentials
        .key(&credential_id)
        .ok_or(Rejection::UnknownCredential)?;
    let signature = DerSignature::from_bytes(&signature).map_err(|_| Rejection::Signature)?;
    let mut signed = authenticator_data;
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    key.verify(&signed, &signature)
        .map_err(|_| Rejection::Signature)
}

/// What a credential must be bound to.
pub struct RegistrationExpectation<'a> {
    /// The registration payload bytes exactly as PUT; the challenge is their SHA-256.
    pub registration: &'a [u8],
    pub page: &'a Page,
    /// The payload's `expires` and the Mac's clock, in Unix seconds.
    pub expires: i64,
    pub now: i64,
}

/// An accepted credential: what `add` records (DR-0011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub credential_id: Vec<u8>,
    pub public_key: VerifyingKey,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// The attestation statement is not verified (the page asks for `attestation: "none"`); the
/// credential is bound to the registration through the challenge, the origin and the
/// capability URL it was PUT to (DR-0011).
pub fn verify_registration(
    body: &[u8],
    expected: &RegistrationExpectation,
) -> Result<Registered, Rejection> {
    if expected.now >= expected.expires {
        return Err(Rejection::Expired);
    }
    if body.len() > MAX_CREDENTIAL {
        return Err(Rejection::TooLarge);
    }
    let credential: Credential = serde_json::from_slice(body).map_err(|_| Rejection::Malformed)?;
    let decode = |text: &str| base64url_decode(text).ok_or(Rejection::Malformed);
    let credential_id = decode(&credential.credential_id)?;
    let client_data_json = decode(&credential.client_data_json)?;
    let attestation_object = decode(&credential.attestation_object)?;

    check_client_data(
        &client_data_json,
        "webauthn.create",
        expected.registration,
        expected.page,
    )?;
    let authenticator_data = match cbor::decode(&attestation_object) {
        Some((object, [])) => object
            .get(&Value::Text("authData".into()))
            .and_then(Value::bytes)
            .map(<[u8]>::to_vec)
            .ok_or(Rejection::AttestationObject)?,
        _ => return Err(Rejection::AttestationObject),
    };
    let flags = check_authenticator_data(&authenticator_data, expected.page)?;
    if flags & FLAG_ATTESTED == 0 {
        return Err(Rejection::AttestedCredentialData);
    }
    let (attested_id, cose_key) = attested_credential(&authenticator_data, flags)?;
    let public_key = es256_key(&cose_key)?;
    if attested_id != credential_id {
        return Err(Rejection::CredentialIdMismatch);
    }
    Ok(Registered {
        credential_id,
        public_key,
        backup_eligible: flags & FLAG_BACKUP_ELIGIBLE != 0,
        backup_state: flags & FLAG_BACKUP_STATE != 0,
    })
}

/// The credential id and the COSE key of the attested credential data, which with the
/// extensions (ED) must use up authenticatorData exactly.
fn attested_credential(
    authenticator_data: &[u8],
    flags: u8,
) -> Result<(Vec<u8>, Value), Rejection> {
    let rest = &authenticator_data[MIN_AUTHENTICATOR_DATA..];
    if rest.len() < ATTESTED_CREDENTIAL_HEADER {
        return Err(Rejection::AttestedCredentialData);
    }
    let length = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
    if length == 0 || length > MAX_CREDENTIAL_ID {
        return Err(Rejection::CredentialIdLength);
    }
    let rest = &rest[ATTESTED_CREDENTIAL_HEADER..];
    if rest.len() < length {
        return Err(Rejection::AttestedCredentialData);
    }
    let (id, rest) = rest.split_at(length);
    let (key, rest) = cbor::decode(rest).ok_or(Rejection::AttestedCredentialData)?;
    let rest = if flags & FLAG_EXTENSIONS != 0 {
        match cbor::decode(rest) {
            Some((Value::Map(_), rest)) => rest,
            _ => return Err(Rejection::AttestedCredentialData),
        }
    } else {
        rest
    };
    if !rest.is_empty() {
        return Err(Rejection::AttestedCredentialData);
    }
    Ok((id.to_vec(), key))
}

fn es256_key(key: &Value) -> Result<VerifyingKey, Rejection> {
    let label = |label: i128| key.get(&Value::Integer(label));
    if label(COSE_ALG).and_then(Value::integer) != Some(COSE_ALG_ES256) {
        return Err(Rejection::Algorithm);
    }
    if label(COSE_KTY).and_then(Value::integer) != Some(COSE_KTY_EC2)
        || label(COSE_CRV).and_then(Value::integer) != Some(COSE_CRV_P256)
    {
        return Err(Rejection::PublicKey);
    }
    let coordinate = |label_value| {
        label(label_value)
            .and_then(Value::bytes)
            .filter(|bytes| bytes.len() == 32)
            .ok_or(Rejection::PublicKey)
    };
    let mut point = vec![0x04];
    point.extend_from_slice(coordinate(COSE_X)?);
    point.extend_from_slice(coordinate(COSE_Y)?);
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| Rejection::PublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Authenticator, Draft};

    const REQUEST: &[u8] = br#"{"kind":"approve","nonce":"test"}"#;

    fn page() -> Page {
        Page::parse("https://pam-passkey.github.io/").unwrap()
    }

    fn check(body: &[u8], credentials: &CredentialSet) -> Result<(), Rejection> {
        let page = page();
        verify_assertion(
            body,
            &Expectation {
                request: REQUEST,
                page: &page,
                credentials,
                expires: 2_000,
                now: 1_000,
            },
        )
    }

    fn registered() -> (Authenticator, CredentialSet) {
        let authenticator = Authenticator::new(3, b"registered-credential");
        let mut set = CredentialSet::default();
        set.insert(
            authenticator.credential_id.clone(),
            authenticator.public_key(),
        );
        (authenticator, set)
    }

    /// An assertion that satisfies every condition, then exactly one change before signing.
    fn tampered(change: impl FnOnce(&mut Draft)) -> Result<(), Rejection> {
        let (authenticator, set) = registered();
        let page = page();
        let mut draft = Draft::valid(&authenticator, REQUEST, &page);
        change(&mut draft);
        check(&draft.finish(&authenticator), &set)
    }

    // The baseline the tamper vectors start from is accepted.
    #[test]
    fn valid_assertion_passes() {
        assert_eq!(tampered(|_| {}), Ok(()));
        // crossOrigin may also be absent.
        assert_eq!(
            tampered(|draft| {
                draft.client_data.remove("crossOrigin");
            }),
            Ok(())
        );
        // BE / BS set (a synced passkey) and a non-zero signCount change nothing.
        assert_eq!(
            tampered(|draft| {
                draft.authenticator_data[32] |= 0x18;
                draft.authenticator_data[36] = 9;
            }),
            Ok(())
        );
    }

    // Authenticators may produce either of the two equivalent ECDSA signatures (s or n - s).
    #[test]
    fn high_s_signature_passes() {
        let (authenticator, set) = registered();
        let page = page();
        let mut draft = Draft::valid(&authenticator, REQUEST, &page);
        draft.high_s = true;
        assert_eq!(check(&draft.finish(&authenticator), &set), Ok(()));
    }

    // One vector per row of the acceptance table, each breaking that row alone.
    #[test]
    fn type_must_be_webauthn_get() {
        assert_eq!(
            tampered(|draft| {
                draft.client_data["type"] = "webauthn.create".into();
            }),
            Err(Rejection::Type)
        );
    }

    #[test]
    fn challenge_must_hash_the_put_request() {
        assert_eq!(
            tampered(|draft| {
                draft.client_data["challenge"] =
                    base64url(&Sha256::digest(b"other request")).into();
            }),
            Err(Rejection::Challenge)
        );
        // The challenge as a value (not the hash of the request bytes) is not accepted either.
        assert_eq!(
            tampered(|draft| {
                draft.client_data["challenge"] = base64url(REQUEST).into();
            }),
            Err(Rejection::Challenge)
        );
    }

    #[test]
    fn origin_must_match_exactly() {
        for origin in [
            "https://pam-passkey.github.io:443",
            "https://pam-passkey.github.io/",
            "http://pam-passkey.github.io",
            "https://evil.github.io",
        ] {
            assert_eq!(
                tampered(|draft| {
                    draft.client_data["origin"] = origin.into();
                }),
                Err(Rejection::Origin),
                "{origin}"
            );
        }
    }

    #[test]
    fn cross_origin_must_be_false_or_absent() {
        assert_eq!(
            tampered(|draft| {
                draft.client_data["crossOrigin"] = true.into();
            }),
            Err(Rejection::CrossOrigin)
        );
    }

    #[test]
    fn top_origin_must_be_absent() {
        assert_eq!(
            tampered(|draft| {
                draft
                    .client_data
                    .insert("topOrigin".into(), "https://pam-passkey.github.io".into());
            }),
            Err(Rejection::TopOrigin)
        );
    }

    #[test]
    fn rp_id_hash_must_match() {
        assert_eq!(
            tampered(|draft| {
                draft.authenticator_data[..32].copy_from_slice(&Sha256::digest(b"github.io"));
            }),
            Err(Rejection::RpIdHash)
        );
    }

    #[test]
    fn user_presence_and_verification_are_required() {
        assert_eq!(
            tampered(|draft| draft.authenticator_data[32] &= !FLAG_USER_PRESENT),
            Err(Rejection::UserPresent)
        );
        assert_eq!(
            tampered(|draft| draft.authenticator_data[32] &= !FLAG_USER_VERIFIED),
            Err(Rejection::UserVerified)
        );
    }

    #[test]
    fn authenticator_data_length_is_bounded() {
        assert_eq!(
            tampered(|draft| draft.authenticator_data.truncate(36)),
            Err(Rejection::AuthenticatorDataLength)
        );
        assert_eq!(
            tampered(|draft| draft
                .authenticator_data
                .resize(MAX_AUTHENTICATOR_DATA + 1, 0)),
            Err(Rejection::AuthenticatorDataLength)
        );
        assert_eq!(
            tampered(|draft| draft.authenticator_data.resize(MAX_AUTHENTICATOR_DATA, 0)),
            Ok(())
        );
    }

    // The credential id is checked against the helper's own set, whatever the page offered.
    #[test]
    fn credential_must_be_registered() {
        assert_eq!(
            tampered(|draft| draft.credential_id = b"unregistered".to_vec()),
            Err(Rejection::UnknownCredential)
        );
    }

    #[test]
    fn signature_must_verify_under_the_registered_key() {
        // Corrupted signature bytes.
        assert_eq!(
            tampered(|draft| draft.corrupt_signature = true),
            Err(Rejection::Signature)
        );
        // A well-formed signature by another key for the registered credential id.
        let (authenticator, set) = registered();
        let impostor = Authenticator::new(4, &authenticator.credential_id);
        let page = page();
        let draft = Draft::valid(&impostor, REQUEST, &page);
        assert_eq!(
            check(&draft.finish(&impostor), &set),
            Err(Rejection::Signature)
        );
        // The signature covers clientDataJSON: the same fields with one more space after
        // signing break the signature, not any client data check.
        assert_eq!(
            tampered(|draft| {
                let mut json = serde_json::to_vec(&draft.client_data).unwrap();
                json.push(b' ');
                draft.client_data_after_signing = Some(json);
            }),
            Err(Rejection::Signature)
        );
    }

    #[test]
    fn assertion_size_is_bounded() {
        let (authenticator, set) = registered();
        let page = page();
        let mut body = Draft::valid(&authenticator, REQUEST, &page).finish(&authenticator);
        // Whitespace keeps it valid JSON, so only the size decides.
        body.resize(MAX_ASSERTION + 1, b' ');
        assert_eq!(check(&body, &set), Err(Rejection::TooLarge));
        body.truncate(MAX_ASSERTION);
        assert_eq!(check(&body, &set), Ok(()));
    }

    #[test]
    fn deadline_is_the_macs_clock() {
        let (authenticator, set) = registered();
        let page = page();
        let body = Draft::valid(&authenticator, REQUEST, &page).finish(&authenticator);
        let at = |now| {
            verify_assertion(
                &body,
                &Expectation {
                    request: REQUEST,
                    page: &page,
                    credentials: &set,
                    expires: 2_000,
                    now,
                },
            )
        };
        assert_eq!(at(1_999), Ok(()));
        assert_eq!(at(2_000), Err(Rejection::Expired));
    }

    // A refusal from the page is any unsigned content in the assertion's place.
    #[test]
    fn junk_is_rejected() {
        let (_, set) = registered();
        assert_eq!(check(b"", &set), Err(Rejection::Malformed));
        assert_eq!(check(b"reject", &set), Err(Rejection::Malformed));
        assert_eq!(
            check(
                br#"{"credential_id":"","client_data_json":"","authenticator_data":"","signature":"","extra":1}"#,
                &set
            ),
            Err(Rejection::Malformed)
        );
        assert_eq!(
            check(
                br#"{"credential_id":"!","client_data_json":"","authenticator_data":"","signature":""}"#,
                &set
            ),
            Err(Rejection::Malformed)
        );
        assert_eq!(
            tampered(|draft| draft.client_data_after_signing = Some(b"[]".to_vec())),
            Err(Rejection::ClientData)
        );
    }

    mod registration {
        use super::super::*;
        use super::page;
        use crate::cbor::{Value, encode};
        use crate::test_support::{Authenticator, RegistrationDraft};

        const REGISTRATION: &[u8] = br#"{"kind":"register","user_name":"kawaz"}"#;

        fn authenticator() -> Authenticator {
            Authenticator::new(6, b"new-credential")
        }

        fn check_at(body: &[u8], now: i64) -> Result<Registered, Rejection> {
            let page = page();
            verify_registration(
                body,
                &RegistrationExpectation {
                    registration: REGISTRATION,
                    page: &page,
                    expires: 2_000,
                    now,
                },
            )
        }

        /// A credential that satisfies every condition, then exactly one change.
        fn tampered(change: impl FnOnce(&mut RegistrationDraft)) -> Result<Registered, Rejection> {
            let page = page();
            let mut draft = RegistrationDraft::valid(&authenticator(), REGISTRATION, &page);
            change(&mut draft);
            check_at(&draft.finish(), 1_000)
        }

        fn rejected(change: impl FnOnce(&mut RegistrationDraft)) -> Rejection {
            tampered(change).unwrap_err()
        }

        // The baseline is accepted and yields the attested id, key and backup flags.
        #[test]
        fn valid_credential_registers() {
            let registered = tampered(|_| {}).unwrap();
            assert_eq!(registered.credential_id, b"new-credential");
            assert_eq!(registered.public_key, authenticator().public_key());
            assert!(registered.backup_eligible && registered.backup_state);
            // A device-bound passkey (BE / BS clear) is accepted and recorded as such, and
            // crossOrigin may be absent.
            let registered = tampered(|draft| {
                draft.head[32] &= !0x18;
                draft.client_data.remove("crossOrigin");
            })
            .unwrap();
            assert!(!registered.backup_eligible && !registered.backup_state);
            // Extensions after the key are allowed when the ED flag declares them.
            assert!(
                tampered(|draft| {
                    draft.head[32] |= 0x80;
                    draft.extensions = Some(Value::Map(vec![(
                        Value::Text("credProtect".into()),
                        Value::Integer(1),
                    )]));
                })
                .is_ok()
            );
        }

        // One vector per row of the registration table, each breaking that row alone.
        #[test]
        fn client_data_rows() {
            assert_eq!(
                rejected(|draft| draft.client_data["type"] = "webauthn.get".into()),
                Rejection::Type
            );
            assert_eq!(
                rejected(|draft| {
                    draft.client_data["challenge"] =
                        base64url(&Sha256::digest(b"other registration")).into();
                }),
                Rejection::Challenge
            );
            assert_eq!(
                rejected(|draft| draft.client_data["origin"] = "https://evil.github.io".into()),
                Rejection::Origin
            );
            assert_eq!(
                rejected(|draft| draft.client_data["crossOrigin"] = true.into()),
                Rejection::CrossOrigin
            );
            assert_eq!(
                rejected(|draft| {
                    draft
                        .client_data
                        .insert("topOrigin".into(), "https://pam-passkey.github.io".into());
                }),
                Rejection::TopOrigin
            );
        }

        #[test]
        fn rp_id_hash_and_flags() {
            assert_eq!(
                rejected(|draft| draft.head[..32].copy_from_slice(&Sha256::digest(b"github.io"))),
                Rejection::RpIdHash
            );
            assert_eq!(
                rejected(|draft| draft.head[32] &= !0x01),
                Rejection::UserPresent
            );
            assert_eq!(
                rejected(|draft| draft.head[32] &= !0x04),
                Rejection::UserVerified
            );
            assert_eq!(
                rejected(|draft| draft.head[32] &= !0x40),
                Rejection::AttestedCredentialData
            );
        }

        #[test]
        fn key_must_be_es256() {
            // RS256 (-257) and EdDSA (-8) are other algorithms, however the key looks.
            for alg in [-257, -8] {
                assert_eq!(
                    rejected(|draft| draft.cose_key[1].1 = Value::Integer(alg)),
                    Rejection::Algorithm
                );
            }
            assert_eq!(
                rejected(|draft| {
                    draft.cose_key.remove(1);
                }),
                Rejection::Algorithm
            );
            // alg ES256 on something that is not a P-256 point.
            assert_eq!(
                rejected(|draft| draft.cose_key[2].1 = Value::Integer(2)),
                Rejection::PublicKey
            );
            assert_eq!(
                rejected(|draft| draft.cose_key[0].1 = Value::Integer(1)),
                Rejection::PublicKey
            );
            assert_eq!(
                rejected(|draft| draft.cose_key[4].1 = Value::Bytes(vec![0; 32])),
                Rejection::PublicKey
            );
            assert_eq!(
                rejected(|draft| draft.cose_key[3].1 = Value::Bytes(vec![1; 31])),
                Rejection::PublicKey
            );
        }

        #[test]
        fn credential_id_length_is_bounded() {
            assert_eq!(
                rejected(|draft| draft.attested_id = vec![7; MAX_CREDENTIAL_ID + 1]),
                Rejection::CredentialIdLength
            );
            assert_eq!(
                rejected(|draft| draft.attested_id = Vec::new()),
                Rejection::CredentialIdLength
            );
            let longest = tampered(|draft| {
                draft.attested_id = vec![7; MAX_CREDENTIAL_ID];
                draft.named_id = Some(vec![7; MAX_CREDENTIAL_ID]);
            })
            .unwrap();
            assert_eq!(longest.credential_id.len(), MAX_CREDENTIAL_ID);
        }

        // The id the page names must be the one the authenticator attested.
        #[test]
        fn named_id_must_be_the_attested_id() {
            assert_eq!(
                rejected(|draft| draft.named_id = Some(b"other-credential".to_vec())),
                Rejection::CredentialIdMismatch
            );
        }

        // authenticatorData parses exactly to its end: no trailing bytes, no undeclared or
        // malformed extensions, no truncated credential id.
        #[test]
        fn attested_credential_data_is_exact() {
            assert_eq!(
                rejected(|draft| draft.trailing = vec![0]),
                Rejection::AttestedCredentialData
            );
            assert_eq!(
                rejected(|draft| {
                    draft.extensions = Some(Value::Map(Vec::new()));
                }),
                Rejection::AttestedCredentialData
            );
            assert_eq!(
                rejected(|draft| {
                    draft.head[32] |= 0x80;
                    draft.extensions = Some(Value::Integer(1));
                }),
                Rejection::AttestedCredentialData
            );
            assert_eq!(
                rejected(|draft| draft.head[32] |= 0x80),
                Rejection::AttestedCredentialData
            );
            let page = page();
            let draft = RegistrationDraft::valid(&authenticator(), REGISTRATION, &page);
            let mut data = draft.authenticator_data();
            data.truncate(37 + 18 + 4);
            assert_eq!(
                rejected(|draft| {
                    draft.attestation_object = Some(encode::to_vec(&Value::Map(vec![(
                        Value::Text("authData".into()),
                        Value::Bytes(data),
                    )])));
                }),
                Rejection::AttestedCredentialData
            );
        }

        #[test]
        fn attestation_object_shape() {
            for object in [
                b"not cbor".to_vec(),
                encode::to_vec(&Value::Array(Vec::new())),
                encode::to_vec(&Value::Map(vec![(
                    Value::Text("authData".into()),
                    Value::Text("text".into()),
                )])),
                // A valid object followed by another item.
                [
                    encode::to_vec(&Value::Map(vec![(
                        Value::Text("authData".into()),
                        Value::Bytes(vec![0; 40]),
                    )])),
                    vec![0],
                ]
                .concat(),
            ] {
                assert_eq!(
                    rejected(|draft| draft.attestation_object = Some(object)),
                    Rejection::AttestationObject
                );
            }
        }

        #[test]
        fn size_deadline_and_junk() {
            let page = page();
            let mut body = RegistrationDraft::valid(&authenticator(), REGISTRATION, &page).finish();
            assert!(check_at(&body, 1_999).is_ok());
            assert_eq!(check_at(&body, 2_000), Err(Rejection::Expired));
            body.resize(MAX_CREDENTIAL + 1, b' ');
            assert_eq!(check_at(&body, 1_000), Err(Rejection::TooLarge));
            body.truncate(MAX_CREDENTIAL);
            assert!(check_at(&body, 1_000).is_ok());
            assert_eq!(check_at(b"{}", 1_000), Err(Rejection::Malformed));
            assert_eq!(
                check_at(br#"{"rejected":true}"#, 1_000),
                Err(Rejection::Malformed)
            );
        }
    }
}
