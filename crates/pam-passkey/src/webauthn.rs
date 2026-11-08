//! The helper's acceptance of an assertion (docs/design/webauthn-verification.md, 認証).

use crate::settings::Page;
use crate::store::MAX_ASSERTION;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use protocol::Assertion;
use protocol::encoding::{base64url, base64url_decode};
use sha2::{Digest, Sha256};

/// rpIdHash (32) + flags (1) + signCount (4) is the shortest authenticatorData. Assertions
/// carry no attested credential data, so only extensions can add to it; this bounds them.
const MIN_AUTHENTICATOR_DATA: usize = 37;
pub const MAX_AUTHENTICATOR_DATA: usize = 1024;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;

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

/// Why an assertion was not accepted, one per row of the acceptance table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    TooLarge,
    /// Not the assertion object, or a value that is not base64url.
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

    let client_data: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&client_data_json).map_err(|_| Rejection::ClientData)?;
    if client_data.get("type").and_then(|value| value.as_str()) != Some("webauthn.get") {
        return Err(Rejection::Type);
    }
    let challenge = client_data
        .get("challenge")
        .and_then(|value| value.as_str())
        .and_then(base64url_decode);
    if challenge.as_deref() != Some(Sha256::digest(expected.request).as_slice()) {
        return Err(Rejection::Challenge);
    }
    if client_data.get("origin").and_then(|value| value.as_str())
        != Some(expected.page.origin.as_str())
    {
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

    if !(MIN_AUTHENTICATOR_DATA..=MAX_AUTHENTICATOR_DATA).contains(&authenticator_data.len()) {
        return Err(Rejection::AuthenticatorDataLength);
    }
    if authenticator_data[..32] != *Sha256::digest(expected.page.rp_id.as_bytes()) {
        return Err(Rejection::RpIdHash);
    }
    let flags = authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(Rejection::UserPresent);
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(Rejection::UserVerified);
    }

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
}
