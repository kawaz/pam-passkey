//! Test doubles: an authenticator that signs like a passkey would (without a page or a
//! browser), signed passkey records, and a throwaway MinIO server.

use crate::records::{EcPublicJwk, PasskeyRecord, sign_record};
use crate::settings::Page;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use protocol::encoding::base64url;
use sha2::{Digest, Sha256};

/// A P-256 credential, the key of a registered passkey.
pub struct Authenticator {
    key: SigningKey,
    pub credential_id: Vec<u8>,
}

impl Authenticator {
    /// A deterministic key per `seed` (non-zero, so the scalar is valid).
    pub fn new(seed: u8, credential_id: &[u8]) -> Self {
        let mut secret = [0u8; 32];
        secret[31] = seed;
        secret[0] = 0x11;
        Self {
            key: SigningKey::from_slice(&secret).unwrap(),
            credential_id: credential_id.to_vec(),
        }
    }

    pub fn public_key(&self) -> VerifyingKey {
        *self.key.verifying_key()
    }
}

/// The parts of an assertion before it is signed. Every field starts out valid.
pub struct Draft {
    pub client_data: serde_json::Map<String, serde_json::Value>,
    pub authenticator_data: Vec<u8>,
    pub credential_id: Vec<u8>,
    /// Sign with the other of the two equivalent ECDSA signatures (n - s).
    pub high_s: bool,
    pub corrupt_signature: bool,
    /// clientDataJSON as sent, replacing the one that was signed.
    pub client_data_after_signing: Option<Vec<u8>>,
}

impl Draft {
    pub fn valid(authenticator: &Authenticator, request: &[u8], page: &Page) -> Self {
        let mut client_data = serde_json::Map::new();
        client_data.insert("type".into(), "webauthn.get".into());
        client_data.insert(
            "challenge".into(),
            base64url(&Sha256::digest(request)).into(),
        );
        client_data.insert("origin".into(), page.origin.clone().into());
        client_data.insert("crossOrigin".into(), false.into());
        let mut authenticator_data = Sha256::digest(page.rp_id.as_bytes()).to_vec();
        // UP | UV, signCount 0 (as Apple's synced passkeys report).
        authenticator_data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
        Self {
            client_data,
            authenticator_data,
            credential_id: authenticator.credential_id.clone(),
            high_s: false,
            corrupt_signature: false,
            client_data_after_signing: None,
        }
    }

    /// The assertion object as the page PUTs it.
    pub fn finish(self, authenticator: &Authenticator) -> Vec<u8> {
        let client_data_json = serde_json::to_vec(&self.client_data).unwrap();
        let mut signed = self.authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let mut signature: Signature = authenticator.key.sign(&signed);
        if self.high_s {
            let (r, s) = signature.split_scalars();
            signature = Signature::from_scalars(r, -*s).unwrap();
        }
        let mut der = signature.to_der().as_bytes().to_vec();
        if self.corrupt_signature {
            let last = der.len() - 1;
            der[last] ^= 0x01;
        }
        let client_data_json = self.client_data_after_signing.unwrap_or(client_data_json);
        serde_json::to_vec(&serde_json::json!({
            "credential_id": base64url(&self.credential_id),
            "client_data_json": base64url(&client_data_json),
            "authenticator_data": base64url(&self.authenticator_data),
            "signature": base64url(&der),
        }))
        .unwrap()
    }
}

/// The System Keychain signing key of a test installation.
pub fn record_signer(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// One `users/<user>` line registering `authenticator` for `user`.
pub fn signed_record(
    signer: &ed25519_dalek::SigningKey,
    user: &str,
    authenticator: &Authenticator,
) -> String {
    sign_record(
        signer,
        &PasskeyRecord {
            user: user.into(),
            credential_id: base64url(&authenticator.credential_id),
            user_id: base64url(&[9; 16]),
            public_key: EcPublicJwk::from_key(&authenticator.public_key()),
            label: "test".into(),
            registered: "2026-11-09T00:00:00Z".into(),
            backup_eligible: true,
            backup_state: true,
        },
    )
}

/// A store configuration whose endpoint refuses connections (the discard port on loopback).
pub fn unreachable_store() -> crate::store::StoreConfig {
    crate::store::StoreConfig {
        endpoint: "http://127.0.0.1:9".into(),
        bucket: "bucket".into(),
        region: "us-east-1".into(),
        prefix: "pam-passkey/".into(),
        access_key: "AKIAEXAMPLE".into(),
        secret: "secret".into(),
        put_once: false,
    }
}

pub mod minio {
    //! A MinIO server for one test, in its own temporary directory, stopped on drop.

    use crate::store::StoreConfig;
    use std::ffi::CString;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    const USER: &str = "pam-passkey-test";
    const PASSWORD: &str = "pam-passkey-test-password";
    pub const BUCKET: &str = "bucket";

    pub struct Minio {
        child: Child,
        base: PathBuf,
        pub endpoint: String,
    }

    /// A fresh directory under the system temporary directory (mkdtemp).
    fn temporary_directory() -> PathBuf {
        let template = std::env::temp_dir().join("pam-passkey-minio.XXXXXX");
        let template = CString::new(template.as_os_str().as_bytes()).unwrap();
        let raw = template.into_raw();
        // SAFETY: mkdtemp rewrites the NUL-terminated template in place.
        let made = unsafe { libc::mkdtemp(raw) };
        // SAFETY: `raw` came from into_raw and is reclaimed exactly once.
        let template = unsafe { CString::from_raw(raw) };
        assert!(!made.is_null(), "mkdtemp failed");
        PathBuf::from(template.into_string().unwrap())
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    impl Minio {
        /// Starts MinIO and returns once it serves requests, with the test bucket created.
        pub fn start() -> Self {
            let base = temporary_directory();
            let (api, console) = (free_port(), free_port());
            let endpoint = format!("http://127.0.0.1:{api}");
            // HOME and the certs directory point into the base, so nothing is written outside it.
            let mut child = Command::new("minio")
                .arg("server")
                .arg(base.join("data"))
                .arg("--address")
                .arg(format!("127.0.0.1:{api}"))
                .arg("--console-address")
                .arg(format!("127.0.0.1:{console}"))
                .arg("--certs-dir")
                .arg(base.join("certs"))
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", &base)
                .env("MINIO_ROOT_USER", USER)
                .env("MINIO_ROOT_PASSWORD", PASSWORD)
                .env("MINIO_BROWSER", "off")
                .env("MINIO_UPDATE", "off")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("minio is not on PATH (brew install minio)");
            // MinIO prints its API endpoint on standard error once it accepts requests.
            let stderr = child.stderr.take().unwrap();
            let mut lines = BufReader::new(stderr).lines();
            loop {
                match lines.next() {
                    Some(Ok(line)) if line.contains("API:") => break,
                    Some(Ok(_)) => {}
                    other => panic!("minio exited before serving: {other:?}"),
                }
            }
            // Keep draining its output so it never blocks on a full pipe.
            std::thread::spawn(move || lines.for_each(drop));
            let minio = Self {
                child,
                base,
                endpoint,
            };
            minio.create_bucket();
            minio
        }

        pub fn config(&self, put_once: bool) -> StoreConfig {
            StoreConfig {
                endpoint: self.endpoint.clone(),
                bucket: BUCKET.into(),
                region: "us-east-1".into(),
                prefix: "pam-passkey/".into(),
                access_key: USER.into(),
                secret: PASSWORD.into(),
                put_once,
            }
        }

        /// An HTTP client without our credentials, as a page uses the presigned URLs.
        pub fn page_agent(&self) -> ureq::Agent {
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into()
        }

        fn create_bucket(&self) {
            use rusty_s3::S3Action;
            let bucket = rusty_s3::Bucket::new(
                self.endpoint.parse().unwrap(),
                rusty_s3::UrlStyle::Path,
                BUCKET,
                "us-east-1",
            )
            .unwrap();
            let credentials = rusty_s3::Credentials::new(USER, PASSWORD);
            let url = bucket
                .create_bucket(&credentials)
                .sign(std::time::Duration::from_secs(60));
            let status = self
                .page_agent()
                .put(url.as_str())
                .send_empty()
                .unwrap()
                .status();
            assert_eq!(status, 200, "create bucket");
        }

        /// GET the bucket with one query parameter (`cors`, `lifecycle`, `list-type=2`) as root.
        pub fn bucket_get(&self, (name, value): (&str, &str)) -> (u16, String) {
            let bucket = rusty_s3::Bucket::new(
                self.endpoint.parse().unwrap(),
                rusty_s3::UrlStyle::Path,
                BUCKET,
                "us-east-1",
            )
            .unwrap();
            let url = rusty_s3::signing::sign(
                &jiff::Timestamp::now(),
                rusty_s3::Method::Get,
                bucket.base_url().clone(),
                USER,
                PASSWORD,
                None,
                "us-east-1",
                60,
                [(name, value)].into_iter(),
                std::iter::empty(),
            );
            let mut response = self.page_agent().get(url.as_str()).call().unwrap();
            let status = response.status().as_u16();
            (status, response.body_mut().read_to_string().unwrap())
        }
    }

    impl Drop for Minio {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }
}
