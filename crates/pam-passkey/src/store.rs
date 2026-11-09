//! The S3-compatible store (DR-0005). Every request, the pages' and our own, goes through a
//! SigV4 presigned URL, so the access key and secret never leave this process.

use md5::{Digest, Md5};
use rusty_s3::{Bucket, Credentials, Method, S3Action, UrlStyle};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use std::time::Duration;
use ureq::tls::{RootCerts, TlsConfig};
use url::Url;

/// Upper bounds of the objects (exchange-format サイズ上限).
pub const MAX_REQUEST: usize = 64 * 1024;
pub const MAX_ASSERTION: usize = 16 * 1024;
pub const MAX_CREDENTIAL: usize = 16 * 1024;

/// Our own requests are signed for this long: they are sent right after signing.
const OWN_REQUEST_VALIDITY: Duration = Duration::from_secs(60);

/// The System Keychain `store` item (DESIGN 状態と設定). `put_once` is decided by `setup`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub access_key: String,
    pub secret: String,
    pub put_once: bool,
}

/// The secret never appears in logs or errors (DR-0011: ストアの秘密は出力に出さない).
impl fmt::Debug for StoreConfig {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("StoreConfig")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("access_key", &self.access_key)
            .field("secret", &"<redacted>")
            .field("put_once", &self.put_once)
            .finish()
    }
}

#[derive(Debug)]
pub enum StoreError {
    /// The configuration cannot address a bucket (bad endpoint, bucket name, ...).
    Config(String),
    /// The request did not complete (DNS, TLS, connection, timeout).
    Transport(String),
    /// The store answered with an unexpected HTTP status.
    Status(u16),
}

impl fmt::Display for StoreError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(out, "store configuration: {message}"),
            Self::Transport(message) => write!(out, "store request failed: {message}"),
            Self::Status(status) => write!(out, "store answered HTTP {status}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ureq::Error> for StoreError {
    fn from(error: ureq::Error) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Transport(error.to_string())
    }
}

/// The outcome of a GET with a size cap.
#[derive(Debug, PartialEq, Eq)]
pub enum Fetched {
    Missing,
    Found(Vec<u8>),
    /// The object is larger than the cap; its content is not read.
    TooLarge,
}

pub struct Store {
    bucket: Bucket,
    credentials: Credentials,
    prefix: String,
    put_once: bool,
    agent: ureq::Agent,
}

impl Store {
    pub fn new(config: &StoreConfig) -> Result<Self, StoreError> {
        let endpoint = Url::parse(&config.endpoint)
            .map_err(|error| StoreError::Config(format!("endpoint: {error}")))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(StoreError::Config("endpoint must be http or https".into()));
        }
        if config.bucket.is_empty() || config.region.is_empty() {
            return Err(StoreError::Config("bucket and region are required".into()));
        }
        if config.access_key.is_empty() || config.secret.is_empty() {
            return Err(StoreError::Config(
                "access key and secret are required".into(),
            ));
        }
        // Design rationale: path-style addressing works with every S3-compatible store
        // (R2, MinIO, AWS) and with IP / localhost endpoints; virtual-host style does not.
        let bucket = Bucket::new(
            endpoint,
            UrlStyle::Path,
            config.bucket.clone(),
            config.region.clone(),
        )
        .map_err(|error| StoreError::Config(error.to_string()))?;
        let agent = ureq::Agent::config_builder()
            // Statuses are answers to interpret (404 = not yet, 412 = already written).
            .http_status_as_error(false)
            // Neither the environment nor the store chooses where our requests go.
            .proxy(None)
            .max_redirects(0)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        Ok(Self {
            bucket,
            credentials: Credentials::new(config.access_key.clone(), config.secret.clone()),
            prefix: config.prefix.clone(),
            put_once: config.put_once,
            agent,
        })
    }

    /// `<prefix><request ID>/<name>`: the objects of one request share one directory.
    pub fn key(&self, id: &str, name: &str) -> String {
        format!("{}{id}/{name}", self.prefix)
    }

    /// A presigned GET for a page, valid for `valid_for` (the request's remaining lifetime).
    pub fn presign_get(&self, key: &str, valid_for: Duration) -> Url {
        self.bucket
            .get_object(Some(&self.credentials), key)
            .sign(valid_for)
    }

    /// A presigned PUT for a page. With `put_once`, `If-None-Match: *` is a signed header, so
    /// the URL writes at most once (DR-0005).
    pub fn presign_put(&self, key: &str, valid_for: Duration) -> Url {
        self.signed_put(key, self.put_once, valid_for)
    }

    fn signed_put(&self, key: &str, once: bool, valid_for: Duration) -> Url {
        let mut action = self.bucket.put_object(Some(&self.credentials), key);
        if once {
            action.headers_mut().insert("if-none-match", "*");
        }
        action.sign(valid_for)
    }

    /// PUT `body` and return the HTTP status. `once` sends (and signs) `If-None-Match: *`.
    pub fn put(
        &self,
        key: &str,
        body: &[u8],
        once: bool,
        timeout: Duration,
    ) -> Result<u16, StoreError> {
        let url = self.signed_put(key, once, OWN_REQUEST_VALIDITY);
        let mut request = self
            .agent
            .put(url.as_str())
            .config()
            .timeout_global(Some(timeout))
            .build();
        if once {
            request = request.header("If-None-Match", "*");
        }
        Ok(request.send(body)?.status().as_u16())
    }

    /// GET at most `limit` bytes. 404 is `Missing`; other non-200 statuses are errors.
    pub fn get(&self, key: &str, limit: usize, timeout: Duration) -> Result<Fetched, StoreError> {
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(OWN_REQUEST_VALIDITY);
        let response = self
            .agent
            .get(url.as_str())
            .config()
            .timeout_global(Some(timeout))
            .build()
            .call()?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(Fetched::Missing),
            status => return Err(StoreError::Status(status)),
        }
        let mut body = Vec::new();
        response
            .into_body()
            .into_with_config()
            .reader()
            .take(limit as u64 + 1)
            .read_to_end(&mut body)?;
        if body.len() > limit {
            return Ok(Fetched::TooLarge);
        }
        Ok(Fetched::Found(body))
    }

    /// GET while waiting for a page's object (the assertion, the credential).
    ///
    /// Design rationale: without `s3:ListBucket` AWS answers a GET of a missing object with 403
    /// instead of 404, and the store's access key is not meant to list the bucket (MANUAL). The
    /// key was checked by `setup`, so 403 during a wait is read as "not there yet"; the cost is
    /// that a key revoked later makes the wait run to its deadline without a message.
    pub fn poll(&self, key: &str, limit: usize, timeout: Duration) -> Result<Fetched, StoreError> {
        match self.get(key, limit, timeout) {
            Err(StoreError::Status(403)) => Ok(Fetched::Missing),
            other => other,
        }
    }

    /// DELETE; a missing object counts as deleted.
    pub fn delete(&self, key: &str, timeout: Duration) -> Result<(), StoreError> {
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(OWN_REQUEST_VALIDITY);
        let response = self
            .agent
            .delete(url.as_str())
            .config()
            .timeout_global(Some(timeout))
            .build()
            .call()?;
        match response.status().as_u16() {
            200 | 204 | 404 => Ok(()),
            status => Err(StoreError::Status(status)),
        }
    }

    /// PUT a bucket subresource (`cors`, `lifecycle`) with an XML body. These APIs require
    /// `Content-MD5`; it is signed along with the host.
    fn put_bucket_subresource(
        &self,
        subresource: &str,
        body: &str,
        timeout: Duration,
    ) -> Result<(), StoreError> {
        let digest = base64_standard(&Md5::digest(body.as_bytes()));
        let url = rusty_s3::signing::sign(
            &jiff::Timestamp::now(),
            Method::Put,
            self.bucket.base_url().clone(),
            self.credentials.key(),
            self.credentials.secret(),
            None,
            self.bucket.region(),
            OWN_REQUEST_VALIDITY.as_secs(),
            [(subresource, "")].into_iter(),
            [("content-md5", digest.as_str())].into_iter(),
        );
        let response = self
            .agent
            .put(url.as_str())
            .config()
            .timeout_global(Some(timeout))
            .build()
            .header("Content-MD5", &digest)
            .header("Content-Type", "application/xml")
            .send(body)?;
        match response.status().as_u16() {
            200 | 204 => Ok(()),
            status => Err(StoreError::Status(status)),
        }
    }

    /// The page's origin may GET the request and result and PUT the assertion (DR-0006, DR-0010).
    pub fn put_cors(&self, origin: &str, timeout: Duration) -> Result<(), StoreError> {
        self.put_bucket_subresource("cors", &cors_xml(origin), timeout)
    }

    /// Objects under the prefix expire after a day (DR-0006: 残ったオブジェクトの削除).
    pub fn put_lifecycle(&self, timeout: Duration) -> Result<(), StoreError> {
        self.put_bucket_subresource("lifecycle", &lifecycle_xml(&self.prefix), timeout)
    }
}

fn xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn cors_xml(origin: &str) -> String {
    format!(
        "<CORSConfiguration><CORSRule><AllowedOrigin>{}</AllowedOrigin>\
         <AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>\
         <AllowedHeader>If-None-Match</AllowedHeader><AllowedHeader>Content-Type</AllowedHeader>\
         </CORSRule></CORSConfiguration>",
        xml_text(origin)
    )
}

pub fn lifecycle_xml(prefix: &str) -> String {
    format!(
        "<LifecycleConfiguration><Rule><ID>pam-passkey</ID><Filter><Prefix>{}</Prefix></Filter>\
         <Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
         </LifecycleConfiguration>",
        xml_text(prefix)
    )
}

/// Standard base64 with padding (RFC 4648 §4), the form `Content-MD5` takes.
fn base64_standard(bytes: &[u8]) -> String {
    let mut text: String = protocol::encoding::base64url(bytes)
        .chars()
        .map(|symbol| match symbol {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while !text.len().is_multiple_of(4) {
        text.push('=');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::minio::Minio;

    fn config(endpoint: &str) -> StoreConfig {
        StoreConfig {
            endpoint: endpoint.into(),
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            prefix: "pam-passkey/".into(),
            access_key: "AKIAEXAMPLE".into(),
            secret: "very-secret-value".into(),
            put_once: true,
        }
    }

    // Content-MD5 is standard base64 with padding (RFC 1864), unlike every other binary value.
    #[test]
    fn content_md5_is_padded_standard_base64() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(&[0xfb, 0xff]), "+/8=");
        // RFC 1321 test vector for MD5("").
        assert_eq!(
            base64_standard(&Md5::digest(b"")),
            "1B2M2Y8AsgTpgAmY7PhCfg=="
        );
    }

    // The secret is part of the configuration but never of its debug output.
    #[test]
    fn debug_output_redacts_the_secret() {
        let text = format!("{:?}", config("http://127.0.0.1:9000"));
        assert!(!text.contains("very-secret-value"), "{text}");
        assert!(text.contains("<redacted>"));
    }

    // Objects of one request live under <prefix><id>/, and the URLs handed to pages are
    // path-style, signed for the requested lifetime, and carry If-None-Match only with put_once.
    #[test]
    fn keys_and_presigned_urls() {
        let store = Store::new(&config("https://store.example")).unwrap();
        assert_eq!(store.key("abc", "request"), "pam-passkey/abc/request");
        let get = store.presign_get("pam-passkey/abc/request", Duration::from_secs(90));
        assert!(
            get.as_str()
                .starts_with("https://store.example/bucket/pam-passkey/abc/request?"),
            "{get}"
        );
        assert!(get.as_str().contains("X-Amz-Expires=90"), "{get}");
        assert!(get.as_str().contains("X-Amz-SignedHeaders=host&"), "{get}");
        assert!(!get.as_str().contains("very-secret-value"));
        let put = store.presign_put("pam-passkey/abc/assertion", Duration::from_secs(90));
        assert!(
            put.as_str()
                .contains("X-Amz-SignedHeaders=host%3Bif-none-match&"),
            "{put}"
        );
        let mut overwritable = config("https://store.example");
        overwritable.put_once = false;
        let store = Store::new(&overwritable).unwrap();
        let put = store.presign_put("pam-passkey/abc/assertion", Duration::from_secs(90));
        assert!(put.as_str().contains("X-Amz-SignedHeaders=host&"), "{put}");
    }

    // A configuration that cannot address a bucket is refused before any request is made.
    #[test]
    fn rejects_unusable_configuration() {
        for broken in [
            StoreConfig {
                endpoint: "ftp://store.example".into(),
                ..config("")
            },
            StoreConfig {
                endpoint: "not a url".into(),
                ..config("")
            },
            StoreConfig {
                bucket: String::new(),
                ..config("https://store.example")
            },
            StoreConfig {
                secret: String::new(),
                ..config("https://store.example")
            },
        ] {
            assert!(
                matches!(Store::new(&broken), Err(StoreError::Config(_))),
                "{broken:?}"
            );
        }
    }

    // The bucket configuration documents are well-formed for any origin or prefix text.
    #[test]
    fn bucket_documents_escape_their_values() {
        let cors = cors_xml("https://a.example");
        assert!(cors.contains("<AllowedOrigin>https://a.example</AllowedOrigin>"));
        assert!(cors.contains("<AllowedHeader>If-None-Match</AllowedHeader>"));
        assert!(cors.contains("<AllowedHeader>Content-Type</AllowedHeader>"));
        assert!(lifecycle_xml("a&b<c>/").contains("<Prefix>a&amp;b&lt;c&gt;/</Prefix>"));
        assert!(lifecycle_xml("").contains("<Days>1</Days>"));
    }

    // (1) presign / PUT / GET / DELETE / If-None-Match against a real S3 implementation.
    #[test]
    #[ignore = "needs MinIO on PATH (brew install minio); run with: cargo test -- --ignored"]
    fn round_trip_against_minio() {
        let minio = Minio::start();
        let store = Store::new(&minio.config(true)).unwrap();
        let timeout = Duration::from_secs(5);
        let key = store.key("round-trip", "object");

        assert_eq!(store.get(&key, 16, timeout).unwrap(), Fetched::Missing);
        assert_eq!(store.put(&key, b"first", false, timeout).unwrap(), 200);
        assert_eq!(
            store.get(&key, 16, timeout).unwrap(),
            Fetched::Found(b"first".to_vec())
        );
        // The cap is exact: an object one byte longer is not read.
        assert_eq!(
            store.get(&key, 5, timeout).unwrap(),
            Fetched::Found(b"first".to_vec())
        );
        assert_eq!(store.get(&key, 4, timeout).unwrap(), Fetched::TooLarge);
        // If-None-Match: * refuses to replace an existing object, and a plain PUT does.
        assert_eq!(store.put(&key, b"second", true, timeout).unwrap(), 412);
        assert_eq!(store.put(&key, b"third", false, timeout).unwrap(), 200);
        assert_eq!(
            store.get(&key, 16, timeout).unwrap(),
            Fetched::Found(b"third".to_vec())
        );
        store.delete(&key, timeout).unwrap();
        assert_eq!(store.get(&key, 16, timeout).unwrap(), Fetched::Missing);
        // Deleting what is not there is not an error (the helper deletes on every exit path).
        store.delete(&key, timeout).unwrap();

        // The URLs handed to pages work without our credentials, as a browser would use them.
        let page = minio.page_agent();
        let put_url = store.presign_put(&key, Duration::from_secs(30));
        let get_url = store.presign_get(&key, Duration::from_secs(30));
        let status = |response: Result<ureq::http::Response<ureq::Body>, ureq::Error>| {
            response.unwrap().status().as_u16()
        };
        assert_eq!(status(page.get(get_url.as_str()).call()), 404);
        // With put_once the signed If-None-Match header is part of the capability: without it
        // the PUT is refused (MinIO answers 400, AWS 403) and nothing is written.
        let unsigned = status(page.put(put_url.as_str()).send(&b"x"[..]));
        assert!(matches!(unsigned, 400 | 403), "{unsigned}");
        assert_eq!(status(page.get(get_url.as_str()).call()), 404);
        assert_eq!(
            status(
                page.put(put_url.as_str())
                    .header("If-None-Match", "*")
                    .send(&b"page"[..])
            ),
            200
        );
        assert_eq!(
            status(
                page.put(put_url.as_str())
                    .header("If-None-Match", "*")
                    .send(&b"again"[..])
            ),
            412
        );
        let mut response = page.get(get_url.as_str()).call().unwrap();
        assert_eq!(response.body_mut().read_to_vec().unwrap(), b"page");
        // The capability is bound to its key: the same signature on another path is refused.
        let moved = get_url
            .as_str()
            .replace("/round-trip/object?", "/round-trip/other?");
        assert_eq!(status(page.get(&moved).call()), 403);
        store.delete(&key, timeout).unwrap();

        // A refused GET is an error to `get` but "not there yet" to `poll` (AWS refuses GETs of
        // missing objects with 403 when the key cannot list the bucket; here: a wrong secret).
        let refused = Store::new(&StoreConfig {
            secret: "wrong-secret".into(),
            ..minio.config(true)
        })
        .unwrap();
        assert!(matches!(
            refused.get(&key, 16, timeout),
            Err(StoreError::Status(403))
        ));
        assert_eq!(refused.poll(&key, 16, timeout).unwrap(), Fetched::Missing);
        assert_eq!(store.poll(&key, 16, timeout).unwrap(), Fetched::Missing);
    }
}
