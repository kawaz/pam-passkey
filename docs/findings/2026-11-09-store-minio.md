# S3 互換ストア (MinIO) に対する presign / 条件付き PUT / CORS / lifecycle の挙動

- Date: 2026-11-09
- 対象: `crates/pam-passkey` の `store.rs` (rusty-s3 の SigV4 presign + ureq)、`setup.rs`、`auth.rs` の remote 経路。テストは MinIO (RELEASE.2025-10-15、`brew install minio`) をテスト内で起動して実行 (`cargo test -p pam-passkey -- --ignored`)
- 環境: macOS 26.5.2。AWS S3 / Cloudflare R2 では未検証

## 判明した事実

- `If-None-Match: *` を署名ヘッダに含めた presigned PUT で、同じキーへの 2 回目の PUT は 412 になる (`put_once` の判定に使える)
- `if-none-match` を署名に含めた presigned PUT をヘッダ無しで送ると MinIO は 400 を返し、何も書かれない (AWS は 403 の見込み、未検証)
- presigned GET の署名を別のキーのパスに付け替えると 403
- MinIO の `PutBucketCors` は 501 NotImplemented (MinIO の CORS はサーバ全体の設定)。`PutBucketLifecycleConfiguration` は `Content-MD5` を署名に含めれば 200 で、`GET ?lifecycle` で設定 (Days 1、prefix) を確認できる
- 承認の一周 (request PUT → 承認 URL → assertion PUT → 検証 → result PUT → DELETE) と、受理条件を 1 つだけ破った assertion 12 種の拒否、`finish` / stdin close / `send_command` / `open` の各終了経路が MinIO 相手に通る
- p256 crate の ES256 検証は high-S の署名も通す (WebAuthn では low-S の正規化を要求しないので問題ない)
- MinIO の起動バナー (`API:` の行) は stderr に出る (stdout を待つとハングする)

## 実用的な示唆

- `put_once` は `setup` の疎通確認で実測して決める設計で足りる (MinIO は対応)
- CORS を `setup` が設定できないストア (MinIO) があるので、501 なら警告して必要な設定を表示し、続行する。403 等は止める
- 承認ページは `put_once` のとき `If-None-Match: *` を付けて PUT する (presigned URL の `X-Amz-SignedHeaders` に `if-none-match` が入る)

## 未観測

- AWS S3 / Cloudflare R2 での同じ観測 (特に CORS の XML、lifecycle、`If-None-Match` の 412 / ヘッダ無し時の応答)
- 本物の `_auth` を PAM → root helper から System Keychain の `store` を読んで動かす経路 (実装 ③b の実機一周で観測)
