# exchange-format: ストアを介して交換するオブジェクトの形

## コンテキスト

[DESIGN-ja.md](../DESIGN-ja.md) の「承認 URL と交換の流れ」と「登録」を補足する。helper / `add` と静的ページが S3 互換ストアを介して受け渡すオブジェクトの形。各オブジェクトの意味と扱いは、承認が [DR-0006](../decisions/DR-0006-approval-url-and-exchange.md)、登録が [DR-0011](../decisions/DR-0011-user-keychain-signed-records.md) が正本。

## 詳細

### 共通

- オブジェクトは UTF-8 の JSON。result だけは JSON でない (下記)
- バイナリの値は base64url の文字列にする
- 時刻は RFC 3339 の UTC で書く (例: `2026-11-03T12:00:00Z`)

### request (承認、helper → ページ)

| キー | 中身 |
|---|---|
| `kind` | `"approve"` |
| `details` | 要求の詳細 (下表) |
| `nonce` | 要求 ID ([helper-protocol](./helper-protocol.md)) |
| `expires` | 要求の期限。PAM が決めて helper に渡した値 ([helper-protocol](./helper-protocol.md)) |
| `allow_credentials` | `PAM_USER` の登録済み credential id の配列。ページは `allowCredentials` に渡す |
| `assertion_put_url` | assertion を PUT する presigned URL |
| `result_get_url` | result を GET する presigned URL |

`details` (helper は同じ JSON のバイト列を `send_command` の `PAM_PASSKEY_DETAILS` にも渡す。[DR-0008](../decisions/DR-0008-pluggable-send-command.md)):

| キー | 中身 |
|---|---|
| `host` | Mac のホスト名 |
| `user` | `PAM_USER` |
| `caller_uid` | 呼び出し元の uid |
| `tty` | 呼び出し元の tty のパス。無ければ `null` |
| `time` | 要求時刻 |
| `argv` | 呼び出し元の argv (文字列の配列) |
| `processes` | 呼び出し元から launchd までの祖先チェーン (配列。要素は下表) |

`processes` の各要素 (値が無いものは `null`):

| キー | 中身 |
|---|---|
| `pid` | pid |
| `uid` | プロセスの uid |
| `cwd` | cwd |
| `path` | 実行パス |
| `argv` | argv (文字列の配列) |
| `signing_id` | 署名 ID |
| `team_id` | Team ID |
| `signer` | 署名者名 |

### 登録ペイロード (登録、`add` → ページ)

| キー | 中身 |
|---|---|
| `kind` | `"register"` |
| `rp_id` | passkey の RP ID |
| `user_name` | 登録するユーザの OS ユーザ名 |
| `user_id` | WebAuthn の user handle。登録ごとの乱数 16 バイト |
| `expires` | 登録要求の期限 |
| `credential_put_url` | credential を PUT する presigned URL |

### assertion (承認、ページ → helper)

| キー | 中身 |
|---|---|
| `credential_id` | credential id |
| `client_data_json` | `clientDataJSON` |
| `authenticator_data` | `authenticatorData` |
| `signature` | 署名 |

### credential (登録、ページ → `add`)

| キー | 中身 |
|---|---|
| `credential_id` | credential id |
| `client_data_json` | `clientDataJSON` |
| `attestation_object` | `attestationObject` |

### result (helper → ページ)

本文は文字列 `pass` か `fail` (JSON でない)。

### JWS (login keychain の passkey の項目)

- JSONL の各行は JWS の flattened JSON serialization (`protected` / `payload` / `signature`)
- protected header は `{"alg":"Ed25519"}` だけを受け付ける。署名鍵と検証用の公開鍵は `kty: OKP` / `crv: Ed25519` の JWK
- ペイロードのキー: `user` (OS ユーザ名) / `credential_id` / `user_id` (user handle) / `public_key` (P-256 の JWK: `kty: EC`, `crv: P-256`, `x`, `y`) / `label` / `registered` (RFC 3339 UTC) / `backup_eligible` / `backup_state`

### ストアのオブジェクトのキーと `store` 設定

- オブジェクトのキーは `<prefix><要求 ID>/request` / `.../assertion` / `.../result` (登録は `.../registration` / `.../credential`)。`prefix` は文字列としてそのまま前に付ける
- `store` (ユーザの login keychain の `config` の中) の JSON のキー: `endpoint` / `bucket` / `region` / `prefix` / `access_key` / `secret` / `put_once`。アドレスは path-style
- `put_once` が true のとき presigned PUT は `X-Amz-SignedHeaders` に `if-none-match` を含むので、ページは PUT に `If-None-Match: *` を付ける

### サイズ上限

| オブジェクト | 上限 |
|---|---|
| request | 64 KiB |
| assertion | 16 KiB (`authenticatorData` は 1024 バイト) |
| credential | 16 KiB |

## 制約 / 前提

- challenge は request / 登録ペイロードのバイト列全体の SHA-256 なので、helper / `add` は PUT したバイト列をそのまま保持する ([DR-0006](../decisions/DR-0006-approval-url-and-exchange.md))

## 関連

- [DESIGN-ja.md](../DESIGN-ja.md) — 親文書
- [DR-0006](../decisions/DR-0006-approval-url-and-exchange.md) — 承認 URL と交換
- [DR-0011](../decisions/DR-0011-user-keychain-signed-records.md) — 登録と passkey の置き場
- [DR-0008](../decisions/DR-0008-pluggable-send-command.md) — `details` を `send_command` にも渡す
- [helper-protocol](./helper-protocol.md) — PAM モジュールと helper の取り決め
- [webauthn-verification](./webauthn-verification.md) — 認証と登録の受理条件
