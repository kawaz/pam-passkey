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
| `expires` | 要求の期限 |
| `assertion_put_url` | assertion を PUT する presigned URL |
| `result_get_url` | result を GET する presigned URL |

`details`:

| キー | 中身 |
|---|---|
| `host` | Mac のホスト名 |
| `user` | `PAM_USER` |
| `caller_uid` | 呼び出し元の uid |
| `tty` | 呼び出し元の tty のパス。無ければ `null` |
| `time` | 要求時刻 |
| `argv` | 呼び出し元の argv (文字列の配列) |
| `processes` | 呼び出し元から launchd までの祖先チェーン (配列)。各要素に載せる値は DESIGN-ja の「承認画面に見せるもの」 |

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

- 署名アルゴリズムは ES256。署名鍵と公開鍵は P-256 の JWK
- ペイロードの中身は [DR-0011](../decisions/DR-0011-user-keychain-signed-records.md)

### サイズ上限

| オブジェクト | 上限 |
|---|---|
| request | 64 KiB |
| assertion | 16 KiB |
| credential | 16 KiB |

## 制約 / 前提

- challenge は request / 登録ペイロードのバイト列全体の SHA-256 なので、helper / `add` は PUT したバイト列をそのまま保持する ([DR-0006](../decisions/DR-0006-approval-url-and-exchange.md))

## 関連

- [DESIGN-ja.md](../DESIGN-ja.md) — 親文書
- [DR-0006](../decisions/DR-0006-approval-url-and-exchange.md) — 承認 URL と交換
- [DR-0011](../decisions/DR-0011-user-keychain-signed-records.md) — 登録と passkey の置き場
- [helper-protocol](./helper-protocol.md) — PAM モジュールと helper の取り決め
- [webauthn-verification](./webauthn-verification.md) — 認証と登録の受理条件
