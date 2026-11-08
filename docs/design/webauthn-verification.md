# webauthn-verification: 認証と登録の受理条件

## コンテキスト

[DESIGN-ja.md](../DESIGN-ja.md) の「署名の束縛と検証」と「登録」を補足する。helper が assertion を pass にする条件 ([DR-0006](../decisions/DR-0006-approval-url-and-exchange.md)) と、`add` が credential を登録する条件 ([DR-0011](../decisions/DR-0011-user-keychain-signed-records.md)) の一覧。ここに挙げた条件を 1 つでも満たさないものは受理しない。

## 詳細

### 認証 (assertion)

| 対象 | 条件 |
|---|---|
| `clientDataJSON.type` | `"webauthn.get"` |
| `clientDataJSON.challenge` | helper が PUT した request のバイト列全体の SHA-256 と一致する |
| `clientDataJSON.origin` | `page_url` の origin と scheme / host / port まで完全一致する |
| `clientDataJSON.crossOrigin` | `false` または不在 |
| `clientDataJSON.topOrigin` | 不在 (iframe に埋め込まれた状態での署名を拒む) |
| `authenticatorData.rpIdHash` | `SHA-256(rp_id)` と一致する |
| `authenticatorData` の flags | UP と UV の両方が立っている |
| `authenticatorData` の長さ | 上限を超えない |
| credential id | 認証対象ユーザの登録済み集合に含まれる。判定は helper 側で行い、ページの `allowCredentials` には頼らない |
| 署名 | 登録済みの公開鍵で、`authenticatorData ‖ SHA-256(clientDataJSON)` に対して検証が通る。アルゴリズムは ES256 に固定する |
| challenge の使用回数 | 1 回限り。assertion を受け取って判定したら、その要求の待ち状態を破棄する |
| 期限 | request の `expires` 内。判定は Mac の時計で helper が行う |
| signCount | 検証しない。Apple の同期 passkey は常に 0 を返し、保証にならない |

### 登録 (credential)

| 対象 | 条件 |
|---|---|
| `clientDataJSON.type` | `"webauthn.create"` |
| `clientDataJSON.challenge` | `add` が PUT した登録ペイロードのバイト列全体の SHA-256 と一致する (承認と同じ形) |
| `clientDataJSON.origin` | `page_url` の origin と scheme / host / port まで完全一致する |
| `clientDataJSON.crossOrigin` | `false` または不在 |
| `clientDataJSON.topOrigin` | 不在 |
| `authenticatorData.rpIdHash` | `SHA-256(rp_id)` と一致する |
| `authenticatorData` の flags | UP、UV、AT (attested credential data あり) が立っている |
| 公開鍵の COSE alg | ES256 (`-7`) だけを受け入れる |
| credential id の長さ | 1 以上 1023 バイト以下 (WebAuthn の credentialIdLength の上限) |
| credential id の一致 | credential オブジェクトの `credential_id` が authenticatorData の attested credential data の id と一致する |
| authenticatorData の形 | attested credential data (と ED が立っていれば extensions) で末尾まで過不足なく読める |
| attestation statement | 検証しない (`fmt` / `attStmt` は見ない)。credential は challenge・origin・capability URL で登録要求に束縛される |
| BE / BS フラグ | 同期される passkey (BE が立つもの) も受け入れる。値は登録時に JWS のペイロードに記録する |
| challenge の使用回数 | 1 回限り。credential を受け取って判定したら、その登録要求の待ちを破棄する |
| 期限 | 登録ペイロードの `expires` 内。判定は Mac の時計で `add` が行う |

### テスト

各条件について、条件を 1 つだけ破った入力が拒否されることを確かめる改ざんテストベクタを実装時に用意する。

## 制約 / 前提

- ページの配信元と rp_id のドメインは信頼の前提に入る (DESIGN-ja「信頼の前提」)。上の条件は中継での差し替えと、別 origin・iframe からの署名を落とすためのもので、配信元の改ざんは防げない
- passkey が iCloud で同期されることを前提にする

## 関連

- [DESIGN-ja.md](../DESIGN-ja.md) — 親文書
- [DR-0006](../decisions/DR-0006-approval-url-and-exchange.md) — 承認 URL と交換
- [DR-0011](../decisions/DR-0011-user-keychain-signed-records.md) — 登録と passkey の置き場
- [exchange-format](./exchange-format.md) — assertion と credential の形、サイズ上限
