---
title: 実装 ③b 承認 / 登録ページ (pam-passkey.github.io) と add / list / del、実機の一周
status: resolved
category: task
created: 2026-11-09T03:23:04+09:00
last_read:
open_entered: 2026-11-09T03:23:04+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-11-09T12:50:55+09:00
discard_reason:
pending_reason:
close_reason: ["implemented","finding/2026-11-09-end-to-end"]
blocked_by:
origin: 自リポ TODO
---

# 実装 ③b 承認 / 登録ページ (pam-passkey.github.io) と add / list / del、実機の一周

## 概要

承認ページと登録ページ (1 ファイル) を GitHub Pages のリポ `pam-passkey/pam-passkey.github.io` に実装し、`add` / `list` / `del` を実装して、iPhone (または Mac のブラウザ) の passkey で sudo を一周できる状態にする。

## 読むもの

docs/DESIGN-ja.md、DR-0004 / DR-0006 / DR-0010 / DR-0011、docs/design/exchange-format.md (JWS の形式、store のキー、`put_once` と `If-None-Match`)、docs/design/webauthn-verification.md、docs/design/helper-protocol.md、docs/findings/2026-11-09-store-minio.md、crates/pam-passkey/src/{auth,records,webauthn,store,setup,keychain,child}.rs (③a の実装。`sign_record` / `parse_signing_jwk` / `EcPublicJwk::from_key` は add 用に置いてある)。

## 作るもの

### ページ (リポ `pam-passkey/pam-passkey.github.io`、main ブランチ、GitHub Pages で `https://pam-passkey.github.io/`)

- clone 先は `~/.local/share/repos/github.com/pam-passkey/pam-passkey.github.io/main` (無ければ `gh repo clone`。jj は使わず git でよい。push は統括が行う)
- `index.html` 1 ファイル。外部スクリプト・外部 CSS を読まない。`<meta http-equiv="Content-Security-Policy">` で `default-src 'none'; script-src 'sha256-...' (inline を hash で許可) ; connect-src <任意の https>` 相当 (ストアの endpoint は利用者ごとに違うので connect-src は `https:`)。フレーム埋め込みは WebAuthn 側の `crossOrigin` / `topOrigin` 検証で弾くので CSP では扱わない
- 動作: `location.hash` の presigned GET URL を fetch → バイト列を保持 → JSON を parse → `kind` で画面を切替
  - `approve`
    - details (host / user / caller_uid / tty / time / argv / processes の祖先チェーン。DESIGN「承認画面に見せるもの」の形。制御文字と bidi はエスケープ、長い値は省略を明示) を表示
    - `result_get_url` を低頻度 (3 秒) で poll (pass / fail が来たら表示)
    - 「承認」ボタンで `navigator.credentials.get` (`challenge` = 取得したバイト列の SHA-256、`rpId` = location.hostname、`allowCredentials` = request の `allow_credentials`、`userVerification: required`)
    - assertion (exchange-format の形、base64url) を `assertion_put_url` に PUT (presigned URL の `X-Amz-SignedHeaders` に `if-none-match` があれば `If-None-Match: *` を付ける)
    - result を高頻度 (1 秒) で poll、PUT から 10 秒か `expires` の早い方で打ち切って「結果を確認できなかった」
    - 「拒否」ボタンは署名なしの内容 (`{"rejected":true}`) を同じ URL に PUT
  - `register`
    - `user_name` / `rp_id` を表示
    - 「登録」で `navigator.credentials.create` (`challenge` = バイト列の SHA-256、`rp.id` = rp_id、`user.id` = `user_id`、`user.name` = `user_name`、`pubKeyCredParams` ES256 のみ、`attestation: "none"`、`authenticatorSelection.residentKey: "required"`、`userVerification: "required"`)
    - credential (exchange-format の形) を `credential_put_url` に PUT
    - 「登録データを送りました。Mac 側の add が続きを行います」
- 文言は日本語と英語の 2 系統を `navigator.language` で切替 (JS 内の辞書)。見た目は素朴でよいが、承認ボタンを押す前に argv と祖先が読める配置にする
- GitHub Pages の設定 (Settings → Pages → main / root) は gh API で行う (`gh api -X POST repos/pam-passkey/pam-passkey.github.io/pages -f build_type=legacy -f source[branch]=main -f source[path]=/`)。失敗したら統括に報告

### CLI (`crates/pam-passkey`)

- `add [label]`: DR-0011 の手順
  1. `LAContext` の `deviceOwnerAuthentication` で本人確認 (PAM_USER = 自分。`pam_passkey` crate の touch_id を使い回せるなら protocol か別 crate に移してよい)
  2. 登録ペイロード (exchange-format: `kind: register`、`rp_id`、`user_name`、`user_id` 乱数 16 バイト、`expires` 90 秒、`credential_put_url`) を PUT し、登録 URL `<page_url>#<presigned GET>` を `send_command` に渡すか tty に表示
  3. credential を poll
  4. webauthn-verification の登録の受理条件で検証 (type create、challenge、origin、crossOrigin / topOrigin、rpIdHash、UP / UV / AT、COSE alg ES256、credential id 長、期限、1 回限り)
  5. 同じプロセス内で署名鍵 (System Keychain、ACL で自分だけ) で JWS を作り、login keychain の `users/<自分>` に 1 行追記 (項目が無ければ作る。ACL は自分だけ)
  6. 登録ペイロードと credential を DELETE
  - label の既定は登録日時
- `list`: `users/<自分>` の各行の label / credential id / 登録日を出す (JWS 検証はしない)
- `del <label|id>`: id 優先、label が複数一致ならエラーで候補を出す
- テスト: 登録の受理条件を 1 つだけ破った credential を拒否するテストベクタ (③a のテスト用署名器を拡張)、MinIO 相手の add の一周 (ページ無しで credential をテストコードが PUT)

### 実機の一周 (kawaz の手元。統括が permit で回す)

1. ページを push して GitHub Pages が配信されるのを確認 (`curl -I https://pam-passkey.github.io/`)
2. `just install`、`pam-passkey setup` (ストアは kawaz が用意。R2 か MinIO。MinIO なら iPhone から到達できる必要があるので、まずは Mac のブラウザで一周してよい)
3. `pam-passkey add` → ブラウザで登録ページ → `list` に出る
4. sudo_local を `pam_passkey.so` だけにして `sudo -k true` → 「詳細を確認」→ 承認ページで passkey → sudo が通る。iPhone からも同じ URL で通る (通知は tty の URL を手で開く)
5. 観測: 承認 / 拒否 / 期限切れ / Touch ID 先勝ちでページが pass に変わる / 「詳細を確認」後にダイアログが出し直されて Touch ID でも通る (前面の挙動)

## 背景

③a (helper の store 連携と setup) の続き。remote 承認と登録の両端 (ページ側と Mac 側の add) を揃えて sudo を一周させる。

## 進め方の規約

- Bash は 1 呼び出し 1 コマンド。classifier に止められたら、そのコマンド 1 行を統括に SendMessage。SendMessage の拒否では止まらない。中間報告は送らない (送るのは止められたコマンド / sudo が要る手順 / DR に反する点 / 完了報告)
- 設計で決まっていない点は仮置きして完了報告に列挙 (DR に反することだけ止める)

## 受け入れ条件

- [ ] ページが 1 ファイルで、外部リソース無し、CSP あり
- [ ] `cargo test --workspace` (MinIO の ignored テスト含む) が通る
- [ ] 実機の一周 5 の観測結果 (統括が findings に記録)
- [ ] commit はパス指定、push しない (ページのリポも統括が push)
