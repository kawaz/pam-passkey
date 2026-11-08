---
title: 実装 ② PAM モジュール本体 (LAContext + helper spawn + helper-protocol + DR-0012 の状態遷移)
status: open
category: task
created: 2026-11-09T01:48:54+09:00
last_read:
open_entered: 2026-11-09T01:48:54+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# 実装 ② PAM モジュール本体 (LAContext + helper spawn + helper-protocol + DR-0012 の状態遷移)

## 概要

`crates/pam_passkey` を検証専用から本番の形にする。Touch ID (LAContext) と remote (helper) を並走させ、DR-0012 の状態遷移と helper-protocol どおりに `PAM_SUCCESS` / `PAM_AUTH_ERR` / `PAM_IGNORE` を返す。helper 側 (`crates/pam-passkey`) はこの段では protocol を喋る骨格まで (ストア連携は実装 ③)。

## 背景

読むもの: docs/DESIGN-ja.md、DR-0002 / DR-0003 / DR-0004 / DR-0009 / DR-0012、docs/design/helper-protocol.md、docs/design/exchange-format.md、docs/findings/2026-11-02-pam-poc.md、docs/findings/2026-11-09-login-keychain-from-pam.md、poc/pam/src/ (LAContext の ObjC shim と祖先チェーン取得の C shim。流用してよい)、現在の crates/pam_passkey/src/lib.rs と crates/pam-passkey/src/main.rs、crates/protocol/src/lib.rs。

## 作るもの

### PAM モジュール (`crates/pam_passkey`)

- `pam_sm_authenticate`: 順序は DR-0012 の「seteuid の順序」どおり。
  1. PAM_USER を取り、uid / GUI セッションの有無 (`SessionGetInfo` 相当) を調べる
  2. プロセス情報 (呼び出し元の argv と launchd までの祖先チェーン: pid / uid / cwd / path / argv / 署名 ID / Team ID / 署名者名。exchange-format の `processes` の形) を集める
  3. 置き場検査 → helper を spawn → pid の署名検査 → stdin に起動時の入力 JSON (`user` / `caller_uid` / `id` / `expires` / `tty` / `details`) を 1 行書く
  4. GUI セッションがあり呼び出し元 euid が 0 なら PAM_USER の uid に seteuid して LAContext を別スレッドで評価、終わったら seteuid(0) (戻せなければ `PAM_AUTH_ERR`)。呼び出し元 euid が 0 でなく uid が PAM_USER と違えば Touch ID は使わない
  5. helper の stdout のイベント (`unavailable` / `url` / `result`) と LAContext の結果を 1 つのループで待ち、DR-0012 の表どおりに戻り値を決める
- `url` は `PAM_TEXT_INFO` で tty に出す
- Touch ID 成功なら `{"cmd":"finish","pass":true}` を送って待たずに `PAM_SUCCESS`
- キャンセル / 期限切れは stdin を close して `PAM_AUTH_ERR`
- 「詳細を確認」(-3) は新しい LAContext で出し直してから `{"cmd":"open"}`、続けて `{"cmd":"reactivate"}`
- 全ての待ちは `expires` (既定 90 秒) まで
- 要求 ID は 16 バイトの乱数 (base64url)、`expires` は RFC 3339 UTC
- `PAM_IGNORE` は Touch ID と remote が両方使えない時だけ。helper 無し / 署名検査不合格 / `unavailable` は「remote が使えない」
- ダイアログ本文は `localizedReason` に収まるよう中央省略
- モジュールはプロセスを落とさない (全て `catch_unwind` の内側、失敗は `PAM_AUTH_ERR` か `PAM_IGNORE`)

### helper (`crates/pam-passkey`)

- 内部サブコマンド `_auth` (PAM から spawn される): stdin 1 行目の入力を読み、`users/<PAM_USER>` を降格した子で読む。項目が無い / 読めない → `unavailable` (`no-credentials` / `keychain-locked`) を出して終了。この段では登録が無いので常にそこで終わってよいが、`open` / `finish` / `reactivate` / stdin close の受け口とイベントの型 (`crates/protocol`) は揃える。ストアへの PUT / poll / 検証は実装 ③
- `open` の実装: PAM_USER に降格した子で `LSOpenCFURLRef` 相当を呼ぶ (`/usr/bin/open` を exec しない)。URL はこの段ではダミーでよい

### 検証 (kawaz の手元で sudo。統括が permit で回す)

- `just install` → sudo_local 先頭に `auth sufficient /usr/local/lib/pam/pam_passkey.so` を足し `pam_tid` 行はコメントアウト
- 観測:
  - (a) Touch ID で `sudo true` が通る (パスワード無し)
  - (b) キャンセルでパスワードに落ちる
  - (c) 「詳細を確認」でダイアログが出し直され Touch ID で通る (ブラウザはダミー URL を開く)
  - (d) ssh 経由で remote 不可 → パスワード
  - (e) 登録 0 件なので remote は常に `unavailable` で Touch ID だけで動く
- 期待と違えば statetable の該当行と比較して報告

## 進め方の規約

- Bash は 1 呼び出し 1 コマンド (`&&` / `;` で繋がない)。classifier に止められたら、そのコマンド 1 行を統括に SendMessage して結果を待つ。SendMessage 自体が止められても作業は止めない
- 中間報告は送らない。送るのは (a) 止められたコマンド、(b) sudo が要る手順の一覧、(c) DR に反する点、(d) 完了報告
- findings は統括が書く (観測結果は表で完了報告に入れる)

## 受け入れ条件

- [ ] `cargo build --release && cargo test --workspace` と `just build` が通る
- [ ] 上記 (a)〜(e) の観測結果 (統括が findings に記録)
- [ ] sudo_local を `auth       sufficient     pam_tid.so` の 1 行に戻した
- [ ] commit はパス指定、push しない
