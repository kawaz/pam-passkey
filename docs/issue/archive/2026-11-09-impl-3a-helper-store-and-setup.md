---
title: 実装 ③a helper のストア連携 (presign / request / assertion 検証 / result) と setup
status: resolved
category: task
created: 2026-11-09T02:43:37+09:00
last_read:
open_entered: 2026-11-09T02:43:37+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-11-09T03:22:24+09:00
discard_reason:
pending_reason:
close_reason: ["implemented","finding/store-minio"]
blocked_by:
origin: 自リポ TODO
---

# 実装 ③a helper のストア連携 (presign / request / assertion 検証 / result) と setup

## 概要

helper の `_auth` を、登録済み passkey がある場合に remote 承認を一周できる形にする (ストアへの request PUT → 承認 URL を `send_command` / `url` イベントで届ける → assertion を poll → WebAuthn 検証 → result PUT → DELETE)。あわせて `setup` を実装し、ストア設定・署名鍵・ページ URL を System Keychain に置けるようにする。承認ページ本体と `add` は実装 ③b。

## 背景

読むもの: docs/DESIGN-ja.md、DR-0005 / DR-0006 / DR-0008 / DR-0010 / DR-0011、docs/design/helper-protocol.md、docs/design/exchange-format.md、docs/design/webauthn-verification.md、現在の crates/ (pam-passkey の auth.rs / child.rs / keychain.rs、protocol)。

作るもの (`crates/pam-passkey`、必要なら `crates/protocol`):

- S3 互換クライアント
  - SigV4 の presign (GET / PUT、期限 = request の `expires`)、PUT / GET / DELETE
  - `put_once` が true なら presigned PUT の署名ヘッダに `If-None-Match: *` を含める
  - endpoint / bucket / region / prefix / access key / secret / put_once は System Keychain の `store` (JSON) から読む
  - crate は `aws-sdk-s3` か `rusty-s3` のような軽いもの (選定理由を報告に 1 行)
- `_auth` の remote 経路
  - `users/<PAM_USER>` の JWS 行を System Keychain の公開鍵 (Ed25519) で検証し、有効な credential の集合を作る (0 件なら `unavailable no-credentials`)
  - request JSON (exchange-format: `kind: approve`、details、nonce = 要求 ID、expires、assertion_put_url、result_get_url、allow_credentials) を組み立て、PUT したバイト列を保持
  - 承認 URL `<page_url>#<presigned GET>` を `send_command` (System Keychain。`/bin/sh -c`、PAM_USER に降格、環境は DR-0008 の許可リスト、cwd は HOME、stdin に URL) に渡す。未設定なら `url` イベントで PAM に返す
  - assertion を 1 秒間隔で poll (期限まで)。最初に取得したオブジェクトで判定を確定
  - webauthn-verification の全項目 (type、challenge = PUT したバイト列の SHA-256、origin 完全一致、crossOrigin / topOrigin、rpIdHash、UP / UV、credential id が集合に含まれる、ES256 署名、サイズ上限) → pass / fail
  - result (`pass` / `fail` の文字列) を PUT し、`result` イベントを返し、request と assertion を DELETE
- PAM からのコマンド
  - `finish` → result `pass` を PUT、DELETE、終了
  - stdin close → result `fail` を PUT、DELETE、終了
  - `open` / `reactivate` は既存
- `setup [--module <path>] [page_url]` (DR-0010 どおり)
  - root でなければ入力 (対話: page_url / endpoint / bucket / region / prefix / access key / secret / send_command。非対話: stdin の JSON 1 行) を集める
  - ストアの疎通 (PUT → GET → `If-None-Match` 付き 2 回目 PUT が 412 か → DELETE) で `put_once` を判定
  - CORS (`AllowedOrigins` = page_url の origin、`AllowedMethods` GET / PUT、`AllowedHeaders` に `If-None-Match` と `Content-Type`) と lifecycle (1 日で期限切れ) を設定
  - 自分の置き場の所有権を検査してから `sudo <self> setup --stdin` で書き込みだけ root で行う
  - 署名鍵 (Ed25519、JWK) は無ければ生成、あれば「既存の登録は全て無効になる」と出して y/N (N なら鍵を維持して設定だけ更新。`regenerate_key`)
  - 全項目の ACL は `pam-passkey` バイナリに絞る (既存の Keychain 層)
- テスト
  - (1) MinIO (`brew install minio` 済みでなければ入れてよい。`mktemp -d` の下にデータを置き、テスト内で起動・停止) を使った presign / PUT / GET / DELETE / `If-None-Match` の実機テスト
  - (2) ページ無しで一周させるテスト用の署名器 (P-256 の鍵で WebAuthn の clientDataJSON / authenticatorData / signature を組み立てる。テストコードのみ) で、`_auth` が pass / fail / 改ざん各種 (webauthn-verification の各条件を 1 つだけ破る) を正しく判定することを確認
  - (3) `setup` の非対話経路を MinIO 相手に通す (Keychain 書き込みは root が要るので、ユーザ権限で動く部分まで)

進め方の規約:

- Bash は 1 呼び出し 1 コマンド (`&&` / `;` で繋がない)。classifier に止められたら、そのコマンド 1 行を統括に SendMessage して結果を待つ。SendMessage 自体が止められても作業は止めない
- 中間報告は送らない。送るのは (a) 止められたコマンド、(b) sudo が要る手順の一覧、(c) DR に反する点・設計で決まっていない点、(d) 完了報告
- 新 crate の追加は可 (報告に選定理由)。DR に無い振る舞いを足さない

## 受け入れ条件

- [ ] `cargo build --release && cargo test --workspace` と `just build` が通る。MinIO が無い環境ではストアのテストは skip でなく「MinIO が要る」と明示して fail させない (`#[ignore]` + 理由)
- [ ] 改ざんテストベクタが webauthn-verification の各条件に 1 つずつある
- [ ] commit はパス指定、push しない。findings は統括が書く (観測は完了報告に表で)
