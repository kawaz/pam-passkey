---
title: send_command に URL だけでなく要求の要約も渡す
status: wip
category: task
created: 2026-11-09T12:55:19+09:00
last_read:
open_entered: 2026-11-09T12:55:19+09:00
wip_entered: 2026-11-09T15:43:10+09:00
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

# send_command に URL だけでなく要求の要約も渡す

## 概要

通知の本文に argv や起動元 (user@host、呼び出しプロセス、祖先の代表) を出せるようにする。今は stdin に承認 URL 1 行だけなので、通知は「〜から認可要求」止まり。

## 方式 (DR-0008 の変更。統括が決定 2026-11-09)

渡し方は環境変数の 1 本に決める (stdin の後続行は読まないスクリプトが多い。stdin は今までどおり URL 1 行だけで、既存の send_command を壊さない)。

| 環境変数 | 中身 | approve | register |
|---|---|---|---|
| `PAM_PASSKEY_URL` | stdin と同じ URL | ✓ | ✓ |
| `PAM_PASSKEY_KIND` | `approve` / `register` | ✓ | ✓ |
| `PAM_PASSKEY_USER` | `PAM_USER` (register では自分) | ✓ | ✓ |
| `PAM_PASSKEY_HOST` | Mac のホスト名 (request の `details.host` と同じ値) | ✓ | ✓ |
| `PAM_PASSKEY_COMMAND` | 呼び出し元の argv を sh の引用で 1 行に連結した表示用文字列 (空白・引用符・制御文字を含む要素だけ単一引用符で囲む) | ✓ | |
| `PAM_PASSKEY_DETAILS` | request の `details` オブジェクトを **ストアに PUT したものと同じ JSON** (1 行) | ✓ | |

- `details` を丸ごと渡すのは、通知用に並行スキーマを作らないため (exchange-format の `details` が唯一の定義)。secret を足さない。env は `details` に無いので載らない
- 子の環境は DR-0008 の許可リスト + 上の変数。`child.rs` の `SHELL_ENV_ALLOWED` の仕組みに「helper が明示的に足す変数」を乗せる形 (allowlist を広げるのではない)
- `add` (register) 側も同じ経路で `URL` / `KIND` / `USER` / `HOST` を渡す。`deliver` と helper の `send` で env を組む処理を 1 か所にする (置き場は `child.rs` の shell 起動に寄せるのが自然。新 module を作るなら責務名で)
- サイズ: `details` は request の 64 KiB 上限に収まるので環境変数で問題ない (ARG_MAX の範囲)
- 通知経路は信頼境界の内側 (DR-0008) なので、argv を渡しても URL から読めるもの以上は漏れない。将来の要求詳細の暗号化 (`docs/issue/2026-11-09-encrypt-request-envelope.md`) でもこの経路は平文のままでよい (提言の前提どおり)

## 触ってよい範囲 / 触らない範囲

- 触ってよい: `crates/pam-passkey/src/{auth,add,child}.rs` とそのテスト、`docs/decisions/DR-0008-pluggable-send-command.md`、`docs/design/helper-protocol.md`、`docs/design/exchange-format.md`、`docs/MANUAL-ja.md` と `docs/MANUAL.md` (同じ commit で両方)、`docs/DESIGN-ja.md` / `docs/DESIGN.md` の send_command の 1 文 (必要なら。他セッションの未コミット差分があるので、その行以外に触れない)
- 触らない: `crates/protocol/src/dialog.rs`、`crates/pam_passkey/src/lib.rs`、`crates/pam-passkey/src/main.rs`、`docs/decisions/DR-0004-*`、`artifacts/` (別 worker が編集中)
- keychain / LAContext / sudo を触るテスト・コマンドは書かない・実行しない (ダイアログが出る)

## 進め方の規約

- Bash は 1 呼び出し 1 コマンド (`&&` / `;` で繋がない)。classifier に止められたら、そのコマンド 1 行を統括に SendMessage。SendMessage の拒否では止まらない。中間報告は送らない (送るのは止められたコマンド / DR に反する点 / 完了報告)
- 設計で決まっていない点は仮置きして完了報告に列挙 (DR に反することだけ止める)
- commit はパス指定 (`jj commit -m "<msg>" <files...>`)。push しない
- 完了報告: `jj log -r 'ancestors(@, 3)'` と `jj status` の実出力、変更ファイル一覧、`cargo test --workspace` の実出力 (件数)、仮置きの一覧

## 受け入れ条件

- [ ] DR-0008 と helper-protocol / exchange-format / MANUAL (ja・en) の該当を更新 (表は MANUAL に、取り決めは DR-0008 に)
- [ ] 既存の「URL 1 行だけ読む」スクリプトがそのまま動く (stdin は変えない)
- [ ] `PAM_PASSKEY_DETAILS` がストアに PUT した request の `details` とバイト一致するテスト
- [ ] `PAM_PASSKEY_COMMAND` の引用のテスト (空白・単一引用符・空要素)
- [ ] MANUAL の Bark / ntfy の例スクリプトが本文に `$PAM_PASSKEY_USER@$PAM_PASSKEY_HOST` と `$PAM_PASSKEY_COMMAND` を出す
- [ ] `cargo test --workspace` (ignored を除く) が通る
