---
title: send_command に URL だけでなく要求の要約も渡す
status: open
category: task
created: 2026-11-09T12:55:19+09:00
last_read:
open_entered: 2026-11-09T12:55:19+09:00
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

# send_command に URL だけでなく要求の要約も渡す

## 概要

通知の本文に argv や起動元 (user@host、呼び出しプロセス、祖先の代表) を出せるようにする。今は stdin に承認 URL 1 行だけなので、通知は「〜から認可要求」止まり。

## 方式 (DR-0008 の変更)

- stdin の 1 行目は今までどおり URL (既存の send_command を壊さない)
- 2 行目以降に JSON 1 行で要約: `{"kind":"approve"|"register","user":...,"host":...,"argv":[...],"caller":{"path":...,"signing_id":...},"expires":...}`。secret を含めない。env は含めない
- 環境変数でも同じ値を渡す (`PAM_PASSKEY_USER` / `_HOST` / `_ARGV` 等) と、シェルスクリプトから使いやすい。どちらか 1 つに決める (推し: 環境変数。stdin の後続行は読まないスクリプトが多い)
- MANUAL の send_command の節に例 (Bark / ntfy) を載せる

## 受け入れ条件

- [ ] DR-0008 と helper-protocol / exchange-format の該当を更新
- [ ] 既存の「URL 1 行だけ読む」スクリプトがそのまま動く
- [ ] Bark の例スクリプトで本文に argv と user@host が出る
