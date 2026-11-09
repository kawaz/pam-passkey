---
title: 期限切れ時の helper が poll の HTTP timeout を Error ログに出す
status: open
category: task
created: 2026-11-09T22:44:30+09:00
last_read:
open_entered: 2026-11-09T22:44:30+09:00
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

# 期限切れ時の helper が poll の HTTP timeout を Error ログに出す

## 概要

期限切れ時の helper が poll の HTTP timeout を Error ログに出す (ノイズ)。実機 2026-11-09 22:42 のログ: `polling for the assertion: store request failed: timeout: global` が E レベルで出た直後に `ended Expired`。期限 (90 秒) と HTTP の timeout が同時に来ているだけで異常ではない。

## 背景

直し方の候補は 2 つ。

- poll の HTTP timeout を残り時間に合わせる (期限を超えて待たない)
- 期限到達後の timeout は Error にしない

小粒。

## 受け入れ条件

- [ ] 期限切れだけの一周で E レベルのログが出ない
