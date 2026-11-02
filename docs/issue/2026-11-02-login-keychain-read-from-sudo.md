---
title: sudo 内 helper から呼び出しユーザの login keychain を読めるかの検証 (DR-0011 前提)
status: open
category: task
created: 2026-11-02T22:18:47+09:00
last_read:
open_entered: 2026-11-02T22:18:47+09:00
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

# sudo 内 helper から呼び出しユーザの login keychain を読めるかの検証 (DR-0011 前提)

## 概要

DR-0011 の前提「sudo 内の helper が呼び出しユーザに降格した子プロセスから、そのユーザの login keychain の項目を無ダイアログで読める」は未検証。PoC (poc/keychain) は System Keychain しか見ていない。

確認する:

- (1) sudo の PAM から spawn した子 (setuid で呼び出しユーザ、exec 後) が login keychain の generic password を読めるか、ダイアログが出ないか
- (2) 画面ロック中・login keychain がロックされた状態 (`security lock-keychain`) での挙動
- (3) ssh ログイン (GUI セッション無し) からの sudo での挙動

## 受け入れ条件

- [ ] 上記 (1)〜(3) の結果を docs/findings に追記する
- [ ] 読めない条件があれば DR-0011 の Consequences に fallback (remote 承認無効 → パスワードへ) を書く
