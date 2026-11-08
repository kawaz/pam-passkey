---
title: sudo 内 helper から PAM_USER の login keychain を読めるかの検証 (DR-0011 / DR-0012 前提)
status: resolved
category: task
created: 2026-11-02T22:18:47+09:00
last_read: 2026-11-04T12:32:44+09:00
open_entered: 2026-11-02T22:18:47+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-11-09T01:47:28+09:00
discard_reason:
pending_reason:
close_reason: ["finding/2026-11-09-login-keychain-from-pam","done:GUI ログイン中は無ダイアログで読めた。ssh 経由は -25308 で remote 不可→パスワードへ。ファストユーザスイッチ中/keychain パスワード不一致/画面ロック中は未観測(実装中に拾う)"]
blocked_by:
origin: 自リポ TODO
---

# sudo 内 helper から PAM_USER の login keychain を読めるかの検証 (DR-0011 / DR-0012 前提)

## 概要

DR-0011 / DR-0012 の前提「PAM → root の helper → PAM_USER に永久降格した子 (setgroups / setgid / setuid) の 2 段構成で、降格した子が PAM_USER の login keychain の項目を無ダイアログで読める」は未検証。PoC (poc/keychain) は System Keychain しか見ていない。

確認する:

- (1) 上記 2 段構成の降格後の子 (exec 後) が PAM_USER の login keychain の generic password を読めるか、ダイアログが出ないか
- (2) 画面ロック中・login keychain がロックされた状態 (`security lock-keychain`) での挙動
- (3) ssh ログイン (GUI セッション無し) からの sudo での挙動
- (4) ファストユーザスイッチ中 (別ユーザが前面にいる状態) での挙動
- (5) login keychain のパスワードがログインパスワードと不一致でロックされたままの状態での挙動
- (6) ssh 由来の audit session から見た securityd の見え方 (降格した子が PAM_USER の securityd / keychain に到達できるか)

## 受け入れ条件

- [ ] 上記 (1)〜(6) の結果を docs/findings に追記する
- [ ] 読めない条件があれば DR-0011 の Consequences に fallback (remote 承認無効 → パスワードへ) を書く
