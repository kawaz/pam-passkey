---
title: Keychain ACL を Developer ID 署名の helper に絞る設計 (DR-0011) の実機検証
status: resolved
category: task
created: 2026-11-02T22:07:30+09:00
last_read: 2026-11-04T12:32:27+09:00
open_entered: 2026-11-02T22:07:30+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-11-09T01:47:32+09:00
discard_reason:
pending_reason:
close_reason: ["finding/2026-11-06-keychain-acl-developer-id","done:実機観測済み。同 Team ID の別 identifier / 再ビルド後 / System Keychain 側は未観測で実装中に拾う"]
blocked_by:
origin: 自リポ TODO
---

# Keychain ACL を Developer ID 署名の helper に絞る設計 (DR-0011) の実機検証

## 概要

DR-0011 は、Keychain の全項目の読み書きを pam-passkey バイナリの ACL に限定する。対象は次の 2 系統。

- System Keychain の全項目 (page_url / store / send_command / 署名鍵 / 公開鍵)
- login keychain の `users/<PAM_USER>` 項目

PoC は全アプリ可の ACL しか確認していない (findings/2026-11-02-keychain-poc.md の未観測)。ACL 限定の挙動は未検証。

## 背景

実装初期に確認する。SecAccessCreate の trustedlist に署名済み pam-passkey バイナリの SecTrustedApplication を渡して上記の項目を作り、以下を実機で観測して findings に追記する。

## 受け入れ条件

- [ ] (1) pam-passkey バイナリからは無ダイアログで読める
- [ ] (2) 別のプロセス (security CLI、別 binary) からは拒否かダイアログになる
- [ ] (3) ad-hoc 署名で build し直すと ACL が外れる
- [ ] (4) ユーザ権限の `add` (署名鍵の読み出し) と root の helper の両方で、無ダイアログで読める
- [ ] (5) 次のそれぞれから読めるか観測する
  - 同じ Team ID の別 identifier のバイナリ
  - 旧版 (別ハッシュ) のバイナリ
  - root の `security find-generic-password -w`
- [ ] (6) ACL 外のアプリが項目を削除・同名で作り直せるか観測する
- [ ] (7) 再ビルド・再署名 (Developer ID) 後も ACL が維持されるか観測する
- [ ] 観測結果を findings に追記した
