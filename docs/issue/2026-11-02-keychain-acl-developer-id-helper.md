---
title: Keychain ACL を Developer ID 署名の helper に絞る設計 (DR-0011) の実機検証
status: open
category: task
created: 2026-11-02T22:07:30+09:00
last_read:
open_entered: 2026-11-02T22:07:30+09:00
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

# Keychain ACL を Developer ID 署名の helper に絞る設計 (DR-0011) の実機検証

## 概要

秘密項目 (store のアクセスキー) の Keychain ACL を Developer ID 署名の helper に絞る設計 (DR-0011) は未検証。PoC は全アプリ可の ACL しか確認していない (findings/2026-11-02-keychain-poc.md の未観測)。

## 背景

実装初期に確認する。SecAccessCreate の trustedlist に署名済み helper の SecTrustedApplication を渡して項目を作り、以下 3 点を実機で観測して findings に追記する。

## 受け入れ条件

- [ ] (1) helper からは無ダイアログで読める
- [ ] (2) 別のプロセス (security CLI、別 binary) からは拒否かダイアログになる
- [ ] (3) ad-hoc 署名で build し直すと ACL が外れる
- [ ] 観測結果を findings に追記した
