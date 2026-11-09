---
title: 要求詳細を要求ごとの鍵で AEAD 暗号化し、鍵を承認 URL の fragment で運ぶ
status: open
category: task
created: 2026-11-09T11:27:03+09:00
last_read:
open_entered:
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

# 要求詳細を要求ごとの鍵で AEAD 暗号化し、鍵を承認 URL の fragment で運ぶ

## 目的

argv に紛れる秘密 (`--token=…` 等) や、将来 env の許可リストを載せた場合に、ストア側 (運営者、漏れた access key、バックアップ、バージョニング、複製) に平文を残さない。通知経路と URL を見た者には今までどおり読める (DR-0008 の前提のまま)。kawaz の提言 (2026-11-07) に基づく。

## 方式

- helper が要求ごとに 32 バイト鍵 K と 12 バイト IV を生成し、request JSON を AES-256-GCM で暗号化 (AAD は形式の版と kind)。ストアには封筒 (版、IV、暗号文) だけ PUT。K はメモリだけ
- 承認 URL は `<page_url>#r=<presigned GET URL>&k=<K の base64url>`
- ページは封筒を GET して K で復号。失敗したら何も表示せず署名もしない
- challenge は今どおり「取得したバイト列全体の SHA-256」(対象は封筒。AEAD なので表示内容と一対一)
- assertion / result は平文のまま。登録ペイロードも同じ封筒に揃える (ページの処理を 1 本に)
- `setup` でバケットのバージョニングが有効なら警告

## 条件

採用は決定済み (kawaz 2026-11-09)。着手は一周 (B の置き場変更 + 通知) が安定してから。DR-0006 の「暗号化しない」を置き換える新 DR を起こし、DESIGN / exchange-format / webauthn-verification / DR-0010 を更新。env を載せる判断をする時は許可リスト (提言 2) を併せて。

## 未決

- 封筒を JSON にするかバイナリ連結にするか
- バージョニング有効のバケットを拒否するか警告に留めるか
