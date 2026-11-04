---
title: 実装 ① Keychain 層と login keychain の sudo 内読み出し (DR-0011 の前提検証を兼ねる)
status: open
category: task
created: 2026-11-04T12:26:46+09:00
last_read:
open_entered: 2026-11-04T12:26:46+09:00
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

# 実装 ① Keychain 層と login keychain の sudo 内読み出し (DR-0011 の前提検証を兼ねる)

## 概要

本体実装の第 1 段。Rust workspace を起こし、Keychain 層 (System Keychain / login keychain の generic password の読み書き、ACL を `pam-passkey` バイナリに絞る) を実装し、DR-0011 の未検証前提 2 件 (docs/issue の `login-keychain-read-from-sudo` と `keychain-acl-developer-id-helper`) を本物のコードで実機観測して findings に記録する。

## 読むもの

docs/DESIGN-ja.md、DR-0003 / DR-0011 / DR-0012、docs/design/helper-protocol.md、docs/findings/2026-11-02-keychain-poc.md、poc/keychain/ (C shim の `SecAccessCreate` / `SecACLSetContents` の使い方)、上記 issue 2 件。

## 作るもの

- リポ直下に Cargo workspace。crate は `crates/pam-passkey` (bin。CLI と helper) と `crates/pam_passkey` (cdylib。PAM モジュール) と `crates/protocol` (helper-protocol / exchange-format の型。serde)。PoC の構成 (Rust + C / ObjC shim、`security-framework` 3.x) を踏襲
- `crates/pam-passkey` に Keychain 層: System Keychain の項目 (`page_url` / `store` / `send_command` / 署名鍵 / 公開鍵) と login keychain の `users/<user>` 項目の read / write / delete。全項目の ACL は `SecTrustedApplicationCreateFromPath(自分の実行パス)` だけを trusted list にし、prompt selector は既定
- 内部サブコマンド `pam-passkey _read-user-keys <user>` (PAM_USER に永久降格した子として login keychain の項目を読んで stdout に出す) と、検証用の一時サブコマンド
- justfile に `build` (cargo build --release + `codesign -s 8397C1D2A3AAE1E47BE23855C0C9E83EA52BC1B1 --options runtime --timestamp --force`) と `install` (sudo で /usr/local/libexec/pam-passkey と /usr/local/lib/pam/pam_passkey.so へ root 所有で install) を足す
- `crates/pam_passkey` は今段では「helper を spawn して `_read-user-keys` の結果を PAM_TEXT_INFO に出す」だけの薄い版でよい (LAContext は次段)

## 実機観測 (docs/findings/2026-11-04-keychain-impl.md に表で記録)

1. ユーザ権限の `pam-passkey` (Developer ID 署名) が System Keychain の全項目と login keychain の項目を無ダイアログで読めるか
2. `security find-generic-password -w` (別バイナリ) で拒否かダイアログになるか
3. ad-hoc 署名で build し直すと ACL が外れるか / Developer ID で再 build (ハッシュが変わる) すると維持されるか
4. ACL 外のアプリが項目を削除・同名で作り直せるか
5. sudo 内 PAM → root helper → PAM_USER に降格した子、の経路で login keychain の項目を読めるか: GUI ログイン中の tty / `security lock-keychain` 後 / `ssh localhost` 経由 / ファストユーザスイッチ中 (できる範囲)
6. 子を降格せず root のまま読んだ場合 (比較)

## 環境

- `/etc/pam.d/sudo_local` は kawaz に write ACL があり sudo 不要で書ける。今は `auth       sufficient     pam_tid.so` の 1 行。検証中は `auth sufficient /usr/local/lib/pam/pam_passkey.so` を先頭に足し、終わったら 1 行に戻す
- `/usr/local/lib/pam/` の `pam_kcpoc.so` / `pam_poc.so` は前 PoC の残り。触らない
- worker の Bash には tty が無く、sudo の認証 (Touch ID / パスワード) は通らない。sudo が要る手順はコマンド列を揃えて統括経由で kawaz に手元で実行してもらい、出力を受け取る

## 受け入れ条件

- [ ] workspace と 3 crate が `cargo build --release` で通り、`just build` で署名まで通る
- [ ] 観測 1〜6 を findings に表で記録 (期待 vs 実態、エラーコード)
- [ ] 読めない条件があれば DR には手を入れず報告に書く (DR の修正は統括)
- [ ] `sudo_local` を 1 行に戻した
- [ ] commit はパス指定 (`target/` を含めない)、push しない
