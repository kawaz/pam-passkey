# System Keychain の書き込み権限と、sudo 内 PAM からの読み出しの PoC

- Date: 2026-11-02
- 対象: [poc/keychain](../../poc/keychain/) (`kc-poc` CLI と `pam_kcpoc.so`、Rust + C shim)
- 環境: macOS 26.5.2 (25F84、本記録の作成時点のバージョン)、`security-framework` 3.7.0 / `security-framework-sys` 2.17.0

## 判明した事実

- ユーザ権限のプロセスから System Keychain (`/Library/Keychains/System.keychain`) への generic password の `SecItemAdd` は `-61` (wrPermErr) で失敗する
- `AuthorizationCreate` で `system.keychain.modify` の right を取得した後でも、同じ書き込みは `-61` で失敗する
- `security` CLI でユーザ権限から System Keychain に書き込もうとしても同じく書き込めない
- root (sudo) で実行すると同じ書き込みは成功する
- 読み出しの ACL を「全アプリ可」(`SecACLSetContents` に application list `NULL`、prompt selector `0`) にした項目は、ユーザ権限のプロセスからダイアログ無しで読める
- 同じ項目は、sudo プロセス内の PAM モジュール (`pam_kcpoc.so`) からもダイアログ無しで読める
- `security-framework` 3.7.0 で、System Keychain の open (`SecKeychain::open`)、`kSecMatchSearchList` を絞った search / delete ができる
- `security-framework` 3.7.0 の `ItemAddOptions` は `kSecAttrAccess` の指定に対応せず、`security-framework-sys` 2.17.0 にも `SecAccessCreate` / `SecACLSetContents` の binding が無い。ACL の設定は C shim (`SecAccessCreate` → `SecAccessCopyMatchingACLList(kSecACLAuthorizationDecrypt)` → `SecACLSetContents(acl, NULL, ..., 0)`) で行った。これらは deprecated で build 時に警告が出るが動作する

## 実用的な示唆 / ベストプラクティス

- securityd は System Keychain への書き込みを、Authorization right でなく呼び出し元の euid で判定していると解釈できる。ユーザ権限から書き込ませる設計は成立しないので、書き込みは `sudo pam-passkey setup` / `add` / `del` のように root で行う
- この性質は、ユーザ権限のプロセスが鍵を登録して自分の sudo を承認する経路を塞ぐ歯止めとして使える
- 秘密でない項目は「全アプリ可」の ACL にすれば、sudo 内 PAM からの読み出しで main executable (`/usr/bin/sudo`) の ACL 問題を踏まない

## 検証の詳細

### 書き込み

| 実行者 | 方法 | 結果 |
|---|---|---|
| ユーザ権限 | `SecItemAdd` (`kc-poc write`) | `-61` |
| ユーザ権限 | `system.keychain.modify` の right を取得してから `SecItemAdd` | `-61` |
| ユーザ権限 | `security add-generic-password … /Library/Keychains/System.keychain` | `SecKeychainItemCreateFromContent (/Library/Keychains/System.keychain): Write permissions error.` (= `-61`) |
| root (`sudo kc-poc write`) | 同じ `SecItemAdd` | 成功 (`written:` と表示。root でも `AuthorizationCreate` が Touch ID ダイアログを出すので、本実装では euid=0 の時は right を取らない) |

### 読み出し (「全アプリ可」ACL の項目)

| 実行者 | 方法 | 結果 |
|---|---|---|
| ユーザ権限 | `kc-poc read` | ダイアログ無しで読める |
| sudo プロセス内の PAM | `pam_kcpoc.so` | ダイアログ無しで読める |

### 未観測

- 秘密の項目について ACL を特定の署名 (Developer ID の helper) に絞った場合の読み出し
