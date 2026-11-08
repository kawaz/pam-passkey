# sudo 内の PAM から起動した helper の降格した子が PAM_USER の login keychain を読めるか

- Date: 2026-11-09
- 対象: `crates/pam_passkey` (検証専用の PAM モジュール。helper を spawn し、結果を `PAM_TEXT_INFO` で tty に出して常に `PAM_IGNORE`)、`crates/pam-passkey` の `_probe-auth` (root の helper) と `_read-probe-user-keys` (PAM_USER に永久降格した子)。項目は `_probe-login write` で作った検証用 (service `pam-passkey-probe`、ACL は `pam-passkey` バイナリのみ)
- 環境: macOS 26.5.2、`/etc/pam.d/sudo_local` の先頭に `auth sufficient /usr/local/lib/pam/pam_passkey.so` を一時追加、`/usr/local/libexec/pam-passkey` と `/usr/local/lib/pam/pam_passkey.so` は root 所有・Developer ID 署名

## 判明した事実

- GUI ログイン中の tty からの `sudo true` で、PAM → root の helper → `setgroups` / `setgid` / `setuid` で PAM_USER に永久降格した子、の経路で login keychain の項目を無ダイアログで読めた (`31 bytes`)
- `security lock-keychain` で login keychain をロックした直後でも同じ経路で読めた (ダイアログ無し)。ロックが securityd に効いていたかは未確認
- `ssh localhost` 経由 (GUI セッション無し) の `sudo true` では、降格した子の読み出しが `-25308` (`errSecInteractionNotAllowed`) で失敗し、helper は「使えない」を返した。sudo はパスワード認証へ進んだ
- spawn 直後の helper の pid に対する `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` (identifier と Team ID の requirement) は sudo の中 (euid 0、ruid はユーザ) から成功する。ad-hoc 署名のバイナリは `-67050` で弾かれる
- `pre_exec` で fd 3 以降を全部閉じると、Rust の `Command` が exec 失敗を親に報告する CLOEXEC パイプも閉じ、子が `fatal runtime error: assertion failed: output.write(&bytes).is_ok()` で abort する (exit code 無し)。Rust が開く fd は全て CLOEXEC なので、この close ループは不要
- `getgrouplist` の結果は `NGROUPS_MAX` (16) を超えうる。超えた配列を `setgroups` に渡すと失敗するので、16 に切る

## 実用的な示唆

- DR-0011 / DR-0012 の前提 (helper の降格した子が PAM_USER の login keychain を読む、unlock されていなければ remote は使えずパスワードへ) は成立する
- ssh 経由の sudo では remote 承認が使えない。GUI セッションが無い経路 (ssh / ログイン画面) は設計どおりパスワードに落ちる
- `build.rs` で C を compile する crate は `cargo:rerun-if-changed=<C ファイル>` を出す。無いと C の変更が反映されず、古いオブジェクトのまま link される

## 検証の詳細

| 条件 | helper の pid 署名検査 | 降格した子の読み出し | PAM の後続 |
|---|---|---|---|
| GUI ログイン中の tty | 成功 | 読めた (31 bytes、無ダイアログ) | `PAM_IGNORE` → pam_tid の Touch ID |
| `security lock-keychain` 直後 | 成功 | 読めた (31 bytes、無ダイアログ) | 同上 |
| `ssh -t localhost 'sudo true'` | 成功 | `-25308` (interaction not allowed) | パスワードが要求された |

## 未観測

- ファストユーザスイッチ中 (別ユーザが前面) の読み出し
- login keychain のパスワードがログインパスワードと不一致でロックされたままの状態
- `security lock-keychain` が実際にロックしていたか (直後の読み出しが通った理由)
- 画面ロック中 (スクリーンセーバ) の読み出し
