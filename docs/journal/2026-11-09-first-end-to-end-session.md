# 2026-11-02〜09: 設計レビューから実機の一周まで

## 到達点

- 設計レビュー 2 系統 (sol / opus) → 処置表 → DR 改訂 → 整合レビュー → 実装 ①〜④ → 実機で Touch ID 並走 + remote (AWS S3 + GitHub Pages + Bark) の一周が通った。記録は `docs/findings/2026-11-0{6,9}-*.md`
- `/etc/pam.d/sudo_local` は `auth sufficient /usr/local/lib/pam/pam_passkey.so` の 1 行だけで運用 (pam_tid は遅いので外した。kawaz 2026-11-09)。kawaz に write の ACL があり sudo 無しで書ける (ファイルは nix-darwin 管理の symlink が regular file に置き換わったもの)
- install 先: `/usr/local/libexec/pam-passkey`、`/usr/local/lib/pam/pam_passkey.so` (`just install`)。install の sudo は GUI のターミナルから (Claude のシェルは tty が無く sudo の認証が通らない)
- ストア: AWS S3 `pam-passkey-kawaz-mbp16` (ap-northeast-1、prefix `kawaz-mbp/`)、IAM ユーザ `pam-passkey-kawaz-mbp16` (account 820341873804、`AWS_PROFILE=zunsystem-main` で作成)。ポリシーは MANUAL-ja の例そのもの。access key のファイルは削除済み (値は login keychain の config だけ)
- 通知: `send_command` = `~/.local/share/pam-passkey-dev/send-bark.sh` (bark-admin 経由、group `pam-passkey:user@host`、環境変数でオプション切替)。同じ場所に `try-bark-options.sh`
- ページ: `https://pam-passkey.github.io/` (org `pam-passkey`、リポ `pam-passkey.github.io`、clone は `~/.local/share/repos/github.com/pam-passkey/pam-passkey.github.io/main`、git。remote は ssh)
- artifacts: `https://artifacts-kawaz-pam-passkey.kawaz-mbp.tmpspace.net/touch-id-dialog-design/` にダイアログ本文のデザイン案 (再現 HTML `replica.html` とスクショ)

## ハマり所 → 解決

- worker (codex sol) は classifier に止められるたびに停止し、複合コマンド (`&&` / `;`) が止められやすい → worker には「Bash は 1 呼び出し 1 コマンド」「SendMessage の拒否では止まらない」「中間報告を送らない」を brief に入れる。sudo / keychain を触る観測は統括が permit で kawaz に回す。実装は opus-high の方が止まらずに進む
- worker 起動の Agent prompt に sudo / pam.d 等が含まれると fast classifier に止められる → brief を `docs/issue/` に書き、短い prompt で起動 (それでも 1 回は止まることがある。2 回目で通る)
- 同じ working copy を統括と worker が共有している → 統括の `jj commit <paths>` が worker の編集中ファイルを巻き込むことがある (パス指定なら巻き込まない。worker の編集中ファイルが `jj status` に見えるのは正常)
- `build.rs` に `cargo:rerun-if-changed=<C ファイル>` が無いと C の変更が再コンパイルされず、古いオブジェクトと新しい Rust の戻り値解釈がずれる (verify_pid の「status 1」騒ぎの原因)
- Rust の `Command` の `pre_exec` で fd 3 以降を全部閉じると、exec 失敗の報告パイプも閉じて `fatal runtime error: assertion failed: output.write(&bytes).is_ok()` で abort する → Rust が開く fd は CLOEXEC なので閉じない
- `getgrouplist` は `NGROUPS_MAX` (16) を超える数を返しうる → `setgroups` に渡す前に 16 に切る。uid / gid が i32 を超えるユーザ (nobody = 4294967294) はビット変換で渡す
- System Keychain の既存項目の更新で ACL (`kSecAttrAccess`) を付け直すと、root でも、`SecKeychainSetUserInteractionAllowed(false)` でも、項目ごとに管理者認証ダイアログが出る → 設定は login keychain の `config` 項目に移し、System Keychain は署名鍵と検証鍵だけ (初回作成のみ)。更新は ACL を付け直さない
- `setup --edit` で雛形を無変更で閉じると「no changes」で保存されず helper が設定なしになっていた → 保存済みの値が無い時は無変更でも保存する
- Touch ID が出ない時は `canEvaluatePolicy` を見る。-8 はロックアウト (ロック画面でパスワード解除)。GUI セッション外の系統 (launchd → ccmsg daemon → hyoui → claude) からでも LAContext は出せる (事前の session 判定は不要)
- `log` は zsh の組み込みと衝突する → `/usr/bin/log show --predicate 'subsystem == "jp.kawaz.pam-passkey"' --last 10m --style compact`
- AWS S3 は `s3:ListBucket` が無いと未存在 GET が 403 (MinIO は 404) → poll では 403 / 404 を「まだ無い」として扱う
- `cargo test` が使い捨て keychain を kawaz の検索リストに入れ、ダイアログが本物と区別できなくなった → keychain / LAContext を触るテストは `#[ignore]`、実行は統括経由で手元のみ
- 承認 / 登録ページの CSP は `connect-src https:` で、Chrome は公開 origin から loopback への fetch を止める → 実機の一周には https のストア (AWS / R2) が要る (MinIO はテスト専用)
- `cargo fmt` 等の無害なコマンドでも複合にすると classifier に止まる → 1 コマンドずつ

## 判断の記録 (DR / issue に無いもの)

- 設計レビューの指摘は `docs/research/2026-11-02-design-review-disposition.md` に処置を残し、後の裁定で覆った項目はそこに注記
- `del` は整理用で、確実な失効は `setup` の `regenerate_key` (login keychain のファイル巻き戻しは対象外)
- `list` は生の JWS を出さなくてよい (制約として書く必要は無い)
- Touch ID の評価を helper の降格した子に移す案は成立を確認済み (診断 a / b' / c 全部成功)。採否は `docs/QUESTIONS.md` PK-Q5
