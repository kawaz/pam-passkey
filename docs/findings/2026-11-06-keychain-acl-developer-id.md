# login keychain の項目の ACL を Developer ID 署名の `pam-passkey` に絞った時の挙動

- Date: 2026-11-06
- 対象: `crates/pam-passkey` の Keychain 層 (`SecAccessCreate` + `SecACLSetContents` で trusted application を `SecTrustedApplicationCreateFromPath(自分の実行パス)` だけにする C shim)、検証用サブコマンド `_probe-login` (service `pam-passkey-probe`、固定値)
- 環境: macOS 26.5.2、`pam-passkey` は `Developer ID Application: ZunSystem Inc. (3QMEVK549R)` で `--options runtime` 署名。ダイアログの有無は kawaz が画面で確認

## 判明した事実

- Developer ID 署名の `pam-passkey` が作った項目の ACL は、信頼アプリの requirement が `identifier "pam-passkey" and anchor apple generic and ... certificate leaf[subject.OU] = "3QMEVK549R"` (designated requirement)、partition が `teamid:3QMEVK549R` になる。cdhash ではないので、同じ identifier と Team ID で再ビルド・再署名しても ACL は維持されると見込める (再ビルドでの実機確認は未実施)
- ad-hoc 署名のバイナリが作った項目では、信頼アプリの requirement は `cdhash H"..."`、partition は `cdhash:...` の列になる。ビルドごとに外れる
- Developer ID 署名の `pam-passkey` は自分が作った項目を無ダイアログで読める
- ACL 外のアプリ (`security` CLI、別 identifier の ad-hoc 署名コピー) が読むとパスワード付きの Keychain ダイアログになり、拒否すると `-128` (User canceled)。「常に許可」を押すとそのアプリが項目の ACL に追加される (ad-hoc なら cdhash で)
- ACL 外のアプリ (`security`) は `pam-passkey` が作った項目を無ダイアログで削除でき、同名の項目を作り直せる
- ACL 外のアプリが作った同名項目を `pam-passkey` が読むとダイアログになる (拒否で `-128`)。削除しようとすると拒否時に `-25244` (Invalid attempt to change the owner of this item)

## 実用的な示唆

- DR-0011 の「Keychain の項目の読み書きを `pam-passkey` バイナリに限定する」は、読み出しについて成立する。Developer ID 署名が前提で、ad-hoc 署名ではビルドごとに外れる
- 削除と同名での作り直しは ACL では止まらない。同 uid のプロセスが `users/<user>` を消す・差し替えると、helper は項目を読めず (非対話なのでダイアログは出せない) remote が使えなくなりパスワードに落ちる。昇格にはならない (DR-0011 の前提どおり)
- 「常に許可」を押すと ACL が広がるので、helper の読み出しは常に非対話 (ダイアログを出さない) にし、利用者にダイアログを見せない

## 検証の詳細

| # | 実行者 | 操作 | 結果 |
|---|---|---|---|
| 1 | Developer ID 署名の `pam-passkey` | 自分が作った項目を `read` | 値が返る、無ダイアログ |
| 2 | `security find-generic-password -w` | 同じ項目を読む | パスワード付きダイアログ、拒否で読めない |
| 3 | 別 identifier の ad-hoc 署名コピー | `read` | ダイアログ、拒否で `-128` |
| 4a | `security delete-generic-password` | `pam-passkey` が作った項目を削除 | 無ダイアログで削除成功 |
| 4b | `security add-generic-password` → `pam-passkey` | 同名項目を作成 → `pam-passkey` で `read` | ダイアログ、拒否で `-128` |
| 4c | `pam-passkey` | `security` が作った項目を `delete` | ダイアログ、拒否で `-25244` |

## 未観測

- 同じ identifier と Team ID で再ビルドしたバイナリからの読み出し (ACL の維持)
- 同じ Team ID の別 identifier のバイナリからの読み出し
- System Keychain の項目 (root で作成) に対する同じ観測
- sudo 内の PAM → root の helper → PAM_USER に降格した子、の経路での login keychain の読み出し (GUI / ロック中 / ssh / ファストユーザスイッチ)
