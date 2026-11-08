# PAM モジュール本体 (Touch ID と helper の並走) の実機観測

- Date: 2026-11-09
- 対象: `crates/pam_passkey` (DR-0012 の状態遷移を実装した本番の形) と `crates/pam-passkey` の `_auth` (ストア連携前。登録 0 件なので常に `unavailable no-credentials`)、`_probe-open`、`_probe-dialog`
- 環境: macOS 26.5.2、`/etc/pam.d/sudo_local` を `auth sufficient /usr/local/lib/pam/pam_passkey.so` の 1 行だけ (pam_tid はコメントアウト) にして観測。install 先は root 所有・Developer ID 署名

## 判明した事実

- Touch ID ダイアログは pam_tid より表示も反応も速い。ダイアログは `localizedReason` に `sudo -k true` を出し、ボタンは「キャンセル」「詳細を確認」
- ダイアログの本文は OS が「<呼び出したプロセス名> で次の操作を実行しようとしています: <localizedReason>」の形に組む。前置きと後置き (「許可するには Touch ID を使用するか…」) は変えられない。`localizedReason` 内の改行は効き、ダイアログは横幅固定 (約 34 半角 / 22 全角で折り返し) で縦に伸びる
- 登録 0 件のとき: Touch ID 成功 → パスワード無しで exit 0 / キャンセル → パスワード / 「詳細を確認」→ ダイアログが閉じてパスワード (remote が使えないので DR-0012 の該当行どおり) / 90 秒放置 → ダイアログが閉じてパスワード / ssh 経由 → ダイアログ無しでパスワード
- sudo が SIGINT を受けてもモジュールの待ちは起きない。待ちの間だけ SIGINT ハンドラを入れて自己パイプで起こすようにすると、Ctrl-C 1 回目でダイアログが閉じてパスワードへ、2 回目で sudo が中断する
- 待ちの最中に別の tty で sudo すると、2 つ目のダイアログが独立に出る。座標は同じで重なる
- `_probe-open` (root → PAM_USER に永久降格した子が `LSOpenCFURLRef` 相当で開く) で既定ブラウザが URL を開いて前面に出た。環境変数を空にして起動しても LaunchServices は動く
- helper の `_auth` は、期限切れの入力を拒否し、PAM_USER が nobody (uid 4294967294) でも降格した子として動いて `unavailable no-credentials` を返す (uid / gid を i32 に収める変換は失敗するので、`getgrouplist` にはビット変換で渡す)
- プロセスの祖先チェーンで ad-hoc / platform / Developer ID の 3 種の署名 ID・Team ID・署名者名が取れた

## 実用的な示唆

- DR-0012 の状態遷移は登録 0 件の範囲で実機と一致する。remote が走る行は実装 ③ (ストア連携) の後に観測する
- `localizedReason` は `"\n\n" + コマンド` にして OS の前置きと段落を分ける
- 同時に走る複数の認証のダイアログは重なる。位置の制御は API に無い (DR-0009 の対象外)

## 検証の詳細

| 操作 | 結果 | DR-0012 の行 |
|---|---|---|
| Touch ID で通す | パスワード無し、exit 0 | remote 不可 → Touch ID 成功で `PAM_SUCCESS` |
| キャンセル | パスワード要求 | キャンセル → `PAM_AUTH_ERR` |
| 「詳細を確認」(登録 0 件) | ダイアログが閉じてパスワード | remote 不可時の「詳細を確認」→ `PAM_AUTH_ERR` |
| 90 秒放置 | ダイアログが閉じてパスワード | 期限切れ → `PAM_AUTH_ERR` |
| ssh 経由 | ダイアログ無しでパスワード | GUI セッション無し + remote 不可 → `PAM_IGNORE` |
| Ctrl-C (修正前) | 効かない | 期待と不一致 (修正) |
| Ctrl-C (修正後) | 1 回目でダイアログが閉じてパスワード、2 回目で中断 | Ctrl-C → キャンセルと同じ |
| `_probe-open` | ブラウザが開いて前面 | DR-0004 の open |
| `_probe-dialog $'sudo\n-k true'` | 本文が 2 行で表示 | 改行が効く |

## 未観測

- remote が走る経路 (登録あり、ストアあり) の各行。実装 ③ 以降
- 「詳細を確認」後にダイアログを出し直した時の前面の挙動とタッチの反応 (remote が使える時だけ到達する)
- `LAErrorSystemCancel` (-4) になる条件 (tty 無しの sudo で観測済みだが、モジュールは Touch ID の失敗として扱う)
