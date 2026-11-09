# helper-protocol: PAM モジュールと helper の取り決め

## コンテキスト

[DESIGN-ja.md](../DESIGN-ja.md) の「アーキテクチャ」を補足する。`pam_passkey.so` が helper (`pam-passkey` バイナリの内部サブコマンド) を起動し、要求を渡し、結果を受け取るまでの取り決め。起動の手順と置き場は [DR-0003](../decisions/DR-0003-helper-outside-sudo.md)、受け取った結果を PAM の戻り値にどう結びつけるかは [DR-0012](../decisions/DR-0012-auth-state-transitions.md) が正本。

## 詳細

### 起動

- PAM は `pam-passkey` バイナリを絶対パスで起動し、argv[1] に内部サブコマンド名を置く。パスの決め方は [DR-0003](../decisions/DR-0003-helper-outside-sudo.md)
- 要求 ID は PAM が生成する乱数 (16 バイト、base64url)。helper がストアに置く request の `nonce` はこれと同じ値 ([exchange-format](./exchange-format.md))

### fd

| fd | 向き | 中身 |
|---|---|---|
| 0 | PAM → helper | 1 行目が起動時の入力、2 行目以降がコマンド。いずれも 1 行 1 つの JSON |
| 1 | helper → PAM | イベント。1 行 1 つの JSON |
| 2 | helper → ログ | helper のログ。PAM は読まない |

### 起動時の入力 (標準入力の 1 行目)

| キー | 中身 |
|---|---|
| `user` | `PAM_USER` |
| `caller_uid` | 呼び出し元の uid |
| `id` | 要求 ID |
| `expires` | 要求の期限 (RFC 3339 の UTC)。PAM が決める (既定は要求から 90 秒後)。helper はこれを request の `expires` と presigned URL の期限に使う |
| `tty` | 呼び出し元の tty のパス。無ければ `null` |
| `details` | PAM が呼び出し元のプロセス内で集めたプロセス情報 |

### helper から PAM へのイベント (標準出力)

| イベント | 意味 |
|---|---|
| `{"event":"unavailable","reason":"no-credentials"}`<br>`{"event":"unavailable","reason":"store-unreachable"}`<br>`{"event":"unavailable","reason":"keychain-locked"}` | remote が使えない (順に、`PAM_USER` の登録が 0 件 / ストアに届かないか `PAM_USER` の設定 (`config`) が無い / `PAM_USER` の login keychain が unlock されていない) |
| `{"event":"url","url":"..."}` | `send_command` が未設定の時に送る承認 URL。PAM が conversation の `PAM_TEXT_INFO` で tty に出す。helper は自分では表示しない |
| `{"event":"result","id":"<要求 ID>","pass":true}`<br>`{"event":"result","id":"<要求 ID>","pass":false}` | remote の結果 |

PAM は、起動時に渡した要求 ID を持つ `result` の `pass: true` 以外を成功と見なさない。

### PAM から helper へのコマンド (標準入力の 2 行目以降)

| コマンド | 意味と helper の動作 |
|---|---|
| `{"cmd":"open"}` | 「詳細を確認」が押された (PAM はダイアログを出し直してから送る)。helper は `PAM_USER` に降格した子で承認ページを開いてブラウザを activate し、PAM からの `reactivate` に応えてもう一度 activate する ([DR-0004](../decisions/DR-0004-fallback-button-as-details.md)) |
| `{"cmd":"reactivate"}` | `open` の後に常に送る (ダイアログの表示がブラウザより遅れた場合の保険)。helper は降格した子でブラウザをもう一度 activate する ([DR-0009](../decisions/DR-0009-foreground-control.md)) |
| `{"cmd":"notify_lockout"}` | Touch ID が lockout (`canEvaluatePolicy` が -8) で、`PAM_USER` の GUI セッションがある。helper は `PAM_USER` に降格した子で通知を出す ([DR-0012](../decisions/DR-0012-auth-state-transitions.md))。書き込めなくても PAM は remote の失敗とは見なさない |
| `{"cmd":"finish","pass":true}` | Touch ID が成功した。PAM は送った後、helper の終了を待たずに `PAM_SUCCESS` を返す。helper は result に `pass` を PUT し、request と assertion を DELETE して自分で終了する |
| 標準入力の close | キャンセル。helper は result に `fail` を PUT して終了する |

helper はコマンドを起動直後から受け取り、assertion の待ちに入ってから順に応える。`unavailable` を送った時は、その後も標準入力の close (または `finish`、期限) まで残り、`notify_lockout` だけに応える。

helper から応答が無ければ、PAM は期限 (`expires`) の後に終了シグナルを送る。

### `send_command` への受け渡し

`send_command` が設定されていれば、helper は request を PUT した後、`PAM_USER` に降格した子で起動し ([DR-0008](../decisions/DR-0008-pluggable-send-command.md))、承認 URL を標準入力に 1 行書いて閉じる。要約は環境変数で渡し、値は起動時の入力から取る (変数の一覧は [MANUAL](../MANUAL-ja.md))。

| 変数 | 起動時の入力のどこから |
|---|---|
| `PAM_PASSKEY_USER` / `PAM_PASSKEY_HOST` | `details.user` / `details.host` |
| `PAM_PASSKEY_COMMAND` | `details.argv` を表示用に引用して 1 行にしたもの |
| `PAM_PASSKEY_DETAILS` | `details`。request に入れて PUT したのと同じバイト列 |

## 制約 / 前提

- 終了経路ごとに helper が PUT する result の値は [DR-0006](../decisions/DR-0006-approval-url-and-exchange.md)

## 関連

- [DESIGN-ja.md](../DESIGN-ja.md) — 親文書
- [DR-0003](../decisions/DR-0003-helper-outside-sudo.md) — helper の起動の手順と置き場
- [DR-0006](../decisions/DR-0006-approval-url-and-exchange.md) — result の意味と値
- [DR-0008](../decisions/DR-0008-pluggable-send-command.md) — `send_command` に渡すもの
- [DR-0009](../decisions/DR-0009-foreground-control.md) — 前面制御
- [DR-0012](../decisions/DR-0012-auth-state-transitions.md) — 状態遷移と helper の成功判定
- [exchange-format](./exchange-format.md) — ストアに置く JSON の形
