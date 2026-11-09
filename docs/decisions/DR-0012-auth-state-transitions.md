# DR-0012: 認証の状態遷移と不変条件

- Status: Accepted
- Date: 2026-11-03

## Context

`pam_passkey.so` は一般の PAM auth モジュールで (主用途は sudo)、呼び出し元のプロセス内で Touch ID (`LAContext`) と remote 承認 (helper) を並走させ、先に成功した方で通す ([DR-0002](./DR-0002-single-module-parallel-auth.md))。モジュールは認証の入口に居るので、どの状況でも有限時間で戻り、失敗は後続のパスワード認証に流れなければならない。モジュールが戻らないと、パスワード認証にも降りられない。

2 経路の状況は、GUI セッションの有無、Touch ID の policy を評価できるか、利用者の操作 (キャンセル / 「詳細を確認」/ Ctrl-C)、helper の起動可否で変わる。組合せごとに、Touch ID と remote それぞれの動作と PAM の戻り値を決めておく必要がある。

呼び出したユーザと認証対象のユーザ (`PAM_USER`) は一致するとは限らない (sudoers の `targetpw` / `rootpw`、`su` 等)。どちらの passkey と生体で認証するかを決めておく必要がある。

また、`LAContext` の評価のために行う `seteuid` はスレッドでなくプロセス全体に効く。並走する処理との順序を決めておかないと、helper が root でない euid で spawn される。

## Decision

### 認証に使うのは PAM_USER のものだけ

- 使う passkey と Touch ID の生体は `PAM_USER` のものにする
  - passkey は `PAM_USER` の login keychain の `users/<PAM_USER>` の項目を読む ([DR-0011](./DR-0011-user-keychain-signed-records.md))
  - `LAContext` は `PAM_USER` の uid に `seteuid` して評価する
  - `send_command` と承認ページを開く子も `PAM_USER` に降格する ([DR-0003](./DR-0003-helper-outside-sudo.md))
- 呼び出し元の euid が 0 でなく、かつ呼び出し元の uid が `PAM_USER` の uid と違う時は、Touch ID は使えないものとして扱う (remote だけで待つ)。`LAContext` が呼び出し元の生体で評価されるのを避ける
- 認証対象と違うユーザの passkey や生体では通らない。`PAM_USER` が root (sudoers の `targetpw` 等) なら passkey も生体も無いので、自然に失敗してパスワード認証に落ちる

### 2 経路の独立

- Touch ID の可否と remote の成否は独立に扱う。Touch ID が使えなくても remote は走る。Touch ID と remote が両方とも使えない時だけ `PAM_IGNORE`
- remote が使えないとは、helper の起動失敗 (`pam-passkey` バイナリが無い / 置き場の検査に通らない / spawn の失敗 / spawn した helper の署名の検査に通らない)、または helper が `unavailable` イベント (`PAM_USER` の登録が 0 件、ストアに届かない、`PAM_USER` の login keychain が unlock されていない) を返した場合を指す ([helper-protocol](../design/helper-protocol.md))。それ以外で remote が通らないものは remote の失敗として扱う
- 片方でも走れば、走った経路の結果で `PAM_SUCCESS` / `PAM_AUTH_ERR` を返す
- どちらかが成功したらもう片方を止めて `PAM_SUCCESS`、両方失敗したら `PAM_AUTH_ERR` ([DR-0002](./DR-0002-single-module-parallel-auth.md))
- Touch ID のダイアログを出せなければ、remote だけで待つ。出せるかは事前にセッションの属性で判定せず、`canEvaluatePolicy` と `evaluatePolicy` を試して決める (LocalAuthentication は GUI ログインセッション外のプロセスからもダイアログを出せる)。`canEvaluatePolicy` が false の時と、評価が system cancel (-4)、passcode 未設定 (-5)、biometry 不可 (-6)、未登録 (-7)、not interactive (-1004) で返った時が「出せない」。その時は tty に LAError の値を 1 行出す
- remote が走っている間に Touch ID が失敗しても (生体の不一致、lockout)、remote は止めず、Touch ID 側だけを終える
- 「詳細を確認」の fallback ボタンは常に出す。押された時に remote が使えない (helper が `unavailable` を返した後、または `open` に helper が応えられない) なら、両方を止めて `PAM_AUTH_ERR`
- キャンセルは両方を止めて `PAM_AUTH_ERR`

### 待ちの期限

- 期限の起点は request の `expires` 一本にする。値は PAM が決めて helper に渡す ([helper-protocol](../design/helper-protocol.md))。全ての待ち (`LAContext` の応答、helper の応答) は、PAM も helper も同じ値で打ち切る
- 期限が来たら両方を止めて `PAM_AUTH_ERR`
- 期限の後に届いた assertion は検証せず、fail にする

### helper の成功判定

- helper の成功は、PAM が渡した要求 ID を持つ `result` イベントの `pass: true` でだけ認める。exit 0、EOF、`pass: false`、要求 ID の違う `result`、それ以外の出力は失敗として扱う。メッセージの形は [helper-protocol](../design/helper-protocol.md)

### seteuid の順序

- プロセス情報の収集と helper の spawn を済ませてから、`LAContext` の評価のために euid を `PAM_USER` の uid に落とす。評価後に `seteuid(0)` で戻す
- euid を root に戻せなかったら、Touch ID の結果にかかわらず `PAM_AUTH_ERR`
- 呼び出し元の euid が 0 でなければ、`seteuid` も降格もせず、呼び出し元の権限のまま評価する

### 状態遷移表

| 状況 | Touch ID | remote | PAM の戻り値 |
|---|---|---|---|
| Touch ID のダイアログを出せない (`evaluatePolicy` が -4 / -5 / -6 / -7 / -1004 で返る) | 使えない | 走る | remote 成功: `PAM_SUCCESS`<br>remote 失敗 / 期限切れ: `PAM_AUTH_ERR`<br>remote も使えない: `PAM_IGNORE` |
| Touch ID を使えない (policy を評価できない (`canEvaluatePolicy` が false)、または呼び出し元の euid が 0 でなく uid が `PAM_USER` と違う) | 使えない | 走る | remote 成功: `PAM_SUCCESS`<br>remote 失敗 / 期限切れ: `PAM_AUTH_ERR`<br>remote も使えない: `PAM_IGNORE` |
| Touch ID ダイアログのキャンセル | 止める | 止める | `PAM_AUTH_ERR` |
| remote の走行中に Touch ID が失敗 (生体の不一致、lockout) | 終える | 走り続ける | remote 成功: `PAM_SUCCESS`<br>remote 失敗 / 期限切れ: `PAM_AUTH_ERR` |
| 「詳細を確認」(fallback) | ダイアログを出し直す | 走り続け、helper が承認ページを開く ([DR-0004](./DR-0004-fallback-button-as-details.md)) | Touch ID / remote 成功: `PAM_SUCCESS`<br>remote 失敗 / 期限切れ: `PAM_AUTH_ERR` |
| remote が使えない時の「詳細を確認」 | 止める | 使えない | `PAM_AUTH_ERR` |
| 期限切れ | 止める | 止める | `PAM_AUTH_ERR` |
| remote が使えない (helper の起動失敗 / 登録 0 件 / ストア不達 / login keychain が unlock されていない) | 出す | 使えない | Touch ID 成功: `PAM_SUCCESS`<br>Touch ID 失敗 / 期限切れ: `PAM_AUTH_ERR`<br>Touch ID も使えない: `PAM_IGNORE` |
| Ctrl-C | 止める | 止める | `PAM_AUTH_ERR` (キャンセルと同じ) |

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| `seteuid` の代わりに `pthread_setugid_np` でスレッド単位に資格情報を切り替える | `LAContext` がスレッド単位の切替で `PAM_USER` の生体登録を見るかが未検証。spawn を降格の前に済ませる順序の固定で、並走する spawn との競合は避けられる |

## Consequences

- どの状況でも、モジュールは期限内に `PAM_SUCCESS` / `PAM_AUTH_ERR` / `PAM_IGNORE` のいずれかで戻る。`PAM_AUTH_ERR` と `PAM_IGNORE` は後続のパスワード認証に流れる
- `LAContext` の評価中は呼び出し元プロセス全体の euid が `PAM_USER` になる。この間に root を要する処理を始めない
- 認証中の Ctrl-C がモジュールにどう届くか、キャンセル時のエラーコード、GUI アプリから起動した sudo での PAM の挙動全体、`sudo -n` は実機で未観測 ([findings](../findings/2026-11-02-pam-poc.md))

## 関連

- [DR-0002](./DR-0002-single-module-parallel-auth.md)
- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0004](./DR-0004-fallback-button-as-details.md)
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
- [findings: PAM モジュールの PoC](../findings/2026-11-02-pam-poc.md)
- [helper-protocol](../design/helper-protocol.md) — PAM モジュールと helper の取り決め
