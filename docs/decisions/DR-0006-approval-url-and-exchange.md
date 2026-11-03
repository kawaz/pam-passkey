# DR-0006: 承認 URL は 1 本、challenge はページが取得した要求そのものの SHA-256、result は pass / fail で poll する

- Status: Accepted
- Date: 2026-11-02

## Context

承認の受け手には URL を 1 本届けるだけにしたい ([DR-0008](./DR-0008-pluggable-send-command.md))。要求詳細 (argv やプロセスツリー) は量が多い。承認ページは静的ホスティング (既定は GitHub Pages) に置き、設定を持たない。

承認ページが表示する内容と、passkey が署名する対象は結びついていなければならない。ページが request から challenge を値として受け取って署名させる作りだと、同じ uid のプロセスが「偽の詳細 + 本物の challenge」の request を用意し、ユーザに偽の詳細を見せたまま本物の要求に署名させられる。

## Decision

- 承認 URL は `<page_url>#<request の presigned GET URL>` の 1 本にする。fragment はページのホストへのリクエストに含まれない。URL の長さは presigned URL 1 本分で、詳細が大きくなっても伸びない
- request JSON は kind (`approve`)、details (host / `PAM_USER` / 呼び出し元の uid / tty / argv / プロセスツリー / 要求時刻)、nonce (要求 ID)、expires、assertion_put_url (presigned PUT)、result_get_url (presigned GET) を持つ。challenge のフィールドは持たない。credential id も入れない (discoverable credential が前提)。オブジェクトの形は [exchange-format](../design/exchange-format.md)
- challenge は、ページが presigned GET で取得したペイロード全体 (バイト列そのまま) の SHA-256 にする。ページは表示するのと同じバイト列から challenge を計算する。helper は自分が PUT したバイト列を保持して同じ値を計算するので、正規化は要らない
- 要求詳細は暗号化しない。URL を持つ者は誰でも GET でき、持たない者は presigned GET できないので、暗号化して守れる相手はストアの運営者 (利用者自身のバケット) だけになる
- helper は assertion を [受理条件](../design/webauthn-verification.md) で検証する。assertion を 1 件受け取った時点で判定を確定し (junk なら fail)、以後の上書きは見ない
- presigned PUT では書き込まれるサイズを縛れないので、helper は assertion の GET にサイズの上限を設ける (値は [exchange-format](../design/exchange-format.md))
- result は、この要求の認証全体の結論にする。pass / fail の 2 値で、オブジェクトが無ければ待ち。理由は出さない。PUT は冪等。helper が終了経路ごとに次の値を PUT する

| 終了経路 | result |
|---|---|
| remote で受け取った assertion の検証が通った | pass |
| Touch ID の成功 (PAM から通知を受けた helper が PUT して終了する。[helper-protocol](../design/helper-protocol.md)) | pass |
| assertion の検証失敗、拒否 | fail |
| キャンセル、期限切れ、両方の失敗 | fail |

- ページは result を低頻度で poll し、署名する前に result が出ればそれを表示する (Touch ID で通れば「承認済み」)。署名して PUT した後は高頻度で poll して pass / fail を表示する
- 拒否は、ページが assertion の場所に署名なしの内容を PUT するだけにする。helper は検証失敗 → fail とする。拒否専用の経路は持たない
- helper は終了時に、終了経路を問わず request と assertion のオブジェクトをストアから DELETE する。result は消さず、lifecycle ルールに任せる
- バケットには lifecycle ルール (残ったオブジェクトの削除) と CORS (ページの origin からの GET / PUT を許す) が要る。設定は `setup` が行う ([DR-0010](./DR-0010-cli-shape.md))

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 要求詳細を URL に直接載せる | 情報量が多く URL が伸びる |
| 拒否専用の経路を持つ | 署名なしの PUT が検証失敗になるだけで拒否として働くので、別経路が要らない |

## Consequences

- 承認は、ページが表示した要求の内容そのものに束縛される。中継での差し替え・再生は署名不一致で落ちる
- 承認 URL を見た者は、期限内なら要求詳細を読め、assertion の置き場に書ける。通知経路は信頼境界の内側に置く ([DR-0008](./DR-0008-pluggable-send-command.md))。期限を過ぎれば presigned URL は無効になる
- 拒否は署名不要 (URL 保持者が待ちを止めるだけ)、承認だけ署名必須。presigned PUT URL を知る者が junk を先に書くと fail が確定する (最悪 DoS)
- result はストアで書き換えられるので、ページに出る pass / fail は Mac 側の判定を保証しない。result が理由を持たないので、ページは失敗理由を表示できない

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md) — 通信と検証を行う root の helper と、`PAM_USER` に降格した子
- [DR-0005](./DR-0005-s3-compatible-store.md)
- [DR-0008](./DR-0008-pluggable-send-command.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [DR-0012](./DR-0012-auth-state-transitions.md)
- [WebAuthn の受理条件](../design/webauthn-verification.md)
- [exchange-format](../design/exchange-format.md) — 交換するオブジェクトの形
- [helper-protocol](../design/helper-protocol.md) — PAM モジュールと helper の取り決め
