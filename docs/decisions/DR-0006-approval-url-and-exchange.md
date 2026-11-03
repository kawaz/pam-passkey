# DR-0006: 承認 URL は 1 本、challenge はページが取得した要求そのものの SHA-256、result は pass / fail で poll する

- Status: Accepted
- Date: 2026-11-02

## Context

承認の受け手には URL を 1 本届けるだけにしたい ([DR-0008](./DR-0008-pluggable-send-command.md))。要求詳細 (argv やプロセスツリー) は量が多い。承認ページは静的ホスティング (既定は GitHub Pages) に置き、設定を持たない。

承認ページが表示する内容と、passkey が署名する対象は結びついていなければならない。ページが request から challenge を値として受け取って署名させる作りだと、同じ uid のプロセスが「偽の詳細 + 本物の challenge」の request を用意し、ユーザに偽の詳細を見せたまま本物の要求に署名させられる。

## Decision

- 承認 URL は `<page_url>#<request の presigned GET URL>` の 1 本にする。fragment はページのホストへのリクエストに含まれない。URL の長さは presigned URL 1 本分で、詳細が大きくなっても伸びない
- request JSON は details (host / user / tty / argv / プロセスツリー)、nonce、expires、assertion_put_url (presigned PUT)、result_get_url (presigned GET) を持つ。challenge のフィールドは持たない
- challenge は、ページが presigned GET で取得したペイロード全体 (バイト列そのまま) の SHA-256 にする。ページは表示するのと同じバイト列から challenge を計算する。helper は自分が PUT したバイト列を保持して同じ値を計算するので、正規化は要らない
- 要求詳細は暗号化しない。URL を持つ者は誰でも GET でき、持たない者は presigned GET できないので、暗号化して守れる相手はストアの運営者 (利用者自身のバケット) だけになる
- helper は assertion を [受理条件](../design/webauthn-verification.md) で検証する。assertion を 1 件受け取った時点で判定を確定し (junk なら fail)、以後の上書きは見ない
- presigned PUT では書き込まれるサイズを縛れないので、helper は assertion の GET にサイズの上限を設ける
- helper は判定を result として PUT する。result は pass / fail の 2 値で、オブジェクトが無ければ待ち。理由は出さない。PUT は冪等
- ページは result を低頻度で poll し、先に Touch ID で通れば「承認済み」に切り替える。署名して PUT した後は高頻度で poll して pass / fail を表示する
- 拒否は、ページが assertion の場所に署名なしの内容を PUT するだけにする。helper は検証失敗 → fail とする。拒否専用の経路は持たない
- 承認後、helper は request と assertion のオブジェクトをストアから DELETE する
- バケットの lifecycle ルール (残ったオブジェクトの削除) と CORS (ページの origin からの GET / PUT を許す) の設定は `setup` の手順に含める

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

- [DR-0003](./DR-0003-helper-outside-sudo.md) — 通信と検証を行う降格した子
- [DR-0005](./DR-0005-s3-compatible-store.md)
- [DR-0008](./DR-0008-pluggable-send-command.md)
- [WebAuthn の受理条件](../design/webauthn-verification.md)
