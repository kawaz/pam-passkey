# DR-0006: 承認 URL は 1 本、詳細は暗号化してストアに置き、result は 3 値で poll する

- Status: Accepted
- Date: 2026-11-02

## Context

承認の受け手には URL を 1 本届けるだけにしたい ([DR-0008](./DR-0008-pluggable-send-command.md))。その経路 (通知サーバ / APNs / チャット) は信頼できず、要求詳細 (argv やプロセスツリー) は秘密を含み得て量も多い。承認ページは静的ホスティング (既定は GitHub Pages) に置き、設定を持たない。

## Decision

- 承認 URL は `<page_url>#<request の presigned GET URL>.<復号鍵>` の 1 本にする。fragment はサーバに送られないので、ページのホストは URL も中身も見ない。URL の長さは presigned URL 1 本分で、詳細が大きくなっても伸びない
- 要求詳細は fragment の鍵で暗号化してストアに置く。request JSON は details (host / user / tty / argv / プロセスツリー)、challenge、expires、assertion_put_url (presigned PUT)、result_get_url (presigned GET) を持つ
- `challenge = SHA-256(要求詳細 + nonce + 期限)`。helper は assertion の `clientDataJSON.challenge` が自分の計算値と一致すること、`origin` / `rpIdHash` / UV flag / signCount を検証する
- helper は検証結果を result として PUT する。result は 404 (待ち) / pass / fail の 3 値だけで、理由は出さない。PUT は冪等
- ページは result を低頻度で poll し、先に Touch ID で通れば「承認済み」に切り替える。署名して PUT した後は高頻度で poll して pass / fail を表示する
- 拒否は、ページが assertion の場所に署名なしの内容を PUT するだけにする。helper は検証失敗 → fail とする。拒否専用の経路は持たない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 要求詳細を URL に直接載せる | 情報量が多く URL が伸びる。経路上で URL を見られると中身が読める |
| 拒否専用の経路を持つ | 署名なしの PUT が検証失敗になるだけで拒否として働くので、別経路が要らない |

## Consequences

- 承認は要求の内容そのものに束縛され、中継での差し替え・再生は署名不一致で落ちる
- 経路上で URL を見られても、期限内に中身を読まれにくい。期限を過ぎれば presigned URL は無効になる
- 拒否は署名不要 (URL 保持者が待ちを止めるだけ)、承認だけ署名必須。presigned PUT URL を知る者が junk を書いても検証で落ちる (最悪 DoS)
- result が理由を持たないので、ページは失敗理由を表示できない

## 関連

- [DR-0005](./DR-0005-s3-compatible-store.md)
- [DR-0008](./DR-0008-pluggable-send-command.md)
