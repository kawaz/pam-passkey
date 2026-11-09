# DR-0005: 中継は S3 互換ストアと presigned URL で行う

- Status: Accepted
- Date: 2026-11-02

## Context

Mac (helper) と承認ページ (iPhone / Mac のブラウザ) の間で、要求詳細・assertion・結果を受け渡す中継が要る。`add` が登録ページから credential を受け取る時も同じ中継を使う ([DR-0011](./DR-0011-user-keychain-signed-records.md))。Mac 側に常駐サーバや受信ポートを持たず、中継側にもデプロイして維持するコードを置きたくない。中継は信頼しない前提で、真正性は passkey 署名の検証で担保する ([DR-0006](./DR-0006-approval-url-and-exchange.md))。

## Decision

- 中継は S3 互換のオブジェクトストアにする (R2 を想定。API 互換なら差し替え可)
- ページからの読み書きは helper が発行する presigned URL (GET / PUT) で行う。presigned URL が期限付きの capability を兼ねる
- presigned GET を使うことで、バケットに公開読みのポリシーを設定せずに済ませる
- presigned PUT (assertion / credential) は、ストアが対応していれば `If-None-Match: *` を署名ヘッダに含めて 1 回限りにする。対応の有無は `setup` が確かめて `store` 設定の `put_once` (true / false) に持ち ([DR-0010](./DR-0010-cli-shape.md))、helper と `add` は `put_once` が true の時だけヘッダを付ける。非対応のストアでは上書きできるまま
- 接続情報 (endpoint / bucket / region / prefix / access key / secret / `put_once`) は、ユーザの login keychain の `config` 項目の `store` に置く。設定はユーザ単位で、同じ Mac でもユーザごとに別のストアを使える ([DR-0011](./DR-0011-user-keychain-signed-records.md))

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| Cloudflare Worker + KV | Worker のコードをデプロイして維持する必要がある |
| 既存の通知ツールのサーバに相乗りする | そのサーバが公開ネットワークから到達できることに依存する |

## Consequences

- 中継側に置くコードが無い。利用者が用意するのはバケットと access key だけ
- ストアの access key / secret は秘密なので、`config` 項目の ACL を Developer ID 署名の `pam-passkey` バイナリに絞る
- presigned URL と request の期限を揃える

## 関連

- [DR-0006](./DR-0006-approval-url-and-exchange.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
