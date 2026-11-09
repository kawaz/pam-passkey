# DR-0008: 通知は `send_command` でプラガブルにし、既定は tty 表示にする

- Status: Accepted
- Date: 2026-11-02

## Context

承認 URL と登録 URL を受け手 (iPhone / Mac) に届ける手段は人によって違う (Bark、ntfy、ssh、チャット等)。

## Decision

- モジュールと helper は「URL を 1 本届ける」ことしか知らない。届け方は `send_command` (URL を stdin で受けるコマンド) の中身に任せる。`send_command` はユーザの login keychain の `config` 項目の 1 キーとして、ユーザごとに設定する (認証では `PAM_USER` のものを使う)。承認 URL と、`add` が発行する登録 URL ([DR-0011](./DR-0011-user-keychain-signed-records.md)) がこの経路を通る
- stdin は URL 1 行だけで、書いたら閉じる。通知の本文に出す要求の要約 (種類、ユーザとホスト、呼び出し元のコマンド、要求の詳細) は `PAM_PASSKEY_*` の環境変数で渡す。変数の一覧と中身は [MANUAL](../MANUAL-ja.md) の表が正本
- 承認では request の `details` を、ストアに PUT した request の中と同じバイト列の JSON で渡す。通知用の別スキーマは作らず、[exchange-format](../design/exchange-format.md) の `details` を唯一の定義にする。要約に `details` に無いもの (秘密、呼び出し元の環境変数) を足さない
- `send_command` が stdin を読まずに閉じても失敗にしない (URL は `PAM_PASSKEY_URL` でも受け取れる)
- `send_command` が未設定なら URL を tty に表示する。terminal のリンククリックか、コピペ (ユニバーサルクリップボードで iPhone へ) で足りる
- 通知経路 (`send_command` の先) は、利用者が選んだ経路として信頼境界の内側に置く
- `send_command` の子プロセスは `PAM_USER` に永久降格して起動する (起動の手順は [DR-0003](./DR-0003-helper-outside-sudo.md))
- `send_command` はシェル (`/bin/sh -c`) で起動する。環境は許可リスト `PATH` `HOME` `USER` `LOGNAME` `LANG` `LC_*` `TMPDIR` `SSH_AUTH_SOCK` に、helper / `add` が自分で値を決める `PAM_PASSKEY_*` を足したもの (呼び出し元の環境からは許可リストしか引き継がない)。cwd は `PAM_USER` の HOME
- `send_command` の失敗は警告のみで、認証失敗にしない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 特定の通知ツールの API を組み込む | その通知ツールは届け方の 1 つにすぎない。`send_command` の中身として書ける |
| 要約を stdin の 2 行目以降に書く | 1 行目だけ読むコマンドには届かず、stdin 全体を URL として扱うコマンド (`curl --data-binary @-` 等) は壊れる。環境変数なら既存のコマンドに影響せず、読みたいものだけ読める |
| 通知用に要約の JSON スキーマを別に定める | `details` と並行の定義になり、片方だけ変わる。`details` そのものを渡せば、ページが見せるものと通知が受け取るものが同じになる |

## Consequences

- 新しい通知手段への対応はコマンドを書くだけで済み、モジュールの変更が要らない
- 通知の本文に「誰が・どこで・何を」を出せる。経路に渡る要約は承認 URL から読める request の `details` と同じ範囲なので、経路を信頼境界の内側に置く前提は変わらない。将来 request を暗号化しても、この経路の要約は平文のまま渡す (経路は境界の内側)
- 要約の大きさは request の上限 (64 KiB) に収まり、環境変数で渡せる (ARG_MAX の範囲)
- URL は期限付きの capability なので、経路上で URL を見た者は期限内にそれを使える。承認 URL なら要求詳細を読め、assertion の置き場に書ける (署名が無いので pass にはできない。[DR-0006](./DR-0006-approval-url-and-exchange.md))。登録 URL なら自分の credential を登録させられる。経路を信頼境界の内側に置くのはこのため

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0006](./DR-0006-approval-url-and-exchange.md)
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
- [exchange-format](../design/exchange-format.md) — `details` の定義
- [MANUAL](../MANUAL-ja.md) — `send_command` が受け取る環境変数の表
