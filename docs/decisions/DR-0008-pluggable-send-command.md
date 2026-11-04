# DR-0008: 通知は `send_command` でプラガブルにし、既定は tty 表示にする

- Status: Accepted
- Date: 2026-11-02

## Context

承認 URL と登録 URL を受け手 (iPhone / Mac) に届ける手段は人によって違う (Bark、ntfy、ssh、チャット等)。

## Decision

- モジュールと helper は「URL を 1 本届ける」ことしか知らない。届け方は `send_command` (URL を stdin で受けるコマンド) の中身に任せる。`send_command` は System Keychain の項目として設定する。承認 URL と、`add` が発行する登録 URL ([DR-0011](./DR-0011-user-keychain-signed-records.md)) がこの経路を通る
- `send_command` が未設定なら URL を tty に表示する。terminal のリンククリックか、コピペ (ユニバーサルクリップボードで iPhone へ) で足りる
- 通知経路 (`send_command` の先) は、利用者が選んだ経路として信頼境界の内側に置く
- `send_command` の子プロセスは `PAM_USER` に永久降格して起動する (起動の手順は [DR-0003](./DR-0003-helper-outside-sudo.md))
- `send_command` はシェル (`/bin/sh -c`) で起動する。環境の許可リストは `PATH` `HOME` `USER` `LOGNAME` `LANG` `LC_*` `TMPDIR` `SSH_AUTH_SOCK`、cwd は `PAM_USER` の HOME
- `send_command` の失敗は警告のみで、認証失敗にしない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 特定の通知ツールの API を組み込む | その通知ツールは届け方の 1 つにすぎない。`send_command` の中身として書ける |

## Consequences

- 新しい通知手段への対応はコマンドを書くだけで済み、モジュールの変更が要らない
- URL は期限付きの capability なので、経路上で URL を見た者は期限内にそれを使える。承認 URL なら要求詳細を読め、assertion の置き場に書ける (署名が無いので pass にはできない。[DR-0006](./DR-0006-approval-url-and-exchange.md))。登録 URL なら自分の credential を登録させられる。経路を信頼境界の内側に置くのはこのため

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0006](./DR-0006-approval-url-and-exchange.md)
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
