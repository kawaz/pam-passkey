# DR-0008: 通知は `send_command` でプラガブルにし、既定は tty 表示にする

- Status: Accepted
- Date: 2026-11-02

## Context

承認 URL を受け手 (iPhone / Mac) に届ける手段は人によって違う (Bark、bark-admin、ntfy、ssh、チャット等)。

## Decision

- モジュールと helper は「URL を 1 本届ける」ことしか知らない。届け方は `send_command` (承認 URL を stdin で受けるコマンド) の中身に任せる。`send_command` は System Keychain の項目として設定する
- `send_command` が未設定なら承認 URL を tty に表示する。terminal のリンククリックか、コピペ (ユニバーサルクリップボードで iPhone へ) で足りる
- `send_command` の子プロセスはユーザ権限で動かす
- `send_command` の失敗は警告のみで、認証失敗にしない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| bark-admin の API を組み込む | bark-admin は届け方の 1 つにすぎない。`send_command` の中身として書ける |

## Consequences

- 新しい通知手段への対応はコマンドを書くだけで済み、モジュールの変更が要らない
- 経路上で URL を見られる前提になるので、URL の中身は暗号化と期限で守る ([DR-0006](./DR-0006-approval-url-and-exchange.md))

## 関連

- [DR-0006](./DR-0006-approval-url-and-exchange.md)
- [DR-0007](./DR-0007-system-keychain-only.md)
