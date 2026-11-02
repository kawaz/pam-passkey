# DR-0003: remote 承認のロジックは sudo プロセス外の helper に置き、PAM モジュールは薄層にする

- Status: Accepted
- Date: 2026-11-02

## Context

remote 承認には、要求詳細の暗号化とストアへの PUT、通知コマンドの起動、ポーリング、passkey 署名の検証、ブラウザの `open` が要る。PAM モジュールは sudo プロセス内で動くが、sudo は setuid プロセスで、次の制約がある。

- AppKit を初期化するとプロセスごと exit する (sudo 自体が落ち、コマンドが実行されない) ([findings](../findings/2026-11-02-pam-poc.md))
- root の sudo プロセスの中でネットワーク (TLS) を喋ることになる
- デバッグが難しく、動作確認のたびに sudo を経由する

## Decision

- helper は `pam-passkey` CLI の内部サブコマンドとして実装し、PAM モジュールはこれを spawn する薄い層にする。ロジックは CLI 側に置く
- helper は root で動かす。ユーザ権限に落とすのは `open` と `send_command` の子プロセスだけ
- `pam-passkey test` で、sudo を介さずに承認経路を一周できるようにする

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| ロジックを PAM モジュール内に置く | setuid プロセスでは AppKit を使えずプロセスごと落ちる。root の sudo 内で TLS を喋ることになる。sudo 抜きの動作確認ができない |

## Consequences

- PAM モジュールに入れてよいのは、プロセスを落とさない要素だけになる。モジュールが落ちない限り失敗は後続のパスワード認証に流れるので、不具合で sudo が通らず setup もできなくなる事態を避けられる
- helper が無い / 起動できない場合、モジュールは remote 側だけ諦めて Touch ID を出す
- フォーカス操作 (AX で SecurityAgent の window を raise する等) も helper 側で行う

## 関連

- [DR-0002](./DR-0002-single-module-parallel-auth.md)
- [DR-0009](./DR-0009-foreground-control.md)
- [DR-0010](./DR-0010-cli-shape.md)
