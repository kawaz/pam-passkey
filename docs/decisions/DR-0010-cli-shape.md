# DR-0010: CLI は 1 バイナリにまとめ、サブコマンドは動詞だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

PAM モジュールから呼ばれる helper と、設定・passkey 管理の機能が要る。helper のロジックは呼び出し元のプロセス外の CLI 側に置く ([DR-0003](./DR-0003-helper-outside-sudo.md))。

## Decision

- helper と管理機能を `pam-passkey` の 1 バイナリにまとめる
- サブコマンドは `setup [--module <path>] [page_url]` / `add [label]` / `list` / `del <label|id>` と、PAM から呼ばれる内部用サブコマンド
- passkey の操作は `ssh-add` / `useradd` の感触で動詞だけにする (操作対象はツール名から自明)
- `setup`:
  - `page_url` を省略すると既定の `https://pam-passkey.github.io/` を使う
  - `store` と `send_command` は対話で入力する (秘密の値は画面に出さない)。標準入力が tty でなければ、標準入力から JSON 1 行で受ける。キーは `page_url`、`store` (オブジェクト)、`send_command`、`regenerate_key` (bool。既定は false で、署名鍵があれば維持する)
  - 署名鍵が既にあれば、作り直すと既存の登録が全て無効になる旨を 1 行出して y/N で確認する。N なら署名鍵は維持し、設定 (`page_url` / `store` / `send_command`) だけを更新する
  - ストアへの到達を確かめ、バケットの CORS と lifecycle ルール ([DR-0006](./DR-0006-approval-url-and-exchange.md)) を設定する。権限が無ければエラーで止まり、必要な設定を表示する
  - 自分の実行ファイルの置き場を [DR-0003](./DR-0003-helper-outside-sudo.md) の基準で検査する。`.so` の置き場は `--module <path>` が与えられた時だけ検査する
- `add` の label の既定値は登録日時 (`YYYY-MM-DD HH:MM`)。label は一意でなくてよい
- `del` は引数が credential id に一致すればそれを優先する。label が複数の passkey に一致したらエラーで止まり、候補を出す
- `list` は label、credential id、登録日を出す。JWS の検証はしない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 登録の動詞を `enroll` にする | WebAuthn の語彙で、利用者にとって重い |
| `passkey add` のように対象名詞を挟む | 対象は名前から自明で、名詞を挟む必要が無い |

## Consequences

- PAM モジュールが spawn する対象は `pam-passkey` だけになる
- root (`sudo pam-passkey ...`) が要るのは System Keychain に署名鍵と設定を書く `setup` だけ。`add` / `del` / `list` はユーザ権限で動く ([DR-0011](./DR-0011-user-keychain-signed-records.md))

## 関連

- [DR-0001](./DR-0001-naming.md)
- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0006](./DR-0006-approval-url-and-exchange.md)
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
