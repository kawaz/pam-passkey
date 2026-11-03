# DR-0010: CLI は 1 バイナリにまとめ、サブコマンドは動詞だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

PAM モジュールから呼ばれる helper と、設定・passkey 管理の機能が要る。helper のロジックは sudo プロセス外の CLI 側に置く ([DR-0003](./DR-0003-helper-outside-sudo.md))。

## Decision

- helper と管理機能を `pam-passkey` の 1 バイナリにまとめる
- サブコマンドは `setup [page_url]` / `add [label]` / `list` / `del <label|id>` と、PAM から呼ばれる内部用サブコマンド
- passkey の操作は `ssh-add` / `useradd` の感触で動詞だけにする (操作対象はツール名から自明)
- `setup` の `page_url` を省略すると既定の `https://pam-passkey.github.io/` を使う
- 疎通確認 (ストアへの到達、バケットの CORS、`.so` と helper の置き場の所有権) は `setup` が行う

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
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
