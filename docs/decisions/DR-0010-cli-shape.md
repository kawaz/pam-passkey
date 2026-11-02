# DR-0010: CLI は 1 バイナリにまとめ、サブコマンドは動詞だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

PAM モジュールから呼ばれる helper と、設定・passkey 管理・動作確認の機能が要る。helper のロジックは sudo プロセス外の CLI 側に置く ([DR-0003](./DR-0003-helper-outside-sudo.md))。

## Decision

- helper と管理機能を `pam-passkey` の 1 バイナリにまとめる
- サブコマンドは `setup <page_url>` / `add [label]` / `list` / `del <label|id>` / `test` / `doctor` と、PAM から呼ばれる内部用サブコマンド
- passkey の操作は `ssh-add` / `useradd` の感触で動詞だけにする (操作対象はツール名から自明)
- `test` は sudo を介さずに承認経路を一周する

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 登録の動詞を `enroll` にする | WebAuthn の語彙で、利用者にとって重い |
| `passkey add` のように対象名詞を挟む | 対象は名前から自明で、名詞を挟む必要が無い |

## Consequences

- PAM モジュールが spawn する対象は `pam-passkey` だけになる
- `setup` / `add` / `del` は System Keychain への書き込みを伴うので root (`sudo pam-passkey ...`) で実行する ([DR-0007](./DR-0007-system-keychain-only.md))

## 関連

- [DR-0001](./DR-0001-naming.md)
- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0007](./DR-0007-system-keychain-only.md)
