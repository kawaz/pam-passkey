# DR-0001: 名前は `pam_passkey` / `pam-passkey`

- Status: Accepted
- Date: 2026-11-02

## Context

PAM モジュール、helper と管理機能を兼ねる CLI、リポジトリ、それぞれに名前が要る。PAM モジュールは `pam_tid.so` のように `pam_<名前>.so` の形でファイル名を持ち、CLI とリポジトリはハイフン区切りの名前を持つ。

## Decision

- PAM モジュール: `pam_passkey` (ファイル名 `pam_passkey.so`)
- CLI: `pam-passkey`
- リポジトリ: `kawaz/pam-passkey`

同じ名前をモジュールではアンダースコア、CLI とリポジトリではハイフンで書く。

## 不採用案と理由

- `sudo-remote-approve` のように sudo を名前に含める: 実体は PAM モジュールで、sudo 以外の PAM service (`screensaver` 等) にも置けるので sudo 限定の名前は責務より狭い
- `pam_remote` / `pam_remote_passkey`: remote 承認は特徴だが、Touch ID 併用の手元認証も同じモジュールが担う。`pam_tid` と同様に認証手段 (passkey) を名前にし、remote であることは名前で言わない。`pam_remote_passkey` は長さに見合う情報が増えない

## Consequences

- `/etc/pam.d/sudo_local` には `auth sufficient pam_passkey.so` (またはそのフルパス) を書く
- helper は独立したコマンドではなく `pam-passkey` の内部サブコマンドとして呼ばれるので、利用者が覚える名前は `pam_passkey.so` と `pam-passkey` の 2 つだけになる

## 関連

- [DR-0010](./DR-0010-cli-shape.md) — CLI の形
