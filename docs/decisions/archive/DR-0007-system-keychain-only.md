# DR-0007: 状態と設定は System Keychain 一本に置き、ファイルを持たない

- Status: Superseded by DR-0011
- Date: 2026-11-02

## Context

モジュールと helper は、承認ページの URL、ストアの接続情報 (秘密を含む)、通知コマンド、ユーザごとの passkey 公開鍵を読む必要がある。これらは sudo の承認可否を左右するので、ユーザ権限のプロセスが書き換えられてはならない (書き換えられれば、自分で鍵を登録して自分の sudo を承認できる = 権限昇格)。一方で読み出しは、sudo プロセス内の PAM (root) からダイアログ無しで行える必要がある。

## Decision

- 全状態を System Keychain (`/Library/Keychains/System.keychain`) の generic password 項目に置く。ファイル・ディレクトリ・パーミッションを一切持たない
- 書き込みは root で行う (`sudo pam-passkey setup` / `add` / `del`)。sudo に依存するのは設定変更時だけで、認証時 (読み出し) は依存しない
- login keychain には書かない (実装で固定する)
- 公開鍵・設定は秘密でないので、読み出しの ACL は「全アプリ可」にする。main executable が `/usr/bin/sudo` であることによる ACL の問題を踏まず、ダイアログ無しで読める
- 秘密 (ストアの鍵) だけ ACL を Developer ID 署名の helper に絞る
- 項目は `page_url` / `store` / `send_command` / `users/<os user>` の 4 種。それ以外 (ポーリング間隔、ボタン文言、Touch ID の有無) はコードの既定値にする

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| root 所有の設定ファイル | root 所有ファイルの管理責務を持つことになる。配布形態 (自前 build / brew / nix) ごとに setup 手順が分かれる |
| login keychain | ユーザ権限で書き込めるので、ユーザ権限のプロセスが鍵を登録して自分の sudo を承認できる (権限昇格) |
| 特権 helper (SMAppService) を立てて書き込みを仲介する | 導入が重い |
| ユーザ権限から Authorization right (`system.keychain.modify`) を取って書く | right を取得しても `-61` (wrPermErr) で書けないことを実機で確認した ([findings](../../findings/2026-11-02-keychain-poc.md)) |

## Consequences

- ユーザ権限のプロセスによる鍵の登録は、System Keychain への書き込みに root が要ることで塞がれる
- ACL を Developer ID 署名の helper に絞るため、helper の Developer ID 署名が前提になる。ad-hoc 署名は build ごとに変わって ACL が外れる
- ACL の設定 (`SecAccessCreate` / `SecACLSetContents`) は Rust crate に binding が無く、deprecated の API を C shim で呼ぶ
- `list` は自ユーザの `users/<os user>` 項目を読むだけで済む

## 関連

- [DR-0005](../DR-0005-s3-compatible-store.md)
- [DR-0010](../DR-0010-cli-shape.md)
- [findings: System Keychain の PoC](../../findings/2026-11-02-keychain-poc.md)
