# DR-0011: passkey はユーザの login keychain に署名付きで置き、sudo に依存するのは setup だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

モジュールと helper は、承認ページの URL、ストアの接続情報 (秘密を含む)、通知コマンド、ユーザごとの passkey 公開鍵を読む必要がある。これらは sudo の承認可否を左右するので、ユーザ権限のプロセスが勝手に鍵を登録して自分の sudo を承認する経路 (権限昇格) は塞がなければならない。

一方、pam-passkey は sudo に手を入れるツールなので、sudo への依存は `setup` の 1 回に限りたい。`add` / `del` まで sudo を要すると、モジュールの不具合で sudo が通らない時に鍵の追加・削除までできなくなる (ハシゴ外し)。また passkey はユーザ自身のものなので、ユーザの keychain に置くのが責務としても自然である。

ただし login keychain に素で置くと昇格経路になる。login keychain のファイルはユーザ所有で差し替えられ、署名済みの CLI 自体もユーザ権限のプロセスから実行できるので、Keychain の ACL では塞げない。

## Decision

- `setup` (root、1 回): 署名鍵 (JWK、秘密鍵) を生成して System Keychain に置く。ACL は Developer ID 署名の helper だけにする。設定項目 (`page_url` / `store` / `send_command`) も System Keychain に置く
- `add` (ユーザ権限):
  1. helper が `LAContext` で Touch ID を要求する (policy は `deviceOwnerAuthentication`。Touch ID 非搭載機はパスワード)
  2. 成功してから登録 URL を発行し、ページで passkey を作成する
  3. 貼り付けを受けて検証する
  4. **同じプロセス内で** System Keychain の署名鍵で JWS を作る。ペイロードに OS ユーザ名を含める (別ユーザの項目をコピーして使えないようにする)
  5. login keychain の項目 `users/<os user>` (JSONL) に保存する
- `del` (ユーザ権限): login keychain から消すだけ
- PAM / helper の検証: helper は呼び出しユーザに降格した子プロセスで login keychain の項目を読む (ユーザのセッションで unlock 済みの keychain を、root でなくユーザとして読む。改ざんは署名検証で弾くので読み手がユーザ権限でも問題ない)。System Keychain の署名鍵の公開鍵で JWS を検証し、検証に通らないもの、ペイロードの OS ユーザ名が認証対象のユーザと一致しないものは無効として無視する
- signCount は署名の外 (項目の可変フィールド) に置く。署名済みペイロードは credential id / 公開鍵 / ラベル / 登録日 / OS ユーザ名の不変部分だけ。Apple の同期 passkey は signCount を常に 0 で返すので、検証は「減少していない」の確認にとどめる
- 昇格を塞ぐ根拠:
  - 悪意あるユーザ権限のプロセスは helper を実行できるが、Touch ID のダイアログを通せない
  - 署名は、Touch ID が成功したのと同じプロセス (hardened runtime + Developer ID 署名) の中で行う。同じ uid のプロセスからの制御の改変・署名鍵の覗き見を防ぐ
  - login keychain のファイルを差し替えても、署名検証で無効になる
- `del` は悪意あるプロセスにも可能だが、効果は remote 承認が消えてパスワード認証に落ちるだけで、昇格にはならない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 全状態を System Keychain に置き、`add` / `del` も root (sudo) で行う | 安全性は同等だが、sudo への依存が `add` / `del` まで広がる |
| Authorization Services の right (`authenticate-admin`) を `add` の gate にする | 成立するが、authorizationdb への right の登録が `setup` に増える。Touch ID (`LAContext`) で足りる |
| 署名鍵を Secure Enclave に置き、`kSecAccessControl` で biometry を必須にする | OS が Touch ID 無しの鍵使用を拒むので、helper が侵害されても署名できない上位の硬化案。ただし SE の鍵はユーザ側の keychain に作られ、その公開鍵の登録に root が 1 回要るので初版では採らない。後の硬化オプションとして残す |
| login keychain に署名なしで置く | ファイルはユーザ所有で差し替えられ、署名済み CLI もユーザ権限のプロセスから実行できるので、Keychain の ACL では塞げず昇格経路になる |

## Consequences

- helper は hardened runtime + Developer ID 署名が必須になる。署名鍵の ACL も昇格を塞ぐ根拠もこの署名に依存する。ad-hoc 署名は build ごとに変わって ACL が外れる
- JWS の生成・検証の実装と、署名鍵のローテーション手順が要る
- ACL を Developer ID 署名の helper に絞る設計の実機検証は未了 ([issue](../issue/2026-11-02-keychain-acl-developer-id-helper.md))
- ACL の設定 (`SecAccessCreate` / `SecACLSetContents`) は Rust crate に binding が無く、deprecated の API を C shim で呼ぶ ([findings](../findings/2026-11-02-keychain-poc.md))
- `list` はユーザの login keychain を読むだけで済む

## 関連

- [DR-0005](./DR-0005-s3-compatible-store.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [findings: System Keychain の PoC](../findings/2026-11-02-keychain-poc.md)
- [issue: Keychain ACL を Developer ID 署名の helper に絞る設計の実機検証](../issue/2026-11-02-keychain-acl-developer-id-helper.md)
