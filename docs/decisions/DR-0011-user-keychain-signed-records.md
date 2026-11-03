# DR-0011: passkey はユーザの login keychain に署名付きで置き、sudo に依存するのは setup だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

helper は、承認ページの URL、ストアの接続情報 (秘密を含む)、通知コマンド、ユーザごとの passkey 公開鍵を読む必要がある。これらは sudo の承認可否を左右するので、ユーザ権限のプロセスが勝手に鍵を登録して自分の sudo を承認する経路 (権限昇格) は塞がなければならない。

一方、pam-passkey は sudo に手を入れるツールなので、sudo への依存は `setup` の 1 回に限りたい。`add` / `del` まで sudo を要すると、モジュールの不具合で sudo が通らない時に鍵の追加・削除までできなくなる (ハシゴ外し)。また passkey はユーザ自身のものなので、ユーザの keychain に置くのが責務としても自然である。

ただし login keychain に素で置くと昇格経路になる。login keychain のファイルはユーザ所有で差し替えられ、署名済みの CLI 自体もユーザ権限のプロセスから実行できるので、Keychain の ACL では塞げない。

## Decision

- 前提: Keychain の項目の読み書きは helper バイナリ (Developer ID 署名) に限定する。System Keychain の項目も、`add` が書く login keychain の項目も、ACL を helper に絞る。PAM モジュールは Keychain を読まない
- `setup` (root): 署名鍵 (JWK、秘密鍵) を生成し、署名鍵と検証用の公開鍵を System Keychain に置く。設定項目 (`page_url` / `store` / `send_command`) も System Keychain に置く
  - 再実行すると署名鍵を作り直し、既存の登録は全て無効になる (各ユーザが `add` し直す)
  - 署名鍵のローテーション手順は持たない
- `add` (ユーザ権限):
  1. helper が `LAContext` で Touch ID を要求する (policy は `deviceOwnerAuthentication`。Touch ID 非搭載機はパスワード)
  2. 成功してから登録要求をストアに置き、登録 URL を発行する。登録 URL は tty に表示するか `send_command` の stdin に渡すだけで、それ以外 (プロセスの argv 等) には出さない
  3. 登録ページが passkey を作成し、credential を presigned PUT でストアに返す
  4. `add` はストアを poll して credential を受け取り、[受理条件](../design/webauthn-verification.md) で検証する
  5. **同じプロセス内で** System Keychain の署名鍵で JWS を作る。ペイロードは OS ユーザ名 (別ユーザの項目をコピーして使えないようにする)、credential id、公開鍵、ラベル、登録日、登録時の BE / BS フラグ
  6. login keychain の項目 `users/<os user>` (JSONL) に保存する。読み出しの ACL は helper に絞る
- 登録 URL は承認 URL と同じく期限付きの capability なので、URL を見ていない第三者は credential を PUT できない。登録ページと `add` の間で credential の指紋を照合する手順は持たない
- `del` (ユーザ権限): login keychain から消すだけ
- `list` (ユーザ権限): 自ユーザの項目を読んで一覧する。生の JWS は出さない
- 認証時の検証: helper は呼び出しユーザに降格した子プロセスで login keychain の項目を読む (ユーザのセッションで unlock 済みの keychain を、root でなくユーザとして読む。改ざんは署名検証で弾くので読み手がユーザ権限でも問題ない)。System Keychain の公開鍵で JWS を検証し、検証に通らないもの、ペイロードの OS ユーザ名が認証対象のユーザと一致しないものは無効として無視する
- signCount は記録しない (検証に使わない。[受理条件](../design/webauthn-verification.md))
- 昇格を塞ぐ根拠:
  - 悪意あるユーザ権限のプロセスは helper を実行できるが、Touch ID のダイアログを通せない
  - 署名は、Touch ID が成功したのと同じプロセス (hardened runtime + Developer ID 署名) の中で行う。同じ uid のプロセスからの制御の改変・署名鍵の覗き見を防ぐ
  - helper の入口を次の規律で絞る。署名済みの helper はどの uid からも起動できるので、正規の入口 (サブコマンド、引数、環境変数、stdin) から秘密を使わせない
    - 署名鍵を読むのは `add` の、Touch ID 成功後の 1 か所だけ。PAM から呼ばれる内部サブコマンドは、ユーザ権限から直接起動されても署名鍵を使わない
    - 環境変数で参照先 (Keychain の項目、`page_url`、rp_id) を切り替えられない
    - `list` は生の JWS を出さない (署名済みの行を写し取らせない)
  - login keychain のファイルを差し替えても、署名検証で無効になる
- `del` は悪意あるプロセスにも可能だが、効果は remote 承認が消えてパスワード認証に落ちるだけで、昇格にはならない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 全状態を System Keychain に置き、`add` / `del` も root (sudo) で行う | sudo への依存が `add` / `del` まで広がる |
| Authorization Services の right (`authenticate-admin`) を `add` の gate にする | 成立するが、authorizationdb への right の登録が `setup` に増える。Touch ID (`LAContext`) で足りる |
| 署名鍵を Secure Enclave に置き、`kSecAccessControl` で biometry を必須にする | OS が Touch ID 無しの鍵使用を拒むので、helper が侵害されても署名できない上位の硬化案。ただし SE の鍵はユーザ側の keychain に作られ、その公開鍵の登録に root が 1 回要るので初版では採らない。後の硬化オプションとして残す |
| login keychain に署名なしで置く | ファイルはユーザ所有で差し替えられ、署名済み CLI もユーザ権限のプロセスから実行できるので、Keychain の ACL では塞げず昇格経路になる |

## Consequences

- helper は hardened runtime + Developer ID 署名が必須になる。Keychain の ACL も昇格を塞ぐ根拠もこの署名に依存する。ad-hoc 署名は build ごとに変わって ACL が外れる
- JWS の生成・検証の実装が要る
- 署名鍵を失った時や作り直した時の復旧は、`setup` の再実行と全ユーザの再 `add` になる
- ACL を Developer ID 署名の helper に絞る設計の実機検証は未了 ([issue](../issue/2026-11-02-keychain-acl-developer-id-helper.md))
- 降格した子から login keychain を読めるかの実機検証は未了 ([issue](../issue/2026-11-02-login-keychain-read-from-sudo.md))
- ACL の設定 (`SecAccessCreate` / `SecACLSetContents`) は Rust crate に binding が無く、deprecated の API を C shim で呼ぶ ([findings](../findings/2026-11-02-keychain-poc.md))

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0005](./DR-0005-s3-compatible-store.md)
- [DR-0006](./DR-0006-approval-url-and-exchange.md) — 登録も同じくストアを介して受け取る
- [DR-0008](./DR-0008-pluggable-send-command.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [WebAuthn の受理条件](../design/webauthn-verification.md)
- [findings: System Keychain の PoC](../findings/2026-11-02-keychain-poc.md)
- [issue: Keychain ACL を Developer ID 署名の helper に絞る設計の実機検証](../issue/2026-11-02-keychain-acl-developer-id-helper.md)
- [issue: sudo 内 helper から呼び出しユーザの login keychain を読めるかの検証](../issue/2026-11-02-login-keychain-read-from-sudo.md)
