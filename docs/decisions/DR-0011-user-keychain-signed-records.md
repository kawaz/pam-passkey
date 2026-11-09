# DR-0011: passkey と設定はユーザの login keychain に置き (passkey は署名付き)、sudo に依存するのは署名鍵を作る初回の setup だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

helper は、承認ページの URL、ストアの接続情報 (秘密を含む)、通知コマンド、ユーザごとの passkey 公開鍵を読む必要がある。これらは sudo の承認可否を左右するので、ユーザ権限のプロセスが勝手に鍵を登録して自分の sudo を承認する経路 (権限昇格) は塞がなければならない。

一方、pam-passkey は sudo に手を入れるツールなので、sudo への依存は `setup` の 1 回に限りたい。`add` / `del` まで sudo を要すると、モジュールの不具合で sudo が通らない時に鍵の追加・削除までできなくなる (ハシゴ外し)。また passkey はユーザ自身のものなので、ユーザの keychain に置くのが責務としても自然である。

ただし login keychain に素で置くと昇格経路になる。login keychain のファイルはユーザ所有で差し替えられ、署名済みの CLI 自体もユーザ権限のプロセスから実行できるので、Keychain の ACL では塞げない。

## Decision

- 前提: Keychain の項目の読み書きは `pam-passkey` バイナリ (Developer ID 署名) に限定する。System Keychain の項目も、`setup` / `add` が書く login keychain の項目も、ACL を `pam-passkey` バイナリに絞る。PAM モジュールは Keychain を読まない
- `setup` (ユーザ権限): 設定 (`page_url` / `store` / `send_command`) を自分の login keychain の項目 `config` (JSON) に置く。署名は付けない。設定はユーザ単位で、passkey を登録するユーザがそれぞれ `setup` を実行する
  - 署名鍵 (Ed25519 の JWK、秘密鍵) と検証用の公開鍵は System Keychain に置く。作るのは、まだ無い時 (その Mac の最初の `setup`) と `regenerate_key` の時だけで、その瞬間だけ `setup` が `sudo <self> _setup-write` で root になる。System Keychain の既存項目の変更は root でも管理者認証のダイアログを出すので、作った後の鍵には触らない ([findings](../findings/2026-11-02-keychain-poc.md) の「root なら書ける」は新規作成の観測)
  - `config` に署名が無くても昇格にならない理由: 同じ uid のプロセスは `config` を書き換えられるが、`store` は承認の真正性を左右しない (DESIGN 信頼の前提。改ざんは fail か待ち)、`send_command` は `PAM_USER` として動くだけで、URL を受け取った者にできるのは拒否 (DoS) と詳細の閲覧、`page_url` を別の origin に変えると helper の照合先 (origin と `rpIdHash`) も変わるが、登録済みの passkey は元の rp_id に束縛されていて別の rp_id の assertion を作れないので、検証は通らない
  - 再実行で署名鍵を作り直すと、既存の登録は全て無効になる (各ユーザが `add` し直す)。再実行時の確認は [DR-0010](./DR-0010-cli-shape.md)
  - 署名鍵のローテーション手順は持たない
- `add` (ユーザ権限):
  1. `add` が `LAContext` で本人確認を求める (policy は `deviceOwnerAuthentication`。Touch ID、非搭載機はパスワード)
  2. 成功してから登録ペイロードをストアに置き、登録 URL を発行する。登録 URL は承認 URL と同じ形 (`<page_url>#<登録ペイロードの presigned GET URL>`) で、tty に表示するか `send_command` の stdin に渡すだけで、それ以外 (プロセスの argv 等) には出さない
  3. 登録ページが passkey を作成し、credential を presigned PUT でストアに返す
  4. `add` はストアを poll して credential を受け取り、[受理条件](../design/webauthn-verification.md) で検証する。待ちの期限は登録ペイロードの `expires`
  5. **同じプロセス内で** System Keychain の署名鍵で JWS を作る。ペイロードは OS ユーザ名 (別ユーザの項目をコピーして使えないようにする)、credential id、user handle (`user_id`)、公開鍵、ラベル、登録日、登録時の BE / BS フラグ
  6. login keychain の項目 `users/<os user>` (JSONL) に保存する。読み出しの ACL は `pam-passkey` バイナリに絞る
  7. 終了時に、終了経路を問わず登録ペイロードと credential のオブジェクトをストアから DELETE する
- 登録ペイロードは kind (`register`)、rp_id、user_name (登録するユーザの OS ユーザ名)、user_id (WebAuthn の user handle。登録ごとの乱数 16 バイト)、expires、credential_put_url (presigned PUT) を持つ。オブジェクトの形は [exchange-format](../design/exchange-format.md)
- 登録ページと承認ページは同じ 1 つのファイルで、取得したペイロードの kind (`register` / `approve`) で画面を切り替える。登録では attestation を `none`、`pubKeyCredParams` を ES256 だけにして passkey を作らせる
- 登録 URL は承認 URL と同じく期限付きの capability なので、URL を見ていない第三者は credential を PUT できない。登録ページと `add` の間で credential の指紋を照合する手順は持たない
- `del` (ユーザ権限): login keychain から消すだけ
- `list` (ユーザ権限): 自ユーザの項目を読んで一覧する
- 認証時の検証: helper は `PAM_USER` に降格した子プロセスで、`PAM_USER` の login keychain の `config` と `users/<PAM_USER>` の項目を読む (`config` が無ければ remote は使えない) (ユーザのセッションで unlock 済みの keychain を、root でなくユーザとして読む。改ざんは署名検証で弾くので読み手がユーザ権限でも問題ない)。System Keychain の公開鍵で JWS を検証し、検証に通らないもの、ペイロードの OS ユーザ名が認証対象のユーザと一致しないものは無効として無視する
- signCount は記録しない (検証に使わない。[受理条件](../design/webauthn-verification.md))
- 昇格を塞ぐ根拠:
  - 悪意あるユーザ権限のプロセスは `pam-passkey` バイナリを実行できるが、本人確認のダイアログを通せない
  - 署名は、本人確認が成功したのと同じプロセス (hardened runtime + Developer ID 署名) の中で行う。同じ uid のプロセスからの制御の改変・署名鍵の覗き見を防ぐ
  - `pam-passkey` バイナリの入口を次の規律で絞る。署名済みのバイナリはどの uid からも起動できるので、正規の入口 (サブコマンド、引数、環境変数、stdin) から秘密を使わせない
    - 署名鍵を読むのは `add` の、本人確認の成功後の 1 か所だけ。PAM から呼ばれる内部サブコマンドは、ユーザ権限から直接起動されても署名鍵を使わない
    - ストアの秘密 (access key / secret) はどのサブコマンドも出力に出さない。root の helper が `PAM_USER` の `config` を受け取る内部サブコマンド `_read-user` は、親プロセスが euid 0 で `pam-passkey` の署名 (identifier と Team ID) を持つ時だけ出力し、それ以外の起動では何も出さずに終わる。helper が root でない時 (呼び出し元が root でない PAM 経路) は、helper 自身が `PAM_USER` として login keychain を直接読む
    - 環境変数で参照先 (Keychain の項目、`page_url`、rp_id) を切り替えられない
  - login keychain のファイルを差し替えても、署名検証で無効になる
- `del` は悪意あるプロセスにも可能だが、効果は remote 承認が消えてパスワード認証に落ちるだけで、昇格にはならない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 全状態を System Keychain に置き、`add` / `del` も root (sudo) で行う | sudo への依存が `add` / `del` まで広がる |
| Authorization Services の right (`authenticate-admin`) を `add` の gate にする | 成立するが、authorizationdb への right の登録が `setup` に増える。本人確認 (`LAContext`) で足りる |
| 署名鍵を Secure Enclave に置き、`kSecAccessControl` で biometry を必須にする | OS が Touch ID 無しの鍵使用を拒むので、`pam-passkey` バイナリが侵害されても署名できない上位の硬化案。ただし SE の鍵はユーザ側の keychain に作られ、その公開鍵の登録に root が 1 回要るので初版では採らない。後の硬化オプションとして残す |
| passkey の記録を login keychain に署名なしで置く | ファイルはユーザ所有で差し替えられ、署名済み CLI もユーザ権限のプロセスから実行できるので、Keychain の ACL では塞げず昇格経路になる |
| 設定 (`page_url` / `store` / `send_command`) を System Keychain に置き、システムで 1 つにする | 設定を変えるたびに System Keychain の既存項目の変更になり、root でも項目ごとに管理者認証のダイアログが出る (実機) |

## Consequences

- `pam-passkey` バイナリは hardened runtime + Developer ID 署名が必須になる。Keychain の ACL も昇格を塞ぐ根拠もこの署名に依存する。ad-hoc 署名は build ごとに変わって ACL が外れる
- JWS の生成・検証の実装が要る
- 署名鍵を失った時や作り直した時の復旧は、`setup` の再実行と全ユーザの再 `add` になる
- 設定はユーザ単位になる。passkey を使うユーザはそれぞれ `setup` を実行し、同じ Mac でもユーザごとに別のストアと `send_command` を持てる
- ACL を Developer ID 署名の `pam-passkey` バイナリに絞る設計の実機検証は未了 ([issue](../issue/2026-11-02-keychain-acl-developer-id-helper.md))
- 降格した子から login keychain を読めるかの実機検証は未了 ([issue](../issue/2026-11-02-login-keychain-read-from-sudo.md))
- ACL の設定 (`SecAccessCreate` / `SecACLSetContents`) は Rust crate に binding が無く、deprecated の API を C shim で呼ぶ ([findings](../findings/2026-11-02-keychain-poc.md))

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0005](./DR-0005-s3-compatible-store.md)
- [DR-0006](./DR-0006-approval-url-and-exchange.md) — 登録も同じくストアを介して受け取る
- [DR-0008](./DR-0008-pluggable-send-command.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [WebAuthn の受理条件](../design/webauthn-verification.md)
- [exchange-format](../design/exchange-format.md) — 登録ペイロードと credential の形
- [findings: System Keychain の PoC](../findings/2026-11-02-keychain-poc.md)
- [issue: Keychain ACL を Developer ID 署名の helper に絞る設計の実機検証](../issue/2026-11-02-keychain-acl-developer-id-helper.md)
- [issue: sudo 内 helper から呼び出しユーザの login keychain を読めるかの検証](../issue/2026-11-02-login-keychain-read-from-sudo.md)
