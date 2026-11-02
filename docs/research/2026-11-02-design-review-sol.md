# 設計レビュー (sol、初見)

## 総評

**現状の設計をセキュリティ上成立した仕様として本実装に移すべきではありません。** PAM と Keychain の PoC は有用ですが、検証したのは限定された単独経路です。中継を信頼しないという最重要要件に対し、URL 全体の機密性と静的ページの完全性に依存していることが設計に反映されていません。また、`sudo` 内での長時間の euid 切り替えと並列処理の組合せは、単独の Touch ID PoC では安全性を確認できません。

既存 issue に記録済みの「Developer ID ACL の実機確認」「降格した子からの login keychain 読み出し」は、新たな欠陥として重複計上していません。

## Critical

### 1. 「通知経路で URL を見られても詳細は読めない」は成立しない

- **根拠:** `docs/DESIGN-ja.md:73,88-90`、`docs/decisions/DR-0006-approval-url-and-exchange.md:12,23,29`、`docs/decisions/DR-0008-pluggable-send-command.md:25-26`
- **問題:** URL の fragment に *presigned GET URL と復号鍵の両方*を入れている。fragment が HTTP リクエストでページホストへ送られないことは、通知サービス・APNs・チャット・`send_command` が受け取る URL を隠すことと別である。URL 全体を見られる経路では、期限内なら要求詳細を復号でき、そこに含まれる assertion の PUT URL も得られる。
- **シナリオ:** 通知の配信事業者、通知ログの閲覧者、転送先の侵害者が承認 URL から argv・プロセスツリーを読む。PUT URL へ署名なしデータを書けば、ユーザの承認より先に当該試行を失敗させられる。
- **修正要求:** URL を渡す相手に要求詳細を秘匿できるという記述を撤回する。秘匿が必須なら、復号鍵を通知 URL と独立した認証済み経路から渡すなど、脅威モデルを満たす設計へ変更する。「URL の漏えいは機密性と可用性を失わせるが、署名なしの認証成功は許さない」と明示的に割り切る案もあるが、その場合は目的に掲げた「中継は可用性にだけ影響する」を修正する必要がある。

### 2. 静的ページを信頼しない前提と、ページに表示・署名・登録を任せる設計が両立しない

- **根拠:** `docs/DESIGN-ja.md:12,39,49,73,77-79,88,92-94`、`docs/decisions/DR-0006-approval-url-and-exchange.md:8,12-14,28`
- **問題:** fragment が通常の HTTP リクエストに含まれなくても、ホストが配信する JavaScript は `location.hash` を読める。配信ページを変更できる攻撃者は、復号鍵と PUT URL の取得、要求詳細の偽表示、WebAuthn 呼び出し内容の変更ができる。Mac の検証で challenge が正しくても、**ユーザが見て承認した内容と、実際に署名した challenge の対象が一致する保証にはならない**。
- **シナリオ:** 改ざんされた承認ページが「無害なコマンド」を表示し、裏では本物の sudo 要求から得た challenge に対して passkey 操作を促す。登録ページの改ざんでは、利用者が `add` の Touch ID を通した後、ページが意図しない credential の登録応答を提示できる可能性がある。いずれも、署名が正しくても画面の真正性までは証明しない。
- **修正要求:** ページの配信元と実行コードの完全性を、認証判断に必要な信頼境界として明記する。配信元を信頼しないことを必須要件とするなら、署名前の表示・要求内容との照合を信頼できるクライアント側で完結させる設計が必要。承認と登録の両方について、改ざんされた JS の到達可能性を個別に評価する。

### 3. `sudo` プロセス全体の euid を Touch ID 待機中に変更しながら、別経路を並走させる

- **根拠:** `docs/DESIGN-ja.md:30-36,55-56`、`docs/decisions/DR-0002-single-module-parallel-auth.md:12-15,23-26`、`poc/pam/src/touch_id.m:19-42`
- **問題:** euid の変更は Touch ID 用スレッドだけを独立して降格する操作ではない。同じ `sudo` プロセスで別スレッドの helper 起動・PAM 処理と並走するなら、どの権限で `spawn`、Keychain アクセス、復元処理が実行されるか競合する。PoC は並列 helper を起動していない。さらに PoC は `seteuid` の降格・復元の戻り値を成功条件に含めず、認証自体が成功すれば復元失敗後でも成功を返す。
- **失敗シナリオ:** Touch ID の待機中に別スレッドが想定外の euid で helper を起動する。あるいは復元失敗後に `PAM_SUCCESS` を返して `sudo` に制御を戻す。逆方向では、root のまま誤った利用者の生体コンテキストで評価する。
- **修正要求:** `sudo` 本体の資格情報を跨スレッドで変更しない構成を優先して検討する。やむを得ず採用する場合でも、process-wide な資格情報変更と並列動作の契約を OS 上で検証し、降格・復元失敗を明示的な失敗として処理し、PAM の後続動作まで試験する。単独 PoC の成功を並行設計の実証として扱わない。

### 4. root helper から起動する「ユーザ権限の子」の特権分離が定義されていない

- **根拠:** `docs/DESIGN-ja.md:31,40,104`、`docs/decisions/DR-0003-helper-outside-sudo.md:14-17`、`docs/decisions/DR-0008-pluggable-send-command.md:10-14`
- **問題:** `send_command` は外部コマンドを起動し、`open` も外部プログラムに渡る。仕様は「ユーザ権限に落とす」とだけ記載し、実 UID・保存 UID・GID・補助グループ・継承 FD・環境変数・実行ファイルの解決方法を規定していない。`seteuid` のみでは保存された root 権限が残り得る。
- **攻撃シナリオ:** ユーザが変更できる通知コマンド、またはその実行環境が root の保存資格情報や root helper の FD を引き継ぐと、本来の一般ユーザ権限という境界を越えられる。
- **修正要求:** 子プロセスの永久降格を仕様化し、UID/GID/補助グループ、FD、環境、実行パスを明示的に制限する。敵対的な `send_command` を使った権限復元・FD 経由操作の否定試験を実装前提にする。

## Major

### 5. Touch ID 不可時の即 `PAM_IGNORE` は remote 承認の目的と矛盾

- **根拠:** `docs/DESIGN-ja.md:7,11,30-37,60-64`
- biometry 不可の端末 / SSH でも登録済み passkey が使えるなら remote helper は待つべき。Touch ID だけ失敗として remote の成否を待つ状態遷移に修正。

### 6. WebAuthn の受理条件・登録時検証が未定義

- **根拠:** `docs/DESIGN-ja.md:86-94,101-106`、`DR-0011:17-29`
- challenge / origin / rpIdHash / UV / signCount の列挙だけでなく、`clientDataJSON.type` (get / create)、credential ID と登録公開鍵の対応、authenticatorData と clientDataJSON ハッシュに対する署名、UP、登録での attestation / authData の整合、サイズ / 重複 / 未知 flag の扱いを規定し、改ざんテストを用意する。同期 passkey の signCount=0 は複製検知の保証にならない。user-editable な signCount は信頼できない。

### 7. 署名鍵の喪失・ローテーション・再 setup と旧レコードの失効 / 復旧が未定義

- **根拠:** `docs/DESIGN-ja.md:96-115`、`DR-0011:41-46`
- System Keychain の署名鍵交換で login keychain の全 JWS が無効化され得る。既存 2 つの Keychain issue に、user `add` と root helper の両 ACL 動作、更新署名 (リリース更新) での安定性を受入条件として含め、ローテーション / 復旧を仕様化する。

### 8. PAM 失敗時にパスワードへ確実に流れる保証が無い

- **根拠:** `docs/DESIGN-ja.md:36-38,58,63,66-69`、`DR-0003:26-29`、`findings/2026-11-02-pam-poc.md:12-19,45-49`
- モジュールが crash / 無期限 wait なら後続の PAM に進まず、実際の PAM stack の制御と timeout に依存する。実導入 stack で success / auth_err / ignore / 欠落 / crash / timeout の遷移を確認し、別経路の復旧手順を設ける。

### 9. 祖先 PID / argv / 署名 ID は表示用 snapshot であり、承認主体の証明ではない

- **根拠:** `docs/DESIGN-ja.md:132-141`
- PID 再利用・argv 変更・署名済みアプリが任意実行するケースを考慮し、証明でなく参考情報として表示し、取得失敗時の承認可否を決める。

## Minor

### 10. signCount の署名範囲が DESIGN と DR 間で矛盾

- **根拠:** `docs/DESIGN-ja.md:104,115`、`DR-0011:24-25`
- DESIGN の表は JWS ペイロードに signCount を含むよう読めるが DR は署名対象外と定義。JSONL の行構造と署名対象を一意にし双方を統一する。

### 11. 署名なし拒否・junk PUT・検証失敗が同じ `fail`、「PUT は冪等」だけでは競合時の規則が不明

- **根拠:** `docs/DESIGN-ja.md:82-84,90`、`DR-0006:15-17,29-31`
- 通知 URL 漏洩で連続妨害されても故障と区別できない。ページ向け 3 値を維持しても Mac 側では拒否 / 不正 assertion / ストア障害 / timeout を区別し、書込競合と結果の確定規則を定める。

## 評価不能・未検証

- Developer ID ACL が root helper とユーザ権限 `add` で無対話に機能し、別 binary を拒否するかは未検証 (既知 issue)
- sudo から恒久降格した子の login keychain 読み出しは GUI / 画面ロック / SSH 条件で未検証 (既知 issue)
- LAContext と helper 並列時の euid の境界は PoC 対象外。`sudo -n`、GUI 起動、キャンセル時の PAM 挙動は findings に未観測と記載
- S3 互換ストアの CORS、presigned PUT/GET・期限切れ・書込競合、静的ページの WebAuthn 動作を完成 PoC で確認していない
- root 侵害は PAM / 鍵 / ACL の変更が可能なため本設計で防御できず、同一 uid 悪意プロセス、端末物理操作、iCloud 同期先・アカウント侵害は各々別の脅威境界として明記する

## 実装前に潰す優先順位

1. URL 全体の漏えい時の機密性と静的ページ完全性の信頼境界を確定
2. sudo プロセスの euid と並列制御を実機検証し、安全な隔離方式を選定
3. root helper からユーザコマンドを起動する際の real/saved UID、GID、groups、FD、環境の永久降格を設計・検証
4. 登録・認証の WebAuthn 全受理条件と改ざんテストを確定
5. Touch ID 不可時の remote 継続と PAM fallback / 復旧経路を確定
6. 既知の Keychain 2 issue を解消し、署名鍵のローテーションと復旧を定義
