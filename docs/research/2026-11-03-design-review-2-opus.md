# 改訂後の設計の整合レビュー (opus high、初見)

対象: 2026-11-03 のレビュー裁定反映後の DESIGN-ja / DR-0001〜0012 / webauthn-verification。観点は矛盾・曖昧・過不足 (脅威の再発見はしない)。

## 総評

DESIGN-ja と DR の骨格はおおむね揃っている。気になる点は次の 3 つ。

- 最新コミット (検証は root の helper 自身) に追従していない参照が 2 か所ある
- PAM モジュールと helper の間のやり取り (何を渡し、何を返し、どの fd を使うか) がどこにも決まっていない。DR-0012 の判定規則 (使えない / 失敗 / 成功) と DESIGN のページの振る舞い (Touch ID で通ったら「承認済み」) が、この欠落のせいで実装できない
- 前回の処置表のうち数件が未反映か、後の裁定で覆ったのに注記が無い
- 対象外だが、英語版 DESIGN.md と README が暗号化・クリップボード・test/doctor・signCount の設計のままで、正本と大きく食い違っている

## 指摘 (重要度順)

### 1. [矛盾] DR-0003 の要約が「通信と検証は降格した子」のまま

- 根拠: DESIGN-ja.md:194、DR-0006:42
- 正本: DESIGN-ja.md:98、DR-0003:19-20 は「通信・検証・result の PUT は root の helper 自身が行い、子は PAM_USER の権限が要る処理だけ」
- 直し方: 2 か所を DR-0003 の現在の Decision に合わせる

### 2. [矛盾/不足] Touch ID で通った時にページが「承認済み」になる仕組みが無い

- 根拠: DESIGN-ja.md:107、DR-0006:21 (先に Touch ID で通ればページが「承認済み」に切り替わる)。一方 DR-0012:31 と DESIGN:54 は「どちらか成功したらもう片方を止める」。DR-0006:20 は result を「helper の判定 (assertion の検証結果)」として定義
- 問題: ページが切り替わるには、Touch ID 成功を知った helper が止まる前に result=pass を PUT する必要がある。誰が・いつ PUT するか、pass の意味 (assertion の検証結果か、認証全体の結果か) が決まっていない。キャンセル / 期限切れ / Touch ID 失敗の時にページが何を表示するかも未定
- 直し方: result を「この要求の認証全体の結論」と定義し直す。終了経路ごとに helper が PUT する値 (pass / fail / 書かない) を DR-0006 か DR-0012 に表で足す

### 3. [不足] PAM モジュールと helper の間の取り決めが未定義で、DR-0012 の 3 値判定が実装できない

- 根拠: DR-0012:42 は「成功は要求 ID を含む明示メッセージだけ。exit 0・EOF・それ以外の出力は失敗」。一方 DR-0012:28-29 と DESIGN-ja.md:83 は、remote が「使えない」(登録 0 件、ストア不達、keychain ロック中) 場合を PAM_IGNORE のために「失敗」と区別する
- 問題: 登録 0 件・ストア不達・keychain ロックは helper の起動後にしか分からないが、helper が「使えない」を伝える手段が定義されていない。DR-0012:42 の規則に従うと全部「失敗」になる
- 同じく未定: 要求 ID を誰が作るか (request JSON の `nonce` との関係) / PAM から helper へ渡すもの (PAM_USER、プロセス情報、要求 ID) とその経路 (argv か stdin か) / 「詳細を確認」が押されたことを helper に伝える経路 / キャンセルや期限で helper を止める方法 (signal か pipe close か) / `send_command` 未設定時の「tty 表示」を helper が fd 1/2 に書くのか PAM の conversation に戻すのか
- 直し方: helper の入出力の取り決め (fd ごとの役割、メッセージの種類 = 成功 / 使えない / 失敗 / 表示してほしい URL、要求 ID の生成者) を DR-0003 か DR-0012 に 1 節足す

### 4. [不足] PAM が helper の絶対パスをどう知るか、setup が `.so` の置き場をどう知るか

- 根拠: DR-0003:23、DR-0003:28-29
- 問題: PAM モジュールは Keychain を読まないので、helper のパスはビルド時の固定値か pam.d のモジュール引数。nix-darwin は store パスなので固定値にできない。`setup` が `.so` の実際の場所をどう特定するかも未定
- 直し方: helper のパスの決め方 (例: pam.d の引数) と、setup がそれを知る経路を DR-0003 に書く

### 5. [矛盾] 「呼び出し元の euid が 0 でなければ降格しない」と「使うのは PAM_USER のものだけ」が両立しない

- 根拠: DR-0012:48 と DR-0012:20-24。DESIGN:98 と DR-0003:31 も同じ
- 問題: euid≠0 の呼び出し元が自分と違う PAM_USER を認証すると、Touch ID は呼び出し元の生体で評価されてしまう
- 直し方: 「euid≠0 かつ 呼び出し元の uid ≠ PAM_USER の uid なら Touch ID を使えない扱い」等の規則を DR-0012 に足す

### 6. [曖昧] setup の再実行の扱いと、設定の受け取り方

- 根拠: DESIGN:143、DR-0011:18、DESIGN:163、DR-0010:13
- 問題 1: y/N で N の時に setup 全体を中止するのか、署名鍵は残して他の設定だけ更新するのかが未定。後者が無いと send_command を変えるだけで全登録が無効になる
- 問題 2: `store` (JSON、秘密を含む) と `send_command` を setup がどこから受け取るか (対話入力か stdin か) が未定
- 直し方: N の時の動作と設定だけ更新する経路の有無、store と send_command の入力方法を DR-0010 に書く

### 7. [不足] 登録の交換形式が承認と比べて決まっていない

- 根拠: webauthn-verification:32、DESIGN:131
- 未定: 登録ペイロードのフィールド (credential の PUT 先、期限、`user.id` / `user.name`、`pubKeyCredParams`、attestation の要否) / 登録 URL の形 / 1 つの `page_url` から登録ページと承認ページを区別する方法 / `add` の待ちの期限 / 登録側の受理条件に「期限」「1 回限り」の行が無い
- 注: `user.id` の決め方によっては、同じ iCloud アカウント上で既存の passkey が上書きされる可能性がある (未検証)
- 直し方: DR-0006 の request JSON と同じ粒度で、登録ペイロードと登録 URL を DR-0011 に書く。webauthn-verification の登録表に期限と使用回数の行を足す

### 8. [曖昧] 実装者が決められない形式・値

- assertion / credential / result オブジェクトの形式 (JSON のキー、base64url か、result の本文が `pass` という文字列か) / `expires` の形式 / JWS の鍵種と alg / サイズ上限の値
- 直し方: 未決事項に入れるか、design/ に交換形式の付随文書を起こす

### 9. [矛盾] 目的の「ストアは可用性にだけ影響」が DR-0006 と食い違う

- 根拠: DESIGN-ja.md:12、DESIGN:41 と DR-0006:38 (result はストアで書き換えられる)、DESIGN:41 (要求詳細は暗号化しない)
- 直し方: 「承認を通す方向には働かない」に留め、「可用性にだけ」を削る

### 10. [用語] 「helper」が 2 つの意味で使われている

- DESIGN:49/66 は「PAM から呼ばれる内部サブコマンド」。DESIGN:141、DR-0011:16,21,33、DR-0005:27 は「Developer ID 署名のバイナリ全体」
- 直し方: ACL と署名の文脈では「`pam-passkey` バイナリ」と書き、helper は内部サブコマンドに限定

### 11. [不足] 状態遷移表の欠けた行

- 「詳細を確認」を押した時に remote が使えなかった場合 (fallback ボタンを出すか) / remote 走行中に Touch ID が失敗した場合 (継続するか) / LAError コードと行の対応 / 「生体が登録されていない」は policy が companion を含むので「policy を評価できない」が正確 / GUI セッション有無の判定方法

### 12. [曖昧] プロセス情報を集めるのは誰か

- DESIGN:181 / DR-0012:46 は PAM 内で集める (SecCode* 含む)。DESIGN:19 は「呼び出し元プロセス内のロジックは増やさない」。root の helper でも全 pid は取れる
- 直し方: PAM に置く理由を書くか、収集を helper に移す

### 13. [曖昧] send_command の起動形式と環境の許可リスト

- シェル経由か argv 分割か、許可リストの中身 (PATH / HOME / LANG、ssh なら SSH_AUTH_SOCK)、cwd の値

### 14. [反映漏れ] issue 2 件が処置表 #12 と現在の設計に追従していない

- 受け入れ条件の拡張が未反映。login-keychain の issue は「呼び出しユーザ」「sudo の PAM から spawn した子」のまま。ACL の issue の対象は store だけ

### 15. [反映漏れ / 後で覆った件に注記が無い] 処置表の項目

- #20 (解析は降格した子) は逆になったが DR-0003 の不採用案に無い。DR-0003 の不採用理由「root の sudo 内で TLS」は論拠が弱い (要点は「sudo プロセス内」)
- #17 (getuid / 許可リスト) は置き換わったが処置表に注記が無い
- #14 の「list は生の JWS を出さない」が文書に無い (撤回済みなら処置表を直す)
- #4 の pthread_setugid_np 検証 issue が未起票
- #22 の Touch ID 本文の切り詰めが DESIGN に無い
- PK-Q2 / PK-Q3 の裁定結果が辿れる形で残っていない

### 16. [状態の不整合] PK-Q4

- QUESTIONS で b にチェック済みのまま裁定待ちに残り、DESIGN は未決、処置表 #16 は「出す」

### 17. [矛盾] DR-0012 の未観測と findings が一致しない

- DR-0012:72 の Ctrl-C と GUI 起動 sudo は findings の未観測に無い (GUI は PAM_TEXT_INFO の送出先のみ)

### 18. [曖昧] 期限の起点

- PAM のタイマーと request の `expires` のどちらか。期限ぎりぎりの assertion を検証中に PAM が諦めた場合

### 19. [曖昧] DELETE の範囲

- 承認後以外 (fail / 拒否 / Touch ID 成功 / 期限切れ)、result、登録のオブジェクト

### 20. [曖昧] setup が CORS と lifecycle を「設定するのか、確認するのか」

### 21. [過剰] DESIGN 内の重複と説明

- :81-88 は DR-0012 の言い直し (:84 は :83 の部分集合、:86 は DR-0012 に無い独自行) / :113 と :124 で拒否を 2 回 / :142 の Authorization right は findings で足りる / :145 は DR-0011 の写し / :150 の fork は :37 と重複 / 承認 URL の節 (:102-116) は DR-0006 とほぼ同文

### 22. [曖昧] DESIGN:157 の「Touch ID の有無」をコードの既定値とする記述 (意味が取れない)

### 23. [曖昧] AX によるウィンドウの raise

- DESIGN:73 と DR-0003:43 は確定事項のように書くが DR-0009:26 は条件付き、findings では問題は未再現。root helper と子のどちらが行うかも未定

### 24. [不足] DR-0002 が古い (PAM_IGNORE と DR-0012 への参照が無い)

### 25. [曖昧] request JSON の details

- `user` が呼び出したユーザか PAM_USER か / 承認画面の「時刻」がフィールド一覧に無い / request に credential id (allowCredentials) を入れるか

### 26. [用語] 「sudo プロセス」と「呼び出し元のプロセス」の揺れ。add の本人確認は policy が deviceOwnerAuthentication なのでパスワードでも通る (「Touch ID」と書き切っている箇所)

### 27. [曖昧] CLI の細部: `add` の label 既定値、label の一意性、`list` の出力項目と JWS 検証の有無

### 28. [範囲外の不整合] 英語版 DESIGN.md と README (暗号化、fragment の鍵、クリップボード、signCount、test / doctor、3 値 result が残っている)

### 29. [規約] 文中改行・HTML コメント・経緯表現・レビュアー名は本文に無し。research/ のファイル名と処置表にレビュアー名・「統括」「インキュベーター」が出る
