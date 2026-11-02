# pam-passkey 設計レビュー (opus high、初見・第三者の立場から)

## 総評

方向性は筋が良い。PAM を薄くして sudo の外に処理を出す点、中継を信頼せず passkey 署名の検証で真正性を担保する点は妥当。

ただし、このまま実装に入るのは止めるべき。「中継を信頼しない」「同じ uid のプロセスに昇格させない」という主張が、現状の記述では成り立っていない。崩れているのは次の 2 点:

- **承認ページが、表示した内容と署名対象を結びつけていない**。ローカルのマルウェアが偽の詳細を見せて、本物の challenge に署名させられる (C1)
- **DR-0011 の `add` で、Touch ID がどの鍵に署名するかに結びついていない**。結果として、ユーザ権限から鍵を登録させる装置になっている (C2、C3)

どちらも実装の注意で済む話ではなく、プロトコルとデータの置き場所の設計を直す必要がある。加えて、信頼の前提の記述に事実と違う箇所が複数ある (ページを配信する側を信頼していないと書いている、通知経路から中身が読めないと書いている、承認が 1 件の要求に結びつくと書いている)。

この場で実際に確かめたのは: `/opt/homebrew` 配下はユーザ (kawaz) が所有している / 他ユーザ (root 含む) のプロセスの argv が `ps` で読める。これ以外の環境依存の主張は「未検証」。

## Critical

### C1. 承認ページが challenge を表示内容から計算する決まりがない。ローカルのマルウェアが偽の詳細で本物の要求に署名させられる

- **根拠**: DESIGN-ja「承認 URL と交換の流れ」(request JSON が `details` と `challenge` を別フィールドで持つ)、「暗号学的な束縛」(Mac 側だけが challenge の一致を検証)、DR-0006
- **問題**: helper は「assertion の challenge が自分の計算値と一致するか」だけを見る。ページが何を表示したうえで署名させたかは何にも結びついていない。ページが request の `challenge` をそのまま WebAuthn に渡す実装だと、表示と署名対象を別々に作れる
- **攻撃シナリオ** (同じ uid のマルウェア、中継の侵害は不要):
  1. マルウェアが `sudo <悪性コマンド>` を起動。`send_command` 未設定なら承認 URL はマルウェア自身の pty に出る。設定済みでも `send_command` の実体はユーザが書き換えられるスクリプトで、URL を横取りできる
  2. URL の鍵で request を復号し、本物の `challenge` / `nonce` / `expires` / `assertion_put_url` を得る
  3. `details` だけ無害な内容に差し替えた request を自前ホストに置き、`page_url#<偽 GET URL>.<偽の鍵>` を作る。ページのドメインは本物なので passkey は使える
  4. その URL をユーザに届ける (ユーザ権限の通知コマンドを自分で叩く / Mac 上で `open` して「詳細を確認」で開いたように見せる)
  5. ユーザは無害な詳細を見て署名。ページは本物の `assertion_put_url` に PUT し、helper は challenge 一致で pass。悪性コマンドが root で走る
- **修正要求**:
  - ページは `challenge = SHA-256(正規化した details ‖ nonce ‖ expires)` を**自分が描画する details のバイト列から自分で計算する**。request に `challenge` フィールドを持たせない
  - details の正規化 (canonical serialization) を仕様として決め、helper とページで同じ実装を共有する (テストベクタを用意)
  - 表示の無害化も仕様にする: 制御文字 / bidi / ゼロ幅文字はエスケープして見せる、切り詰めは明示、切り詰めたら全文を見るまで署名ボタンを有効にしない
  - これで中継経路からの差し替えは防げる。ページそのものの改ざんは防げないので C4 と合わせて対処

### C2. `add` の Touch ID がどの鍵に署名するかに結びついていない。クリップボードを差し替えると攻撃者の鍵が登録される

- **根拠**: DR-0011 Decision の `add` 手順 1〜4、DESIGN-ja「登録」
- **問題**: Touch ID は手順の先頭にあり、その後に貼り付けられる公開鍵の中身を見ていない。同じ uid のプロセスはペーストボードを自由に書き換えられる。attestation を使わない (`none`) なら登録データは誰でも作れる。registration challenge も登録 URL を `open` した時点で argv に出る (M5) ので攻撃者から見える。「CLI が検証する」の中身は形式と challenge の確認だけ
- **攻撃シナリオ**: マルウェアが `pam-passkey add` の実行を `ps` で待ち、ユーザが Touch ID を通してページで passkey を作りコピーした直後にペーストボードを自分の鍵ペアの登録データに差し替える。CLI は検証・署名・保存。以後マルウェアは自分の秘密鍵で自分の sudo を承認できる
- **修正要求**:
  - Touch ID の評価を**貼り付けと検証の後、署名の直前**に移す。`localizedReason` に credential の短い指紋 (公開鍵 SHA-256 の先頭 8 バイト程度) とラベルを出す
  - 登録ページ (iPhone 側) にも同じ指紋を表示し、ユーザに照合させる
  - 登録 challenge は 1 回限りにし、`add` プロセスが生きている間だけ有効
  - 指紋照合はユーザの注意力に頼る方式。DR-0011 の「昇格を塞ぐ根拠」は「ユーザが指紋を照合する」前提つきに書き直す。より強くするなら M3 の選択肢

### C3. helper が「ユーザが自由に起動でき、秘密を使える」プログラムになっている。秘密を使う全ての入口を絞る決まりが設計にない

- **根拠**: DESIGN-ja「状態と設定」(ACL は Developer ID 署名の helper だけ)、DR-0011「昇格を塞ぐ根拠」
- **問題**: Keychain の ACL は uid でなく**コードの同一性**で判定する。署名済みの `pam-passkey` を起動さえすれば、どの uid からでも署名鍵と store の秘密に届く。hardened runtime が防ぐのはメモリ介入とライブラリ注入だけで、**正規の入口 (サブコマンド、引数、環境変数、標準入力) からの呼び出し**は防げない。秘密を使う経路は Touch ID の関門を通るものだけ、という不変条件が設計に無い
- **失敗シナリオ**: PAM 用内部サブコマンドが stdin で「検証済み」状態や署名対象を受け取る実装になる / `test` や `doctor` が署名鍵を使う・store 設定を表示する / 環境変数で参照先 (Keychain の service 名、`page_url`、rp_id) を切り替えられる
- **修正要求**:
  - 「署名鍵を読むのは `add` の、Touch ID 成功後の 1 か所だけ」を設計上の不変条件として DESIGN に書き、テストで固定する
  - 内部サブコマンド (PAM から呼ばれるもの) は、ユーザ権限から直接呼ばれても署名鍵を読まない作りにする。「PAM から起動された」ことは証明できない (親が root / ruid と euid の組で推定はできるが偽装余地がある) ので、検証の正しさをそこに頼らず「内部サブコマンドは秘密を使わない」設計にするのが本筋
  - `test` / `doctor` は署名鍵を読まず、store の秘密を表示しない
  - 環境変数・引数で参照先 (Keychain の service 名、`page_url`、rp_id) を切り替えられないようにする。読む環境変数は許可リスト制

### C4. helper と `.so` の置き場の所有権が設計に無い。ユーザ所有の場所 (Homebrew 等) に置くと同 uid から即 root

- **根拠**: DESIGN-ja「増やさないもの: Mac 上のファイル・ディレクトリ・パーミッション」、DR-0003 (helper は root で動く)、archive の DR-0007 は配布形態に brew を挙げていた
- **問題**: helper は root で spawn される。実機で `/opt/homebrew`、`/opt/homebrew/bin`、`/opt/homebrew/lib` が kawaz 所有であることを確認した。helper か `.so` (または親ディレクトリ) がユーザの書けるパスにあれば、同 uid のプロセスが差し替えて root を取れる。「パーミッションを持たない」という原則のせいで、この検討が設計から抜けている
- **攻撃シナリオ**: brew で入れた `pam-passkey` を、同 uid のマルウェアが自前のバイナリに置き換える → 次の sudo で PAM が root で spawn → root 奪取 (passkey も Touch ID も不要)
- **修正要求**:
  - DESIGN に「`.so` と helper は、親ディレクトリまで root 所有・他者書き込み不可のパスに置く」「PAM は spawn 前に owner/mode を確認し、合わなければ remote 経路を諦める」「`doctor` も検査する」を明記
  - helper のコード署名 (designated requirement) を PAM が検査するのは補助としては良いが、検査から exec までの TOCTOU があるので所有権要件の代わりにはならない
  - spawn の手順を決める: 絶対パスで起動、環境は空にして必要なものだけ渡す (`PATH` / `HTTPS_PROXY` / `SSL_CERT_FILE` / `DYLD_*` / `AWS_*` 等を sudo の環境から引き継がない)、0/1/2 と専用 pipe 以外の fd を閉じる、umask と cwd を固定

### C5. 信頼の前提の記述が事実と違う。ページの配信元と rp_id のドメインは TCB に入っている

- **根拠**: DESIGN-ja「目的」(中継路 = オブジェクトストア / 通知サービス / APNs / CDN は信頼しない)、コンポーネント表 (既定は GitHub Pages、`rp_id` は `page_url` から導出)
- **問題**:
  - ページの JS は、復号鍵を受け取り、表示し、WebAuthn に署名させる当事者。配信元 (GitHub Pages、そのリポの書き込み権、作者の GitHub アカウント) を改ざんできれば、C1 を直した後でも「見せる内容」と「署名させる challenge」を分けられる。中継ではなく TCB そのもの
  - `<user>.github.io` を既定にすると、同じユーザの全 project pages が同一 origin (origin にパスは含まれない) になる。他リポのどれか 1 つに XSS / 悪意ある依存 / 侵害があれば、そこから同じ RP の passkey で assertion を作れ、helper の origin 検証では区別できない
  - 既定の `page_url` を使う全利用者が作者の GitHub アカウントを信頼することになる (サプライチェーン)
- **修正要求**:
  - 信頼の前提を書き直し「ページの配信元と rp_id のドメインは TCB」と明記
  - rp_id はこの用途専用の origin にする (専用カスタムドメイン、または専用 org の `*.github.io`)。共用の user pages は不可
  - ページは外部スクリプトを読まない単一ファイルにし、`<meta>` で CSP を設定。リリースごとのハッシュ公開も検討
  - GitHub Pages は `frame-ancestors` をヘッダで付けられず meta CSP では効かないので、M7 の `crossOrigin` / `topOrigin` 検証が必須

## Major

### M1. 「承認は要求の内容そのものに束縛される」は実効上成り立たない (sudo の timestamp で 5 分間無認証)

- **根拠**: DESIGN-ja「暗号学的な束縛」と「扱わないもの」(timestamp は sudoers の責務)、findings/pam-poc
- **問題**: remote 承認の主用途は、離席中にエージェント等が叩いた sudo の承認。1 件承認すると、同じ tty の後続 sudo は承認なしで通る。ユーザが見て署名したのは 1 コマンドだが、実際に許したのは「その tty で 5 分間 root」
- **修正要求**: DESIGN と承認画面に明記 (未決事項 3 番目は「出す」で確定)。remote 承認を使う場合は `Defaults timestamp_timeout=0` (対象ユーザ限定でも可) を推奨設定にし、`doctor` で警告する。モジュール側から timestamp を制御できないことも書く

### M2. PAM_USER と呼び出しユーザの一致が不変条件として明示されていない

- **根拠**: poc/pam/src/touch_id.m は `getuid()` で評価、DESIGN の login keychain 読み出しは「呼び出しユーザ」、検証は「認証対象のユーザと一致」、DR-0001 は sudo 以外のサービスにも置けると書く
- **問題**: sudoers の `targetpw` / `rootpw`、`su` / `login` のスタックに入れた場合、呼び出しユーザの Touch ID / passkey で別ユーザ (root) として認証されてしまう。ruid が root のサービスでは seteuid の前提も崩れる
- **修正要求**: 「PAM_USER が getuid() のユーザ名と一致し、service が許可リスト (初版は sudo のみ) に含まれる時だけ動く。それ以外は `PAM_IGNORE`」を設計上の不変条件にする

### M3. DR-0011 の得失。「安全性は同等」は誤りで、失効ができない

- **根拠**: DR-0011 不採用案表の 1 行目、Decision の `del`、signCount の扱い
- **問題**:
  1. 失効ができない: `del` は項目を消すだけ。署名済みの行を事前に写しておいた同 uid のプロセスはいつでも書き戻せる。紛失端末の passkey を `del` してもマルウェアが戻せば有効のまま。真の失効は署名鍵の再生成 (setup やり直し + 全ユーザ再登録) しか無く、その手順も設計に無い
  2. C2 / C3 はこの DR で初めて生じた。DR-0007 方式ならユーザ権限で起動できる署名オラクル自体が存在しない
  3. signCount の「減少していない」確認は無意味: 署名の外のユーザ書き込み可能な項目なので攻撃者が値を戻せる。Apple の同期 passkey は常に 0
  4. ハシゴ外しの根拠が弱い: モジュールが壊れても失敗はパスワードに流れるので `sudo pam-passkey add` は動く。`sudo_local` を直すにはどのみち root が要る。`add` を sudo 抜きにしても復旧可否は変わらず、得られるのは「`add` でパスワードを打たなくて済む」利便性だけ
  5. 前提が未検証 (login keychain のロック / ssh / ユーザ切替。既存 issue)
- **代替案** (混ぜずに並列):
  - (A) DR-0007 方式に戻す。全状態を root が書く場所に置き、`add` / `del` は sudo。失効が成立し、署名オラクルが生まれない。コストはパスワード入力 1 回分
  - (B) DR-0011 維持 + C2 修正 (指紋照合) + 失効用の root 書き込み状態 (失効リストか世代番号) を System Keychain に追加。ただし `del` を効かせるには root が要り、DR の目的と矛盾する
  - (C) Secure Enclave + biometry ACL の鍵。OS が Touch ID 無しの署名を拒むので C3 は塞がるが、C2 (何に署名するか) は残る
  - 推奨は (A)。(B) は利便性と引き換えに失効を諦めることになる

### M4. Developer ID の ACL が実際に何を信頼するか。旧版への巻き戻し、fork、nix で破綻する

- **根拠**: DR-0011 Consequences、DESIGN-ja「PAM への組み込み」(nix-darwin では store パス)
- **問題**:
  - ACL の照合は通常 identifier + Team ID の designated requirement。同じ Team ID で署名された旧版 helper も全部通る。旧版に C3 型の不具合があれば、それを入手して実行するだけで署名鍵を読める。バージョン固定はできない
  - fork で自前ページを使う人・自前 build の人は自前の Developer ID (年額) が要る
  - nix-darwin の derivation で build した成果物は ad-hoc 署名なので、DESIGN にある nix-darwin 導線と両立しない
  - 依存する `SecAccessCreate` / `SecTrustedApplication` はレガシーなファイル型 keychain の deprecated API で、将来が不透明
- **修正要求**: 既存 issue の受け入れ条件に「同 Team ID の別 identifier から読めるか」「旧版バイナリから読めるか」「root の `security find-generic-password -w` から読めるか」を追加。配布形態 (Developer ID + notarize の pkg のみか、nix / brew も対象か) を DR で決める。M3 で (A) を選び helper が root なら、store の秘密は「root だけが読める置き場」で守れ、Developer ID 依存そのものを外せる。この比較案を DR に載せるべき

### M5. Mac 側の「詳細を確認」経路は iPhone 側より明確に弱い

- **根拠**: DESIGN-ja の受け手 (Mac)、DR-0004
- **問題**:
  - `open <承認 URL>` で復号鍵入りの URL が argv に載る。実機で他ユーザ (root 含む) のプロセスの argv が `ps` で読めることを確認した。同じ Mac の別ユーザにも見える
  - ブラウザ履歴に fragment ごと残る可能性 (未検証)。Safari 履歴が iCloud 同期されれば他端末にも広がる
  - 同 uid のマルウェアはブラウザ拡張や Apple Events (TCC 許可要) で本物の origin 上に任意の内容を描ける。macOS の passkey ダイアログは RP とアカウントしか出さず、何に署名するかは出ない
  - registration challenge も同じ経路 (`add` の `open`) で argv に出る (C2 の攻撃者がこれを得られる)
- **修正要求**: Mac 経路は「同 uid のマルウェアが居ない前提でのみ有効」と信頼の前提に書く。承認が済んだら helper がストアのオブジェクトを DELETE し、バケットの lifecycle ルールも保険として推奨。argv 露出を許容するかを明記する

### M6. 「経路上で URL を見られても期限内に中身を読まれない」は誤り

- **根拠**: DESIGN-ja「暗号学的な束縛」2 項目め、DR-0006 Consequences
- **問題**: 復号鍵は URL の fragment にあり、`send_command` には URL ごと渡す。通知サーバ・APNs ペイロード・チャットのサーバは、期限内なら中身を読める。暗号化が守るのはストア運営者とページのホストに対してだけ。DESIGN 自身が「argv は秘密を含み得る」と書いており、「中継は可用性にだけ影響する」は機密性について成り立たない
- **修正要求**: 記述を事実に合わせる。通知事業者に見せたくない人向けに argv を伏せる (コマンド名だけ見せる) 既定または選択肢を検討

### M7. WebAuthn の検証項目が不足

- **根拠**: DESIGN-ja「暗号学的な束縛」(列挙は origin / rpIdHash / UV / signCount のみ)
- 認証時に追加が要る項目: `clientDataJSON.type == "webauthn.get"` / origin は scheme・host・port の完全一致 / `crossOrigin` が false または不在、`topOrigin` 不在 (C5 のため iframe 埋め込みでの署名を拒む) / UP と UV の両フラグ / credential id がそのユーザの登録済み集合に含まれること (ページの `allowCredentials` は改ざんされ得るので helper 側で判定) / 署名アルゴリズムを ES256 に固定、authData 長の上限 / challenge は 1 回限り (helper の待ち状態を消費したら破棄) / 期限は Mac の時計で helper 自身が判定
- 登録時: `type == "webauthn.create"`、AT フラグ、COSE alg の制限、credential id 長の上限
- 同期 passkey: BE / BS フラグの扱い (同期鍵を許すか) を決め、受け入れたものを登録時に記録
- signCount: 検証項目から外すか、「セキュリティ上の効果は無い」と明記

### M8. 同期 passkey により iCloud (またはサードパーティの passkey プロバイダ) が TCB に入る

- **根拠**: DR-0004 (「iCloud 同期された同じ passkey」)。信頼の前提への記載なし
- **問題**: iCloud キーチェーンが同期される全端末、passkey 共有グループのメンバー (未検証)、1Password 等のプロバイダのクラウドが承認主体に含まれる。アカウント乗っ取り + ローカルで sudo を起こされることで昇格
- **修正要求**: 信頼の前提に明記。デバイス束縛の鍵だけを受け入れる設定 (BE=0) や AAGUID 制限を選択肢として検討 (Apple の AAGUID の扱いは未検証)

### M9. 失敗時の分岐 (Touch ID 不可、キャンセル、ssh、ハング) が未定で、一部 DR と矛盾

- **根拠**: DESIGN-ja「失敗時の振る舞い」、DR-0002、findings/pam-poc 未観測、PoC は `DISPATCH_TIME_FOREVER` で待つ
- **問題**:
  - Touch ID 不可時 (蓋閉じ・指紋未登録・GUI セッション無し) に remote だけでも走らせるのかが曖昧。走らないなら主用途が成り立たない
  - ssh 経由の sudo: Touch ID ダイアログが手元 Mac の画面に出ると confused deputy になる。ssh 鍵を盗んだ攻撃者が sudo すると作業中のユーザの画面にダイアログが出て反射的にタッチされる (未検証)
  - キャンセル: Touch ID をキャンセルしても remote 側が最大 90 秒待ち続け、パスワードに降りられないと読める
  - ハング: LAContext の reply や helper が返らないと sudo が無期限に止まる。もう 1 つのハシゴ外し
  - 成功判定: helper の exit 0 を成功とみなすと crash / pipe EOF 時の扱いが曖昧
- **修正要求**: 状態遷移表を DR として書く (GUI 有無 / ssh 由来 / 指紋登録有無 / キャンセル / fallback / 期限切れ / helper 起動失敗 / Ctrl-C ごとに、Touch ID と remote それぞれの動作と PAM の戻り値)。ssh 由来なら Touch ID を出さず remote のみ。キャンセルは両方止めて即 `PAM_AUTH_ERR`。全ての待ちに期限。helper の成功は要求 ID を含む明示メッセージでのみ認め、それ以外は失敗 (デフォルト拒否)

### M10. seteuid はプロセス全体に効き、並走処理と競合する

- **根拠**: DESIGN-ja「PAM モジュールの制約」、poc/pam/src/touch_id.m
- **問題**: 最大 90 秒の評価中、sudo プロセス全体の euid がユーザになる。その間に別スレッドで helper を spawn すると helper は root にならず DR-0003 の前提が崩れる。PoC は `seteuid(0)` の復帰失敗時に何もしていない
- **修正要求**: 順序を固定 (helper spawn とプロセス情報の収集を済ませてから euid を落とす)。復帰失敗は `PAM_AUTH_ERR`。代案として `pthread_setugid_np` でのスレッド単位の切替、または LAContext をユーザ uid の子プロセスで評価する案を検証 (どちらも未検証)

### M11. helper を root で動かす必要性の説明が無く、攻撃者が制御するデータを root で解析する

- **根拠**: DR-0003 Decision (理由が無い)
- **問題**: presigned PUT を持つ者 (通知経路で URL を見た者を含む) が書いた assertion を、root の helper が TLS / JSON / CBOR / COSE で解析する。root が要るのは他 uid のプロセス情報の取得くらいで、それは PAM 内 (既に root) で集めて pipe で渡せる
- **修正要求**: root が要る処理を列挙し、それ以外は権限を落とした子に分ける。少なくともネットワークと解析は無権限で行い、root 側は「検証済みか」だけを受け取る構成を DR で検討

## Minor

- **signCount の記述が食い違い**: DESIGN-ja の状態表はペイロードに signCount を含める。同じ DESIGN の「認証時の読み出し」と DR-0011 は「署名の外」。どちらかに揃える (M3 / M7 の結論次第で項目ごと消す)
- **findings の古い示唆**: findings/keychain-poc の「実用的な示唆」に「書き込みは `sudo pam-passkey setup` / `add` / `del` のように root で」が残り DR-0011 と矛盾。示唆の節に DR-0011 への相互参照を付ける
- **検証用の公開鍵の置き場が無い**: 状態表に署名鍵 (秘密鍵) しかない。検証するのが秘密鍵を読める helper だけなら非対称の JWS は不要で HMAC で足りる。どちらにするか明記
- **fragment の形式**: `<presigned GET URL>.<鍵>` の区切りが `.` で URL 自体に `.` が含まれる。「最後の `.` で分割、鍵は base64url」と仕様化するか `#u=...&k=...` 形式にする
- **Touch ID ダイアログ本文の切り詰め**: PoC は 120 バイトで切る。空白で埋めれば危険な末尾を隠せる。「コマンド名 + 引数の数 + 末尾」を見せる等の工夫の余地
- **承認画面の偽装**: ad-hoc 署名のバイナリに「Terminal」等の名前を付けられる。署名なし / ad-hoc / platform を視覚的に強く区別
- **result オブジェクトは偽装可能**: ストア運営者は result を書き換えてページに偽の pass / fail を表示させられる。「ページの表示は参考情報」とページ側にも書く
- **presigned PUT と DoS**: presigned PUT ではサイズを縛れないので helper は GET サイズに上限を設ける。同じ URL への上書き競争で DoS。「junk でも fail 確定か、期限まで待ち続けるか」を決める
- **バケットの CORS 設定**: ページ origin からの GET / PUT を許す CORS 設定が setup 手順にも `doctor` にも無い
- **同一 Mac の複数ユーザ**: store と `send_command` はシステムで 1 つ。別ユーザの sudo 通知が setup したユーザの端末に飛ぶ
- **承認疲れ (MFA fatigue)**: マルウェアが sudo を連打すると通知も連打。レート制限の方針が無い
- **Apple Watch**: policy `...WithBiometricsOrCompanion` では Apple Watch での承認も通る。明記
- **`test` が本番経路と一致しない**: `test` はユーザ権限で一周するが本番の helper は root (M11)
- **sudo 内での待ちと Ctrl-C**: `dispatch_semaphore_wait(DISPATCH_TIME_FOREVER)` 中に Ctrl-C が効くか未観測

## 評価できなかった点・未検証と明記すべき点

- macOS 26 のペーストボードのプライバシー制限 (プログラムからの読み書きに確認が出るか): 未検証。C2 の攻撃は書き込みだけで足りるので結論は変わらないと見ている
- ssh セッションからの sudo での pam_tid / LAContext の挙動 (M9)
- `pthread_setugid_np` 下での LAContext 評価 (M10)
- setuid 状態の親から exec された hardened runtime の helper での `DYLD_*` 等の扱い。結論に関わらず環境を空にする対策 (C4) は要る
- Developer ID の ACL が旧版・同 Team ID の別バイナリを通すかは一般仕様としての理解で、実機未確認 (M4)
- ブラウザ履歴が fragment ごと残るか、iCloud で同期されるか (M5)
- passkey 共有グループ、Apple の AAGUID と BE/BS の実際の値 (M8)
- root の helper から `open` した時にユーザの GUI セッションへ届くか (`launchctl asuser` が要るか)
- 既存 issue `login-keychain-read-from-sudo` に足すべき観点: ファストユーザスイッチ、login keychain のパスワードがログインパスワードとずれてロックされたままの状態、ssh 由来の子の audit session での securityd の見え方
- 実機で確認済み: `/opt/homebrew`、`/opt/homebrew/bin`、`/opt/homebrew/lib` は kawaz 所有。他ユーザ (root 含む) のプロセスの argv は `ps` で読める
- 設計外だが環境で気づいたこと: 稼働中の `/etc/pam.d/sudo_local` に PoC の 2 行が残っている。`pam_poc.so` は Touch ID 成功で `PAM_SUCCESS` を返すため本番の sudo 認証経路に入ったまま

## 実装前に潰すべきもの (優先順)

1. **C1**: ページが challenge を表示内容から自分で計算する。details の正規化仕様とテストベクタ
2. **M3 の判断**: (A) DR-0007 方式に戻すか (B) DR-0011 維持かを決める。これで C2・C3・M4 の要否が決まるので他より先に
3. **C2 / C3**: (B) なら `add` の Touch ID を署名直前に移して指紋照合。秘密を使う入口の不変条件を書いてテストで固定
4. **C4 / M11**: 置き場の所有権要件、spawn 手順 (絶対パス / 空の環境 / fd を閉じる)、helper の権限分割
5. **C5 / M1 / M6 / M8**: 信頼の前提を書き直す (ページの origin と専用 rp_id、iCloud・passkey プロバイダ、通知経路での機密性、timestamp)
6. **M2**: PAM_USER と getuid の一致、service の許可リストを不変条件にする
7. **M9 / M10**: 状態遷移表の DR (ssh / キャンセル / ハング / 成功判定)、seteuid と spawn の順序
8. **M7**: WebAuthn 検証項目の一覧を仕様にする
9. **未検証事項の実機確認**: 既存 issue 2 件に上の観点を足して検証
10. **Minor の文書修正**: signCount の食い違い、findings の示唆、fragment 形式、公開鍵の置き場、CORS
