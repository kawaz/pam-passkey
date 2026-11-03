# pam-passkey 設計

> [English](./DESIGN.md) | 日本語

## ドメイン

macOS の PAM の auth (`pam_tid` と同じ層) で、手元の Touch ID と、手元に居ない時の iPhone からの passkey 承認を同時に受け付ける。一般の PAM auth モジュールで、主用途は sudo の認証。

### 目的

- 離席中・リモート作業中でも sudo などの認証を iPhone から通せる
- 承認の真正性は Mac 側での passkey 署名検証で担保する。中継のストアは真正性について信頼しない (ストアの障害や改ざんは承認を通す方向には働かず、可用性にだけ影響する)。信頼するものは [信頼の前提](#信頼の前提) に挙げたものに限る
- 手元に居る時は Touch ID でそのまま通り、remote 承認の待ちを挟まない

### 増やさないもの

- 常駐サーバ・受信ポート・自前の HTTPS サーバ (Mac 側にも中継側にも、デプロイして維持するコードを置かない)
- 設定・状態のファイル (状態と設定は Keychain だけに置く)
- 呼び出し元プロセス内のロジック (PAM モジュールは helper を起動する薄い層に留める)

### 扱わないもの

- 何を認証対象にするかの条件: PAM の設定と呼び出し側の責務 (sudo なら sudoers)
- 承認後の無認証期間: 呼び出し側の責務 (sudo なら timestamp。sudoers の `timestamp_timeout` がそのまま効く)。モジュール側で制御しない
- 通知の届け方: `send_command` の中身の責務。モジュールは「URL を 1 本届ける」ことしか知らない

## 信頼の前提

承認の可否を左右し、侵害されると承認を偽れるもの (TCB):

- ページの配信元: GitHub org `pam-passkey` のリポ `pam-passkey.github.io` (GitHub Pages) と、そのリポへの書き込み権。ページの JS は要求詳細を表示し passkey 署名を求める当事者なので、改ざんされると表示する内容と署名させる内容を分けられる。同じ origin を共有させないため、org `pam-passkey` には他の GitHub Pages を置かない
- rp_id のドメイン `pam-passkey.github.io`: この origin で動く JS は、登録済みの passkey で assertion を作れる
- iCloud (passkey の同期先): 同期された端末とそのアカウントは、承認できる主体に含まれる。同期される passkey を受け入れる (iCloud 同期が設計の前提)
- 通知経路 (`send_command` の先): 利用者が選んだ経路として信頼境界の内側に置く。承認 URL と登録 URL は期限付きの capability で、URL を見た者は期限内にそれを使える ([DR-0008](./decisions/DR-0008-pluggable-send-command.md))
- helper の Developer ID 署名: Keychain の項目の読み書きを helper に限定する根拠 ([DR-0011](./decisions/DR-0011-user-keychain-signed-records.md))

既定のページを使う利用者は、配信元 (org `pam-passkey`) を信頼することになる。信頼しない場合は fork して自分でホストし、`page_url` を差し替える。

信頼しないもの:

- S3 互換ストア: 要求・assertion・result を中継するだけで、承認の真正性は Mac 側の署名検証で決まる。ストアでの改ざんは fail か待ちにしかならない。要求詳細は暗号化しないので、ストアの運営者からは読める (ストアは利用者自身のバケット)。result はストアで書き換えられるので、ページに出る pass / fail は Mac 側の判定を保証しない

## アーキテクチャ

図は主用途の sudo から呼ばれる場合の例。

```
sudo ─ pam_passkey.so ──┬─ スレッド A: LAContext (Touch ID ダイアログ、fallback ボタン = 「詳細を確認」)
                        └─ spawn ─▶ helper = `pam-passkey` CLI の内部サブコマンド (root。通信・検証・open・send_command は PAM_USER に永久降格した子で行う)
                                     │ 1. 要求 (詳細と presigned URL) を S3 互換ストアに PUT
                                     │ 2. 承認 URL を `send_command` の stdin に渡す。未設定なら tty に表示
                                     │ 3. assertion の object をポーリング (期限まで)
                                     │ 4. passkey 署名を検証して結果を返す
                        どちらか成功 → もう片方をキャンセル → PAM_SUCCESS
                        両方失敗 / timeout → PAM_AUTH_ERR で後続 (パスワード) へ

受け手 (iPhone): 通知から URL を開く → 静的ページ → 要求を GET して表示 → passkey 署名 → presigned PUT
受け手 (Mac):    「詳細を確認」→ helper の降格した子が同じ承認ページを開いてブラウザを activate (同じ passkey が iCloud 同期で使える)
```

### コンポーネント

| コンポーネント | 責務 |
|---|---|
| `pam_passkey.so` | 呼び出し元のプロセス (主用途は sudo) 内で動く PAM モジュール。Touch ID ダイアログ (LAContext) を出し、並行して helper を spawn し、先に成功した方で `PAM_SUCCESS` を返す |
| `pam-passkey` CLI | helper (PAM から呼ばれる内部サブコマンド) と管理機能を 1 バイナリにまとめる。承認経路のロジックはすべてこちらに置く |
| 静的ページ | 登録ページと承認ページ。固定 HTTPS ドメイン (passkey の RP ID) に置く。既定は `https://pam-passkey.github.io/`。外部スクリプトを読まない単一ファイルにし、CSP を `<meta>` で設定する。ページは設定を持たず、必要な情報は全部 URL から受け取る |
| S3 互換ストア | 要求、assertion、result、登録時の credential の置き場。presigned URL が期限付きの capability を兼ねる。API 互換なら差し替え可 |
| `send_command` | 承認 URL と登録 URL を stdin で受けて届けるコマンド (Bark / ntfy / ssh 等)。未設定なら tty 表示 |

### PAM モジュールの制約

- 呼び出し元が setuid プロセス (sudo 等) の場合、AppKit を PAM モジュール内で初期化できない (初期化時にプロセスごと exit する)。ブラウザで承認ページを開く処理、フォーカス操作 (AX で SecurityAgent の window を raise する等) はすべて helper 側で行う ([findings](./findings/2026-11-02-pam-poc.md))
- `LAContext` は euid の生体登録状態を見るので、評価の間だけ `PAM_USER` の uid に `seteuid` で落とし、終わったら `seteuid(0)` で戻す。`seteuid` はプロセス全体に効くので、プロセス情報の収集と helper の spawn を済ませてから落とす。戻せなければ `PAM_AUTH_ERR` ([DR-0012](./decisions/DR-0012-auth-state-transitions.md))
- policy は `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` (Apple Watch での承認も通る)。fallback ボタンは `localizedFallbackTitle` で「詳細を確認」に差し替え、押下は `LAErrorUserFallback` (-3) で拾う
- モジュールはプロセスを落とさない。モジュールの不具合で sudo が通らず setup もできなくなる事態 (ハシゴ外し) の歯止めは、失敗が後続のパスワード認証に流れること
- 使う passkey と Touch ID の生体は `PAM_USER` のもの。`users/<PAM_USER>` の項目を読み、`LAContext` は `PAM_USER` の uid で評価し、`send_command` / 承認ページを開く子も `PAM_USER` に降格する。`PAM_USER` が root (sudoers の `targetpw` 等) なら passkey も生体も無く、パスワードへ落ちる ([DR-0012](./decisions/DR-0012-auth-state-transitions.md))

### 失敗時の振る舞い

状況ごとの Touch ID と remote の動作、PAM の戻り値は [DR-0012](./decisions/DR-0012-auth-state-transitions.md) の状態遷移表が正本。要点:

- Touch ID の可否と remote の成否は独立。Touch ID が使えなくても remote は走る。両方とも使えない時だけ `PAM_IGNORE` で次のモジュールへ。fail-open にしない
- helper が無い / 置き場の検査に通らない / ストアに届かない: remote 側だけ諦め、Touch ID は出す
- `PAM_USER` の GUI セッションが無ければ Touch ID は出さず remote だけで待つ。キャンセルは両方止めて `PAM_AUTH_ERR`
- ログイン画面 (login keychain が unlock されていない) では passkey の項目を読めず remote が成立しないので、パスワードへ落ちる
- 全ての待ちに期限 (要求の期限と同じ) を設ける
- `send_command` の失敗: 警告のみで認証失敗にしない

### PAM への組み込み

- sudo への導入例: `/etc/pam.d/sudo_local` に `auth sufficient pam_passkey.so` を書く。`pam_tid` (`touchIdAuth`) は off にする
- nix-darwin では `security.pam.services.sudo_local.text` に store パスで 1 行書く (pam-watchid と同じ形)
- `.so` と helper は、親ディレクトリまで root 所有で root 以外に書き込み権の無い場所に置く。Homebrew 配下のようなユーザ所有の置き場は対象外 ([DR-0003](./decisions/DR-0003-helper-outside-sudo.md))

### helper の権限

helper は root で起動するが、root が要るのは子を `PAM_USER` に永久降格させて起動することだけ。ストアとの通信、assertion の解析と検証、login keychain の読み出し、`send_command`、承認ページを開く処理は降格した子で行い、root の helper は判定だけを受け取る。spawn の手順 (絶対パス、空の環境から許可リスト、0/1/2 以外の fd を閉じる、cwd / umask の固定) と降格の順序は [DR-0003](./decisions/DR-0003-helper-outside-sudo.md)。

## 承認 URL と交換の流れ

承認 URL は `<page_url>#<request の presigned GET URL>` の 1 本。fragment はページのホストへのリクエストに含まれない。長さは presigned URL 1 本分で、詳細が大きくなっても URL は伸びない。

```
Mac (helper):  request を PUT (バイト列を保持) → 承認 URL を send → assertion を poll → 検証 → result (pass / fail) を PUT → PAM に返す
request JSON:  details (host / user / tty / argv / プロセスツリー)、nonce、expires、assertion_put_url (presigned PUT)、result_get_url (presigned GET)
ページ:        fragment の URL を GET → 表示し、取得したバイト列から challenge を計算 → result を低頻度 poll (先に Touch ID で通れば「承認済み」に切り替わる)
               → passkey 署名 → assertion_put_url に PUT → result を高頻度 poll → pass / fail を表示
```

- result は pass / fail の 2 値で、オブジェクトが無ければ待ち。理由は出さない
- helper は最初に受け取った assertion で判定を確定する (junk なら fail)。以後の上書きは見ない
- 拒否は、ページが assertion の場所に署名なしの内容を PUT するだけ。拒否専用の経路は持たない
- 要求詳細は暗号化しない。承認後、helper は request と assertion をストアから DELETE する
- バケットの lifecycle ルールと CORS は `setup` の手順に含める
- presigned URL と request の期限は揃える

詳細は [DR-0006](./decisions/DR-0006-approval-url-and-exchange.md)。

## 署名の束縛と検証

- challenge は、ページが presigned GET で取得した request のバイト列全体の SHA-256。ページは表示するのと同じバイト列から challenge を計算し、helper は自分が PUT したバイト列から同じ値を計算する。承認はページが表示した要求の内容そのものに束縛され、中継での差し替え・再生は署名不一致で落ちる
- helper が assertion を受理する条件 (type、origin、`crossOrigin` / `topOrigin`、UP / UV、credential id、ES256、サイズ、1 回限り、期限) は [webauthn-verification](./design/webauthn-verification.md)
- 拒否は署名不要 (URL 保持者が待ちを止めるだけ)。承認だけ署名必須。presigned PUT URL を知る者が junk を書いても pass にはならない (最悪 DoS)

### 登録

登録は 1 回の帯域外手続きで、承認と同じくストアを介す。

1. `pam-passkey add` (ユーザ権限) が Touch ID を求める
2. 成功したら登録要求をストアに置き、登録 URL を tty に表示するか `send_command` の stdin に渡す
3. 登録ページが passkey を作り、credential を presigned PUT でストアに返す
4. `add` はそれを poll して受け取り、[受理条件](./design/webauthn-verification.md) で検証し、同じプロセス内で署名鍵で JWS を作って login keychain に保存する

登録 URL は承認 URL と同じく期限付きの capability で、tty と `send_command` の stdin 以外には出さない。手順の詳細は [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md)。

## 状態と設定: Keychain だけに置く

設定・状態のファイルを持たない。設定と署名鍵は System Keychain (`/Library/Keychains/System.keychain`)、passkey はユーザの login keychain の generic password 項目に置く。

- Keychain の項目の読み書きは helper (Developer ID 署名) に限定し、全項目の ACL を helper に絞る。PAM モジュールは Keychain を読まない。ad-hoc 署名は build ごとに変わって ACL が外れるので、Developer ID 署名が前提
- root (`sudo pam-passkey setup`) が要るのは System Keychain に書く `setup` の 1 回だけ。`add` / `del` / `list` はユーザ権限で動く。ユーザ権限からは Authorization right を取っても System Keychain に書けない ([findings](./findings/2026-11-02-keychain-poc.md))
- `setup` は署名鍵 (JWK、秘密鍵) を生成し、署名鍵と検証用の公開鍵を System Keychain に置く。再実行すると署名鍵を作り直し、既存の登録は全て無効になる (再 `add`)
- 認証時の login keychain の読み出しは、helper が `PAM_USER` に降格した子で行い、`users/<PAM_USER>` の項目を読む (unlock 済みの login keychain をユーザとして読む)。公開鍵で JWS を検証し、通らないもの、ペイロードの OS ユーザ名が認証対象のユーザと一致しないものは無効として無視する
- ユーザ権限のプロセスが勝手に鍵を登録して自分の認証を承認する経路は、署名と helper の入口の規律で塞ぐ (署名鍵を読むのは `add` の Touch ID 成功後の 1 か所だけ、内部サブコマンドは署名鍵を使わない、環境変数で参照先を切り替えられない)。根拠の全体は [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md)
- `store` と `send_command` はシステムに 1 つなので、同じ Mac の別ユーザの認証の URL も同じ `send_command` に渡る

| 置き場 | 項目 | 中身 |
|---|---|---|
| System Keychain | `page_url` | 承認 / 登録ページの URL (既定は `https://pam-passkey.github.io/`)。`rp_id` はここから導出する (既定は `pam-passkey.github.io`)。自分でホスティングする人は fork してここを変える |
| System Keychain | `store` | S3 互換の接続情報 JSON (endpoint / bucket / region / prefix / access key / secret)。秘密を含む |
| System Keychain | `send_command` | 承認 URL と登録 URL を stdin で受けるコマンド。空なら tty 表示 |
| System Keychain | 署名鍵 | passkey の項目に署名する鍵 (JWK、秘密鍵)。秘密 |
| System Keychain | 署名鍵の公開鍵 | 認証時に passkey の項目の JWS を検証する鍵 |
| login keychain | `users/<os user>` | そのユーザの passkey の JSONL。各行は JWS で、ペイロードは OS ユーザ名、credential id、公開鍵、ラベル、登録日、登録時の BE / BS フラグ。1 ユーザ 1 項目 |

それ以外 (ポーリング間隔、ボタン文言、Touch ID の有無) はコードの既定値。

## CLI (`pam-passkey`)

| サブコマンド | 用途 |
|---|---|
| `setup <page_url>` | 初期設定 (root)。ストアへの到達、バケットの CORS、`.so` と helper の置き場の所有権も確認する |
| `add [label]` | passkey を登録する (Touch ID を求める) |
| `list` | 自ユーザの passkey を一覧する (login keychain を読むだけ) |
| `del <label\|id>` | passkey を削除する |

これに PAM から呼ばれる内部用サブコマンドが加わる。

## 承認画面に見せるもの

先頭に host、ユーザ、tty、呼び出しプロセスの argv、時刻、期限。本体は呼び出しプロセスから launchd まで辿った祖先チェーンを pstree 風に縦一覧で出す (祖先は一直線なので折りたたみは不要)。各行は代表値 (プロセス名、署名 ID か Team ID、ユーザ) だけにし、行をクリックすると詳細が開く:

- pid、ユーザ、cwd、実行パス、argv
- 署名 ID (bundle ID 相当)、Team ID (`SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` → `SecCodeCopySigningInformation`)

署名なし / ad-hoc 署名 / platform バイナリは、行の見た目で区別する。

表示は無害化する。制御文字と bidi 制御文字はエスケープして見せ、切り詰めた箇所は切り詰めたことが分かる形で見せる。

env は秘密が混ざるので出さない。プロセス情報は PAM モジュールが呼び出し元のプロセス内で集める。sudo のように root で動く呼び出し元なら `KERN_PROC_PID` / `proc_pidpath` / `KERN_PROCARGS2` / libproc で全 pid 分取れる。情報量が多いので URL には入れず、ストアに置いたものをページが presigned GET で取って描く。

## 未決事項

- 要求の期限: 60〜120 秒の範囲で決める (presigned URL の期限と揃える。仮の既定は 90 秒)
- helper のポーリング間隔: 仮の既定は 1 秒
- 承認画面に「以降は sudo の timestamp の間 (既定 5 分) 無認証」と出すか
- 承認要求のレート制限: 同じ uid のプロセスが認証 (sudo 等) を連打すると通知も連打される。中継側にコードを置かない前提では helper 内の時間窓でしか制限できず、同じ uid のプロセスは helper を迂回して通知だけを送れる

## 主要な設計判断

- [DR-0001](./decisions/DR-0001-naming.md) — 名前は `pam_passkey` / `pam-passkey`
- [DR-0002](./decisions/DR-0002-single-module-parallel-auth.md) — 1 モジュール内で Touch ID と remote 承認を並走
- [DR-0003](./decisions/DR-0003-helper-outside-sudo.md) — ロジックは sudo プロセス外の helper に置き、PAM は薄層。通信と検証は降格した子、置き場は root 所有
- [DR-0004](./decisions/DR-0004-fallback-button-as-details.md) — 「詳細を確認」は LAContext の fallback ボタンを転用
- [DR-0005](./decisions/DR-0005-s3-compatible-store.md) — 中継は S3 互換ストア + presigned URL
- [DR-0006](./decisions/DR-0006-approval-url-and-exchange.md) — 承認 URL 1 本、challenge はページが取得した要求そのものの SHA-256、result は pass / fail
- [DR-0008](./decisions/DR-0008-pluggable-send-command.md) — 通知は `send_command` でプラガブル。通知経路は信頼境界の内側
- [DR-0009](./decisions/DR-0009-foreground-control.md) — 前面制御は承認ページを開いた時のブラウザ activate のみ
- [DR-0010](./decisions/DR-0010-cli-shape.md) — CLI は 1 バイナリ、動詞だけのサブコマンド
- [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md) — passkey は login keychain に署名付きで置き、sudo 依存は `setup` だけ
- [DR-0012](./decisions/DR-0012-auth-state-transitions.md) — 認証の状態遷移と不変条件

## 関連ドキュメント

- [STRUCTURE.md](./STRUCTURE.md) — 物理構造
- [decisions/INDEX.md](./decisions/INDEX.md) — DR 一覧
- [design/webauthn-verification.md](./design/webauthn-verification.md) — 認証と登録の受理条件
- [findings/](./findings/) — 前提検証の観測記録
