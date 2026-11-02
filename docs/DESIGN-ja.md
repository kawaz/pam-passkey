# pam-passkey 設計

> [English](./DESIGN.md) | 日本語

## ドメイン

macOS の sudo 認証 (`pam_tid` と同じ PAM の層) で、手元の Touch ID と、手元に居ない時の iPhone からの passkey 承認を同時に受け付ける。

### 目的

- 離席中・リモート作業中でも sudo の認証を iPhone から通せる
- 承認の真正性は Mac 側での passkey 署名検証だけで担保する。中継路 (オブジェクトストア / 通知サービス / APNs / CDN) は信頼しない。中継は可用性にだけ影響する
- 手元に居る時は Touch ID でそのまま通り、remote 承認の待ちを挟まない

### 増やさないもの

- 常駐サーバ・受信ポート・自前の HTTPS サーバ (Mac 側にも中継側にも、デプロイして維持するコードを置かない)
- Mac 上のファイル・ディレクトリ・パーミッション (状態と設定は Keychain だけに置く)
- sudo プロセス内のロジック (PAM モジュールは helper を起動する薄い層に留める)

### 扱わないもの

- どのコマンドを承認対象にするかの条件: sudoers の責務
- 承認後の無認証期間: sudo の timestamp (sudoers の `timestamp_timeout`) がそのまま効く。モジュール側で制御しない
- 通知の届け方: `send_command` の中身の責務。モジュールは「URL を 1 本届ける」ことしか知らない

## アーキテクチャ

```
sudo ─ pam_passkey.so ──┬─ スレッド A: LAContext (Touch ID ダイアログ、fallback ボタン = 「詳細を確認」)
                        └─ spawn ─▶ helper = `pam-passkey` CLI の内部サブコマンド (root。ユーザ権限に落とすのは `open` と `send_command` の子だけ)
                                     │ 1. 要求詳細を暗号化して S3 互換ストアに PUT
                                     │ 2. 承認 URL を `send_command` の stdin に渡す。未設定なら tty に表示
                                     │ 3. assertion の object をポーリング (期限まで)
                                     │ 4. passkey 署名を検証して結果を返す
                        どちらか成功 → もう片方をキャンセル → PAM_SUCCESS
                        両方失敗 / timeout → PAM_AUTH_ERR で後続 (パスワード) へ

受け手 (iPhone): 通知から URL を開く → 静的ページ → 詳細を GET して復号表示 → passkey 署名 → presigned PUT
受け手 (Mac):    「詳細を確認」→ helper がユーザ権限で同じ承認ページを open してブラウザを activate (同じ passkey が iCloud 同期で使える)
```

### コンポーネント

| コンポーネント | 責務 |
|---|---|
| `pam_passkey.so` | sudo プロセス内で動く PAM モジュール。Touch ID ダイアログ (LAContext) を出し、並行して helper を spawn し、先に成功した方で `PAM_SUCCESS` を返す |
| `pam-passkey` CLI | helper (PAM から呼ばれる内部サブコマンド) と管理機能を 1 バイナリにまとめる。承認経路のロジックはすべてこちらに置く |
| 静的ページ | 登録ページと承認ページ。固定 HTTPS ドメイン (passkey の RP ID) に置く。既定は GitHub Pages。ページは設定を持たず、必要な情報は全部 URL (query と fragment) から受け取る |
| S3 互換ストア | 暗号化した要求詳細、assertion、result の置き場。presigned URL が期限付きの capability を兼ねる。API 互換なら差し替え可 |
| `send_command` | 承認 URL を stdin で受けて届けるコマンド (Bark / ntfy / ssh 等)。未設定なら tty 表示 |

### PAM モジュールの制約

- sudo は setuid プロセスなので、AppKit を PAM モジュール内で初期化できない (初期化時にプロセスごと exit する)。ブラウザの `open`、フォーカス操作 (AX で SecurityAgent の window を raise する等) はすべて helper 側で行う ([findings](./findings/2026-11-02-pam-poc.md))
- `LAContext` は euid の生体登録状態を見るので、評価の間だけ `seteuid(呼び出しユーザ)` に落とし、終わったら `seteuid(0)` で戻す
- policy は `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion`。fallback ボタンは `localizedFallbackTitle` で「詳細を確認」に差し替え、押下は `LAErrorUserFallback` (-3) で拾う
- モジュールはプロセスを落とさない。モジュールの不具合で sudo が通らず setup もできなくなる事態 (ハシゴ外し) の歯止めは、失敗が後続のパスワード認証に流れること

### 失敗時の振る舞い

- helper が無い / ストアに届かない: remote 側だけ諦め、Touch ID は出す
- Touch ID も使えない環境: `PAM_IGNORE` で次のモジュールへ。fail-open にしない
- `send_command` の失敗: 警告のみで認証失敗にしない

### PAM への組み込み

- `/etc/pam.d/sudo_local` に `auth sufficient pam_passkey.so` を書く。`pam_tid` (`touchIdAuth`) は off にする
- nix-darwin では `security.pam.services.sudo_local.text` に store パスで 1 行書く (pam-watchid と同じ形)

## 承認 URL と交換の流れ

承認 URL は `<page_url>#<request の presigned GET URL>.<復号鍵>` の 1 本。fragment はサーバに送られないので、ページのホストは URL も中身も見ない。長さは presigned URL 1 本分で、詳細が大きくなっても URL は伸びない。

```
Mac (helper):  request JSON を暗号化して PUT → 承認 URL を send → assertion を poll → 検証 → result (pass / fail) を PUT → PAM に返す
request JSON:  details (host / user / tty / argv / プロセスツリー)、challenge、expires、assertion_put_url (presigned PUT)、result_get_url (presigned GET)
ページ:        fragment の URL を fetch → 復号して表示 → result を低頻度 poll (先に Touch ID で通れば「承認済み」に切り替わる)
               → passkey 署名 → assertion_put_url に PUT → result を高頻度 poll → pass / fail を表示
```

- result は 404 (待ち) / pass / fail の 3 値だけ。理由は出さない。PUT は冪等
- 拒否は、ページが assertion の場所に署名なしの内容を PUT するだけ。Mac 側は検証失敗 → fail。拒否専用の経路は持たない
- presigned URL と request の期限は揃える

## 暗号学的な束縛

- `challenge = SHA-256(要求詳細 + nonce + 期限)`。Mac 側は assertion の `clientDataJSON.challenge` が自分の計算値と一致すること、`origin` / `rpIdHash` / UV flag / signCount を検証する。承認は要求の内容そのものに束縛され、中継での差し替え・再生は署名不一致で落ちる
- 要求詳細は fragment の鍵で暗号化してストアに置く。`send_command` が何を経由するか (通知サーバ / APNs / チャット) は分からないので、経路上で URL を見られても期限内に中身を読まれないようにする
- 拒否は署名不要 (URL 保持者が待ちを止めるだけ)。承認だけ署名必須。presigned PUT URL を知る者が junk を書いても検証で落ちる (最悪 DoS)

### 登録

登録は 1 回の帯域外手続き。`pam-passkey add` が登録ページを開き、ページで作った公開鍵 + credential id + challenge への束縛をクリップボード経由 (ユニバーサルクリップボード) で CLI に貼り、CLI が検証し、署名を付けてユーザの login keychain に保存する。ストアを通さない。

## 状態と設定: Keychain だけに置く

ファイル・ディレクトリ・パーミッションを一切持たない。設定と署名鍵は System Keychain (`/Library/Keychains/System.keychain`)、passkey はユーザの login keychain の generic password 項目に置く。

- root (`sudo pam-passkey setup`) が要るのは System Keychain に書く `setup` の 1 回だけ。`add` / `del` / `list` はユーザ権限で動く。ユーザ権限からは Authorization right を取っても System Keychain に書けない ([findings](./findings/2026-11-02-keychain-poc.md))
- `setup` は署名鍵 (JWK、秘密鍵) を生成して System Keychain に置く。ACL は Developer ID 署名の helper だけ
- `add` は helper が `LAContext` で Touch ID (policy は `deviceOwnerAuthentication`、非搭載機はパスワード) を要求し、成功してから登録 URL を発行する。貼り付けを検証したら、同じプロセス内で署名鍵で JWS を作り (ペイロードに OS ユーザ名を含める)、login keychain に保存する
- `del` は login keychain から消すだけ
- 認証時の読み出しは helper が呼び出しユーザに降格した子プロセスで行う (unlock 済みの login keychain をユーザとして読む)。signCount は署名の外の可変フィールド
- PAM / helper は login keychain の項目を読み、署名鍵の公開鍵で JWS を検証する。通らないもの、ペイロードの OS ユーザ名が認証対象のユーザと一致しないものは無効として無視する
- ユーザ権限のプロセスが勝手に鍵を登録して自分の sudo を承認する経路は、署名で塞ぐ。悪意あるプロセスは helper を実行できても Touch ID のダイアログを通せず、署名は Touch ID が成功したのと同じプロセス (hardened runtime + Developer ID 署名) の中で行うので、同じ uid からの制御の改変・署名鍵の覗き見もできない。login keychain のファイルを差し替えても署名検証で無効になる。`del` は悪意あるプロセスにもできるが、remote 承認が消えてパスワード認証に落ちるだけで昇格にならない
- 公開鍵・設定は秘密でないので ACL は「全アプリ可」にする (main executable が `/usr/bin/sudo` であることによる ACL の問題を踏まない)。秘密 (署名鍵、ストアの鍵) だけ ACL を Developer ID 署名の helper に絞る。ad-hoc 署名は build ごとに変わって ACL が外れるので、Developer ID 署名が前提

| 置き場 | 項目 | 中身 |
|---|---|---|
| System Keychain | `page_url` | 承認 / 登録ページの URL (既定は GitHub Pages)。`rp_id` はここから導出する。自分でホスティングする人は fork してここを変える |
| System Keychain | `store` | S3 互換の接続情報 JSON (endpoint / bucket / region / prefix / access key / secret)。秘密を含む |
| System Keychain | `send_command` | 承認 URL を stdin で受けるコマンド。空なら tty 表示 |
| System Keychain | 署名鍵 | passkey の項目に署名する鍵 (JWK、秘密鍵)。秘密 |
| login keychain | `users/<os user>` | そのユーザの passkey の JSONL。各行は JWS で、ペイロードは OS ユーザ名、credential id、公開鍵、ラベル、登録日、signCount。1 ユーザ 1 項目 |

それ以外 (ポーリング間隔、ボタン文言、Touch ID の有無) はコードの既定値。

## CLI (`pam-passkey`)

| サブコマンド | 用途 |
|---|---|
| `setup <page_url>` | 初期設定 (root) |
| `add [label]` | passkey を登録する (Touch ID を求める) |
| `list` | 自ユーザの passkey を一覧する (login keychain を読むだけ) |
| `del <label\|id>` | passkey を削除する |
| `test` | sudo を介さずに承認経路を一周する |
| `doctor` | 環境の診断 |

これに PAM から呼ばれる内部用サブコマンドが加わる。

## 承認画面に見せるもの

先頭に host、ユーザ、tty、sudo の argv、時刻、期限。本体は sudo から launchd まで辿った祖先チェーンを pstree 風に縦一覧で出す (祖先は一直線なので折りたたみは不要)。各行は代表値 (プロセス名、署名 ID か Team ID、ユーザ) だけにし、行をクリックすると詳細が開く:

- pid、実行ユーザ、cwd、実行パス、argv
- 署名 ID (bundle ID 相当)、Team ID、署名者名、platform / ad-hoc の別 (`SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` → `SecCodeCopySigningInformation`)
- TCC 上の責任プロセス (`responsibility_get_pid_responsible_for_pid`。private API なので取れなければ「不明」)
- 補助情報があれば付ける (例: ccmsg が pid から引ける Claude セッション名)。表示用であり、承認判断の根拠は署名 ID 側に置く (セッション名は付け替え可能)

env は秘密が混ざるので出さない。sudo は root なので `KERN_PROC_PID` / `proc_pidpath` / `KERN_PROCARGS2` / libproc で全 pid 分取れる。情報量が多いので URL には入れず、暗号化してストアに置いたものをページが取って描く。

## 未決事項

- 要求の期限: 60〜120 秒の範囲で決める (presigned URL の期限と揃える。仮の既定は 90 秒)
- helper のポーリング間隔: 仮の既定は 1 秒
- 承認画面に「以降は sudo の timestamp の間 (既定 5 分) 無認証」と出すか

## 主要な設計判断

- [DR-0001](./decisions/DR-0001-naming.md) — 名前は `pam_passkey` / `pam-passkey`
- [DR-0002](./decisions/DR-0002-single-module-parallel-auth.md) — 1 モジュール内で Touch ID と remote 承認を並走
- [DR-0003](./decisions/DR-0003-helper-outside-sudo.md) — ロジックは sudo プロセス外の helper に置き、PAM は薄層
- [DR-0004](./decisions/DR-0004-fallback-button-as-details.md) — 「詳細を確認」は LAContext の fallback ボタンを転用
- [DR-0005](./decisions/DR-0005-s3-compatible-store.md) — 中継は S3 互換ストア + presigned URL
- [DR-0006](./decisions/DR-0006-approval-url-and-exchange.md) — 承認 URL 1 本、詳細は暗号化、result は 3 値
- [DR-0008](./decisions/DR-0008-pluggable-send-command.md) — 通知は `send_command` でプラガブル
- [DR-0009](./decisions/DR-0009-foreground-control.md) — 前面制御は `open` 時のブラウザ activate のみ
- [DR-0010](./decisions/DR-0010-cli-shape.md) — CLI は 1 バイナリ、動詞だけのサブコマンド
- [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md) — passkey は login keychain に署名付きで置き、sudo 依存は `setup` だけ

## 関連ドキュメント

- [STRUCTURE.md](./STRUCTURE.md) — 物理構造
- [decisions/INDEX.md](./decisions/INDEX.md) — DR 一覧
- [findings/](./findings/) — 前提検証の観測記録
