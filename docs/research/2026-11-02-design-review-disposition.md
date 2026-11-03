# 設計レビュー (2026-11-02) の指摘の処置

初見レビュー 2 本 ([sol](./2026-11-02-design-review-sol.md)、[opus](./2026-11-02-design-review-opus.md)) の指摘を突き合わせ、設計談義側 (インキュベーター) の回答と併せて処置を決める。裁定が要るものは `docs/QUESTIONS.md` に PK-Q として出し、残りは統括が DESIGN / DR に反映する。

設計談義側の回答 (2026-11-02):

- 通知経路は `send_command` でユーザが選んだ経路として信頼境界の内側。守るのはストアとページホスト。「通知経路で見られても読めない」は言い過ぎ
- seteuid の race: 談義の想定は「helper は別プロセス、Keychain 読みは helper 側」で、spawn を降格の前に行えば回避可。`pthread_setugid_np` は未評価
- ページホスト (GitHub Pages) は信頼境界に含める。SRI / hash 固定は構想なし
- findings の実機観測は kawaz 本人が手で回した結果

## 両レビューが一致した指摘 (採る)

| # | 指摘 | sol | opus | 処置 |
|---|---|---|---|---|
| 1 | 承認 URL を見る通知経路は期限内に復号できる。「中継は可用性にだけ影響」は機密性で不成立 | C1 | M6 | 信頼の前提を書き直す: 通知経路は信頼境界の内側 (DR-0006 / DR-0008 / DESIGN 目的)。**要求詳細の暗号化と fragment の鍵は外す** (守れる相手がストア運営者 = 自分のバケットだけで、URL が capability なので暗号化は何も足していない。kawaz 2026-11-03)。argv を伏せる選択肢は PK-Q2 |
| 2 | ページ配信元・rp_id ドメインは TCB。user pages の同一 origin 共有は不可 | C2 | C5 | DESIGN に TCB として明記。専用 origin は PK-Q3。ページは単一ファイル + meta CSP、iframe 拒否は WebAuthn 検証 (`crossOrigin` / `topOrigin`) で |
| 3 | 表示内容と署名対象が結びついていない。request の `challenge` フィールドをそのまま署名に使うと、同 uid のマルウェアが偽 details + 本物 challenge で署名させられる | C2 (UI integrity) | C1 | **設計変更** (kawaz 2026-11-03): request から `challenge` フィールドを外し、challenge = ページが GET したペイロード全体 (バイト列そのまま) の SHA-256。正規化は不要 (helper は PUT したバイト列を覚えておく)。表示の無害化 (制御文字 / bidi / 切り詰め明示) を仕様化 |
| 4 | seteuid はプロセス全体に効く。並走する helper spawn と race。PoC は復元失敗を検査しない | C3 | M10 | 順序を固定: プロセス情報収集と helper spawn を済ませてから euid を落とす。復元失敗は `PAM_AUTH_ERR`。`pthread_setugid_np` は代案として実機検証 issue |
| 5 | root helper から起動する子 (`send_command` / `open`) の永久降格が未規定 | C4 | C4 (spawn 手順) | 仕様化: `setgroups` / `setgid` / `setuid` の順で永久降格、環境は空から許可リストで構築、0/1/2 以外の fd を閉じる、cwd / umask 固定、絶対パス起動 |
| 6 | Touch ID 不可で即 `PAM_IGNORE` は remote 承認の目的と矛盾 | M5 | M9 | 生体の可否と remote の成否を独立させる。Touch ID 不可でも remote は走る。両方不可のときだけ `PAM_IGNORE` |
| 7 | WebAuthn の受理条件が不足 (type、UP、credential id の照合、署名入力、alg 固定、登録時の整合、サイズ上限、challenge の 1 回限り) | M6 | M7 | 検証項目の一覧を設計の付随詳細 (`docs/design/webauthn-verification.md`) に起こし、改ざんテストベクタを実装時に用意 |
| 8 | signCount は保証にならない (同期 passkey は 0、ユーザ書き込み可の項目なら戻せる)。DESIGN の表と DR-0011 で署名範囲が食い違う | M6 / m10 | M3-3 / Minor | 検証項目から外し、記録もしない。DESIGN の表を直す |
| 9 | 署名鍵のローテーション・紛失・再 setup と既存登録の扱いが未定 | M7 | M3-1 | PK-Q1 の結果で変わる。(A) なら署名鍵自体が無くなる |
| 10 | PAM モジュールの crash / 無期限待ちはパスワードに流れない。全ての待ちに期限、キャンセル・Ctrl-C・helper 不在の遷移を決める | M8 | M9 | 状態遷移表を DR に起こす (GUI 有無 / ssh 由来 / 指紋登録 / キャンセル / fallback / 期限切れ / helper 起動失敗 / Ctrl-C)。helper の成功は要求 ID 付きの明示メッセージのみ (デフォルト拒否) |
| 11 | 祖先チェーン / argv は snapshot であり証明ではない | M9 | Minor (偽装) | 注記は書かない (利用者の前提)。署名なし / ad-hoc / platform を視覚的に区別するだけ |
| 12 | 既存 issue 2 件の受け入れ条件を広げる (ユーザ権限 `add` と root helper の両方、同 Team ID の別 identifier / 旧版バイナリ / root の `security` CLI、ファストユーザスイッチ、keychain パスワード不一致、ssh 由来の audit session) | 未検証 | M4 / 未検証 | issue 2 件を update。PK-Q1 で (A) なら ACL issue 自体が不要になる |

## 片方だけの指摘 (採る)

| # | 指摘 | 出所 | 処置 |
|---|---|---|---|
| 13 | `add` の Touch ID がクリップボードの中身に束縛されていない。ペーストボード差し替えで攻撃者の鍵が登録される | opus C2 | **設計変更** (kawaz 2026-11-03): クリップボードを廃止し、登録も承認と同じく登録ページが presigned PUT で返す。登録 URL は capability (tty 表示か `send_command` の stdin にしか出さず、`open` の argv にも載せない) なので第三者は PUT できず、指紋照合は不要 |
| 14 | 署名済み helper はどの uid からも起動でき、秘密を使う入口が絞られていない (署名オラクル) | opus C3 | PK-Q1 で (B) なら「署名鍵を読むのは `add` の Touch ID 成功後の 1 か所だけ」を不変条件化。(A) なら消える。どちらでも「内部サブコマンドは秘密を使わない」「環境変数で参照先を切り替えられない」は採る |
| 15 | helper と `.so` の置き場の所有権。Homebrew 配下はユーザ所有で、差し替えで即 root | opus C4 | DESIGN に「親ディレクトリまで root 所有・他者書き込み不可」を要件化。PAM は spawn 前に owner / mode を検査し、不合格なら remote を諦める。`setup` も検査。brew 配布は対象外と明記 |
| 16 | sudo の timestamp で承認 1 件が「5 分間 root」になる | opus M1 | 承認画面に明記 (未決事項 3 を「出す」で確定)。`timestamp_timeout=0` の推奨は PK-Q4 |
| 17 | PAM_USER と呼び出しユーザの一致、service の許可リスト | opus M2 | 不変条件化: `PAM_USER == getuid() のユーザ名` かつ service が許可リスト (初版は sudo のみ)。それ以外は `PAM_IGNORE` |
| 18 | Mac 側「詳細を確認」経路は argv に復号鍵入り URL が載り (`ps` で他ユーザから見える)、ブラウザ履歴にも残りうる | opus M5 | 降格した子で `NSWorkspace` / `LSOpenCFURLRef` 相当を直接呼ぶ (`/usr/bin/open <URL>` を exec しない)。承認後に helper がストアのオブジェクトを DELETE。lifecycle ルールを setup 手順に |
| 19 | 同期 passkey により iCloud / passkey プロバイダが TCB に入る | opus M8 | 信頼の前提に明記。同期鍵は受け入れる (iCloud 同期が設計の前提)。BE / BS の値は登録時に記録 |
| 20 | helper を root で動かす理由が無く、攻撃者が書ける assertion を root で解析する | opus M11 | root が要る処理を列挙して DR-0003 に書く。PK-Q1 (A) なら store の秘密を root が読む必要があるので helper は root 起動、ネットワークと解析は降格した子で行い root 側は結果だけ受ける構成を DR-0003 に追記 |
| 21 | 拒否 / junk / 検証失敗 / ストア障害 / timeout を Mac 側では区別し、上書き競合の確定規則を決める | sol m11 | DR-0006 に「assertion を 1 つ受け取った時点で判定を確定 (junk なら fail)。以後の上書きは見ない」を追記 |
| 22 | Minor 群: findings の古い示唆、fragment の区切り (`.` は URL に含まれる)、公開鍵の置き場 (JWS か HMAC か)、Touch ID 本文の切り詰め、result の偽装可能性、GET サイズ上限、CORS、複数ユーザ、承認疲れ、Apple Watch、`test` の権限差、Ctrl-C | opus Minor | 文書修正で反映。暗号化を外すので fragment は presigned GET URL だけ。CORS と lifecycle を setup に。`test` / `doctor` は削除 (kawaz 2026-11-03。疎通確認は `setup` に寄せる)。レート制限は未決として残す |

## 却下 / 保留 (理由付き)

- sol C2 の「配信元を信頼しないなら、表示と照合を信頼できるクライアント側で完結させる」: ネイティブ app を持たない設計 (DR-0004 不採用案) と両立しない。配信元を TCB に含める (#2) ことで解消
- opus Minor の「TCC 責任プロセスを外す」(統括案): 祖先チェーンが launchd で切れる (XPC / launchd service 経由) 場合に由来アプリを出す唯一の手段なので残す
- opus C5 の「リリースごとのハッシュ公開」: ブラウザが URL からページのハッシュを検証しないので、利用者の手動照合にしかならない。採らない (fork して自分でホストする道を README に書く)
- opus Minor の「レート制限」: 中継側にコードを置かない前提では helper 内の時間窓でしか実装できず、同 uid のマルウェアは helper を迂回して通知だけ叩ける。未決として残す
