# 裁定・確認待ち一覧 (ユーザ用)

## 運用規約

<details>
<summary>ゼロコンテキストエージェント向け（本セクションは消さない）</summary>

- 裁定/確認待ち項目を 1項目=1ラベル=1セクション で記載
- ラベル形式: XX-Q1（XX は 2-3 文字、バッチやセッション内で一意、Qn単独の使い回し禁止、長期一意性は不要)
- 依頼形式: 「👺XX-Q1 の裁定お願いします」（参照用途ではラベルに👺を付けない。誤陽性がユーザのハイライト/アラームを汚す）
- チャット提示と同一ターンで本ファイルに記録 + path 指定 commit (push はリリース窓に同乗)
- 裁定が下りたら該当セクションを即削除し、内容は正規の記録先 (DR / issue / journal / close_reason) へ反映。本ファイルは常に「現在待ち」だけを持つ
- 参照は[]()で提示（リポ内は相対、リポ外はフルパス）
- 初版質問/依頼は長文で書かない（ユーザが説明を求めらたら本ファイルに説明を追加し、チャットで👺ラベルで再依頼）
- **選択肢・確認項目は `- [ ] a: …` 形式（チェックボックス + ラベル）で書く**。Q / C で記法を分けない。回答は「チェックを付ける」でも「XX-Q1a」と言葉で返すでも通る（複数まとめてチェックし「チェックしたよ」の一言で済ませる運用を想定）

</details>

## 裁定待ち

### 👺PK-Q1: passkey の置き場。DR-0011 (login keychain + 署名) を維持するか、DR-0007 方式 (全状態 System Keychain、`add` / `del` は sudo) に戻すか

- [ ] a (推奨): DR-0007 方式に戻す。全状態を root が書く System Keychain に置き、`add` / `del` は `sudo pam-passkey add`
- [ ] b: DR-0011 維持 + `add` の Touch ID を貼り付け検証後・署名直前に移して credential 指紋を照合 + 失効用の世代番号を System Keychain に持つ (失効には結局 root が要る)
- [ ] c: Secure Enclave + biometry ACL の鍵で署名 (C3 は塞がるが C2 は残り、公開鍵登録に root が要る)

推奨理由: DR-0011 の「安全性は同等」は成立しない ([disposition](./research/2026-11-02-design-review-disposition.md) #9 / #13 / #14)。(1) `del` では失効できない (署名済み行を写した同 uid のプロセスが書き戻せる)、(2) ユーザ権限で起動できる署名オラクルが生まれ、クリップボード差し替えで攻撃者の鍵を登録できる、(3) Developer ID 署名の ACL への依存 (旧版バイナリも通る、nix / 自前 build と両立しない) が設計の芯に入る。一方 DR-0011 が得るものは「`add` でパスワードを打たない」利便性だけで、ハシゴ外しの根拠は弱い (モジュールが壊れても失敗はパスワードに流れるので `sudo pam-passkey add` は動く)。(a) なら #9 / #13 / #14 と ACL issue が丸ごと消え、helper が root で読む秘密は「root だけが読める置き場」で守れて Developer ID 依存を外せる。

### 👺PK-Q2: 通知経路に見せる要求詳細の既定

- [ ] a (推奨): 既定は全部 (argv とプロセスツリー) を見せる。通知経路は `send_command` でユーザが選ぶものなので信頼境界の内側と明記する
- [ ] b: 既定はコマンド名だけで、全部見せるのは設定で opt-in

推奨理由: 承認判断に argv が要る (隠すと承認画面の価値が下がる)。通知経路を信頼する前提は設計談義側の意図と一致。(b) は設定項目が増える。

### 👺PK-Q3: ページの origin (= rp_id)。共用の `kawaz.github.io` は使えない (同一 origin の他リポからも passkey を使える)

- [ ] a (推奨): この用途専用の GitHub org を作り `<org>.github.io` をページ専用にする (そこに他の pages を置かない)
- [ ] b: 専用のカスタムドメイン (例: `pam-passkey.<kawaz のドメイン>`) を GitHub Pages に当てる
- [ ] c: 既定ページを配らず、利用者が各自ホストする (README に手順)

推奨理由: (a) は費用ゼロで origin を分離でき、fork した人も同じ手順で自分の org を作れる。(b) はドメインの維持が要る。(c) は導入の敷居が上がる。

### 👺PK-Q4: sudo の timestamp (承認 1 件で既定 5 分間無認証) への対応

- [ ] a (推奨): 承認画面に「以降 N 分は無認証」と出す + `doctor` が `timestamp_timeout` を読んで 0 でなければ警告する。sudoers は触らない
- [ ] b: `setup` が `/etc/sudoers.d/pam-passkey` に `Defaults timestamp_timeout=0` を書く

推奨理由: sudoers は「扱わないもの」に置いた責務で、(b) はファイルを増やす。警告で足りる。

## 確認待ち

### 👺PK-C1: 稼働中の `/etc/pam.d/sudo_local` に PoC の 2 行 (`pam_kcpoc.so`、`pam_poc.so`) が残っている。`pam_poc.so` は Touch ID 成功で `PAM_SUCCESS` を返すので本番の sudo 認証に入ったまま

- [ ] a: 意図どおり (本実装まで PoC を使う)
- [ ] b: 2 行とも外す (root シェルを確保した上で統括が外す)
