# DR-0004: 「詳細を確認」は LAContext の fallback ボタンを転用する

- Status: Accepted
- Date: 2026-11-02

## Context

手元の Mac で sudo を承認する時、Touch ID ダイアログに出せるのは短い本文 (sudo の argv) 程度に限られる。プロセスツリーや署名情報まで見てから承認したい場合に、承認ページ (iPhone と同じもの) を Mac 上で開く手段が要る。

PAM モジュール内からはブラウザを開けず ([DR-0003](./DR-0003-helper-outside-sudo.md))、Touch ID ダイアログに置けるボタンは LAContext が提供するものに限られる。

## Decision

- LAContext の fallback ボタンを `localizedFallbackTitle` で「詳細を確認」に差し替える
- policy は `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` (生体 / companion のみの系) にする。この系では fallback がパスワード入力に行かず、押下は `LAErrorUserFallback` (-3) で返る
- 押されると `LAContext` の評価は `-3` で返り、ダイアログは閉じる。PAM は新しい `LAContext` でダイアログを出し直してから helper に `open` を送って承認ページを開かせ、Touch ID と remote の両方が使える状態に戻す。押すたびに同じことをする。Mac でも iCloud 同期された同じ passkey で署名できる
- 開く処理は、`PAM_USER` に永久降格した子 ([DR-0003](./DR-0003-helper-outside-sudo.md)) が `NSWorkspace` / `LSOpenCFURLRef` 相当を直接呼んで行う。`/usr/bin/open <URL>` は exec しない。承認 URL をプロセスの argv に出さないためで、argv は `ps` で他ユーザからも読める

### ダイアログの本文

承認ページを開かなくても、ダイアログだけで「どこから来た認証要求か」を判断できるようにする。OS は本文の前に「<プロセス名> で次の操作を実行しようとしています:」を置き、約 34 半角の固定幅で折り返して縦に伸ばす ([findings](../findings/2026-11-09-pam-module-touch-id-path.md))。

```
# cwd:
/Users/kawaz/work

# ancestors:
- 00001 root /sbin/launchd
\- 07734 kawaz …/ghostty
 \- 26724 root …/login -flp k…
  \- 26725 kawaz -/bin/zsh
⭐    \- 79807 root sudo -k true
```

- `localizedReason` は `"\n\n"` で始め (OS の前置きと段落を分ける)、`# cwd:` (呼び出し元の cwd) と `# ancestors:` の 2 段落にする。見出しは言語によらずこの表記
- 祖先は launchd から呼び出し元へ縦に並べ、各行は `<pid (5 桁ゼロ埋め)> <ユーザ> <argv (無ければ実行パス)>`。行頭は pstree 風に `- `、以降 `\- ` を 1 行ごとに 1 字ずつ深くする
- 呼び出し元以外の行は 30 半角 (全角と絵文字は 2 と数える) に収める。超える時は argv[0] のディレクトリを `…/` に縮めて実行ファイル名を残し、それでも超えれば末尾を `…` で切る
- 呼び出し元の行は行頭に ⭐ を付け、30 半角では切らずに出す (折り返しは許す)。400 文字を超える時だけ中央を `…` で省略する。cwd は 200 文字を超える時に中央を省略する
- 祖先チェーンが 7 行を超える時は、先頭 2 行と末尾 4 行 (呼び出し元を含む) を残し、間を `…` 1 行にする。本文の縦の伸びは行数と行長の上限で抑え、全体の文字数では切らない
- argv / パス / ユーザ名は信頼しない。制御文字、行と段落の区切り (U+2028 / U+2029)、bidi 制御文字は `\u{XXXX}` でエスケープし、行や段落を偽れないようにする
- 本文は PAM が呼び出し元のプロセス内で集めた `details.processes` だけから作る (ユーザ名は uid から引く)。分からない値は `?`

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| sudo のたびにブラウザで承認ページを自動で開く | 作業中のブラウザのタブが遷移し、承認後のタブの後始末も要る |
| Mac ネイティブの passkey (ASAuthorization) で承認する | entitlement はメイン実行ファイル (`/usr/bin/sudo`) に付くので PAM モジュール内からは使えない。`pam-passkey` バイナリを .app にする必要があり重い |

## Consequences

- 「詳細を確認」を押した後も、承認ページでの passkey 署名と、出し直したダイアログでの Touch ID のどちらでも通せる
- 出し直したダイアログの前面の挙動とタッチの反応は未検証 ([findings](../findings/2026-11-02-pam-poc.md))
- 承認ページは iPhone と Mac で共通の 1 つで済む

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0009](./DR-0009-foreground-control.md)
- [findings: PAM モジュールの PoC](../findings/2026-11-02-pam-poc.md)
