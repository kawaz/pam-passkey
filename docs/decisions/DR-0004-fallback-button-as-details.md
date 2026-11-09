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

承認ページを開かなくても、ダイアログだけで「何を、どこで、どこから実行しようとしているか」を判断できるようにする。OS は本文の前に「<プロセス名> で次の操作を実行しようとしています:」(英語は「<プロセス名> is trying to」) を置き、プロポーショナルフォントで幅 216px (数字 `0` 約 26.6 字分) の枠に折り返して縦に伸ばす ([findings](../findings/2026-11-09-pam-module-touch-id-path.md))。

```
実行コマンド:
sudo -k true

作業ディレクトリ:
~/.local/share/repos/github.com/kawaz/pam-passkey/main

プロセスツリー:
00001 root /sbin/launchd
07734 kawaz Ghostty.app
08990 root login -flp kawaz…
08991 kawaz -/bin/zsh
57111 root sudo -k true
```

- `localizedReason` は `"\n\n"` で始め (OS の前置きと段落を分ける)、空行で区切った 3 段落にする。見出しはユーザの言語に合わせ、日本語は `実行コマンド:` / `作業ディレクトリ:` / `プロセスツリー:`、それ以外は `Command:` / `Working directory:` / `Process tree:`
- 実行コマンドは呼び出し元の argv 全文 (無ければ実行パス、それも無ければ PAM のサービス名)。折り返してよい。`/` を含む語は `/` の後に ZWSP (U+200B)、`-` の後に WJ (U+2060) を入れ、ディレクトリ境界でだけ折れるようにする。400 文字を超える時だけ中央を `…` で省略する
- 作業ディレクトリは呼び出し元の cwd の全文。PAM_USER のホームとその配下は `~` に縮める。折り返しは実行コマンドと同じ制御で、200 文字を超える時だけ中央を `…` で省略する
- プロセスツリーは launchd から呼び出し元へ 1 行 1 プロセスで並べ、各行は `<pid (5 桁ゼロ埋め)> <ユーザ> <本体>`。呼び出し元の行も同じ規則で、印は付けない
- ツリーの行は折り返さない。行の幅は文字数でなく概算幅で測り、数字 `0` の幅を 1.0 として予算 26 に収める。文字ごとの係数は、空白と `. , : ; ' ! | i j l` が 0.5、`/ ( ) [ ] { } f r t I` が 0.65、`m w M W @ %` が 1.55、それ以外の大文字と `&` が 1.25、それ以外の ASCII が 1.05、絵文字が 2.0、それ以外 (CJK 等) が 1.6 (実機の校正から取った各字種の上限)
- 本体は予算に収まるまで次の順に縮める: argv 全部 → argv[0] が `*.app/Contents/MacOS/*` ならアプリ名 (`Ghostty.app`) + 残りの argv、そうでなければ argv[0] の basename (ログインシェルの `-` は残す) + 残りの argv → 末尾を切って `…`。argv[0] の basename がインタプリタ (`bun` / `deno` / `node` / `python` / `python3` / `ruby` / `perl` / `php` / `sh` / `bash` / `zsh` / `fish` / `dash` / `ksh`) で argv[1] がパス (`/` を含み `-` で始まらない) なら、argv[1] も basename にしてスクリプト名を残す (`bun index.ts daemon run`)
- ツリーが 12 行を超える時は、先頭 3 行と末尾 8 行 (呼び出し元を含む) を残し、間を `…` 1 行にする。本文の縦の伸びは行数と行長の上限で抑え、全体の文字数では切らない
- argv / パス / ユーザ名は信頼しない。制御文字、行と段落の区切り (U+2028 / U+2029)、書式文字 (Unicode の Cf: bidi 制御文字、ZWSP、WJ、U+00AD、タグ文字等) は `\u{XXXX}` でエスケープし、行や段落を偽れず、表示順を入れ替えられず、本文が自分で入れる ZWSP / WJ と紛れないようにする。エスケープは ZWSP / WJ を入れる前に行う
- 本文は PAM が呼び出し元のプロセス内で集めた `details.processes` だけから作る (ユーザ名は uid から引く)。分からない値は `?`
- 再現 HTML (`artifacts` 枝の `touch-id-dialog-design/replica.html` の案 K) は同じ規則の JS 版で、整形の見た目の確認に使う

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| sudo のたびにブラウザで承認ページを自動で開く | 作業中のブラウザのタブが遷移し、承認後のタブの後始末も要る |
| Mac ネイティブの passkey (ASAuthorization) で承認する | entitlement はメイン実行ファイル (`/usr/bin/sudo`) に付くので PAM モジュール内からは使えない。`pam-passkey` バイナリを .app にする必要があり重い |

## Consequences

- 「詳細を確認」を押した後も、承認ページでの passkey 署名と、出し直したダイアログでの Touch ID のどちらでも通せる
- 出し直したダイアログは、ブラウザを前面にした直後に OS がその上へ出すので邪魔になる ([findings](../findings/2026-11-09-end-to-end.md))。出し直しをページからの要求にする案は `docs/QUESTIONS.md` の PK-Q5
- 書式文字 (Cf) を全部エスケープするので、ZWJ (U+200D) で結合した絵文字列 (家族・職業の絵文字等) はコマンドやパスに含まれると結合が解けて見える。表示順の偽装を防ぐ方を優先した結果で、意図どおり
- 承認ページは iPhone と Mac で共通の 1 つで済む

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0009](./DR-0009-foreground-control.md)
- [findings: PAM モジュールの PoC](../findings/2026-11-02-pam-poc.md)
