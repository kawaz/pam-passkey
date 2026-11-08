---
title: Touch ID ダイアログの本文に cwd と祖先チェーンを出す
status: open
category: task
created: 2026-11-09T02:53:39+09:00
last_read:
open_entered: 2026-11-09T02:53:39+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# Touch ID ダイアログの本文に cwd と祖先チェーンを出す

## 概要

承認ページを開かなくても、Touch ID ダイアログだけで「どこから来た認証要求か」を判断できるようにする。kawaz の案 (2026-11-09):

```
pam-passkey で次の操作を実行しようとしています:

# cwd:
/path/to/cwd

# ancestors:
- 00001 root /sbin/launchd
\- 07734 kawaz /(略)/ghostty
 \- 26724 root /usr/bin/login (略)
  \- 26725 kawaz -/bin/zsh
   \- 79807 root sudo -k true
```

## 設計 (DR-0004 に 1 節足してから実装)

- `localizedReason` は `"\n\n"` で始め、`# cwd:` と `# ancestors:` の 2 段落。祖先は launchd → 呼び出し元の順で、各行は pid (5 桁ゼロ埋め) / ユーザ / 実行パスまたは argv
- 各行は横幅 (約 34 半角 / 22 全角) に収まるよう中央を `(略)` で省略
- 祖先が深い時は先頭 2 行 + 末尾 4 行を残し、間を `…` 1 行にする (行数の上限で縦の伸びを抑える)
- 120 文字の上限は撤廃し、行数と行長の上限に置き換える
- 文字列は信頼できない (argv / パス) ので、制御文字と bidi のエスケープは維持
- 情報は PAM が既に集めている `details.processes` から作る (追加の取得は無い)

## 受け入れ条件

- [ ] DR-0004 に本文の仕様を追記
- [ ] `_probe-dialog` 相当で実機の見た目を確認 (スクリーンショット)
- [ ] 深い祖先 / 長いパス / 制御文字入り argv の 3 ケースで崩れない
