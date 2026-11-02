# 退避した Decision Records

後続の DR に置き換えられた DR。各ファイルの `Status: Superseded by DR-NNNN` が正本で、現役の文書からはここも各ファイルも名指ししない (置き換え先を指す)。

| DR | 説明 | 置き換え先 |
|---|---|---|
| [DR-0007](DR-0007-system-keychain-only.md) | 状態と設定は System Keychain 一本。書き込みは root、読み出しは無ダイアログ | [DR-0011](../DR-0011-user-keychain-signed-records.md) |
