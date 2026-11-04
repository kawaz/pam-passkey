# DR-0009: 前面制御は承認ページを開いた時のブラウザ activate のみとし、承認後に起動元へ戻さない

- Status: Accepted
- Date: 2026-11-02

## Context

「詳細を確認」で承認ページを開く時はブラウザを前面に出す必要がある ([DR-0004](./DR-0004-fallback-button-as-details.md))。承認が済んだ後に、sudo を起動した terminal へ前面を戻すかを決める必要がある。

sudo のプロセスツリー (ppid) を辿って得られる起動元は「sudo がどこから来たか」であって、「ユーザが今見ているアプリ」ではない。

## Decision

- 前面制御は、helper が承認ページを開いた時 (開き方は [DR-0004](./DR-0004-fallback-button-as-details.md)) にそのブラウザを activate することと、出し直したダイアログの後にブラウザをもう一度 activate することだけにする
- 「詳細を確認」の後の前面はブラウザが取る。順序は、PAM がダイアログを出し直す → helper の子が承認ページを開いてブラウザを activate → ダイアログの表示がブラウザより遅れた場合の保険として、PAM が続けて `reactivate` を送り helper の子がブラウザをもう一度 activate する ([helper-protocol](../design/helper-protocol.md))。`LAContext` に前面制御の API は無いので、前面の調整は helper 側で行う
- 承認後に起動元 terminal へ前面を戻す処理はしない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 承認後にプロセスツリーの起動元 terminal を前面に戻す | 起動元と操作中のアプリが一致しない。例えば VS Code 内の Claude が叩いた sudo を iPhone / ブラウザで承認した時に、使っていない terminal を前面にしてしまう |

## Consequences

- 承認後の前面は、ユーザが承認に使ったアプリのまま残る
- Touch ID ダイアログのフォーカス (クリック無しでタッチに反応するか) は前面制御の対象に含めない。問題が出た場合は helper の AX raise で対処する

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0004](./DR-0004-fallback-button-as-details.md)
- [helper-protocol](../design/helper-protocol.md) — PAM モジュールと helper の取り決め
