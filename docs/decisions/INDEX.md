# Decision Records 一覧

Status は各 DR ファイルの `Status:` 行が正本。

状態は絵文字とラベルだけ。日付・Phase・裁定の内訳は各 DR 本文に書く。

- `💭 提案`: Decision がまだ裁定されていない。実装に着手しない (本文の `Status: Proposed`)
- `✅ 実装済`: Decision の全部に実装エビデンスがある
- `🟡 部分実装`: 一部のみ実装
- `⬜ 未実装`: 裁定済みで設計のみ、実装エビデンスなし (着手してよい)
- `🚧 進行中`: 実装の途中
- `N/A`: 実装対象でない (命名・思想・プロセス等)
- `❌ 撤退`: 撤退判断済

| DR | 状態 | 説明 |
|---|---|---|
| [DR-0001](DR-0001-naming.md) | N/A | 名前は PAM モジュール `pam_passkey`、CLI とリポジトリは `pam-passkey` |
| [DR-0002](DR-0002-single-module-parallel-auth.md) | ⬜ 未実装 | PAM スタックは直列なので、1 モジュール内で Touch ID と remote 承認を並走させる |
| [DR-0003](DR-0003-helper-outside-sudo.md) | ⬜ 未実装 | ロジックは呼び出し元のプロセス外の helper (`pam-passkey` の内部サブコマンド、root) に置き、PAM モジュールは薄層。`PAM_USER` の権限が要る処理だけ永久降格した子で行い、`.so` と `pam-passkey` バイナリは root 所有の置き場に置く |
| [DR-0004](DR-0004-fallback-button-as-details.md) | ⬜ 未実装 | 「詳細を確認」は LAContext の fallback ボタンを転用し、`LAErrorUserFallback` で拾う。承認ページは降格した子が `NSWorkspace` 相当で開く |
| [DR-0005](DR-0005-s3-compatible-store.md) | ⬜ 未実装 | 中継は S3 互換ストアと presigned URL。デプロイするコードを持たない |
| [DR-0006](DR-0006-approval-url-and-exchange.md) | ⬜ 未実装 | 承認 URL は `page_url#<presigned GET>` の 1 本、challenge はページが取得した要求そのものの SHA-256、result は pass / fail |
| [DR-0008](DR-0008-pluggable-send-command.md) | ⬜ 未実装 | 通知は `send_command` (URL を stdin で受けるコマンド) でプラガブル、既定は tty 表示。通知経路は信頼境界の内側 |
| [DR-0009](DR-0009-foreground-control.md) | ⬜ 未実装 | 前面制御は承認ページを開いた時のブラウザ activate のみ、承認後に起動元 terminal へ戻さない |
| [DR-0010](DR-0010-cli-shape.md) | ⬜ 未実装 | CLI は 1 バイナリ、サブコマンドは `setup` / `add` / `list` / `del` + 内部用。`setup` がバケットの CORS と lifecycle を設定し、置き場を検査する |
| [DR-0011](DR-0011-user-keychain-signed-records.md) | ⬜ 未実装 | passkey (署名付き) と設定はユーザの login keychain、署名鍵は System Keychain。sudo 依存は署名鍵を作る初回の `setup` だけ。Keychain の読み書きは `pam-passkey` バイナリに限定 |
| [DR-0012](DR-0012-auth-state-transitions.md) | ⬜ 未実装 | 認証の状態遷移と不変条件 (使う passkey と生体は `PAM_USER` のもの、Touch ID と remote の独立、全ての待ちに期限、seteuid の順序) |

後続の DR に置き換えられた DR は [archive/INDEX.md](archive/INDEX.md)。
