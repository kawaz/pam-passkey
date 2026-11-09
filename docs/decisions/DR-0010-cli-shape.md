# DR-0010: CLI は 1 バイナリにまとめ、サブコマンドは動詞だけにする

- Status: Accepted
- Date: 2026-11-02

## Context

PAM モジュールから呼ばれる helper と、設定・passkey 管理の機能が要る。helper のロジックは呼び出し元のプロセス外の CLI 側に置く ([DR-0003](./DR-0003-helper-outside-sudo.md))。

## Decision

- helper と管理機能を `pam-passkey` の 1 バイナリにまとめる
- サブコマンドは `setup [--edit|--stdin|--dump] [--module <path>] [page_url]` / `add [label]` / `list` / `del <label|id>` と、PAM から呼ばれる内部用サブコマンド
- 内部用サブコマンド `_setup-write`: sudo で再実行され、`setup` が検証した設定 (標準入力の JSON 1 行) だけを受けて書き込む
- passkey の操作は `ssh-add` / `useradd` の感触で動詞だけにする (操作対象はツール名から自明)
- `setup` は設定を 1 つの JSON 文書として扱う。キーは `page_url`、`store` (オブジェクト: `endpoint` / `bucket` / `region` / `prefix` / `access_key` / `secret`)、`send_command`、`regenerate_key` (bool。既定は false で、署名鍵があれば維持する)
  - `--dump`: 今の設定を整形 JSON で標準出力に出す。`secret` は `"***"` に置き換え、`put_once` と `regenerate_key` は出さない。設定が無ければ page_url だけ既定値を入れた雛形を出す
  - `--stdin`: 標準入力の JSON (1 行でも整形でも) を設定として受ける。`secret` が `"***"` なら今の secret を維持する
  - `--edit`: `--dump` の内容を利用者だけが読める一時ファイルに書いて `$EDITOR` (未設定なら vi) で開き、エディタが正常終了して内容が変わっていれば `--stdin` と同じ処理をする。変わっていなければ何もしない。一時ファイルは終了時に消す
  - 引数が無い時は、標準入力が tty なら `--edit`、tty でなければヘルプを出す
  - `page_url` 引数を省略すると文書の `page_url`、それも無ければ既定の `https://pam-passkey.github.io/` を使う。引数と文書の両方にあって食い違えばエラー
  - 受けた設定は、ユーザ権限で検証し (ストアへの到達、CORS と lifecycle、置き場の検査)、書き込みの瞬間だけ自分の実行ファイルの絶対パスで `sudo <self> _setup-write` を再実行して、検証済みの設定を JSON 1 行で stdin に渡す。root で直接実行された場合はそのまま書く
  - `regenerate_key` が true で署名鍵が既にあれば、作り直すと既存の登録が全て無効になる。`--edit` (端末あり) では y/N で確認し、`--stdin` では文書の値を決定として扱い、その旨を 1 行出す
  - ストアへの到達を確かめ、バケットの CORS と lifecycle ルール ([DR-0006](./DR-0006-approval-url-and-exchange.md)) を設定する。CORS の `AllowedHeaders` には `If-None-Match` を含める。権限が無ければエラーで止まり、必要な設定を表示する
  - 疎通確認で、`If-None-Match: *` を付けた同じキーへの 2 回目の PUT が 412 になるかを試し、結果を `store` 設定の `put_once` (true / false) に持つ ([DR-0005](./DR-0005-s3-compatible-store.md))。`put_once` は `setup` が判定する値で、文書では渡せない (渡されても無視する)
  - 自分の実行ファイルの置き場を [DR-0003](./DR-0003-helper-outside-sudo.md) の基準で検査する。`.so` の置き場は `--module <path>` で与えられた場所、無ければ既定の `/usr/local/lib/pam/pam_passkey.so` が存在する時にそれを検査する
- `add` の label の既定値は登録日時 (`YYYY-MM-DD HH:MM`)。label は一意でなくてよい
- `del` は引数が credential id に一致すればそれを優先する。label が複数の passkey に一致したらエラーで止まり、候補を出す
- `list` は label、credential id、登録日を出す。JWS の検証はしない

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| 登録の動詞を `enroll` にする | WebAuthn の語彙で、利用者にとって重い |
| `passkey add` のように対象名詞を挟む | 対象は名前から自明で、名詞を挟む必要が無い |
| `setup` が対話で項目を 1 つずつ聞く | 再実行で今の値を残す・空にする・secret を出さずに残す、の取り決めが項目ごとに要り、非対話の入口とも別の経路になる。JSON 文書 1 つなら `--dump` / 編集 / `--stdin` が同じ形で往復する |

## Consequences

- PAM モジュールが spawn する対象は `pam-passkey` だけになる
- root が要るのは System Keychain に署名鍵と設定を書く `setup` の書き込みだけで、`setup` が自分で sudo を呼ぶ。`add` / `del` / `list` はユーザ権限で動く ([DR-0011](./DR-0011-user-keychain-signed-records.md))

## 関連

- [DR-0001](./DR-0001-naming.md)
- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0006](./DR-0006-approval-url-and-exchange.md)
- [DR-0011](./DR-0011-user-keychain-signed-records.md)
