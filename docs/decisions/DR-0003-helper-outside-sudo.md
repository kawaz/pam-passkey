# DR-0003: remote 承認のロジックは sudo プロセス外の helper に置き、PAM モジュールは薄層にする

- Status: Accepted
- Date: 2026-11-02

## Context

remote 承認には、要求のストアへの PUT、通知コマンドの起動、ポーリング、passkey 署名の検証、ブラウザで承認ページを開く処理が要る。PAM モジュールは呼び出し元のプロセス内で動く。主用途の sudo は setuid プロセスで、次の制約がある。

- AppKit を初期化するとプロセスごと exit する (sudo 自体が落ち、コマンドが実行されない) ([findings](../findings/2026-11-02-pam-poc.md))
- 呼び出し元のプロセス内でネットワーク (TLS) を喋ることになる
- デバッグが難しく、動作確認のたびに sudo を経由する

また、helper とその子は root から起動されるので、起動の仕方と置き場を誤ると、同じ uid のプロセスから root に届く。

## Decision

- helper は `pam-passkey` バイナリの内部サブコマンドとして実装し、PAM モジュールはこれを spawn する薄い層にする。ロジックは CLI 側に置く。PAM と helper の間の取り決め (渡すもの、返すもの、fd の役割) は [helper-protocol](../design/helper-protocol.md)
- helper は root で起動し、ストアとの通信、assertion の検証、result の PUT を自分で行う
- `PAM_USER` の権限が要る処理 (login keychain の読み出し、`send_command`、承認ページを開く) だけを、`PAM_USER` に永久降格した子で行う (`setgroups` / `setgid` / `setuid`)
- 子の永久降格は、`PAM_USER` の補助グループで `setgroups`、続けて `setgid`、`setuid` の順に行う。real / effective / saved の uid がすべて `PAM_USER` になり、子は root に戻れない
- PAM が起動する `pam-passkey` バイナリの絶対パスは、pam.d のモジュール引数 `helper=<path>` で指定する。省略時はビルド時に埋め込んだ既定のパスを使う
- spawn の手順 (PAM が helper を起動する時と、helper が子を起動する時の両方):
  - 実行ファイルは絶対パスで指定する
  - 環境は空から始め、許可リストに載せた変数だけを入れる (呼び出し元のプロセスの環境を引き継がない)
  - 0/1/2 以外の fd を閉じる
  - cwd と umask を固定する
- 置き場: `.so` と `pam-passkey` バイナリは、ファイルと親ディレクトリ (`/` まで) が root 所有で、root 以外に書き込み権の無い場所に置く
  - PAM は helper を spawn する前に、`pam-passkey` バイナリとその親ディレクトリの owner と mode を検査する。不合格なら remote を諦める (Touch ID は出す)
  - PAM は helper を spawn した直後に、その pid の署名を `SecCodeCopyGuestWithAttributes` (`kSecGuestAttributePid`) → `SecCodeCheckValidity` で Team ID と identifier の requirement に対して検査する。不合格なら helper を止めて remote を諦める (Touch ID は出す)
  - `setup` も同じ基準で置き場を検査する ([DR-0010](./DR-0010-cli-shape.md))
  - 置き場がユーザ所有になる配布 (Homebrew) は対象外
- 呼び出し元の euid が 0 でなければ降格はせず、helper も子も呼び出し元と同じ uid で起動する

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| ロジックを PAM モジュール内に置く | setuid プロセスでは AppKit を使えずプロセスごと落ちる。呼び出し元のプロセス内で TLS を喋ることになる。sudo 抜きの動作確認ができない |
| ストアとの通信と assertion の検証を降格した子で行い、root の helper は結果だけ受ける | IPC が増える割に、子が乗っ取られれば偽の pass を返せるので安全性が変わらない |

## Consequences

- PAM モジュールに入れてよいのは、プロセスを落とさない要素だけになる。モジュールが落ちない限り失敗は後続のパスワード認証に流れるので、不具合で sudo が通らず setup もできなくなる事態を避けられる
- `pam-passkey` バイナリが無い / 起動できない / 置き場の検査か spawn 後の署名の検査に通らない場合、モジュールは remote 側だけ諦めて Touch ID を出す (状況ごとの動作は [DR-0012](./DR-0012-auth-state-transitions.md))
- 置き場がユーザ所有だと、同じ uid のプロセスが `pam-passkey` バイナリを差し替えて次の認証で root として起動させられる。所有権の要件はこれを塞ぐためのもので、コード署名の検査では代わりにならない (spawn 前のファイルの検査は exec までの間に差し替えられ、spawn 後の pid の検査の時点では差し替えたコードが root で動き始めている)
- nix-darwin のように置き場が store パスになる配布では、モジュール引数 `helper=` に store パスを渡す

## 関連

- [DR-0002](./DR-0002-single-module-parallel-auth.md)
- [DR-0009](./DR-0009-foreground-control.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [DR-0012](./DR-0012-auth-state-transitions.md)
- [helper-protocol](../design/helper-protocol.md) — PAM モジュールと helper の取り決め
