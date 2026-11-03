# DR-0003: remote 承認のロジックは sudo プロセス外の helper に置き、PAM モジュールは薄層にする

- Status: Accepted
- Date: 2026-11-02

## Context

remote 承認には、要求のストアへの PUT、通知コマンドの起動、ポーリング、passkey 署名の検証、ブラウザで承認ページを開く処理が要る。PAM モジュールは sudo プロセス内で動くが、sudo は setuid プロセスで、次の制約がある。

- AppKit を初期化するとプロセスごと exit する (sudo 自体が落ち、コマンドが実行されない) ([findings](../findings/2026-11-02-pam-poc.md))
- root の sudo プロセスの中でネットワーク (TLS) を喋ることになる
- デバッグが難しく、動作確認のたびに sudo を経由する

また、helper が受け取る assertion は presigned PUT URL を知る者なら誰でも書ける。helper とその子は root から起動されるので、起動の仕方と置き場を誤ると、同じ uid のプロセスや攻撃者が書いたデータから root に届く。

## Decision

- helper は `pam-passkey` CLI の内部サブコマンドとして実装し、PAM モジュールはこれを spawn する薄い層にする。ロジックは CLI 側に置く
- helper は root で起動する。root が要る処理は、子を呼び出しユーザに永久降格させて起動すること (`setgroups` / `setgid` / `setuid` は root でしか行えない) だけで、root の helper はそれ以外の処理を持たない
- ストアとの通信、assertion の解析と検証、login keychain の読み出し、`send_command`、承認ページを開く処理は、呼び出しユーザに永久降格した子で行う。root の helper は子から判定 (pass / fail) だけを受け取り、攻撃者が書けるデータを root で解析しない
- 子の永久降格は、呼び出しユーザの補助グループで `setgroups`、続けて `setgid`、`setuid` の順に行う。real / effective / saved の uid がすべて呼び出しユーザになり、子は root に戻れない
- spawn の手順 (PAM が helper を起動する時と、helper が子を起動する時の両方):
  - 実行ファイルは絶対パスで指定する
  - 環境は空から始め、許可リストに載せた変数だけを入れる (sudo やその呼び出し元の環境を引き継がない)
  - 0/1/2 以外の fd を閉じる
  - cwd と umask を固定する
- 置き場: `.so` と helper は、ファイルと親ディレクトリ (`/` まで) が root 所有で、root 以外に書き込み権の無い場所に置く
  - PAM は helper を spawn する前に、helper とその親ディレクトリの owner と mode を検査する。不合格なら remote を諦める (Touch ID は出す)
  - `setup` も `.so` と helper の置き場を同じ基準で検査する ([DR-0010](./DR-0010-cli-shape.md))
  - 置き場がユーザ所有になる配布 (Homebrew) は対象外

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| ロジックを PAM モジュール内に置く | setuid プロセスでは AppKit を使えずプロセスごと落ちる。root の sudo 内で TLS を喋ることになる。sudo 抜きの動作確認ができない |

## Consequences

- PAM モジュールに入れてよいのは、プロセスを落とさない要素だけになる。モジュールが落ちない限り失敗は後続のパスワード認証に流れるので、不具合で sudo が通らず setup もできなくなる事態を避けられる
- helper が無い / 起動できない / 置き場の検査に通らない場合、モジュールは remote 側だけ諦めて Touch ID を出す (状況ごとの動作は [DR-0012](./DR-0012-auth-state-transitions.md))
- フォーカス操作 (AX で SecurityAgent の window を raise する等) も helper 側で行う
- 置き場がユーザ所有だと、同じ uid のプロセスが helper を差し替えて次の sudo で root として起動させられる。所有権の要件はこれを塞ぐためのもので、helper のコード署名の検査では代わりにならない (検査から exec までの間に差し替えられる)

## 関連

- [DR-0002](./DR-0002-single-module-parallel-auth.md)
- [DR-0009](./DR-0009-foreground-control.md)
- [DR-0010](./DR-0010-cli-shape.md)
- [DR-0012](./DR-0012-auth-state-transitions.md)
