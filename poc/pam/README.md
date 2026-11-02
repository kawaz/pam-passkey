# pam_poc: macOS OpenPAM のローカル検証

Rust の `cdylib` で作る認証 PoC。`pam_get_user` で利用者を取得し、PAM conversation の `PAM_TEXT_INFO` で `pam_poc: <user> の承認待ち` を表示した後、`KERN_PROCARGS2` で自プロセスの argv、`getppid` / `KERN_PROC_PID` でたどった PID と `proc_pidpath` の実行パスを PID 1 まで表示します。取得・表示の途中で失敗した場合は `PAM_IGNORE` にして、このモジュール自身は認証成功を宣言しません。ツリー表示が成功したら LocalAuthentication の生体認証ダイアログ (本文は `sudo <argv>`) を出し、Touch ID 成功で `PAM_SUCCESS`、キャンセルなどの失敗で `PAM_AUTH_ERR` を返します。ダイアログの「詳細を確認」ボタン (フォールバックボタンの転用) が押されると `LAErrorUserFallback` (-3) を検出して tty に `pam_poc: 詳細を確認が押された (ここで承認 URL を open する想定)` を表示し、`PAM_AUTH_ERR` で後続の認証へ進めます。外部承認への遷移はまだ実装していません。

## ビルドと署名

macOS SDK と Rust、Cargo、Objective-C コンパイラが必要です。PAM FFI は macOS SDK の `security/pam_appl.h`、`pam_modules.h`、`pam_types.h`、`pam_constants.h` に合わせて手書きしています。親 PID 用の C shim は SDK の `struct kinfo_proc` を使用します。生体認証の Objective-C shim は `LocalAuthentication` と `Foundation` を使用します。`libpam` とこの 2 つのフレームワークをリンクします。AppKit はリンクも初期化もしません。`sudo` は setuid プロセスであり、AppKit は初期化時に `running setugid(), which is not allowed` でプロセスごと終了させるため、PAM モジュール内では使えません (`sudo` 自体が落ち、命令が実行されません)。ダイアログのフォーカス制御が必要な場合は、ユーザ権限で動く別プロセス (helper) で行う方針です。

以下はリポジトリの `poc/pam` ディレクトリで実行します。ビルド成果物は `target/` に置かれ、PAM のインストール先には一切触れません。

```sh
cargo build --release && cargo test
cp target/release/libpam_poc.dylib target/pam_poc.so
codesign -s - --force target/pam_poc.so
nm -gU target/pam_poc.so | grep ' _pam_sm_'
otool -L target/pam_poc.so
```

`cdylib` の出力 `libpam_poc.dylib` を、OpenPAM 向けの `pam_poc.so` にコピーします。`codesign -s - --force` は ad-hoc 署名で、認証先の設定変更はしません。署名済み `.so` は `target/pam_poc.so` に残るため、後述の手順も `poc/pam` ディレクトリで実行します。

## 手動インストールと動作確認（ここから先はこの PoC のビルド検証では実行しない）

先に**別のターミナル**で `sudo -s` を開き、root シェルを保ったまま作業してください。認証設定を誤った場合の復旧経路です。これは手順書であり、作成者は `sudo`、`/etc/pam.d/` 変更、root 所有ディレクトリへのコピーを実行していません。

1. 署名済みファイルを root 所有ディレクトリに配置します。配置先ディレクトリ `/usr/local/lib/pam` の所有者・権限を安全に確認し、存在しなければ root が作成してください。

   ```sh
   sudo install -d -m 755 -o root -g wheel /usr/local/lib/pam
   sudo install -m 755 -o root -g wheel target/pam_poc.so /usr/local/lib/pam/pam_poc.so
   ```

2. `/etc/pam.d/sudo_local` がなければ、既存の `/etc/pam.d/sudo_local.template` から root 権限でコピーします。既にあれば現在の設定を保存し、内容を確認してください。この環境では `/etc/pam.d/sudo_local` は `/etc/static/pam.d/sudo_local` への symlink です。編集時はリンク先や既存の管理方法を確認し、リンクの置換を避けます。

   ```sh
   sudo cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local  # sudo_local が存在しない場合だけ
   ```

3. `sudo_local` の**先頭の認証行**、`auth sufficient pam_tid.so` が有効ならその行よりも前に、次の 1 行を追加します。コメントを除く `auth` 行の先頭に置き、ほかの認証行を削除しないでください。

   ```text
   auth sufficient /usr/local/lib/pam/pam_poc.so
   ```

4. 別ターミナルの root シェルを残したまま、対話可能なターミナルで確認します。

   ```sh
   sudo -k; sudo true
   ```

   conversation が呼ばれる場合は `pam_poc: <user> の承認待ち`、続いて `pam_poc: sudo argv: [...]` と `pam_poc: pid <PID>: <実行パス>` が sudo 自身から PID 1 まで表示されます。ツリー表示が成功すると `sudo <引数>` を本文とする Touch ID ダイアログに進みます。成功時は後続認証なしで戻る想定です。前段階で失敗した場合は `PAM_IGNORE` となり、後続の認証に進み得ます。

   モジュールは `LAContext` の評価中だけ euid を呼び出しユーザ (`getuid()`) に `seteuid` で落とし、評価後に `seteuid(0)` で戻します。euid が root のままだと `LAError code=-7 Biometry is not enrolled` になるためです。失敗時の診断行には `(euid drop=<n> restore=<n> uid=<uid>)` が付きます。policy は `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` です。

   実機で確認済みの事項は、`/etc/pam.d/sudo_local` からの load、tty への表示、launchd までのプロセスツリー、Touch ID ダイアログの表示 (本文に `sudo <argv>`)、「詳細を確認」の検出 (`LA error code=-3` と上記の表示) です。Touch ID 成功で `PAM_SUCCESS` になりコマンドが実行されること、ダイアログがクリックなしでタッチに反応することも確認済みです。キャンセル時のエラーコードと説明は未観測です。この手順で観測した結果は [docs/findings/2026-11-02-pam-poc.md](../../docs/findings/2026-11-02-pam-poc.md) にまとめています。

5. tty を持たない条件では `sudo -n true`、GUI 起動からの `sudo` でも検証してください。`sudo -n` は非対話モードであり、既存の認証キャッシュや sudo 自身の非対話判定によって PAM モジュールが呼ばれない可能性もあるため、先に `sudo -k` で timestamp を消し、表示の有無・終了コード・呼び出しの有無を区別してください。GUI 側も利用する conversation の実装によって `PAM_TEXT_INFO` の送出先が異なるため、表示・待機・認証結果を別々に記録してください。これらは実機の PAM 設定での未検証項目です。

6. 戻すときは、保持した root シェルから `/etc/pam.d/sudo_local` の追加した `auth sufficient /usr/local/lib/pam/pam_poc.so` **1 行だけを削除**し、元の行を残します。事前に存在しなかったファイルを template から作成した場合は、元の状態に戻すことも確認してください。root シェルは元の認証が戻ったことを確認するまで閉じないでください。

## 制約

argv は秘密情報を含み得るため、この PoC は argv を tty と認証ダイアログ上にだけ表示し、環境変数は読み取りません。`PAM_MAX_MSG_SIZE`（終端 NUL を含む 512 バイト）を超える argv・プロセス情報の表示、プロセス情報の取得失敗、認証ダイアログを出す前の conversation の失敗は `PAM_IGNORE` とします。親 PID が検証途中に変わったり、対象プロセスが終了したりした場合も `PAM_IGNORE` になり得ます。認証ダイアログが閉じた後の診断情報は 1 メッセージごとに分割して tty に表示し、この表示に失敗した場合は `PAM_AUTH_ERR` です。
