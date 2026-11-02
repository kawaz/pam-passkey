# System Keychain と sudo 内 PAM の PoC

`kc-poc` は `/Library/Keychains/System.keychain` の generic password 項目をユーザ権限から作成・更新・参照・削除する CLI です。`pam_kcpoc.so` は sudo の PAM conversation に同じ項目の読み出し結果を表示し、常に `PAM_IGNORE` を返します。このモジュールは認証を成功させません。サービス名は `pam-passkey-poc`、アカウント名は `pam_get_user` の戻り値に固定しています。値を tty に表示するため、検証用の無害な文字列だけを使用してください。

## ビルド

macOS、Rust/Cargo、macOS SDK と C コンパイラが必要です。以下と後述の手動検証・後始末は、リポジトリの `poc/keychain` ディレクトリで実行します。

```sh
cargo build --release
cp target/release/libpam_kcpoc.dylib target/pam_kcpoc.so
codesign -s - --force target/pam_kcpoc.so
nm -gU target/pam_kcpoc.so | grep ' _pam_sm_authenticate$'
otool -L target/pam_kcpoc.so
target/release/kc-poc --help
```

`codesign -s -` は `target/` 内の PAM モジュールに ad-hoc 署名します。`cargo build` ではレガシー Keychain ACL API が macOS SDK で非推奨のため警告が出ます。モジュールのインストールや System Keychain の変更はビルド時には行いません。

## 手動検証

以下は**ユーザ自身が対話できる端末で実行する手順**です。この PoC の作成者は System Keychain の項目の作成・更新・読み出し・削除を実行していません。先に別のターミナルで `sudo -s` を起動し、`sudo_local` を元に戻せる root シェルを維持してください。`/etc/pam.d/sudo_local` が symlink・宣言的な設定で管理されていないか、編集前に確認してください。認証設定に触れる前に、既存内容を保存してください。

1. 項目を書き込みます。ユーザ権限では `-61` (Write permissions error) で失敗するので、`sudo` を付けて root で書きます。書き込みが成功したら、検索対象を明示した `security` コマンドで **System Keychain** に存在することを確認してください。

   ```sh
   target/release/kc-poc write pam-passkey-poc kawaz hello
   security find-generic-password -s pam-passkey-poc /Library/Keychains/System.keychain
   ```

2. 同じユーザ権限で読み、ダイアログが出ずに `hello` だけが表示されるか確認してください。読み出し時のダイアログや失敗は ACL の検証結果として記録してください。

   ```sh
   target/release/kc-poc read pam-passkey-poc kawaz
   ```

3. `pam_kcpoc.so` をインストールします。宛先ディレクトリの所有者・権限を確認し、存在しない場合だけ root が作成します。`/etc/pam.d/sudo_local` がなければ既存の `/etc/pam.d/sudo_local.template` から作成してください。`sudo_local` の**最初の認証行**（有効な `pam_tid.so` や `pam_poc.so` 行より前）に下の 1 行を追加し、他の行は残します。

   ```sh
   sudo install -d -m 755 -o root -g wheel /usr/local/lib/pam
   sudo install -m 755 -o root -g wheel target/pam_kcpoc.so /usr/local/lib/pam/pam_kcpoc.so
   ```

   ```text
   auth sufficient /usr/local/lib/pam/pam_kcpoc.so
   ```

4. 別ターミナルの root シェルを維持したまま、対話可能な tty で実行してください。`pam_kcpoc: kawaz = hello` が表示されるか、Keychain の読み出しでダイアログが出ないか、失敗なら表示された理由と後続 PAM モジュールの動作を記録してください。`PAM_IGNORE` を返すため後続の認証は通常どおり必要です。

   ```sh
   sudo -k; sudo true
   ```

5. 終了後は `sudo_local` に追加した `pam_kcpoc.so` の行**だけ**を保持中の root シェルから削除してください。元の認証経路が戻ったことを確認してから root シェルを閉じてください。`poc/keychain` ディレクトリで通常ユーザのまま項目を削除し、検索で項目が見つからないことを確認してください。初めから `sudo_local` がなかった場合は template コピーの後始末を含め、変更前の状態に戻してください。

   ```sh
   target/release/kc-poc delete pam-passkey-poc kawaz
   security find-generic-password -s pam-passkey-poc /Library/Keychains/System.keychain
   ```

## API 経路と観察項目

- `security-framework` 3.7.0 の `SecKeychain::open("/Library/Keychains/System.keychain")` が `SecKeychainOpen` を呼び、読み出し・削除の `ItemSearchOptions::keychains` が `kSecMatchSearchList` で System Keychain だけを検索します。CLI と PAM は同じ Rust ライブラリを使います。
- 書き込みの対象は C shim に渡した上記 `SecKeychainRef` と `kSecUseKeychain` で固定します。`SecItemAdd` で新規作成し、`errSecDuplicateItem` の場合は `kSecMatchSearchList` を指定した `SecItemUpdate` で値と ACL を更新します。書き込み時にデフォルトの login keychain へフォールバックしません。
- `security-framework` 3.7.0 の `ItemAddOptions` は System Keychain の指定には対応しますが、`kSecAttrAccess` の指定には対応せず、`security-framework-sys` 2.17.0 にも `SecAccessCreate` や `SecACLSetContents` の binding がありません。C shim で `SecAccessCreate` から decrypt ACL を取得し、`SecACLSetContents(acl, NULL, ..., 0)` で全アプリに読み出しを許可する ACL を設定した後、`kSecAttrAccess` を付けて `SecItemAdd`/`SecItemUpdate` を呼びます。SDK によれば `SecAccessCreate` の trusted-list 引数が `NULL` のままでは**作成元アプリだけ**になるため、decrypt ACL を明示変更します。
- 実機の結果: ユーザ権限の `write` は `system.keychain.modify` の right を取得しても `-61` で失敗し、`sudo kc-poc write` なら成功する。`NULL` application list + selector `0` の ACL で、ユーザ権限の `read` も sudo の PAM からの読み出しもダイアログ無しで通る。詳細は findings を参照。

この手順で観測した結果は [docs/findings/2026-11-02-keychain-poc.md](../../docs/findings/2026-11-02-keychain-poc.md) にまとめています。
