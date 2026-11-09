# pam-passkey マニュアル

> [English](./MANUAL.md) | 日本語

## 必要なもの

- macOS (Touch ID 搭載機。非搭載機では手元の認証はパスワードになる)
- passkey を持つ iPhone / iPad / Mac (iCloud キーチェーンで同期されるもの)
- S3 互換のオブジェクトストアのバケット 1 つ (承認要求の中継に使う。pam-passkey 専用にする)
- 任意: 承認 URL を iPhone に届けるコマンド (Bark / ntfy / ssh 等。無ければ URL は端末に表示される)

## 1. ストアのバケットを用意する

pam-passkey はバケットに短命のオブジェクト (承認要求、署名、結果) を置き、presigned URL でページに読み書きさせる。バケットは pam-passkey 専用にし、`setup` が CORS と lifecycle の設定を置き換えることを前提にする。公開アクセスは不要 (全部ブロックしてよい)。

必要な権限は次の 5 つだけ。access key はこの権限だけを持つ専用ユーザに発行する。

| 操作 | 用途 |
|---|---|
| `s3:PutObject` / `s3:GetObject` / `s3:DeleteObject` (バケット内の全オブジェクト) | 承認要求と署名の受け渡し、終了時の削除、presigned URL の発行 |
| `s3:PutBucketCORS` (バケット) | `setup` がページの origin からの GET / PUT を許可する |
| `s3:PutLifecycleConfiguration` (バケット) | `setup` が残ったオブジェクトを 1 日で消す規則を置く |

### AWS S3 の例

```sh
export AWS_PAGER=""
B=pam-passkey-<自分の名前>      # バケット名 (全世界で一意)
R=ap-northeast-1                # 置くリージョン

aws s3api create-bucket --bucket "$B" --region "$R" --create-bucket-configuration LocationConstraint="$R"
aws s3api put-public-access-block --bucket "$B" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws iam create-user --user-name "$B"
aws iam put-user-policy --user-name "$B" --policy-name pam-passkey-store --policy-document "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"], "Resource": "arn:aws:s3:::$B/*" },
    { "Effect": "Allow", "Action": ["s3:PutBucketCORS", "s3:PutLifecycleConfiguration"], "Resource": "arn:aws:s3:::$B" }
  ]
}
EOF
)"
aws iam create-access-key --user-name "$B"
```

`setup` に渡す値: endpoint `https://s3.<リージョン>.amazonaws.com`、bucket、region、access key と secret。

### Cloudflare R2 の例

1. R2 でバケットを作る (公開アクセスは無効のまま)
2. R2 の API トークンを「オブジェクトの読み書き」権限で、対象をそのバケットに限定して作る
3. `setup` に渡す値: endpoint `https://<account id>.r2.cloudflarestorage.com`、bucket、region `auto`、トークンの access key と secret

R2 で CORS の設定が API から通らない場合は、`setup` が表示する内容をダッシュボードの CORS 設定に手で入れる。

## 2. インストールと設定

```sh
just install                                   # ビルドと Developer ID 署名、root 所有の場所へ配置
pam-passkey setup --module /usr/local/lib/pam/pam_passkey.so
```

`setup` は対話で次を聞く。書き込みの瞬間だけ `sudo` で自分を再実行する。

| 項目 | 入力 |
|---|---|
| page_url | Enter で既定の `https://pam-passkey.github.io/` |
| endpoint / bucket / region / prefix | ストアの接続情報。prefix は省略可 |
| access key / secret | 専用ユーザのもの (画面には出ない) |
| send_command | 承認 URL を標準入力で受けて届けるコマンド。空なら端末に表示 |

`setup` はストアへの疎通、条件付き PUT の対応、CORS と lifecycle の設定、配置先の所有権を確かめてから書き込む。署名鍵が既にある時は「既存の登録は全て無効になる」と出して確認する (N なら鍵を残して設定だけ更新)。

## 3. passkey を登録する

```sh
pam-passkey add [label]
```

本人確認 (Touch ID、非搭載機はパスワード) の後、登録 URL が端末に出る (send_command があればそちらに渡る)。URL を iPhone か Mac のブラウザで開き、passkey を作る。`add` が受け取って検証し、保存する。

```sh
pam-passkey list          # label / credential id / 登録日時
pam-passkey del <label|id>
```

## 4. PAM に組み込む

`/etc/pam.d/sudo_local` に次の 1 行を先頭に書き、`pam_tid.so` の行は外す。

```
auth       sufficient     /usr/local/lib/pam/pam_passkey.so
```

書き換える前に別の端末で `sudo -s` を開いたままにしておくと、設定を誤っても戻せる。nix-darwin では `security.pam.services.sudo_local.text` に同じ行を書き、`pam-passkey` バイナリの store パスをモジュール引数 `helper=<path>` で渡す。

## 5. 使う

`sudo` を実行すると Touch ID のダイアログが出る。手元に居れば Touch ID で通る。離席中は、端末に出た承認 URL (send_command があれば通知で届いた URL) を iPhone で開き、内容を確かめて passkey で承認する。ダイアログの「詳細を確認」を押すと同じ承認ページが Mac のブラウザで開き、ダイアログも出し直される。

どちらでも通らなければ (キャンセル、拒否、期限切れ 90 秒) パスワード認証に落ちる。

## 困った時

- ダイアログが出ない / すぐパスワードになる: `/usr/local/libexec/pam-passkey` と `.so` が root 所有で Developer ID 署名か、`setup` を済ませているかを確認する
- ssh 経由の sudo では Touch ID もリモート承認も使えない (login keychain が unlock されていないため)。パスワードになる
- 登録を全部やり直したい: `pam-passkey setup` で署名鍵を作り直す (全ユーザの登録が無効になる)
