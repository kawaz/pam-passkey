# pam-passkey

> [English](./README.md) | 日本語

macOS の sudo 認証で、手元の Touch ID と iPhone からの passkey 承認を同時に受け付ける PAM モジュール。手元に居れば Touch ID で、離席中なら iPhone に届いた URL から passkey で署名して sudo を通す。ローカルにサーバを持たない。

## 状態

設計と前提検証 (PoC) まで済んでおり、本体は実装前。インストール手順はまだ無い。

## 仕組み

```
sudo ─ pam_passkey.so ──┬─ Touch ID ダイアログ (「詳細を確認」ボタン付き)
                        └─ helper (`pam-passkey` CLI)
                             │ 要求詳細を暗号化して S3 互換ストアに置く
                             │ 承認 URL を通知コマンドに渡す (未設定なら tty に表示)
                             │ passkey の assertion を待って、署名を検証する
                        どちらか先に成功した方で sudo を通す。両方失敗ならパスワードへ

iPhone: 通知から URL を開く → 静的な承認ページで詳細を確認 → passkey で署名
Mac:    「詳細を確認」→ 同じ承認ページがブラウザで開く
```

- 承認の真正性は、Mac 側での passkey 署名の検証だけで担保する。中継 (ストア / 通知サービス / CDN) は信頼しない
- 常駐サーバ・受信ポート・デプロイするコードを持たない。中継は S3 互換ストアと presigned URL だけ
- 通知の手段はプラガブル。承認 URL を stdin で受けるコマンドなら何でもよい (Bark、ntfy、ssh 等)
- 状態と設定は Keychain だけに置き、ファイルを持たない。root が要るのは `setup` の 1 回だけで、passkey の追加・削除はユーザ権限 (Touch ID) で行う

## ドキュメント

- [DESIGN-ja.md](./docs/DESIGN-ja.md) — 設計 (ドメイン + アーキテクチャ)
- [decisions/INDEX.md](./docs/decisions/INDEX.md) — 設計判断の記録 (DR)
- [findings/](./docs/findings/) — 前提検証の観測記録
- [STRUCTURE.md](./docs/STRUCTURE.md) — リポジトリ物理構造

## ライセンス

MIT License, Yoshiaki Kawazu (@kawaz)
