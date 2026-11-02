# リポジトリ物理構造

```
pam-passkey/
  README.md / README-ja.md
  LICENSE
  justfile                  # task runner (lint / push のゲート)
  .gitignore                # target/ を除外
  docs/
    DESIGN-ja.md / DESIGN.md  # 現在の設計
    STRUCTURE.md              # このファイル
    decisions/                # 設計判断の記録 (DR-NNNN-*.md と INDEX.md)
    findings/                 # 前提検証の観測記録 (YYYY-MM-DD-<slug>.md)
  poc/                      # 前提検証の PoC。本体の実装ではない
    pam/                      # 自作 PAM モジュールを sudo から load し Touch ID で通す (Rust cdylib + C / Objective-C shim)
    keychain/                 # System Keychain の書き込み権限と sudo 内 PAM からの読み出し (Rust + C shim、kc-poc CLI と pam_kcpoc.so)
```

PoC はそれぞれ独立した Cargo プロジェクトで、各ディレクトリで `cargo build` する (手順は各 `README.md`)。ビルド成果物は各ディレクトリの `target/` に置かれ、追跡しない。
