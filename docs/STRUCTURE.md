# リポジトリ物理構造

```
pam-passkey/
  README.md / README-ja.md
  LICENSE
  Cargo.toml / Cargo.lock   # workspace (crates/ の 3 crate)
  justfile                  # task runner (build = release ビルド + Developer ID 署名、install、lint、push のゲート)
  .gitignore                # target/ を除外
  crates/
    protocol/                 # helper-protocol / exchange-format の型 (serde)
    pam-passkey/              # CLI と helper (Keychain 層、_auth、setup / add / list / del)
    pam_passkey/              # PAM モジュール (cdylib。LAContext と helper の並走、DR-0012 の状態遷移)
  docs/
    DESIGN-ja.md / DESIGN.md  # 現在の設計
    STRUCTURE.md              # このファイル
    decisions/                # 設計判断の記録 (DR-NNNN-*.md と INDEX.md)
    design/                   # 設計の付随詳細 (<topic>-<sub>.md)
    findings/                 # 前提検証の観測記録 (YYYY-MM-DD-<slug>.md)
    research/                 # 中期テーマの深掘り・レビュー (YYYY-MM-DD-<slug>.md)
    issue/                    # 自リポの TODO と依頼 (YYYY-MM-DD-<slug>.md と INDEX.md)
  poc/                      # 前提検証の PoC。本体の実装ではない
    pam/                      # 自作 PAM モジュールを sudo から load し Touch ID で通す (Rust cdylib + C / Objective-C shim)
    keychain/                 # System Keychain の書き込み権限と sudo 内 PAM からの読み出し (Rust + C shim、kc-poc CLI と pam_kcpoc.so)
```

本体は `just build` (release ビルドと Developer ID 署名) と `just install` (root 所有の `/usr/local/libexec/pam-passkey` と `/usr/local/lib/pam/pam_passkey.so` へ)。PoC はそれぞれ独立した Cargo プロジェクトで、各ディレクトリで `cargo build` する (手順は各 `README.md`)。ビルド成果物は `target/` に置かれ、追跡しない。
