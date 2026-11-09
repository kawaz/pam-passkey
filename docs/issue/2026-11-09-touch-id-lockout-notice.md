---
title: Touch ID ロックアウト (LAError -8) 時に理由と解除方法を tty と画面に出す
status: open
category: task
created: 2026-11-09T12:40:32+09:00
last_read:
open_entered: 2026-11-09T12:40:32+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: 自リポ TODO
---

# Touch ID ロックアウト (LAError -8) 時に理由と解除方法を tty と画面に出す

## 概要

Touch ID が失敗回数超過でロックされている時 (`canEvaluatePolicy` が -8)、利用者には「Touch ID が出ずパスワードに落ちた」としか見えない。理由と解除方法 (ロック画面でパスワード解除) を出す。

## 作るもの

- tty: `pam-passkey: Touch ID is locked after too many failed attempts; unlock the Mac with your password once to use it again` (日本語ロケールは日本語)。-8 以外の不可理由は今の 1 行のまま
- 画面: helper の PAM_USER に降格した子から macOS の通知 (`display notification` 相当、非モーダル、通知センターに残る) を出す。Touch ID を期待できる状況 (GUI セッションあり) で -8 の時だけ。自前の NSAlert は使わない (モーダルや前面奪取を避ける)
- remote の待ちはそのまま続ける (DR-0012 の「Touch ID 不可 → remote のみ」)

## 受け入れ条件

- [ ] 実機でロックアウト状態の `sudo` で tty の行と通知が出る
- [ ] ロック解除後は通常どおり Touch ID が出る
