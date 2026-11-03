# DR-0004: 「詳細を確認」は LAContext の fallback ボタンを転用する

- Status: Accepted
- Date: 2026-11-02

## Context

手元の Mac で sudo を承認する時、Touch ID ダイアログに出せるのは短い本文 (sudo の argv) 程度に限られる。プロセスツリーや署名情報まで見てから承認したい場合に、承認ページ (iPhone と同じもの) を Mac 上で開く手段が要る。

PAM モジュール内からはブラウザを開けず ([DR-0003](./DR-0003-helper-outside-sudo.md))、Touch ID ダイアログに置けるボタンは LAContext が提供するものに限られる。

## Decision

- LAContext の fallback ボタンを `localizedFallbackTitle` で「詳細を確認」に差し替える
- policy は `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` (生体 / companion のみの系) にする。この系では fallback がパスワード入力に行かず、押下は `LAErrorUserFallback` (-3) で返る
- 押されたら helper が承認ページを開く。Mac でも iCloud 同期された同じ passkey で署名できる
- 開く処理は、`PAM_USER` に永久降格した子 ([DR-0003](./DR-0003-helper-outside-sudo.md)) が `NSWorkspace` / `LSOpenCFURLRef` 相当を直接呼んで行う。`/usr/bin/open <URL>` は exec しない。承認 URL をプロセスの argv に出さないためで、argv は `ps` で他ユーザからも読める

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| sudo のたびにブラウザで承認ページを自動で開く | 作業中のブラウザのタブが遷移し、承認後のタブの後始末も要る |
| Mac ネイティブの passkey (ASAuthorization) で承認する | entitlement はメイン実行ファイル (`/usr/bin/sudo`) に付くので PAM モジュール内からは使えない。`pam-passkey` バイナリを .app にする必要があり重い |

## Consequences

- 「詳細を確認」を押した時点で Touch ID ダイアログは閉じ、承認は承認ページ側の passkey 署名で行う
- 承認ページは iPhone と Mac で共通の 1 つで済む

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0009](./DR-0009-foreground-control.md)
- [findings: PAM モジュールの PoC](../findings/2026-11-02-pam-poc.md)
