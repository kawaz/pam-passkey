# DR-0002: 1 つの PAM モジュール内で Touch ID と remote 承認を並走させる

- Status: Accepted
- Date: 2026-11-02

## Context

sudo の認証で、手元に居る時は Touch ID、離席中・リモート作業中は iPhone からの passkey 承認で通したい。どちらの状況かは事前に分からないので、両方を同時に受け付けて、先に来た方で通す必要がある。

PAM スタックは直列で、モジュールは上から 1 つずつ呼ばれ、前のモジュールが戻るまで次は始まらない。

## Decision

`pam_tid` の代わりに `pam_passkey.so` を置き、1 つのモジュールの中で Touch ID (LAContext) と remote 承認 (helper) を並走させる。どちらか成功したらもう片方をキャンセルして `PAM_SUCCESS`、両方失敗 / timeout なら `PAM_AUTH_ERR`、両方とも使えなければ `PAM_IGNORE` で後続 (パスワード) へ流す。状況ごとの動作は [DR-0012](./DR-0012-auth-state-transitions.md)。`pam_tid` (`touchIdAuth`) は off にする。

## 不採用案と理由

| 案 | 不採用理由 |
|---|---|
| `pam_tid` の後ろに remote 承認用の別モジュールを置く | スタックが直列なので、離席時は Touch ID ダイアログが timeout するまで remote 承認が始まらない |
| sudo の approval plugin で承認を足す | approval plugin は認証を免除できず、拒否 (deny) を足せるだけ。承認で sudo を通す用途に使えない |

## Consequences

- モジュールが Touch ID ダイアログの表示と remote 承認の待ちを両方持ち、片方の成功でもう片方を止める並行制御を持つ
- Touch ID の扱い (LAContext の euid、fallback ボタン) もこのモジュールの責務になる ([DR-0004](./DR-0004-fallback-button-as-details.md))
- remote 承認のロジックは呼び出し元のプロセス外の helper に置く ([DR-0003](./DR-0003-helper-outside-sudo.md))

## 関連

- [DR-0003](./DR-0003-helper-outside-sudo.md)
- [DR-0004](./DR-0004-fallback-button-as-details.md)
- [DR-0012](./DR-0012-auth-state-transitions.md)
