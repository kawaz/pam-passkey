# pam-passkey Design

> English | [日本語](./DESIGN-ja.md)

## Domain

In macOS PAM authentication (mainly sudo, the same layer as `pam_tid`), accept both Touch ID at the Mac and, when the user is away, passkey approval from an iPhone at the same time.

### Goals

- Let authentication such as sudo go through from an iPhone while away from the desk or working remotely
- Rest the authenticity of an approval on verifying the passkey signature on the Mac. The relay store is not trusted for authenticity (a failure or tampering at the store never works in the direction of letting an approval through). What is trusted is limited to what is listed in [Trust assumptions](#trust-assumptions)
- When the user is at the Mac, Touch ID lets the authentication through directly without waiting on remote approval

### What not to add

- Resident servers, listening ports, self-hosted HTTPS servers (no code to deploy and maintain, neither on the Mac nor on the relay side)
- Files for settings or state (state and settings live only in the Keychain)
- Approval-path logic inside the calling process (the PAM module stays a thin layer that launches the helper)

### Out of scope

- Conditions for what requires authentication: the responsibility of the PAM configuration and the caller (for sudo, sudoers)
- The unauthenticated period after approval: the caller's responsibility (for sudo, the timestamp; sudoers' `timestamp_timeout` applies as is). The module does not control it
- How notifications are delivered: the responsibility of what `send_command` runs. The module only knows how to "deliver one URL"

## Trust assumptions

What decides whether an approval is granted, and whose compromise lets an approval be forged (the TCB):

- The page origin: the repository `pam-passkey.github.io` of the GitHub org `pam-passkey` (GitHub Pages), and write access to that repository. No other GitHub Pages is placed in the org `pam-passkey` (so that the origin is not shared)
- The rp_id domain `pam-passkey.github.io`: JS running on this origin can create assertions with the enrolled passkeys
- iCloud (where passkeys are synced): the synced devices and their account are among the parties who can approve. Synced passkeys are accepted (iCloud sync is a premise of the design)
- The notification path (what `send_command` goes to): placed inside the trust boundary as a path the user chose. The approval URL and the enrollment URL are time-limited capabilities, and whoever sees the URL can use it within the expiry ([DR-0008](./decisions/DR-0008-pluggable-send-command.md))
- The Developer ID signature of the `pam-passkey` binary: the basis for limiting reads and writes of Keychain items to the `pam-passkey` binary ([DR-0011](./decisions/DR-0011-user-keychain-signed-records.md))

A user of the default page trusts the page origin (the org `pam-passkey`). A user who does not should fork it, host it themselves and swap `page_url`.

Not trusted:

- The S3-compatible store: it only relays requests, assertions and results, and the authenticity of an approval is decided by signature verification on the Mac. Tampering at the store results only in a fail or a wait. The request details are not encrypted (the store is the user's own bucket)

## Architecture

The diagram is an example for the case called from sudo, the main use.

```
sudo ─ pam_passkey.so ──┬─ thread A: LAContext (Touch ID dialog, fallback button = "Show details")
                        └─ spawn ─▶ helper = internal subcommand of the `pam-passkey` CLI (root; reading the login keychain, open and send_command run in a child permanently dropped to PAM_USER)
                                     │ 1. PUT the request (details and presigned URLs) to the S3-compatible store
                                     │ 2. pass the approval URL to `send_command` on stdin; PAM prints it to the tty if unset
                                     │ 3. poll for the assertion object (until expiry)
                                     │ 4. verify the passkey signature and return the result to PAM
                        Either succeeds → cancel the other → PAM_SUCCESS
                        Both fail / timeout → PAM_AUTH_ERR, on to the next module (password)

Receiver (iPhone): open the URL from the notification → static page → GET the request and show it → passkey signature → presigned PUT
Receiver (Mac):    "Show details" → the child of the helper, dropped to the user, opens the same approval page and activates the browser (the same passkey is available via iCloud sync)
```

### Components

| Component | Responsibility |
|---|---|
| `pam_passkey.so` | PAM module running inside the calling process (sudo in the main use). Shows the Touch ID dialog (LAContext), spawns the helper in parallel, and returns `PAM_SUCCESS` on whichever succeeds first |
| `pam-passkey` CLI | One binary bundling the helper (an internal subcommand called from PAM) and the management functions. All approval-path logic lives here |
| Static pages | The enrollment page and the approval page, served from a fixed HTTPS domain (the passkey RP ID). `https://pam-passkey.github.io/` by default. A single file that loads no external scripts, with CSP set via `<meta>`. The pages hold no settings; everything they need comes from the URL |
| S3-compatible store | Holds the request, the assertion, the result and, at enrollment, the credential. Presigned URLs double as time-limited capabilities. Any API-compatible store can be swapped in |
| `send_command` | A command that reads the approval URL and the enrollment URL from stdin and delivers them (Bark / ntfy / ssh, ...). If unset, the URL is printed to the tty |

### Constraints on the PAM module

- If the calling process is setuid (sudo, etc.), AppKit cannot be initialized inside the PAM module (the whole process exits on initialization). Opening the approval page in the browser and bringing it to the front are done by the helper ([findings](./findings/2026-11-02-pam-poc.md))
- `LAContext` checks biometric enrollment for the euid, so the module drops to `seteuid` of the `PAM_USER` uid only during evaluation and returns with `seteuid(0)` afterwards. `seteuid` affects the whole process, so collecting process information and spawning the helper are done before dropping. If it cannot return, `PAM_AUTH_ERR` ([DR-0012](./decisions/DR-0012-auth-state-transitions.md))
- The policy is `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion` (approval on an Apple Watch also goes through). The fallback button is relabeled "Show details" via `localizedFallbackTitle` (the buttons are `Show details` / `Cancel` in English by default, and 「詳細を確認」 / 「キャンセル」 when the first preferred language of `PAM_USER` is Japanese), and a press is detected as `LAErrorUserFallback` (-3)
- The dialog text is fitted to the length limit of `localizedReason` by eliding the middle, not the end (keeping the beginning and the end)
- The module never brings the process down. The safeguard against a lockout (a module bug blocks sudo, so setup cannot be run either) is that failures fall through to the subsequent password authentication
- The passkey and the Touch ID biometrics used belong to `PAM_USER`. The item `users/<PAM_USER>` is read, `LAContext` is evaluated under the uid of `PAM_USER`, and the children that run `send_command` and open the approval page also drop to `PAM_USER`. If `PAM_USER` is root (`targetpw` in sudoers, etc.) there is no passkey or biometrics, and it falls to the password ([DR-0012](./decisions/DR-0012-auth-state-transitions.md))

### Behavior on failure

The state transition table in [DR-0012](./decisions/DR-0012-auth-state-transitions.md) is the source of truth for the behavior of Touch ID and remote and the PAM return value in each situation. In short:

- Whether Touch ID is usable and whether remote succeeds are handled independently, and if either one runs, its result decides `PAM_SUCCESS` / `PAM_AUTH_ERR`. Only when neither is usable does it return `PAM_IGNORE` and move on to the next module (never fail open)
- Cancel and expiry stop both and give `PAM_AUTH_ERR`. The expiry is the request's `expires` alone
- In every situation the module returns within the expiry, and `PAM_AUTH_ERR` and `PAM_IGNORE` fall through to the subsequent password authentication

### PAM integration

- Example for sudo: write `auth sufficient pam_passkey.so` in `/etc/pam.d/sudo_local`, and turn `pam_tid` (`touchIdAuth`) off
- With nix-darwin, write the single line with the store path in `security.pam.services.sudo_local.text` (the same shape as pam-watchid). The store path of the `pam-passkey` binary is passed with the module argument `helper=<path>`
- Place the `.so` and the `pam-passkey` binary where the parent directories are owned by root and not writable by anyone but root. User-owned locations such as under Homebrew are not supported ([DR-0003](./decisions/DR-0003-helper-outside-sudo.md))

### Helper privileges

The helper starts as root (if the caller's euid is not 0 it does not drop, and runs with the same uid as the caller), but communication with the store, assertion verification and the PUT of the result are done by the helper itself. Only the work that needs the privileges of `PAM_USER` (reading the login keychain, `send_command`, opening the approval page) is done in a child permanently dropped to `PAM_USER`. The spawn procedure (absolute path, an allow-listed environment built from empty, closing fds other than 0/1/2, fixing cwd / umask) and the order of dropping are in [DR-0003](./decisions/DR-0003-helper-outside-sudo.md), and the agreement between PAM and the helper (JSON on stdin, events on stdout) is in [helper-protocol](./design/helper-protocol.md).

## Approval URL and exchange flow

```
Approval URL:  <page_url>#<presigned GET URL of the request>
Mac (helper):  PUT request (keep the bytes) → send approval URL → poll assertion → verify → PUT result → return to PAM
Page:          GET the URL in the fragment → show it, and compute the challenge from the fetched bytes → poll result at low frequency (if a result appears before signing, show it)
               → passkey signature → PUT to assertion_put_url → poll result at high frequency → show pass / fail
```

- The result is the conclusion of the whole authentication for this request (pass / fail). The helper PUTs pass also when Touch ID went through
- The helper DELETEs the request and the assertion from the store when it finishes

Details are in [DR-0006](./decisions/DR-0006-approval-url-and-exchange.md), and the shapes of the objects are in [exchange-format](./design/exchange-format.md).

## Signature binding and verification

- The challenge is the SHA-256 of the whole bytes of the request that the page fetched with the presigned GET. The page computes the challenge from the same bytes it displays, and the helper computes the same value from the bytes it PUT. An approval is bound to the content of the request exactly as the page displayed it, so substitution or replay on the relay fails with a signature mismatch
- The conditions under which the helper accepts an assertion (type, origin, `crossOrigin` / `topOrigin`, UP / UV, credential id, ES256, size, single use, expiry) are in [webauthn-verification](./design/webauthn-verification.md)
- Rejection needs no signature (a URL holder can only stop the wait); only approval requires a signature. Anyone who knows the presigned PUT URL and writes junk does not produce a pass (worst case: DoS)

### Enrollment

Enrollment is a one-time out-of-band procedure, and goes through the store just like approval.

1. `pam-passkey add` (user privileges) asks for identity verification (`deviceOwnerAuthentication`: Touch ID, or the password on Macs without it)
2. On success it puts the enrollment payload in the store, and prints the enrollment URL (the same form as the approval URL, `<page_url>#<presigned GET URL>`) to the tty or passes it to the stdin of `send_command`
3. The enrollment page creates the passkey and returns the credential to the store with a presigned PUT
4. `add` polls for it, verifies it against the [acceptance conditions](./design/webauthn-verification.md), and in the same process makes a JWS with the signing key and saves it to the login keychain

The enrollment URL, like the approval URL, is a time-limited capability, and is shown nowhere but the tty and the stdin of `send_command`. The details of the procedure are in [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md).

## State and settings: Keychain only

No files for settings or state are kept. The signing key lives in the System Keychain (`/Library/Keychains/System.keychain`); the settings (`config`) and passkeys live in generic password items of the user's login keychain.

- Reads and writes of Keychain items are limited to the `pam-passkey` binary (Developer ID signed), and the ACL of every item is narrowed to this binary. The PAM module does not read the Keychain. An ad-hoc signature changes on every build and drops off the ACL, so Developer ID signing is a prerequisite
- Root is needed only to create the signing key in the System Keychain (the first `setup`, and `regenerate_key`; `setup` re-runs itself with sudo only at that moment). Changing an existing System Keychain item puts up an administrator authorization dialog, so the signing key is left alone once created. `setup` / `add` / `del` / `list` run with user privileges and read and write the user's own login keychain
- `setup` generates the signing key (a JWK private key), and puts the signing key and the public key for verification in the System Keychain. Regenerating the signing key by re-running invalidates all existing enrollments (run `add` again). The signing key is regenerated only when `regenerate_key` in the settings JSON is true (by default the existing key is kept and only the settings are updated), and `--edit` asks y/N before regenerating ([DR-0010](./decisions/DR-0010-cli-shape.md))
- At authentication time the login keychain is read by a child that the helper dropped to `PAM_USER`, and the items `config` and `users/<PAM_USER>` are read (reading the unlocked login keychain as the user; a helper that is not root reads them itself). Each JWS is verified with the public key, and entries that fail verification, or whose payload OS user name does not match the user being authenticated, are ignored as invalid
- How the path is closed where a user-privileged process enrolls a key on its own and approves its own authentication is in [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md)
- The settings (`page_url` / `store` / `send_command`) are per user. Authentication uses the settings of `PAM_USER`, so users on the same Mac can have their own store and `send_command`. Each user who registers passkeys runs `setup`

| Location | Item | Content |
|---|---|---|
| System Keychain | Signing key | Key that signs the passkey entries (an Ed25519 JWK private key). Secret |
| System Keychain | Public key of the signing key | Key that verifies the JWS of the passkey entries at authentication time (an Ed25519 JWK) |
| login keychain | `config` | That user's settings JSON: `page_url` (URL of the approval / enrollment pages, `https://pam-passkey.github.io/` by default; `rp_id` is derived from it), `store` (S3-compatible connection endpoint / bucket / region / prefix / access key / secret, plus whether presigned PUTs can be made one-time with `If-None-Match: *`, `put_once`, determined by `setup`; contains secrets) and `send_command` (command that reads the approval URL and the enrollment URL from stdin; empty means print to the tty). Not signed |
| login keychain | `users/<os user>` | JSONL of that user's passkeys. Each line is a JWS whose payload holds the OS user name, credential id, user handle, public key, label, enrollment date and the BE / BS flags at enrollment. One item per user |

Everything else (polling interval, button labels) is a code default.

## CLI (`pam-passkey`)

| Subcommand | Purpose |
|---|---|
| `setup [--edit\|--stdin\|--dump] [--module <path>] [page_url]` | Initial setup and changes of the user's own settings (`config` in the login keychain). Only the first run uses sudo, to create the signing key in the System Keychain. The settings are one JSON document: `--dump` prints the current one (the secret as `***`), `--stdin` takes one, and `--edit` edits it in `$EDITOR` (without arguments `setup` shows its help). If `page_url` is omitted, the default `https://pam-passkey.github.io/` is used. Takes `store` and `send_command`, checks that the store is reachable, sets the CORS and lifecycle of the bucket, and checks the ownership of the install locations |
| `add [label]` | Enroll a passkey (asks for identity verification). The default label is the enrollment date and time |
| `list` | List your own passkeys (label, credential id, enrollment date) |
| `del <label\|id>` | Delete a passkey |

Plus internal subcommands called from PAM. The details are in [DR-0010](./decisions/DR-0010-cli-shape.md).

## What the approval page shows

At the top: host, user, tty, the argv of the calling process, time, expiry. The body is the ancestor chain from the calling process up to launchd, listed vertically like pstree (ancestors form a straight line, so no folding is needed). Each row shows only representative values (process name, signing ID or Team ID, user); clicking a row opens the details:

- pid, user, cwd, executable path, argv
- signing ID (bundle ID equivalent), Team ID, signer name (`SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` → `SecCodeCopySigningInformation`)

Unsigned / ad-hoc signed / platform binaries are told apart by how the row looks.

The display is sanitized. Control characters and bidi control characters are shown escaped, and truncated parts are shown in a form that makes the truncation visible.

env is not shown because it may contain secrets. The process information is collected by the PAM module inside the calling process, so that the pid of the caller is reliably the starting point. If the caller runs as root like sudo, `KERN_PROC_PID` / `proc_pidpath` / `KERN_PROCARGS2` / libproc can read all pids. The volume is large, so it is not put in the URL; what is placed in the store is fetched by the page with a presigned GET and rendered.

## Open questions

- Request expiry: to be decided within 60–120 seconds (aligned with the presigned URL expiry; tentative default 90 seconds)
- Helper polling interval: tentative default 1 second
- Rate limiting of approval requests: if processes of the same uid hammer authentication (sudo, etc.), the notifications are hammered too. Given that no code is placed on the relay side, the only limit is a time window inside the helper, and a process of the same uid can bypass the helper and send only notifications

## Key Design Decisions

- [DR-0001](./decisions/DR-0001-naming.md) — Names: `pam_passkey` / `pam-passkey`
- [DR-0002](./decisions/DR-0002-single-module-parallel-auth.md) — Run Touch ID and remote approval in parallel within one module
- [DR-0003](./decisions/DR-0003-helper-outside-sudo.md) — Logic lives in a helper outside the calling process and PAM is a thin layer. Communication and verification are done by the root helper itself; only the work needing `PAM_USER` privileges goes to a dropped child. The install locations are root-owned
- [DR-0004](./decisions/DR-0004-fallback-button-as-details.md) — "Show details" reuses the LAContext fallback button
- [DR-0005](./decisions/DR-0005-s3-compatible-store.md) — The relay is an S3-compatible store with presigned URLs
- [DR-0006](./decisions/DR-0006-approval-url-and-exchange.md) — One approval URL, the challenge is the SHA-256 of the request exactly as the page fetched it, the result is the conclusion of the whole authentication for the request (pass / fail)
- [DR-0008](./decisions/DR-0008-pluggable-send-command.md) — Notification is pluggable via `send_command`. The notification path is inside the trust boundary
- [DR-0009](./decisions/DR-0009-foreground-control.md) — Foreground control is limited to activating the browser when the approval page is opened
- [DR-0010](./decisions/DR-0010-cli-shape.md) — One CLI binary with verb-only subcommands
- [DR-0011](./decisions/DR-0011-user-keychain-signed-records.md) — Passkeys (signed) and the settings live in the login keychain; the only dependency on sudo is the first `setup`, which creates the signing key
- [DR-0012](./decisions/DR-0012-auth-state-transitions.md) — State transitions and invariants of authentication

## Related Documents

- [STRUCTURE.md](./STRUCTURE.md) — Physical structure
- [decisions/INDEX.md](./decisions/INDEX.md) — DR list
- [design/webauthn-verification.md](./design/webauthn-verification.md) — Acceptance conditions for authentication and enrollment
- [design/helper-protocol.md](./design/helper-protocol.md) — The agreement between the PAM module and the helper
- [design/exchange-format.md](./design/exchange-format.md) — The shapes of the objects exchanged through the store
- [findings/](./findings/) — Observations from the prerequisite checks
