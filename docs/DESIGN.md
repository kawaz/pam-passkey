# pam-passkey Design

> English | [日本語](./DESIGN-ja.md)

## Domain

In macOS sudo authentication (the same PAM layer as `pam_tid`), accept both Touch ID at the Mac and, when the user is away, passkey approval from an iPhone at the same time.

### Goals

- Let sudo authentication go through from an iPhone while away from the desk or working remotely
- Rest the authenticity of an approval solely on verifying the passkey signature on the Mac. The relays (object store / notification service / APNs / CDN) are not trusted; they only affect availability
- When the user is at the Mac, Touch ID lets sudo through directly without waiting on remote approval

### What not to add

- Resident servers, listening ports, self-hosted HTTPS servers (no code to deploy and maintain, neither on the Mac nor on the relay side)
- Files, directories or permissions on the Mac (state and settings live only in the System Keychain)
- Logic inside the sudo process (the PAM module stays a thin layer that launches the helper)

### Out of scope

- Conditions for which commands require approval: sudoers' responsibility
- The unauthenticated period after approval: sudo's timestamp (sudoers' `timestamp_timeout`) applies as is. The module does not control it
- How notifications are delivered: the responsibility of what `send_command` runs. The module only knows how to "deliver one URL"

## Architecture

```
sudo ─ pam_passkey.so ──┬─ thread A: LAContext (Touch ID dialog, fallback button = "Show details")
                        └─ spawn ─▶ helper = internal subcommand of the `pam-passkey` CLI (root; only the `open` and `send_command` children drop to the user)
                                     │ 1. encrypt the request details and PUT them to the S3-compatible store
                                     │ 2. pass the approval URL to `send_command` on stdin; print it to the tty if unset
                                     │ 3. poll for the assertion object (until expiry)
                                     │ 4. verify the passkey signature and return the result
                        Either succeeds → cancel the other → PAM_SUCCESS
                        Both fail / timeout → PAM_AUTH_ERR, on to the next module (password)

Receiver (iPhone): open the URL from the notification → static page → GET the details, decrypt and show → passkey signature → presigned PUT
Receiver (Mac):    "Show details" → the helper opens the same approval page as the user and activates the browser (the same passkey is available via iCloud sync)
```

### Components

| Component | Responsibility |
|---|---|
| `pam_passkey.so` | PAM module running inside the sudo process. Shows the Touch ID dialog (LAContext), spawns the helper in parallel, and returns `PAM_SUCCESS` on whichever succeeds first |
| `pam-passkey` CLI | One binary bundling the helper (an internal subcommand called from PAM) and the management functions. All approval-path logic lives here |
| Static pages | The enrollment page and the approval page, served from a fixed HTTPS domain (the passkey RP ID). GitHub Pages by default. The pages hold no settings; everything they need comes from the URL (query and fragment) |
| S3-compatible store | Holds the encrypted request details, the assertion and the result. Presigned URLs double as time-limited capabilities. Any API-compatible store can be swapped in |
| `send_command` | A command that reads the approval URL from stdin and delivers it (Bark / ntfy / ssh, ...). If unset, the URL is printed to the tty |

### Constraints on the PAM module

- sudo is a setuid process, so AppKit cannot be initialized inside the PAM module (the whole process exits on initialization). Opening the browser and focus handling (raising the SecurityAgent window via AX, etc.) are all done by the helper ([findings](./findings/2026-11-02-pam-poc.md))
- `LAContext` checks biometric enrollment for the euid, so the module drops to `seteuid(invoking user)` only during evaluation and returns with `seteuid(0)` afterwards
- The policy is `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion`. The fallback button is relabeled "Show details" via `localizedFallbackTitle`, and a press is detected as `LAErrorUserFallback` (-3)
- The module never brings the process down. The safeguard against a lockout (a module bug blocks sudo, so setup cannot be run either) is that failures fall through to the subsequent password authentication

### Behavior on failure

- Helper missing / store unreachable: give up only on the remote side and still show Touch ID
- Touch ID unavailable as well: return `PAM_IGNORE` and move on to the next module. Never fail open
- `send_command` failure: a warning only; it does not fail authentication

### PAM integration

- Write `auth sufficient pam_passkey.so` in `/etc/pam.d/sudo_local`, and turn `pam_tid` (`touchIdAuth`) off
- With nix-darwin, write the single line with the store path in `security.pam.services.sudo_local.text` (the same shape as pam-watchid)

## Approval URL and exchange flow

The approval URL is a single `<page_url>#<presigned GET URL of the request>.<decryption key>`. The fragment is never sent to the server, so the page host sees neither the URL nor its contents. Its length is that of one presigned URL and does not grow with the details.

```
Mac (helper):  encrypt request JSON and PUT → send approval URL → poll assertion → verify → PUT result (pass / fail) → return to PAM
request JSON:  details (host / user / tty / argv / process tree), challenge, expires, assertion_put_url (presigned PUT), result_get_url (presigned GET)
Page:          fetch the URL in the fragment → decrypt and show → poll result at low frequency (switches to "approved" if Touch ID went through first)
               → passkey signature → PUT to assertion_put_url → poll result at high frequency → show pass / fail
```

- The result has only three values: 404 (pending) / pass / fail. No reason is given. The PUT is idempotent
- Rejection is just the page PUTting unsigned content to the assertion location. The Mac side fails verification → fail. There is no dedicated rejection path
- The expiry of the presigned URLs and of the request are aligned

## Cryptographic binding

- `challenge = SHA-256(request details + nonce + expiry)`. The Mac side checks that the assertion's `clientDataJSON.challenge` matches its own computation, and verifies `origin` / `rpIdHash` / the UV flag / signCount. An approval is bound to the content of the request itself, so substitution or replay on the relay fails the signature check
- The request details are encrypted with the key in the fragment and stored. What `send_command` goes through (notification server / APNs / chat) is unknown, so even if the URL is seen in transit, the contents should not be readable within the expiry
- Rejection needs no signature (a URL holder can only stop the wait); only approval requires a signature. Anyone who knows the presigned PUT URL and writes junk fails verification (worst case: DoS)

### Enrollment

Enrollment is a one-time out-of-band procedure. `pam-passkey add` opens the enrollment page; the public key + credential id + binding to the challenge produced on the page are pasted into the CLI via the clipboard (Universal Clipboard), and the CLI verifies them and stores them in the System Keychain. The store is not involved.

## State and settings: System Keychain only

No files, directories or permissions at all. All state lives in generic password items of the System Keychain (`/Library/Keychains/System.keychain`).

- Writing requires root (`sudo pam-passkey setup` / `add` / `del`). User-level processes cannot write even after acquiring an Authorization right ([findings](./findings/2026-11-02-keychain-poc.md)). sudo is needed only for configuration changes; authentication (reading) does not depend on it
- The path where a user-level process enrolls its own key to approve its own sudo is closed by requiring root to write to the System Keychain. Nothing is written to the login keychain (fixed in the implementation)
- Readers are PAM (inside the sudo process, root) and the helper. Public keys and settings are not secret, so their ACL is "all applications" (avoiding the ACL issue caused by the main executable being `/usr/bin/sudo`). Only the secret (the store credentials) has its ACL narrowed to the Developer ID-signed helper. An ad-hoc signature changes on every build and drops off the ACL, so Developer ID signing is a prerequisite

| Item | Content |
|---|---|
| `page_url` | URL of the approval / enrollment pages (GitHub Pages by default). `rp_id` is derived from it. Self-hosters fork and change this |
| `store` | S3-compatible connection JSON (endpoint / bucket / region / prefix / access key / secret). Contains secrets |
| `send_command` | Command that reads the approval URL from stdin. Empty means print to the tty |
| `users/<os user>` | JSONL of that user's passkeys (credential id, public key, label, enrollment date, signCount). One item per user |

Everything else (polling interval, button labels, whether Touch ID is used) is a code default.

## CLI (`pam-passkey`)

| Subcommand | Purpose |
|---|---|
| `setup <page_url>` | Initial setup (root) |
| `add [label]` | Enroll a passkey (root) |
| `list` | List your own passkeys (just reads your own `users/<os user>` item) |
| `del <label\|id>` | Delete a passkey (root) |
| `test` | Run the approval path end to end without sudo |
| `doctor` | Diagnose the environment |

Plus internal subcommands called from PAM.

## What the approval page shows

At the top: host, user, tty, sudo's argv, time, expiry. The body is the ancestor chain from sudo up to launchd, listed vertically like pstree (ancestors form a straight line, so no folding is needed). Each row shows only representative values (process name, signing ID or Team ID, user); clicking a row opens the details:

- pid, user, cwd, executable path, argv
- signing ID (bundle ID equivalent), Team ID, signer name, platform / ad-hoc (`SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` → `SecCodeCopySigningInformation`)
- the responsible process in TCC terms (`responsibility_get_pid_responsible_for_pid`; a private API, so "unknown" if unavailable)
- auxiliary information if available (e.g. the Claude session name ccmsg can look up from a pid). This is for display only; the basis for an approval decision is the signing ID (session names can be changed)

env is not shown because it may contain secrets. sudo runs as root, so `KERN_PROC_PID` / `proc_pidpath` / `KERN_PROCARGS2` / libproc can read all pids. The volume is large, so it is not put in the URL; it is encrypted and stored, and the page fetches and renders it.

## Open questions

- Request expiry: to be decided within 60–120 seconds (aligned with the presigned URL expiry; tentative default 90 seconds)
- Helper polling interval: tentative default 1 second
- Whether the approval page should say "no further authentication for the sudo timestamp period (5 minutes by default)"

## Key Design Decisions

- [DR-0001](./decisions/DR-0001-naming.md) — Names: `pam_passkey` / `pam-passkey`
- [DR-0002](./decisions/DR-0002-single-module-parallel-auth.md) — Run Touch ID and remote approval in parallel within one module
- [DR-0003](./decisions/DR-0003-helper-outside-sudo.md) — Logic lives in a helper outside the sudo process; the PAM module is a thin layer
- [DR-0004](./decisions/DR-0004-fallback-button-as-details.md) — "Show details" reuses the LAContext fallback button
- [DR-0005](./decisions/DR-0005-s3-compatible-store.md) — The relay is an S3-compatible store with presigned URLs
- [DR-0006](./decisions/DR-0006-approval-url-and-exchange.md) — One approval URL, encrypted details, a three-valued result
- [DR-0007](./decisions/DR-0007-system-keychain-only.md) — State and settings live only in the System Keychain
- [DR-0008](./decisions/DR-0008-pluggable-send-command.md) — Notification is pluggable via `send_command`
- [DR-0009](./decisions/DR-0009-foreground-control.md) — Foreground control is limited to activating the browser on `open`
- [DR-0010](./decisions/DR-0010-cli-shape.md) — One CLI binary with verb-only subcommands

## Related Documents

- [STRUCTURE.md](./STRUCTURE.md) — Physical structure
- [decisions/INDEX.md](./decisions/INDEX.md) — DR list
- [findings/](./findings/) — Observations from the prerequisite checks
