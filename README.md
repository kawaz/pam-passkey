# pam-passkey

> English | [日本語](./README-ja.md)

A PAM module for macOS PAM authentication (mainly sudo) that accepts Touch ID on the Mac and passkey approval from an iPhone at the same time. At the desk, Touch ID lets sudo through; away from the desk, you open the URL delivered to your iPhone and sign with a passkey. No local server is involved.

## Status

The design and the prerequisite proofs of concept are done; the module itself is not implemented yet. There are no installation steps yet.

## How it works

```
sudo ─ pam_passkey.so ──┬─ Touch ID dialog (with a "Show details" button)
                        └─ helper (`pam-passkey` CLI)
                             │ puts the request details in an S3-compatible store
                             │ hands the approval URL to a notification command (prints it to the tty if unset)
                             │ waits for the passkey assertion and verifies the signature
                        Whichever succeeds first lets sudo through. If both fail, fall through to the password

iPhone: open the URL from the notification → review the details on a static approval page → sign with a passkey
Mac:    "Show details" → the same approval page opens in the browser
```

- Authenticity of an approval rests on verifying the passkey signature on the Mac. The relay store is not trusted for authenticity
- No resident server, no listening port, no deployed code. The only relay is an S3-compatible store with presigned URLs
- Notification is pluggable: any command that reads the approval URL from stdin will do (Bark, ntfy, ssh, ...)
- All state and settings live in the Keychain; there are no files. Root is needed only once, for `setup`; adding and removing passkeys runs with user privileges (Touch ID)

## Documentation

- [DESIGN.md](./docs/DESIGN.md) — Design (domain + architecture)
- [decisions/INDEX.md](./docs/decisions/INDEX.md) — Design decision records (Japanese)
- [findings/](./docs/findings/) — Observations from the prerequisite proofs of concept (Japanese)
- [STRUCTURE.md](./docs/STRUCTURE.md) — Repository physical structure

## License

MIT License, Yoshiaki Kawazu (@kawaz)
