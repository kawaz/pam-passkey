# pam-passkey Manual

> English | [日本語](./MANUAL-ja.md)

## Requirements

- macOS (a Mac with Touch ID. On a Mac without it, local authentication is the password)
- An iPhone / iPad / Mac that has the passkey (synced via iCloud Keychain)
- One bucket on an S3-compatible object store (used to relay approval requests. Dedicate it to pam-passkey)
- Optional: a command that delivers the approval URL to the iPhone (Bark / ntfy / ssh, etc. If there is none, the URL is printed to the terminal)

## 1. Prepare the store bucket

pam-passkey puts short-lived objects (the approval request, the signature, the result) in the bucket and lets the page read and write them through presigned URLs. Dedicate the bucket to pam-passkey, on the premise that `setup` replaces its CORS and lifecycle configuration. Public access is not needed (blocking all of it is fine).

Only the following 5 permissions are needed. Issue the access key to a dedicated user that has only these permissions.

| Operation | Purpose |
|---|---|
| `s3:PutObject` / `s3:GetObject` / `s3:DeleteObject` (all objects in the bucket) | Handing over the approval request and the signature, deleting them at the end, issuing presigned URLs |
| `s3:PutBucketCORS` (the bucket) | `setup` allows GET / PUT from the page's origin |
| `s3:PutLifecycleConfiguration` (the bucket) | `setup` puts a rule that deletes leftover objects after 1 day |

### Example: AWS S3

```sh
export AWS_PAGER=""
B=pam-passkey-<your name>       # bucket name (globally unique)
R=ap-northeast-1                # region to place it in

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

Values to pass to `setup`: endpoint `https://s3.<region>.amazonaws.com`, bucket, region, access key and secret.

`s3:ListBucket` is not needed. Without it, AWS returns 403 instead of 404 for a GET of an object that does not exist yet, but pam-passkey treats a 403 during the wait as "not there yet".

### Example: Cloudflare R2

1. Create a bucket in R2 (leave public access disabled)
2. Create an R2 API token with the "object read and write" permission, restricted to that bucket
3. Values to pass to `setup`: endpoint `https://<account id>.r2.cloudflarestorage.com`, bucket, region `auto`, and the token's access key and secret

If the CORS configuration does not go through the API on R2, enter what `setup` prints into the CORS settings of the dashboard by hand.

## 2. Install and configure

```sh
just install                                   # build, sign with Developer ID, place in a root-owned location
pam-passkey setup --edit                       # open the settings in $EDITOR
```

Pass the location with `--module <path>` only when you put the `.so` somewhere other than the default `/usr/local/lib/pam/pam_passkey.so` (the ownership of the location is checked).

`setup` treats the settings of the user who runs it as one JSON document and puts it in that user's login keychain (run it without `sudo`). The settings are per user, so each user who uses a passkey runs `setup`. `pam-passkey setup --edit` opens the current settings (a template the first time) in `$EDITOR` (vi if unset); edit them, save and close. If the content changed, it validates and writes it; if not, it does nothing. Only the first `setup` on that Mac asks for the `sudo` password, to create the signing key in the System Keychain.

```json
{
  "page_url": "https://pam-passkey.github.io/",
  "store": {
    "endpoint": "https://s3.ap-northeast-1.amazonaws.com",
    "bucket": "pam-passkey-<your name>",
    "region": "ap-northeast-1",
    "prefix": "",
    "access_key": "AKIA...",
    "secret": "***"
  },
  "send_command": ""
}
```

| Key | Content |
|---|---|
| page_url | The approval / enrollment page. The default `https://pam-passkey.github.io/` can stay as is |
| store | Connection information for the store. prefix can be empty. Leaving `secret` as `"***"` keeps the current secret |
| send_command | A command that receives the approval URL and the enrollment URL on stdin and delivers them. The summary for the notification comes in environment variables ([Notification command](#notification-command-send_command)). If empty, the URL is printed to the terminal |
| regenerate_key | false if not written. Setting it to true regenerates the signing key and invalidates the enrollments of all users (asks y/N before writing) |

There are also entry points that do not use an editor.

```sh
pam-passkey setup --dump > settings.json      # current settings (secret as "***")
pam-passkey setup --stdin < settings.json     # pass a document to configure (one line or formatted)
```

`setup` checks reachability of the store, support for conditional PUT, the CORS and lifecycle configuration, and the ownership of the install locations before writing.

The `page_url` / `store` / `send_command` items that an earlier version of `setup` wrote to the System Keychain are used for the template values at the first `setup` and not used after that. When they are no longer needed, delete them one at a time with `sudo security delete-generic-password -s pam-passkey -a <page_url|store|send_command> /Library/Keychains/System.keychain` (do not delete the signing key's `signing_key` / `verification_key`).

### Notification command (send_command)

`send_command` is started with `/bin/sh -c` for every approval and enrollment (with that user's privileges, cwd at the home directory). The URL arrives on stdin as one line, and the summary to put in the notification arrives in environment variables. Reading stdin is optional.

| Environment variable | Content | Approval | Enrollment |
|---|---|---|---|
| `PAM_PASSKEY_URL` | The same URL as on stdin | ✓ | ✓ |
| `PAM_PASSKEY_KIND` | `approve` (approval) or `register` (enrollment) | ✓ | ✓ |
| `PAM_PASSKEY_USER` | The user being authenticated (for enrollment, the user who ran `add`) | ✓ | ✓ |
| `PAM_PASSKEY_HOST` | The Mac's host name | ✓ | ✓ |
| `PAM_PASSKEY_COMMAND` | The command that asked for authentication (`sudo ...`) on one line. Only arguments that contain white space, a quote, a control character or a format character (bidi controls, zero-width characters, ...), and empty arguments, are put in single quotes; control characters, the line and paragraph separators (U+2028 / U+2029) and format characters are written in the form `\u{000A}`, as in the Touch ID dialog | ✓ | |
| `PAM_PASSKEY_DETAILS` | The request details the approval page shows. One line of JSON whose keys are the `details` of [exchange-format](./design/exchange-format.md) | ✓ | |

The only other environment variables passed are `PATH` `HOME` `USER` `LOGNAME` `LANG` `LC_*` `TMPDIR` `SSH_AUTH_SOCK`. A URL acts as a time-limited key: whoever sees an approval URL can read the request details until it expires (approving takes the passkey), and whoever sees an enrollment URL can register their own passkey. Deliver to a path only you can read.

Bark example (put it at `~/.local/bin/pam-passkey-bark`, `chmod 700`, with `send_command` set to `"~/.local/bin/pam-passkey-bark"`):

```sh
#!/bin/sh
key='<Bark device key>'
case $PAM_PASSKEY_KIND in
  approve) title='Approve authentication'; what=$PAM_PASSKEY_COMMAND ;;
  *) title='Enroll a passkey'; what='Open the enrollment URL and create a passkey' ;;
esac
body=$(printf '%s\n%s' "$PAM_PASSKEY_USER@$PAM_PASSKEY_HOST" "$what")
jq -n --arg key "$key" --arg title "$title" --arg body "$body" --arg url "$PAM_PASSKEY_URL" \
  '{device_key: $key, title: $title, body: $body, url: $url, group: "pam-passkey", level: "timeSensitive"}' |
  curl -fsS --max-time 10 -H 'Content-Type: application/json; charset=utf-8' --data-binary @- https://api.day.app/push >/dev/null
```

ntfy example (placed the same way as Bark; anyone who knows the name of a topic on the public `ntfy.sh` server can subscribe to it, so use a name that cannot be guessed, or a server with access control):

```sh
#!/bin/sh
topic='<a topic name that cannot be guessed>'
case $PAM_PASSKEY_KIND in
  approve) title='Approve authentication'; what=$PAM_PASSKEY_COMMAND ;;
  *) title='Enroll a passkey'; what='Open the enrollment URL and create a passkey' ;;
esac
body=$(printf '%s\n%s' "$PAM_PASSKEY_USER@$PAM_PASSKEY_HOST" "$what")
jq -n --arg topic "$topic" --arg title "$title" --arg body "$body" --arg url "$PAM_PASSKEY_URL" \
  '{topic: $topic, title: $title, message: $body, click: $url, priority: 4}' |
  curl -fsS --max-time 10 --data-binary @- https://ntfy.sh/ >/dev/null
```

During approval `PATH` is `/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin` (PAM does not pass the caller's environment to the helper). The `jq` and `curl` in the examples are in `/usr/bin`; write commands from other places (such as Homebrew's `/opt/homebrew/bin`) with absolute paths.

## 3. Enroll a passkey

```sh
pam-passkey add [label]
```

After identity verification (Touch ID, or the password on a Mac without it), the enrollment URL is printed to the terminal (passed to send_command if there is one). Open the URL in a browser on the iPhone or Mac and create a passkey. `add` receives it, verifies it and saves it.

```sh
pam-passkey list          # label / credential id / enrollment date and time
pam-passkey del <label|id>
```

## 4. Integrate with PAM

Write the following line at the top of `/etc/pam.d/sudo_local`, and remove the `pam_tid.so` line.

```
auth       sufficient     /usr/local/lib/pam/pam_passkey.so
```

Keeping `sudo -s` open in another terminal before rewriting lets you recover if you get the settings wrong. With nix-darwin, write the same line in `security.pam.services.sudo_local.text`, and pass the store path of the `pam-passkey` binary with the module argument `helper=<path>`.

## 5. Use it

Running `sudo` brings up the Touch ID dialog. If you are at the Mac, Touch ID lets you through. When away, open the approval URL shown in the terminal (the URL delivered by notification, if there is a send_command) on the iPhone, check the content and approve with the passkey. Pressing "Show details" in the dialog opens the same approval page in the browser on the Mac and brings the dialog up again.

If neither goes through (cancel, rejection, expiry at 90 seconds), it falls back to password authentication.

## Troubleshooting

- The dialog does not appear / it goes to the password right away: check that `/usr/local/libexec/pam-passkey` and the `.so` are root-owned and Developer ID signed, and that you have finished `setup`
- With sudo over ssh, neither Touch ID nor remote approval is available (the login keychain is not unlocked). It goes to the password
- To see what happened: the module and the helper leave the progress for each request ID in unified logging (the Touch ID result code, the start of the helper, the reason for unavailable, the PUT / DELETE to the store, the PAM return value. Secrets and URLs are not logged). View it with `/usr/bin/log show --predicate 'subsystem == "jp.kawaz.pam-passkey"' --last 5m`
- To start the enrollments over: add `"regenerate_key": true` with `pam-passkey setup --edit` to regenerate the signing key (the enrollments of all users become invalid)
