# Issue INDEX

active な issue の一覧。close 済みは archive/ にあり、ここには載せない。

| date | category | status | slug | 概要 |
|---|---|---|---|---|
| 2026-11-04 | task | open | [impl-1-keychain-layer](./2026-11-04-impl-1-keychain-layer.md) | 本体実装の第 1 段。Rust workspace を起こし、Keychain 層 (System Keychain / login keychain の generic password の読み書き、ACL を `pam-passkey` バイナリに絞る) を実装し、… |
| 2026-11-02 | task | open | [keychain-acl-developer-id-helper](./2026-11-02-keychain-acl-developer-id-helper.md) | Keychain 全項目 (System Keychain の各項目と login keychain の users/<PAM_USER>) の ACL を pam-passkey バイナリに限定する設計 (DR-0011) は未検証。 |
