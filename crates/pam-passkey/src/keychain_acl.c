#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <limits.h>

int32_t passkey_keychain_is_locked(SecKeychainRef keychain) {
    SecKeychainStatus status = 0;
    if (SecKeychainGetStatus(keychain, &status) != errSecSuccess) return -1;
    return (status & kSecUnlockStateStatus) == 0;
}

// Design rationale: security-framework cannot set kSecAttrAccess, so a C shim is
// necessary for the legacy macOS Keychain ACL; all searches are scoped to one keychain.
// A new item gets the ACL; an existing one keeps its ACL and only its data is updated.
// Design rationale: never set kSecAttrAccess again on update; re-setting an existing item's ACL
// asks for the keychain's (System: an administrator's) authorization in a dialog, even as root
// and with user interaction disabled.
int32_t passkey_write_restricted(SecKeychainRef keychain, const char *self_path,
                                  const char *service, const char *account,
                                  const uint8_t *value, size_t value_len) {
    int32_t status = errSecParam;
    CFStringRef service_ref = NULL, account_ref = NULL, descriptor = NULL;
    CFDataRef value_ref = NULL;
    SecTrustedApplicationRef self = NULL;
    CFArrayRef trusted = NULL, decrypt_acls = NULL, search_list = NULL;
    SecAccessRef access = NULL;
    CFMutableDictionaryRef query = NULL, attributes = NULL, add = NULL;
    if (!keychain || !self_path || !service || !account || (!value && value_len) ||
        value_len > INT32_MAX) return status;
    service_ref = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
    account_ref = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
    descriptor = CFStringCreateWithCString(kCFAllocatorDefault, "pam-passkey", kCFStringEncodingUTF8);
    value_ref = CFDataCreate(kCFAllocatorDefault, value, (CFIndex)value_len);
    if (!service_ref || !account_ref || !descriptor || !value_ref) {
        status = errSecAllocate;
        goto done;
    }
    status = SecTrustedApplicationCreateFromPath(self_path, &self);
    if (status) goto done;
    trusted = CFArrayCreate(kCFAllocatorDefault, (const void **)&self, 1, &kCFTypeArrayCallBacks);
    if (!trusted) { status = errSecAllocate; goto done; }
    status = SecAccessCreate(descriptor, trusted, &access);
    if (status) goto done;
    decrypt_acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
    if (!decrypt_acls || CFArrayGetCount(decrypt_acls) == 0) {
        status = errSecParam;
        goto done;
    }
    // A NULL list means every application; retain the explicit one-application list.
    // 0 preserves the default prompt selector (no password-required flag).
    for (CFIndex i = 0; i < CFArrayGetCount(decrypt_acls); i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(decrypt_acls, i);
        status = SecACLSetContents(acl, trusted, descriptor, 0);
        if (status) goto done;
    }
    query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!query || !attributes) { status = errSecAllocate; goto done; }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service_ref);
    CFDictionarySetValue(query, kSecAttrAccount, account_ref);
    search_list = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
    if (!search_list) { status = errSecAllocate; goto done; }
    CFDictionarySetValue(query, kSecMatchSearchList, search_list);
    CFDictionarySetValue(attributes, kSecValueData, value_ref);
    add = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, query);
    if (!add) { status = errSecAllocate; goto done; }
    CFDictionaryRemoveValue(add, kSecMatchSearchList);
    CFDictionarySetValue(add, kSecUseKeychain, keychain);
    CFDictionarySetValue(add, kSecValueData, value_ref);
    CFDictionarySetValue(add, kSecAttrAccess, access);
    status = SecItemAdd(add, NULL);
    if (status == errSecDuplicateItem) status = SecItemUpdate(query, attributes);
done:
    if (add) CFRelease(add);
    if (attributes) CFRelease(attributes);
    if (query) CFRelease(query);
    if (search_list) CFRelease(search_list);
    if (decrypt_acls) CFRelease(decrypt_acls);
    if (access) CFRelease(access);
    if (trusted) CFRelease(trusted);
    if (self) CFRelease(self);
    if (value_ref) CFRelease(value_ref);
    if (descriptor) CFRelease(descriptor);
    if (account_ref) CFRelease(account_ref);
    if (service_ref) CFRelease(service_ref);
    return status;
}
