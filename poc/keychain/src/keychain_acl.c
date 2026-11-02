#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdio.h>

// Design rationale: the Rust keychain wrappers cannot set kSecAttrAccess, so this shim builds the ACL and SecItemAdd/SecItemUpdate dictionaries while Rust owns the target keychain reference.
int32_t kcpoc_write_all_apps(SecKeychainRef keychain, const char *service,
                             const char *account, const uint8_t *value,
                             size_t value_len) {
    int32_t status = errSecParam;
    CFStringRef service_ref = NULL;
    CFStringRef account_ref = NULL;
    CFDataRef value_ref = NULL;
    SecAccessRef access = NULL;
    CFArrayRef decrypt_acls = NULL;
    CFArrayRef search_list = NULL;
    CFMutableDictionaryRef query = NULL;
    CFMutableDictionaryRef attributes = NULL;
    if (!keychain || !service || !account || (!value && value_len) ||
        value_len > INT32_MAX) {
        return status;
    }

    service_ref = CFStringCreateWithCString(kCFAllocatorDefault, service,
                                            kCFStringEncodingUTF8);
    account_ref = CFStringCreateWithCString(kCFAllocatorDefault, account,
                                            kCFStringEncodingUTF8);
    value_ref = CFDataCreate(kCFAllocatorDefault, value, (CFIndex)value_len);
    if (!service_ref || !account_ref || !value_ref) {
        status = errSecAllocate;
        goto done;
    }
    // Non-root processes get wrPermErr (-61) from SecItemAdd on the System keychain
    // unless they hold the system.keychain.modify right. Acquire it first so the OS
    // shows its admin authorization dialog; the process keeps the right for the write.
    {
        AuthorizationItem right = {"system.keychain.modify", 0, NULL, 0};
        AuthorizationRights rights = {1, &right};
        AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed |
                                   kAuthorizationFlagExtendRights |
                                   kAuthorizationFlagPreAuthorize;
        AuthorizationRef auth = NULL;
        OSStatus auth_status = AuthorizationCreate(&rights, kAuthorizationEmptyEnvironment, flags, &auth);
        fprintf(stderr, "kc-poc: AuthorizationCreate(system.keychain.modify) = %d\n", (int)auth_status);
        if (auth_status != errAuthorizationSuccess) {
            status = auth_status;
            goto done;
        }
        // Keep the AuthorizationRef alive for the lifetime of this write; released at the end.
        (void)auth;
    }
    status = SecAccessCreate(service_ref, NULL, &access);
    if (status != errSecSuccess) {
        goto done;
    }
    decrypt_acls = SecAccessCopyMatchingACLList(access,
                                                 kSecACLAuthorizationDecrypt);
    if (!decrypt_acls || CFArrayGetCount(decrypt_acls) == 0) {
        status = errSecParam;
        goto done;
    }
    for (CFIndex i = 0; i < CFArrayGetCount(decrypt_acls); ++i) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(decrypt_acls, i);
        // A NULL application list permits every app; selector 0 does not ask for a password.
        status = SecACLSetContents(acl, NULL, service_ref, 0);
        if (status != errSecSuccess) {
            goto done;
        }
    }

    query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                      &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
    attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    if (!query || !attributes) {
        status = errSecAllocate;
        goto done;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service_ref);
    CFDictionarySetValue(query, kSecAttrAccount, account_ref);
    search_list = CFArrayCreate(kCFAllocatorDefault, (const void **)&keychain,
                                1, &kCFTypeArrayCallBacks);
    if (!search_list) {
        status = errSecAllocate;
        goto done;
    }
    CFDictionarySetValue(query, kSecMatchSearchList, search_list);
    // The update dictionary contains item attributes only, never the search location.
    CFDictionarySetValue(attributes, kSecValueData, value_ref);
    CFDictionarySetValue(attributes, kSecAttrAccess, access);

    CFMutableDictionaryRef add = CFDictionaryCreateMutableCopy(kCFAllocatorDefault,
                                                               0, query);
    if (!add) {
        status = errSecAllocate;
        goto done;
    }
    CFDictionaryRemoveValue(add, kSecMatchSearchList);
    CFDictionarySetValue(add, kSecUseKeychain, keychain);
    CFDictionarySetValue(add, kSecValueData, value_ref);
    CFDictionarySetValue(add, kSecAttrAccess, access);
    status = SecItemAdd(add, NULL);
    CFRelease(add);
    if (status == errSecDuplicateItem) {
        status = SecItemUpdate(query, attributes);
    }

done:
    if (attributes) CFRelease(attributes);
    if (query) CFRelease(query);
    if (search_list) CFRelease(search_list);
    if (decrypt_acls) CFRelease(decrypt_acls);
    if (access) CFRelease(access);
    if (value_ref) CFRelease(value_ref);
    if (account_ref) CFRelease(account_ref);
    if (service_ref) CFRelease(service_ref);
    return status;
}
