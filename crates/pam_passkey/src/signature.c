#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <string.h>

static SecCodeRef copy_guest(int pid, OSStatus *status) {
    SecCodeRef code = NULL;
    CFNumberRef pid_value = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (!pid_value) { *status = 2; return NULL; }
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { pid_value };
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_value);
    if (!attributes) { *status = 3; return NULL; }
    *status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    return *status == errSecSuccess ? code : NULL;
}

// Check a running process (not just a path) against the project's fixed Team ID and identifier.
// Returns 0 on success, otherwise the failing OSStatus (2: CFNumber allocation, 3: attribute dictionary allocation).
int32_t passkey_verify_pid(int pid) {
    OSStatus status = errSecSuccess;
    SecCodeRef code = copy_guest(pid, &status);
    if (!code) return (int32_t)status;
    CFStringRef text = CFSTR("identifier \"pam-passkey\" and anchor apple generic and certificate leaf[subject.OU] = \"3QMEVK549R\"");
    SecRequirementRef requirement = NULL;
    status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (requirement) CFRelease(requirement);
    CFRelease(code);
    return (int32_t)status;
}

static int copy_string(CFStringRef value, char *out, size_t len) {
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return 0;
    return CFStringGetCString(value, out, (CFIndex)len, kCFStringEncodingUTF8) ? 1 : 0;
}

enum {
    PASSKEY_SIGNING_ID = 1,
    PASSKEY_TEAM_ID = 2,
    PASSKEY_SIGNER = 4,
};

// Signing identity of a running process for the approval page: identifier, Team ID and the
// leaf certificate's subject summary. Only code that passes SecCodeCheckValidity reports
// anything, so an invalid signature looks the same as no signature.
// Returns a bit set of the PASSKEY_* values whose buffers were filled with a NUL-terminated string.
int32_t passkey_signing_info(int pid, char *signing_id, size_t signing_id_len,
                             char *team_id, size_t team_id_len,
                             char *signer, size_t signer_len) {
    if (!signing_id || !team_id || !signer || !signing_id_len || !team_id_len || !signer_len) return 0;
    signing_id[0] = team_id[0] = signer[0] = '\0';
    OSStatus status = errSecSuccess;
    SecCodeRef code = copy_guest(pid, &status);
    if (!code) return 0;
    int32_t filled = 0;
    SecStaticCodeRef static_code = NULL;
    CFDictionaryRef info = NULL;
    if (SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL) != errSecSuccess) goto done;
    if (SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &static_code) != errSecSuccess) goto done;
    if (SecCodeCopySigningInformation(static_code, kSecCSSigningInformation, &info) != errSecSuccess || !info) goto done;
    if (copy_string(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), signing_id, signing_id_len))
        filled |= PASSKEY_SIGNING_ID;
    if (copy_string(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), team_id, team_id_len))
        filled |= PASSKEY_TEAM_ID;
    CFArrayRef certificates = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
    if (certificates && CFGetTypeID(certificates) == CFArrayGetTypeID() && CFArrayGetCount(certificates) > 0) {
        SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certificates, 0);
        CFStringRef summary = SecCertificateCopySubjectSummary(leaf);
        if (summary) {
            if (copy_string(summary, signer, signer_len)) filled |= PASSKEY_SIGNER;
            CFRelease(summary);
        }
    }
done:
    if (info) CFRelease(info);
    if (static_code) CFRelease(static_code);
    CFRelease(code);
    return filled;
}
