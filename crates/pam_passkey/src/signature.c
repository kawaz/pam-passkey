#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>

// Check a running process (not just a path) against the project's fixed Team ID and identifier.
// Returns 0 on success, otherwise the failing OSStatus (2: CFNumber allocation, 3: attribute dictionary allocation).
int32_t passkey_verify_pid(int pid) {
    CFNumberRef pid_value = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (!pid_value) return 2;
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { pid_value };
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_value);
    if (!attributes) return 3;
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    if (status != errSecSuccess) return (int32_t)status;
    CFStringRef text = CFSTR("identifier \"pam-passkey\" and anchor apple generic and certificate leaf[subject.OU] = \"3QMEVK549R\"");
    SecRequirementRef requirement = NULL;
    status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (requirement) CFRelease(requirement);
    CFRelease(code);
    return (int32_t)status;
}
