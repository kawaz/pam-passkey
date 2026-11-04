#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>

// Check a running process (not just a path) against the project's fixed Team ID and identifier.
int passkey_verify_pid(int pid) {
    CFNumberRef pid_value = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (!pid_value) return 0;
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { pid_value };
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
                                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_value);
    if (!attributes) return 0;
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code);
    CFRelease(attributes);
    if (status != errSecSuccess) return 0;
    CFStringRef text = CFSTR("identifier \"pam-passkey\" and anchor apple generic and certificate leaf[subject.OU] = \"3QMEVK549R\"");
    SecRequirementRef requirement = NULL;
    status = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess) status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    if (requirement) CFRelease(requirement);
    CFRelease(code);
    return status == errSecSuccess;
}
