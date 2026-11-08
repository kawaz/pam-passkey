#include <CoreServices/CoreServices.h>
#include <stdint.h>
#include <string.h>

// Design rationale: LaunchServices is called directly instead of exec'ing /usr/bin/open so the
// approval URL never appears in a process argv, which `ps` shows to every user (DR-0004).

static CFURLRef url_from(const char *text) {
    if (!text) return NULL;
    return CFURLCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)text, (CFIndex)strlen(text),
                                kCFStringEncodingUTF8, NULL);
}

// Opens the URL in its default handler, which brings the handler to the front.
// Returns 0 on success, otherwise an OSStatus (-50 for a URL that does not parse).
int32_t passkey_open_url(const char *text) {
    CFURLRef url = url_from(text);
    if (!url) return paramErr;
    OSStatus status = LSOpenCFURLRef(url, NULL);
    CFRelease(url);
    return (int32_t)status;
}

// Brings the URL's default handler (the browser) to the front again without opening the URL
// a second time: opening a running application activates it.
int32_t passkey_activate_handler(const char *text) {
    CFURLRef url = url_from(text);
    if (!url) return paramErr;
    CFURLRef application = LSCopyDefaultApplicationURLForURL(url, kLSRolesAll, NULL);
    CFRelease(url);
    if (!application) return kLSApplicationNotFoundErr;
    OSStatus status = LSOpenCFURLRef(application, NULL);
    CFRelease(application);
    return (int32_t)status;
}
