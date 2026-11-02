#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>
#import <unistd.h>

// AppKit must not be linked or initialized here: sudo is setuid and AppKit
// aborts the whole process ("running setugid(), which is not allowed").
// Focus handling therefore lives in a separate user-level helper, not in-process.

// Return 0 for a biometric match, -3 for the fallback button, -1 otherwise.
// errbuf carries the LA error's code and description on failure.
int pam_poc_touch_id(const char *reason, char *errbuf, size_t errlen) {
    @autoreleasepool {
        if (!reason || !errbuf || !errlen) return -1;
        errbuf[0] = '\0';
        NSString *localized_reason = [NSString stringWithUTF8String:reason];
        if (!localized_reason || !localized_reason.length) return -1;

        // LocalAuthentication evaluates enrollment for the caller's effective uid.
        // Under sudo that is root (never enrolled), so evaluate as the invoking
        // user (real uid) and switch back via the saved uid afterwards.
        uid_t invoking = getuid();
        int dropped = (geteuid() == 0 && invoking != 0) ? seteuid(invoking) : -1;

        LAContext *context = [[LAContext alloc] init];
        context.localizedFallbackTitle = @"詳細を確認";
        context.localizedCancelTitle = @"キャンセル";

        dispatch_semaphore_t completed = dispatch_semaphore_create(0);
        __block BOOL success = NO;
        __block NSError *authentication_error = nil;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion
                localizedReason:localized_reason
                          reply:^(BOOL matched, NSError *error) {
            success = matched;
            authentication_error = error;
            dispatch_semaphore_signal(completed);
        }];
        dispatch_semaphore_wait(completed, DISPATCH_TIME_FOREVER);
        int restored = dropped == 0 ? seteuid(0) : -1;

        if (success) return 0;
        NSInteger code = authentication_error ? authentication_error.code : 0;
        snprintf(errbuf, errlen, "LA error code=%ld %s (euid drop=%d restore=%d uid=%u)", (long)code,
                 authentication_error ? authentication_error.localizedDescription.UTF8String : "(no error)",
                 dropped, restored, invoking);
        return code == LAErrorUserFallback ? -3 : -1;
    }
}
