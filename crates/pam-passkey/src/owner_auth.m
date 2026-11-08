#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

// add's identity check (DR-0011): Touch ID, or the login password on a Mac without it.
// Blocks until the dialog is answered. Returns 0 on success, 1 for an unusable reason string,
// otherwise the LAError code (-2 cancel, -1 failed, ...).
long passkey_owner_authenticate(const char *reason) {
    @autoreleasepool {
        NSString *text = reason ? [NSString stringWithUTF8String:reason] : nil;
        if (!text.length) return 1;
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            return error ? (long)error.code : (long)LAErrorPasscodeNotSet;
        }
        dispatch_semaphore_t answered = dispatch_semaphore_create(0);
        __block long code = LAErrorAuthenticationFailed;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:text
                          reply:^(BOOL matched, NSError *failure) {
            code = matched ? 0 : (failure ? (long)failure.code : (long)LAErrorAuthenticationFailed);
            dispatch_semaphore_signal(answered);
        }];
        dispatch_semaphore_wait(answered, DISPATCH_TIME_FOREVER);
        return code;
    }
}
