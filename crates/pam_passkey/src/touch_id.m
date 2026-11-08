#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

// AppKit must not be linked or initialized here: sudo is setuid and AppKit
// aborts the whole process ("running setugid(), which is not allowed").
// Opening and activating the browser lives in the helper, not in-process.

// One Touch ID dialog. The caller owns the euid around create / can_evaluate / begin / wait;
// cancel may be called from any thread while another thread waits.
@interface PasskeyTouchID : NSObject
@property(nonatomic, strong) LAContext *context;
@property(nonatomic, strong) dispatch_semaphore_t completed;
@property(atomic) long code;
@end

@implementation PasskeyTouchID
@end

static const LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion;

void *passkey_touch_id_create(void) {
    @autoreleasepool {
        PasskeyTouchID *touch = [[PasskeyTouchID alloc] init];
        touch.context = [[LAContext alloc] init];
        touch.context.localizedFallbackTitle = @"詳細を確認";
        touch.context.localizedCancelTitle = @"キャンセル";
        touch.completed = dispatch_semaphore_create(0);
        touch.code = LAErrorAuthenticationFailed;
        return (void *)CFBridgingRetain(touch);
    }
}

// 0 if the policy can be evaluated for the current euid, otherwise the LAError code.
long passkey_touch_id_can_evaluate(void *handle) {
    @autoreleasepool {
        PasskeyTouchID *touch = (__bridge PasskeyTouchID *)handle;
        NSError *error = nil;
        if ([touch.context canEvaluatePolicy:policy error:&error]) return 0;
        return error ? (long)error.code : (long)LAErrorBiometryNotAvailable;
    }
}

// Shows the dialog and returns immediately; the answer arrives through passkey_touch_id_wait.
// Returns 0 if the evaluation was started, -1 for an unusable reason string.
int passkey_touch_id_begin(void *handle, const char *reason) {
    @autoreleasepool {
        PasskeyTouchID *touch = (__bridge PasskeyTouchID *)handle;
        NSString *text = reason ? [NSString stringWithUTF8String:reason] : nil;
        if (!text.length) return -1;
        [touch.context evaluatePolicy:policy
                      localizedReason:text
                                reply:^(BOOL matched, NSError *error) {
            touch.code = matched ? 0 : (error ? (long)error.code : (long)LAErrorAuthenticationFailed);
            dispatch_semaphore_signal(touch.completed);
        }];
        return 0;
    }
}

// Blocks until the started evaluation answers. 0 for a match, otherwise the LAError code
// (-2 cancel, -3 the fallback button, -9 cancelled through passkey_touch_id_cancel, ...).
long passkey_touch_id_wait(void *handle) {
    PasskeyTouchID *touch = (__bridge PasskeyTouchID *)handle;
    dispatch_semaphore_wait(touch.completed, DISPATCH_TIME_FOREVER);
    return touch.code;
}

// Closes the dialog; a pending evaluation answers LAErrorAppCancel.
void passkey_touch_id_cancel(void *handle) {
    @autoreleasepool {
        PasskeyTouchID *touch = (__bridge PasskeyTouchID *)handle;
        [touch.context invalidate];
    }
}

void passkey_touch_id_release(void *handle) {
    if (handle) CFBridgingRelease(handle);
}
