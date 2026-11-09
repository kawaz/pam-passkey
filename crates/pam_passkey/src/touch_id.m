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

static NSString *first_language(NSString *path) {
    NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfURL:[NSURL fileURLWithPath:path] error:nil];
    id languages = preferences[@"AppleLanguages"];
    if (![languages isKindOfClass:[NSArray class]] || [languages count] == 0) return nil;
    id first = languages[0];
    return [first isKindOfClass:[NSString class]] ? first : nil;
}

// 1 if the first of the user's preferred languages (AppleLanguages in <home>'s global
// preferences, else the system's) is Japanese, otherwise 0. The file is read directly rather
// than through CFPreferences: the module runs inside a setuid caller on behalf of PAM_USER.
int passkey_prefers_japanese(const char *home) {
    @autoreleasepool {
        NSString *language = nil;
        NSString *directory = home ? [NSString stringWithUTF8String:home] : nil;
        if (directory.length) {
            language = first_language([directory stringByAppendingPathComponent:@"Library/Preferences/.GlobalPreferences.plist"]);
        }
        if (!language) language = first_language(@"/Library/Preferences/.GlobalPreferences.plist");
        return [language hasPrefix:@"ja"] ? 1 : 0;
    }
}

// The dialog's buttons in English, or in Japanese for a user who prefers it.
void *passkey_touch_id_create(int japanese) {
    @autoreleasepool {
        PasskeyTouchID *touch = [[PasskeyTouchID alloc] init];
        touch.context = [[LAContext alloc] init];
        touch.context.localizedFallbackTitle = japanese ? @"詳細を確認" : @"Show details";
        touch.context.localizedCancelTitle = japanese ? @"キャンセル" : @"Cancel";
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
