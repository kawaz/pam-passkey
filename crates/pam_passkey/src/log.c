#include <dispatch/dispatch.h>
#include <os/log.h>

// Unified logging for diagnosis: subsystem jp.kawaz.pam-passkey, category "pam" (the module)
// or "helper" (pam-passkey). Callers never pass secrets (store keys, URLs, assertions).
// `log show --predicate 'subsystem == "jp.kawaz.pam-passkey"' --last 5m`
static os_log_t category_log(int helper) {
    static os_log_t pam, helper_log;
    static dispatch_once_t pam_once, helper_once;
    if (helper) {
        dispatch_once(&helper_once, ^{ helper_log = os_log_create("jp.kawaz.pam-passkey", "helper"); });
        return helper_log;
    }
    dispatch_once(&pam_once, ^{ pam = os_log_create("jp.kawaz.pam-passkey", "pam"); });
    return pam;
}

// `helper`: 0 for the module, 1 for the helper. `error`: 1 for a failure, 0 for a step.
void passkey_log(int helper, int error, const char *message) {
    if (!message) return;
    os_log_with_type(category_log(helper), error ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_DEFAULT,
                     "%{public}s", message);
}
