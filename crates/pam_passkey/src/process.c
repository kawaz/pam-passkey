#include <Security/AuthSession.h>
#include <bsm/audit.h>
#include <sys/sysctl.h>
#include <sys/types.h>

// Parent pid and effective uid of a process. Returns 0 on success.
int passkey_process_parent(pid_t pid, pid_t *parent, uid_t *uid) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (pid <= 0 || parent == NULL || uid == NULL ||
        sysctl(mib, 4, &info, &size, NULL, 0) != 0 || size != sizeof(info) ||
        info.kp_proc.p_pid != pid) {
        return -1;
    }
    *parent = info.kp_eproc.e_ppid;
    *uid = info.kp_eproc.e_ucred.cr_uid;
    return 0;
}

// Whether the calling process runs in a graphical login session that belongs to `uid`:
// the security session has graphic access and its audit user is `uid`.
// Returns 1 if so, 0 if not, -1 if the session could not be queried.
int passkey_gui_session_of(uid_t uid) {
    SecuritySessionId session = 0;
    SessionAttributeBits attributes = 0;
    if (SessionGetInfo(callerSecuritySession, &session, &attributes) != noErr) return -1;
    if ((attributes & sessionHasGraphicAccess) == 0) return 0;
    struct auditinfo_addr audit;
    if (getaudit_addr(&audit, sizeof(audit)) != 0) return -1;
    return audit.ai_auid == uid ? 1 : 0;
}
