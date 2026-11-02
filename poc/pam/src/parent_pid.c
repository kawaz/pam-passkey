#include <sys/sysctl.h>
#include <sys/types.h>

int pam_poc_parent_pid(pid_t pid, pid_t *parent) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (pid <= 1 || parent == NULL ||
        sysctl(mib, 4, &info, &size, NULL, 0) != 0 || size != sizeof(info) ||
        info.kp_proc.p_pid != pid || info.kp_eproc.e_ppid <= 0) {
        return -1;
    }
    *parent = info.kp_eproc.e_ppid;
    return 0;
}
