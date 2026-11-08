//! Children that run as PAM_USER (DR-0003): the helper re-executes itself with an internal
//! subcommand, permanently dropped to PAM_USER when it runs as root.

use std::error::Error;
use std::ffi::{CStr, CString};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// The user a child is dropped to, resolved in the parent before fork.
pub struct Identity {
    pub uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

/// Who the children run as: PAM_USER when the helper runs as root, otherwise the helper's
/// own uid (DR-0003: 呼び出し元の euid が 0 でなければ降格しない).
pub enum RunAs {
    Dropped(Identity),
    Inherited,
}

pub fn current_user() -> Result<(String, PathBuf), Box<dyn Error>> {
    // SAFETY: getpwuid_r writes to the provided struct/buffer, and pointers are copied before it is dropped.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut storage = vec![0u8; 16384];
        let mut result = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            libc::getuid(),
            &mut pwd,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return Err(format!("resolve current user: {rc}").into());
        }
        Ok((
            CStr::from_ptr(pwd.pw_name).to_str()?.to_owned(),
            PathBuf::from(CStr::from_ptr(pwd.pw_dir).to_str()?),
        ))
    }
}

pub fn identity(user: &str) -> Result<Identity, Box<dyn Error>> {
    let name = CString::new(user)?;
    // Resolve all identities and supplemental groups in the parent, before fork.
    // SAFETY: getpwnam_r / getgrouplist write only into the provided buffers.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut storage = vec![0u8; 16384];
        let mut result = std::ptr::null_mut();
        let rc = libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return Err(format!("resolve PAM_USER: {user} ({rc})").into());
        }
        let mut groups = vec![0 as libc::c_int; 256];
        let mut count = i32::try_from(groups.len())?;
        if libc::getgrouplist(
            name.as_ptr(),
            i32::try_from(pwd.pw_gid)?,
            groups.as_mut_ptr(),
            &mut count,
        ) < 0
        {
            return Err("target user has more than 256 supplemental groups".into());
        }
        // setgroups rejects more than NGROUPS_MAX entries; getgrouplist may return more.
        // NGROUPS_MAX is 16 on macOS (sys/syslimits.h).
        let count = usize::try_from(count)?.min(16);
        let groups: Vec<libc::gid_t> = groups[..count]
            .iter()
            .map(|group| u32::try_from(*group))
            .collect::<Result<_, _>>()?;
        Ok(Identity {
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
            groups,
        })
    }
}

impl RunAs {
    pub fn for_user(user: &str) -> Result<Self, Box<dyn Error>> {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            Ok(Self::Dropped(identity(user)?))
        } else {
            Ok(Self::Inherited)
        }
    }

    /// `pam-passkey <subcommand> <args>` by absolute path, with an empty environment, cwd `/`,
    /// umask 077, and the permanent drop when running as root.
    pub fn command(&self, subcommand: &str) -> Result<Command, Box<dyn Error>> {
        let executable = std::env::current_exe()?;
        if !executable.is_absolute() {
            return Err("helper executable must be absolute".into());
        }
        let mut command = Command::new(executable);
        command.arg(subcommand).env_clear().current_dir("/");
        // Rust opens every descriptor with CLOEXEC, so nothing beyond the configured stdio survives exec.
        // Closing descriptors here would also close the pipe Rust uses to report exec failures.
        // SAFETY: pre_exec executes only async-signal-safe libc calls after fork, before exec.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        if let Self::Dropped(identity) = self {
            let (uid, gid, groups) = (identity.uid, identity.gid, identity.groups.clone());
            // SAFETY: all user and group lookups ran in the parent; pre_exec uses only libc syscalls.
            unsafe {
                command.pre_exec(move || permanently_drop(uid, gid, &groups));
            }
        }
        Ok(command)
    }
}

fn permanently_drop(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
) -> std::io::Result<()> {
    // SAFETY: the identity has been prepared in the parent; only libc syscalls run after fork.
    unsafe {
        if libc::setgroups(
            i32::try_from(groups.len())
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?,
            groups.as_ptr(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::getuid() != uid
            || libc::geteuid() != uid
            || libc::getgid() != gid
            || libc::getegid() != gid
        {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}
