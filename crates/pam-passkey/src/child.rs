//! Children that run as PAM_USER (DR-0003): the helper re-executes itself with an internal
//! subcommand, permanently dropped to PAM_USER when it runs as root.

use std::error::Error;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `send_command`'s environment allowlist (DR-0008), taken from the helper's own environment.
/// HOME / USER / LOGNAME always come from the user database instead.
const SHELL_ENV_ALLOWED: [&str; 4] = ["PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK"];
/// PATH when the helper's environment has none (PAM starts the helper with an empty one):
/// the defaults of /etc/paths.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// The user a child is dropped to, resolved in the parent before fork.
pub struct Identity {
    pub uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    name: String,
    home: PathBuf,
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
            return Err(
                format!("user {user} is not in the user database (getpwnam_r {rc})").into(),
            );
        }
        // Design rationale: getgrouplist takes and returns gids as `int`, while gid_t is unsigned.
        // Groups above i32::MAX exist (nobody / nogroup are -2 = 4294967294), so the values are
        // reinterpreted bit for bit in both directions instead of range-checked.
        let mut groups = vec![0 as libc::c_int; 256];
        let mut count: libc::c_int = 256;
        if libc::getgrouplist(
            name.as_ptr(),
            pwd.pw_gid as libc::c_int,
            groups.as_mut_ptr(),
            &mut count,
        ) < 0
        {
            return Err(format!("user {user} has more than 256 supplemental groups").into());
        }
        // setgroups rejects more than NGROUPS_MAX entries; getgrouplist may return more.
        // NGROUPS_MAX is 16 on macOS (sys/syslimits.h).
        let count = usize::try_from(count).unwrap_or(0).min(16);
        let groups: Vec<libc::gid_t> = groups[..count]
            .iter()
            .map(|group| *group as libc::gid_t)
            .collect();
        Ok(Identity {
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
            groups,
            name: user.to_owned(),
            home: PathBuf::from(CStr::from_ptr(pwd.pw_dir).to_str()?),
        })
    }
}

impl Identity {
    pub fn home(&self) -> &Path {
        &self.home
    }
}

fn shell_env_allowed(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    SHELL_ENV_ALLOWED.contains(&key) || key.starts_with("LC_")
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
        let mut command = self.spawnable(&executable, Path::new("/"));
        command.arg(subcommand);
        Ok(command)
    }

    /// `/bin/sh -c <script>` for `send_command` (DR-0008): cwd is the user's HOME and the
    /// environment holds only the allowlist.
    pub fn shell(&self, script: &str) -> Result<Command, Box<dyn Error>> {
        let (name, home) = match self {
            Self::Dropped(identity) => (identity.name.clone(), identity.home.clone()),
            Self::Inherited => current_user()?,
        };
        let mut command = self.spawnable(Path::new("/bin/sh"), &home);
        command.arg("-c").arg(script);
        command.envs(std::env::vars_os().filter(|(key, _)| shell_env_allowed(key)));
        if std::env::var_os("PATH").is_none() {
            command.env("PATH", DEFAULT_PATH);
        }
        command
            .env("HOME", &home)
            .env("USER", &name)
            .env("LOGNAME", &name);
        Ok(command)
    }

    fn spawnable(&self, program: &Path, cwd: &Path) -> Command {
        let mut command = Command::new(program);
        command.env_clear().current_dir(cwd);
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
        command
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

#[cfg(test)]
mod tests {
    use super::*;

    // send_command (DR-0008) reads the URL on stdin, runs in the user's HOME, and sees only the
    // allowlisted environment plus the user's HOME / USER / LOGNAME (sh itself adds PWD etc.).
    #[test]
    fn shell_runs_in_home_with_the_allowlist() {
        use std::io::Write;
        use std::process::Stdio;
        let (user, home) = current_user().unwrap();
        let mut child = RunAs::Inherited
            .shell("read url; echo \"url=$url\"; echo \"cwd=$(pwd -P)\"; env")
            .unwrap()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "https://example.invalid/#x").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let home = std::fs::canonicalize(home).unwrap();
        assert!(text.contains("url=https://example.invalid/#x\n"), "{text}");
        assert!(
            text.contains(&format!("cwd={}\n", home.display())),
            "{text}"
        );
        assert!(text.contains(&format!("USER={user}\n")), "{text}");
        assert!(text.contains(&format!("LOGNAME={user}\n")), "{text}");
        for line in text.lines().filter(|line| !line.starts_with(['u', 'c'])) {
            let key = line.split('=').next().unwrap();
            assert!(
                shell_env_allowed(OsStr::new(key))
                    || ["HOME", "USER", "LOGNAME", "PWD", "SHLVL", "_", "OLDPWD"].contains(&key),
                "unexpected variable {key}"
            );
        }
    }

    // Users whose ids do not fit in i32 (nobody: uid and gid -2) must still resolve to their exact
    // unsigned ids, or the drop would target the wrong identity or fail before reading anything.
    #[test]
    fn resolves_ids_above_i32_max() {
        let nobody = identity("nobody").unwrap();
        assert_eq!(nobody.uid, 4_294_967_294);
        assert_eq!(nobody.gid, 4_294_967_294);
        assert!(nobody.groups.contains(&4_294_967_294));
    }
}
