//! Children that run as PAM_USER (DR-0003): the helper re-executes itself with an internal
//! subcommand, permanently dropped to PAM_USER when it runs as root.

use protocol::RequestDetails;
use std::error::Error;
use std::ffi::{CStr, CString, OsStr};
use std::io::{ErrorKind, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

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

/// The user name of a uid from the user database.
pub fn user_name(uid: libc::uid_t) -> Option<String> {
    // SAFETY: getpwuid_r writes to the provided struct/buffer; the name is copied before it is dropped.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut storage = vec![0u8; 16384];
        let mut result = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            &mut pwd,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr(pwd.pw_name).to_string_lossy().into_owned())
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

/// What `send_command` is told about the URL it delivers (DR-0008): the URL itself as one line
/// on its standard input, and the `PAM_PASSKEY_*` variables the helper adds to the allowlisted
/// environment, so that a notification can say what is asked and by whom.
pub struct Notice {
    url: String,
    variables: Vec<(&'static str, String)>,
}

impl Notice {
    /// An approval request. `PAM_PASSKEY_DETAILS` is `details` serialized exactly as inside the
    /// request object PUT to the store (exchange-format), so the command reads the same object
    /// the page shows, and nothing else.
    pub fn approve(url: &str, details: &RequestDetails) -> serde_json::Result<Self> {
        Ok(Self::new(
            url,
            "approve",
            &details.user,
            &details.host,
            vec![
                ("PAM_PASSKEY_COMMAND", display_command(&details.argv)),
                ("PAM_PASSKEY_DETAILS", serde_json::to_string(details)?),
            ],
        ))
    }

    /// A registration by `add`: the user is the one running it, the host is this Mac.
    pub fn register(url: &str, user: &str) -> Self {
        Self::new(url, "register", user, &host_name(), Vec::new())
    }

    fn new(
        url: &str,
        kind: &str,
        user: &str,
        host: &str,
        rest: Vec<(&'static str, String)>,
    ) -> Self {
        let mut variables = vec![
            ("PAM_PASSKEY_URL", url.to_owned()),
            ("PAM_PASSKEY_KIND", kind.to_owned()),
            ("PAM_PASSKEY_USER", user.to_owned()),
            ("PAM_PASSKEY_HOST", host.to_owned()),
        ];
        variables.extend(rest);
        Self {
            url: url.to_owned(),
            variables,
        }
    }

    #[cfg(test)]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[cfg(test)]
    pub fn variable(&self, name: &str) -> Option<&str> {
        self.variables
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The Mac's host name, as the PAM module puts it in the request's `details.host`.
/// Design rationale: the module's own `host_name` (pam_passkey/src/lib.rs) is private to that
/// crate, so `add` repeats the same gethostname call to name the Mac the way approvals do.
fn host_name() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most the buffer length.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return String::new();
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// argv as one line in sh quoting, for display: an element that is empty or contains white
/// space, a quote or a control character is put in single quotes (`'` as `'\''`), the others
/// are left as they are. Control characters and the line and paragraph separators are written
/// as `\u{XXXX}` inside the quotes, so that no element can break the line.
fn display_command(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            let quoted = arg.is_empty()
                || arg
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch.is_control() || matches!(ch, '\'' | '"'));
            if !quoted {
                return arg.clone();
            }
            let mut text = String::from("'");
            for ch in arg.chars() {
                match ch {
                    '\'' => text.push_str("'\\''"),
                    _ if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') => {
                        text.push_str(&format!("\\u{{{:04X}}}", u32::from(ch)));
                    }
                    _ => text.push(ch),
                }
            }
            text.push('\'');
            text
        })
        .collect::<Vec<_>>()
        .join(" ")
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

    /// Starts `send_command` (DR-0008) with the notice's variables added to its environment and
    /// the URL as one line on its standard input, then closes that input. The command runs
    /// alongside the caller, which waits for it or stops it.
    pub fn send_command(&self, script: &str, notice: &Notice) -> Result<Child, Box<dyn Error>> {
        let mut command = self.shell(script)?;
        command
            .envs(
                notice
                    .variables
                    .iter()
                    .map(|(key, value)| (*key, value.as_str())),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = command.spawn()?;
        let written = match child.stdin.take() {
            Some(mut stdin) => writeln!(stdin, "{}", notice.url),
            None => Ok(()),
        };
        match written {
            Ok(()) => Ok(child),
            // A command that takes the URL from PAM_PASSKEY_URL may close its input unread.
            Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(child),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(format!("writing the URL to send_command: {error}").into())
            }
        }
    }

    /// `/bin/sh -c <script>` for `send_command` (DR-0008): cwd is the user's HOME and the
    /// environment holds only the allowlist.
    fn shell(&self, script: &str) -> Result<Command, Box<dyn Error>> {
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

    use crate::test_support::minio::temporary_directory;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn details(argv: &[&str]) -> RequestDetails {
        RequestDetails {
            host: "mac".into(),
            user: "kawaz".into(),
            caller_uid: 501,
            tty: Some("/dev/ttys001".into()),
            time: "2026-11-09T00:00:00Z".into(),
            argv: strings(argv),
            processes: Vec::new(),
        }
    }

    // send_command (DR-0008) reads the URL on stdin, runs in the user's HOME, and sees only the
    // allowlisted environment, the user's HOME / USER / LOGNAME and the notice's PAM_PASSKEY_*
    // variables (sh itself adds PWD etc.). A registration carries no command or details.
    #[test]
    fn send_command_runs_in_home_with_the_allowlist_and_the_notice() {
        let (user, home) = current_user().unwrap();
        let home = std::fs::canonicalize(home).unwrap();
        let url = "https://example.invalid/#x";
        let approve = Notice::approve(url, &details(&["sudo", "echo", "a b", "é\"'"])).unwrap();
        let register = Notice::register(url, &user);
        for (notice, kind, notice_user) in [
            (&approve, "approve", "kawaz"),
            (&register, "register", user.as_str()),
        ] {
            let directory = temporary_directory();
            let out = directory.join("out");
            let script = format!(
                "{{ read url; echo \"url=$url\"; echo \"cwd=$(pwd -P)\"; env; }} > '{}'",
                out.display()
            );
            let status = RunAs::Inherited
                .send_command(&script, notice)
                .unwrap()
                .wait()
                .unwrap();
            assert!(status.success());
            let text = std::fs::read_to_string(&out).unwrap();
            std::fs::remove_dir_all(&directory).unwrap();
            assert!(text.contains(&format!("url={url}\n")), "{text}");
            assert!(
                text.contains(&format!("cwd={}\n", home.display())),
                "{text}"
            );
            assert!(text.contains(&format!("USER={user}\n")), "{text}");
            assert!(text.contains(&format!("LOGNAME={user}\n")), "{text}");
            assert!(text.contains(&format!("PAM_PASSKEY_URL={url}\n")), "{text}");
            assert!(
                text.contains(&format!("PAM_PASSKEY_KIND={kind}\n")),
                "{text}"
            );
            assert!(
                text.contains(&format!("PAM_PASSKEY_USER={notice_user}\n")),
                "{text}"
            );
            let host = notice.variable("PAM_PASSKEY_HOST").unwrap();
            assert!(
                text.contains(&format!("PAM_PASSKEY_HOST={host}\n")),
                "{text}"
            );
            for name in ["PAM_PASSKEY_COMMAND", "PAM_PASSKEY_DETAILS"] {
                match notice.variable(name) {
                    Some(value) => {
                        assert!(text.contains(&format!("{name}={value}\n")), "{text}");
                    }
                    None => assert!(!text.contains(name), "{text}"),
                }
            }
            for line in text
                .lines()
                .filter(|line| !line.starts_with("url=") && !line.starts_with("cwd="))
            {
                let key = line.split('=').next().unwrap();
                assert!(
                    shell_env_allowed(OsStr::new(key))
                        || notice.variable(key).is_some()
                        || ["HOME", "USER", "LOGNAME", "PWD", "SHLVL", "_", "OLDPWD"]
                            .contains(&key),
                    "unexpected variable {key}"
                );
            }
        }
        // The approval's host and user are the request's; the registration's host is this Mac.
        assert_eq!(approve.variable("PAM_PASSKEY_HOST"), Some("mac"));
        assert_eq!(
            register.variable("PAM_PASSKEY_HOST"),
            Some(host_name().as_str())
        );
        assert!(!host_name().is_empty());
    }

    // A command that never reads its standard input is still a started command: it has the URL
    // in PAM_PASSKEY_URL. The URL is longer than a pipe holds, so the write meets the closed
    // input instead of landing in the pipe before the command closes it.
    #[test]
    fn send_command_may_leave_the_url_unread() {
        let url = format!("https://example.invalid/#{}", "x".repeat(256 * 1024));
        let directory = temporary_directory();
        let out = directory.join("out");
        let script = format!(
            "exec <&-; printf '%s' \"${{#PAM_PASSKEY_URL}}\" > '{}'",
            out.display()
        );
        let status = RunAs::Inherited
            .send_command(&script, &Notice::register(&url, "kawaz"))
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success());
        let length = std::fs::read_to_string(&out).unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert_eq!(length, url.len().to_string());
    }

    // PAM_PASSKEY_COMMAND quotes only the elements that need it, and sh reads the quoted line
    // back as the same argv; control characters become visible escapes on one line.
    #[test]
    fn command_is_quoted_for_display() {
        assert_eq!(
            display_command(&strings(&["sudo", "ls", "-la", "/tmp"])),
            "sudo ls -la /tmp"
        );
        assert_eq!(
            display_command(&strings(&["echo", "a b", ""])),
            "echo 'a b' ''"
        );
        assert_eq!(
            display_command(&strings(&["echo", "it's"])),
            r"echo 'it'\''s'"
        );
        assert_eq!(
            display_command(&strings(&["say", "\"hi\"", "全角\u{3000}空白"])),
            "say '\"hi\"' '全角\u{3000}空白'"
        );
        assert_eq!(
            display_command(&strings(&["printf", "a\nb\tc", "x\u{2028}y", "\u{1b}[2J"])),
            r"printf 'a\u{000A}b\u{0009}c' 'x\u{2028}y' '\u{001B}[2J'"
        );
        assert_eq!(display_command(&[]), "");
        let argv = strings(&["sudo", "echo", "a b", "", "it's", "\"q\"", "'"]);
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "set -- {}; printf '[%s]' \"$@\"",
                display_command(&argv)
            ))
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "[sudo][echo][a b][][it's][\"q\"][']"
        );
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
