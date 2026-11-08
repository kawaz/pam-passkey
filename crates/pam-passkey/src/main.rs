use pam_passkey::keychain::{Keychain, SystemItem};
use std::error::Error;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const HELP: &str = "pam-passkey — Keychain layer verification

Commands:
  _read-user-keys <user>             Read the specified user's signed public-key records
  _probe-system <write|read|delete> <page_url|store|send_command|signing_key|verification_key>
                                     Inspect isolated, fixed-value System Keychain items
  _probe-login <write|read|delete>   Inspect an isolated, fixed-value login keychain item

Global options:
  --help                             Show this help

Environment: ignored by Keychain item selection; spawned children inherit no environment.
";
const PROBE_VALUE: &str = "pam-passkey-keychain-probe-2026";

fn current_user() -> Result<(String, PathBuf), Box<dyn Error>> {
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

fn user_identity(
    user: &str,
) -> Result<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>), Box<dyn Error>> {
    let name = CString::new(user)?;
    // Resolve all identities and supplemental groups in the parent, before fork.
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
        if pwd.pw_uid == 0 {
            return Err("root has no target login keychain for this verification".into());
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
        let gids: Vec<libc::gid_t> = groups[..count]
            .iter()
            .map(|group| u32::try_from(*group))
            .collect::<Result<_, _>>()?;
        Ok((pwd.pw_uid, pwd.pw_gid, gids))
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

fn clean_child(command: &mut Command) -> &mut Command {
    command.env_clear().current_dir("/");
    // Rust opens every descriptor with CLOEXEC, so nothing beyond the configured stdio survives exec.
    // Closing descriptors here would also close the pipe Rust uses to report exec failures.
    // SAFETY: pre_exec executes only async-signal-safe libc calls after fork, before exec.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    command
}

fn root_probe_helper(user: &str) -> Result<(), Box<dyn Error>> {
    // The PAM process sends one byte only after checking the spawned PID's signature.
    let mut ready = [0u8; 1];
    std::io::stdin().read_exact(&mut ready)?;
    if ready[0] != 1 {
        return Err("PAM signature verification handshake failed".into());
    }
    let executable = std::env::current_exe()?;
    if !executable.is_absolute() {
        return Err("helper executable must be absolute".into());
    }
    let mut command = Command::new(executable);
    clean_child(&mut command)
        .arg("_read-probe-user-keys")
        .arg(user)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if unsafe { libc::geteuid() } == 0 {
        let (uid, gid, groups) = user_identity(user)?;
        // SAFETY: all user and group lookups run above in the parent; pre_exec uses only libc syscalls.
        unsafe {
            command.pre_exec(move || permanently_drop(uid, gid, &groups));
        }
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "user Keychain child failed: {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    // Forward only the fixed probe value, never any production Keychain item.
    std::io::stdout().write_all(&output.stdout)?;
    Ok(())
}

fn probe_system(operation: &str, account: &str) -> Result<(), Box<dyn Error>> {
    let item = match account {
        "page_url" => SystemItem::PageUrl,
        "store" => SystemItem::Store,
        "send_command" => SystemItem::SendCommand,
        "signing_key" => SystemItem::SigningKey,
        "verification_key" => SystemItem::VerificationKey,
        _ => return Err("unknown probe item".into()),
    };
    let keychain = Keychain::system()?;
    match operation {
        "write" => keychain.write_probe_system(item, PROBE_VALUE)?,
        "read" => {
            let value = keychain.read_probe_system(item)?;
            if value != PROBE_VALUE {
                return Err("probe value differs from fixed test value".into());
            }
            println!("{value}");
        }
        "delete" => keychain.delete_probe_system(item)?,
        _ => return Err("unknown probe operation".into()),
    }
    Ok(())
}

fn probe_login(operation: &str) -> Result<(), Box<dyn Error>> {
    let (user, home) = current_user()?;
    let keychain = Keychain::login(Path::new(&home))?;
    match operation {
        "write" => keychain.write_probe_user(&user, PROBE_VALUE)?,
        "read" => {
            let value = keychain.read_probe_user(&user)?;
            if value != PROBE_VALUE {
                return Err("probe value differs from fixed test value".into());
            }
            println!("{value}");
        }
        "delete" => keychain.delete_probe_user(&user)?,
        _ => return Err("unknown probe operation".into()),
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] | [_, ..] if args.is_empty() || args.iter().any(|arg| arg == "--help") => {
            print!("{HELP}")
        }
        [command, user] if command == "_read-user-keys" || command == "_read-probe-user-keys" => {
            let (current, home) = current_user()?;
            if user != &current {
                return Err("read requested for another OS user".into());
            }
            let keychain = Keychain::login(Path::new(&home))?;
            let keys = if command == "_read-user-keys" {
                keychain.read_user(user)?
            } else {
                keychain.read_probe_user(user)?
            };
            print!("{keys}");
        }
        [command, user] if command == "_probe-auth" => root_probe_helper(user)?,
        [command, operation, item] if command == "_probe-system" => probe_system(operation, item)?,
        [command, operation] if command == "_probe-login" => probe_login(operation)?,
        _ => return Err("invalid arguments; run pam-passkey --help".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("pam-passkey: {error}");
        std::process::exit(1);
    }
}
