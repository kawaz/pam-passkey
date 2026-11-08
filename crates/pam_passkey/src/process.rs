//! Process information collected inside the PAM caller, before the euid is dropped
//! (exchange-format `processes`).

use libc::{c_char, c_int, pid_t, uid_t};
use protocol::ProcessDetails;
use std::{mem, ptr};

unsafe extern "C" {
    fn passkey_process_parent(pid: pid_t, parent: *mut pid_t, uid: *mut uid_t) -> c_int;
    fn passkey_signing_info(
        pid: c_int,
        signing_id: *mut c_char,
        signing_id_len: usize,
        team_id: *mut c_char,
        team_id_len: usize,
        signer: *mut c_char,
        signer_len: usize,
    ) -> i32;
}

const SIGNING_ID: i32 = 1;
const TEAM_ID: i32 = 2;
const SIGNER: i32 = 4;
/// launchd is the root of every chain; a longer walk means the parent links loop.
const MAX_ANCESTORS: usize = 64;

/// argv of `pid` from `KERN_PROCARGS2`, without the environment that follows it.
pub fn argv_of(pid: pid_t) -> Option<Vec<String>> {
    let mut argmax: c_int = 0;
    let mut size = mem::size_of_val(&argmax);
    let mut limit = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: sysctl receives writable storage with its exact byte length.
    if unsafe {
        libc::sysctl(
            limit.as_mut_ptr(),
            limit.len() as u32,
            (&mut argmax as *mut c_int).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
        || argmax <= 0
    {
        return None;
    }
    let mut bytes = vec![0u8; usize::try_from(argmax).ok()?];
    let mut size = bytes.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: the writable buffer is `bytes`, and `size` states its capacity.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
        || size > bytes.len()
    {
        return None;
    }
    parse_procargs(&bytes[..size])
}

fn parse_procargs(bytes: &[u8]) -> Option<Vec<String>> {
    let count = i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
    if count <= 0 {
        return None;
    }
    let mut cursor = 4;
    let executable_end = bytes.get(cursor..)?.iter().position(|&byte| byte == 0)? + cursor;
    cursor = executable_end + 1;
    while bytes.get(cursor) == Some(&0) {
        cursor += 1;
    }
    let mut args = Vec::new();
    for _ in 0..count {
        let end = bytes.get(cursor..)?.iter().position(|&byte| byte == 0)? + cursor;
        args.push(String::from_utf8_lossy(&bytes[cursor..end]).into_owned());
        cursor = end + 1;
    }
    Some(args)
}

fn executable_path(pid: pid_t) -> Option<String> {
    let mut bytes = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath writes at most the supplied buffer length.
    let len = unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    let len = usize::try_from(len)
        .ok()
        .filter(|len| (1..=bytes.len()).contains(len))?;
    Some(String::from_utf8_lossy(&bytes[..len]).into_owned())
}

fn cwd_of(pid: pid_t) -> Option<String> {
    // SAFETY: proc_vnodepathinfo is plain old data; zero is a valid bit pattern.
    let mut info: libc::proc_vnodepathinfo = unsafe { mem::zeroed() };
    let size = c_int::try_from(mem::size_of_val(&info)).ok()?;
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info`.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&mut info as *mut libc::proc_vnodepathinfo).cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    let path = &info.pvi_cdir.vip_path;
    let bytes: Vec<u8> = path
        .iter()
        .flatten()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect();
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

fn c_buffer_text(buffer: &[c_char]) -> String {
    let bytes: Vec<u8> = buffer
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn describe(pid: pid_t, uid: uid_t) -> ProcessDetails {
    let mut signing_id = [0 as c_char; 512];
    let mut team_id = [0 as c_char; 64];
    let mut signer = [0 as c_char; 512];
    // SAFETY: every buffer is passed with its exact length; the shim NUL-terminates what it fills.
    let filled = unsafe {
        passkey_signing_info(
            pid,
            signing_id.as_mut_ptr(),
            signing_id.len(),
            team_id.as_mut_ptr(),
            team_id.len(),
            signer.as_mut_ptr(),
            signer.len(),
        )
    };
    let field = |bit, buffer: &[c_char]| (filled & bit != 0).then(|| c_buffer_text(buffer));
    ProcessDetails {
        pid: pid as u32,
        uid,
        cwd: cwd_of(pid),
        path: executable_path(pid),
        argv: argv_of(pid),
        signing_id: field(SIGNING_ID, &signing_id),
        team_id: field(TEAM_ID, &team_id),
        signer: field(SIGNER, &signer),
    }
}

/// The caller and its ancestors up to launchd (pid 1), caller first. A walk that cannot
/// reach launchd keeps what it collected; the page shows the chain as it was found.
pub fn ancestry() -> Vec<ProcessDetails> {
    // SAFETY: getpid has no preconditions.
    let mut current = unsafe { libc::getpid() };
    let mut chain: Vec<ProcessDetails> = Vec::new();
    while chain.len() < MAX_ANCESTORS && !chain.iter().any(|known| known.pid == current as u32) {
        let (mut parent, mut uid) = (0, 0);
        // SAFETY: the shim writes one pid_t and one uid_t after checking the sysctl result.
        if unsafe { passkey_process_parent(current, &mut parent, &mut uid) } != 0 {
            break;
        }
        chain.push(describe(current, uid));
        if current == 1 || parent <= 0 {
            break;
        }
        current = parent;
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    // The environment block follows argv in KERN_PROCARGS2 and must never be read as arguments.
    #[test]
    fn reads_argument_count_without_reaching_environment() {
        let mut bytes = 2i32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"/usr/bin/sudo\0\0\0sudo\0true\0SECRET=not-displayed\0");
        assert_eq!(
            parse_procargs(&bytes),
            Some(vec!["sudo".into(), "true".into()])
        );
    }

    // A truncated buffer is missing data, not a shorter argv.
    #[test]
    fn rejects_missing_arguments() {
        let mut bytes = 2i32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"/usr/bin/sudo\0sudo\0");
        assert_eq!(parse_procargs(&bytes), None);
    }

    // The walk from this test process ends at launchd with the caller first, as the page expects.
    #[test]
    fn ancestry_runs_from_self_to_launchd() {
        let chain = ancestry();
        assert_eq!(chain.first().map(|p| p.pid), Some(std::process::id()));
        assert_eq!(chain.last().map(|p| p.pid), Some(1));
        let own = chain.first().unwrap();
        assert!(
            own.path
                .as_deref()
                .is_some_and(|path| path.starts_with('/'))
        );
        assert!(own.cwd.is_some());
        assert!(own.argv.as_ref().is_some_and(|argv| !argv.is_empty()));
        // arm64 test binaries carry the linker's ad-hoc signature: an identifier, no Team ID, no signer.
        assert!(own.signing_id.is_some());
        assert_eq!(own.team_id, None);
        assert_eq!(own.signer, None);
    }
}
