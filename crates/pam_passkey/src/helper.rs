//! Starting the helper and talking helper-protocol with it (DR-0003 spawn の手順).

use libc::c_int;
use protocol::{HelperCommand, HelperEvent, HelperInput};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Sender, channel};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn passkey_verify_pid(pid: c_int) -> c_int;
}

/// Longest event line accepted from the helper; a URL event is far shorter.
const MAX_EVENT_LINE: u64 = 64 * 1024;
/// How long past the deadline the helper may take to exit before it is signalled.
const EXIT_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum Report {
    Event(HelperEvent),
    /// A line that is not one of the documented events.
    Malformed,
    /// The helper closed its standard output.
    Closed,
    /// A line could not be written to the helper; `command` is `None` for the input line.
    WriteFailed {
        command: Option<HelperCommand>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpawnError {
    Placement,
    Spawn,
    Signature(c_int),
    Pipe,
}

/// The running helper. Dropping it closes the helper's standard input after the queued lines,
/// which the helper takes as cancel unless it has already been told `finish`.
pub struct Helper {
    lines: Sender<(String, Option<HelperCommand>)>,
}

impl Helper {
    pub fn send(&self, command: HelperCommand) {
        if let Ok(line) = serde_json::to_string(&command) {
            let _ = self.lines.send((line, Some(command)));
        }
    }
}

/// The executable and every directory up to `/` must be root-owned, not writable by group or
/// others, and not symlinks.
pub fn secure_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = Some(path);
    while let Some(part) = current {
        let Ok(metadata) = part.symlink_metadata() else {
            return false;
        };
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return false;
        }
        if part == path && !metadata.is_file() || part != path && !metadata.is_dir() {
            return false;
        }
        current = part.parent();
    }
    true
}

/// Placement check, spawn, signature check of the spawned pid, then the input line
/// (helper-protocol 起動). Every failure means remote is unavailable.
pub fn spawn(
    path: &Path,
    input: &HelperInput,
    deadline: Instant,
    report: impl Fn(Report) + Send + Clone + 'static,
) -> Result<Helper, SpawnError> {
    if !secure_path(path) {
        return Err(SpawnError::Placement);
    }
    let input = serde_json::to_string(input).map_err(|_| SpawnError::Pipe)?;
    let mut command = Command::new(path);
    command
        .arg("_auth")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Rust opens every descriptor with CLOEXEC, so only the configured stdio survives exec.
    // The helper gets its own process group: Ctrl-C at the terminal goes to the caller's
    // foreground group, and the module turns it into cancel (closing the helper's input)
    // instead of the signal killing the helper before it can conclude the request.
    // SAFETY: the callback calls only async-signal-safe functions between fork and exec.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Command::spawn returns after exec succeeded, so the pid below runs the helper image.
    let mut child = command.spawn().map_err(|_| SpawnError::Spawn)?;
    let Ok(pid) = c_int::try_from(child.id()) else {
        stop(child);
        return Err(SpawnError::Spawn);
    };
    // SAFETY: the pid belongs to our unreaped child, so it cannot be reused meanwhile.
    let verified = unsafe { passkey_verify_pid(pid) };
    if verified != 0 {
        stop(child);
        return Err(SpawnError::Signature(verified));
    }
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        stop(child);
        return Err(SpawnError::Pipe);
    };
    // A write after the helper exited must fail with EPIPE instead of signalling the caller
    // (sudo's SIGPIPE disposition is not ours to change).
    // SAFETY: the descriptor is owned by `stdin` and stays open.
    if unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) } != 0 {
        stop(child);
        return Err(SpawnError::Pipe);
    }

    let (lines, queue) = channel::<(String, Option<HelperCommand>)>();
    let _ = lines.send((input, None));
    let writer_report = report.clone();
    std::thread::spawn(move || {
        let mut stdin = stdin;
        for (line, command) in queue {
            if writeln!(stdin, "{line}")
                .and_then(|()| stdin.flush())
                .is_err()
            {
                writer_report(Report::WriteFailed { command });
            }
        }
    });
    std::thread::spawn(move || read_events(stdout, report));
    std::thread::spawn(move || reap(child, deadline + EXIT_GRACE));
    Ok(Helper { lines })
}

fn read_events(stdout: impl Read, report: impl Fn(Report)) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = Vec::new();
        match (&mut reader)
            .take(MAX_EVENT_LINE)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => break,
            Ok(_) if line.last() != Some(&b'\n') => {
                report(Report::Malformed);
                break;
            }
            Ok(_) => report(match serde_json::from_slice::<HelperEvent>(&line) {
                Ok(event) => Report::Event(event),
                Err(_) => Report::Malformed,
            }),
        }
    }
    report(Report::Closed);
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Waits for the helper to exit; past `until` it is sent SIGTERM, then SIGKILL.
/// Runs detached, so the caller does not wait for the helper (helper-protocol `finish`).
fn reap(mut child: Child, until: Instant) {
    let pid = child.id() as libc::pid_t;
    if !wait_exit(pid, until.saturating_duration_since(Instant::now())) {
        // SAFETY: the pid is our unreaped child.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        if !wait_exit(pid, EXIT_GRACE) {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

/// Blocks until `pid` exits or `timeout` passes (kqueue EVFILT_PROC). True if it exited.
fn wait_exit(pid: libc::pid_t, timeout: Duration) -> bool {
    // SAFETY: kqueue has no preconditions; the descriptor is closed below.
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        return false;
    }
    let change = libc::kevent {
        ident: pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: kevent is plain old data; zero is a valid bit pattern.
    let mut fired: libc::kevent = unsafe { std::mem::zeroed() };
    let timeout = libc::timespec {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
    };
    // SAFETY: one change and one result slot are passed with their counts.
    let count = unsafe { libc::kevent(queue, &change, 1, &mut fired, 1, &timeout) };
    let error = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: `queue` is our descriptor.
    unsafe { libc::close(queue) };
    match count {
        // Registering a process that already exited fails with ESRCH.
        count if count < 0 => error == Some(libc::ESRCH),
        0 => false,
        _ => fired.flags & libc::EV_ERROR == 0 || fired.data == libc::ESRCH as isize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;

    fn collect(bytes: &'static [u8]) -> Vec<String> {
        let (sender, receiver): (Sender<Report>, Receiver<Report>) = channel();
        read_events(bytes, move |report| {
            let _ = sender.send(report);
        });
        receiver
            .iter()
            .map(|report| format!("{report:?}"))
            .collect()
    }

    // A helper path is trusted only if every component, including / and the binary, is root-owned
    // and non-writable by others; relative paths cannot be checked and are refused.
    #[test]
    fn rejects_relative_and_user_owned_paths() {
        assert!(!secure_path(Path::new("target/release/pam-passkey")));
        // The test binary lives in a user-owned build directory.
        assert!(!secure_path(&std::env::current_exe().unwrap()));
        assert!(secure_path(Path::new("/bin/sh")));
        // A root-owned symlink is still refused (/tmp -> private/tmp).
        assert!(!secure_path(Path::new("/tmp")));
    }

    // Each documented event becomes one report; anything else is reported as malformed, and the
    // end of output is always reported so the driver never waits on a dead helper.
    #[test]
    fn events_are_parsed_line_by_line() {
        assert_eq!(
            collect(b"{\"event\":\"unavailable\",\"reason\":\"no-credentials\"}\nnot json\n"),
            [
                "Event(Unavailable { reason: NoCredentials })",
                "Malformed",
                "Closed"
            ]
        );
        // A final line without its newline is incomplete output.
        assert_eq!(
            collect(b"{\"event\":\"result\",\"id\":\"x\",\"pass\":true}"),
            ["Malformed", "Closed"]
        );
        assert_eq!(collect(b""), ["Closed"]);
    }

    // An event line longer than the cap is cut off and rejected rather than buffered without bound.
    #[test]
    fn oversized_event_line_is_malformed() {
        let mut bytes = b"{\"event\":\"url\",\"url\":\"".to_vec();
        bytes.extend(std::iter::repeat_n(b'a', MAX_EVENT_LINE as usize));
        bytes.extend_from_slice(b"\"}\n");
        let (sender, receiver) = channel();
        read_events(bytes.as_slice(), move |report| {
            let _ = sender.send(format!("{report:?}"));
        });
        assert_eq!(receiver.iter().collect::<Vec<_>>(), ["Malformed", "Closed"]);
    }

    // The reaper must neither wait past the deadline for a hung helper nor signal one that exited.
    #[test]
    fn wait_exit_reports_exit_and_timeout() {
        let mut sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = sleeper.id() as libc::pid_t;
        let started = Instant::now();
        assert!(!wait_exit(pid, Duration::from_millis(200)));
        assert!(started.elapsed() >= Duration::from_millis(200));
        sleeper.kill().unwrap();
        assert!(wait_exit(pid, Duration::from_secs(5)));
        sleeper.wait().unwrap();

        let mut quick = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = quick.id() as libc::pid_t;
        assert!(wait_exit(pid, Duration::from_secs(5)));
        quick.wait().unwrap();
    }

    /// Exit status 42 if a write to a pipe without reader fails with EPIPE, or the wait status
    /// of being killed. Runs in a forked child with SIGPIPE at its default (terminate): in the
    /// single-threaded child no concurrently forked process can hold a copy of the read end.
    fn write_without_reader(nosigpipe: bool) -> c_int {
        // SAFETY: the child calls only async-signal-safe functions before _exit.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let mut fds = [0; 2];
                if libc::pipe(fds.as_mut_ptr()) != 0 {
                    libc::_exit(1);
                }
                libc::close(fds[0]);
                if nosigpipe && libc::fcntl(fds[1], libc::F_SETNOSIGPIPE, 1) != 0 {
                    libc::_exit(2);
                }
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                let written = libc::write(fds[1], b"x".as_ptr().cast(), 1);
                let epipe = written < 0 && *libc::__error() == libc::EPIPE;
                libc::_exit(if epipe { 42 } else { 3 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            status
        }
    }

    // Writing to a helper that has exited must fail with EPIPE, not deliver SIGPIPE to the caller
    // (sudo). The control run without the flag shows the write would otherwise kill the process.
    #[test]
    fn nosigpipe_turns_sigpipe_into_epipe() {
        let guarded = write_without_reader(true);
        assert!(libc::WIFEXITED(guarded) && libc::WEXITSTATUS(guarded) == 42);
        let unguarded = write_without_reader(false);
        assert!(libc::WIFSIGNALED(unguarded) && libc::WTERMSIG(unguarded) == libc::SIGPIPE);
    }
}
