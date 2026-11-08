//! Ctrl-C while the module waits (DR-0012: Ctrl-C はキャンセルと同じ).
//!
//! The caller (sudo) keeps SIGINT from ending the process during authentication, so nothing
//! wakes the wait loop. While the module waits, a SIGINT handler writes to a self-pipe and a
//! thread turns that into a report; the caller's handler and signal mask are restored afterwards.

use libc::c_int;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::JoinHandle;

const INTERRUPTED: u8 = 1;
const STOP: u8 = 0;

/// Write end of the self-pipe for the signal handler; -1 until the pipe exists.
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// Read end. The pipe is created once per process and never closed, so a handler that runs
/// late can never write into a descriptor number that was reused.
static READ_FD: OnceLock<Option<c_int>> = OnceLock::new();

extern "C" fn on_sigint(_: c_int) {
    // SAFETY: errno access, an atomic load and write(2) are async-signal-safe.
    unsafe {
        let saved = *libc::__error();
        let fd = WRITE_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            libc::write(fd, (&INTERRUPTED as *const u8).cast(), 1);
        }
        *libc::__error() = saved;
    }
}

fn read_fd() -> Option<c_int> {
    *READ_FD.get_or_init(|| {
        let mut fds = [0; 2];
        // SAFETY: pipe writes two descriptors into the array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: both descriptors were just created and are owned here for the process lifetime.
        unsafe {
            for fd in fds {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            // The handler must never block, even if the pipe is full.
            let flags = libc::fcntl(fds[1], libc::F_GETFL);
            libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK);
            libc::fcntl(fds[1], libc::F_SETNOSIGPIPE, 1);
        }
        WRITE_FD.store(fds[1], Ordering::SeqCst);
        Some(fds[0])
    })
}

/// Reports Ctrl-C to `on_interrupt` until dropped.
pub struct Watch {
    previous: libc::sigaction,
    reader: Option<JoinHandle<()>>,
}

impl Watch {
    pub fn start(on_interrupt: impl Fn() + Send + 'static) -> Option<Self> {
        let read = read_fd()?;
        let reader = std::thread::spawn(move || {
            // The caller may block SIGINT in the thread we were started from; this thread
            // receives it instead.
            // SAFETY: sigset operations on a local set; pthread_sigmask changes only this thread.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGINT);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            }
            loop {
                let mut byte = 0u8;
                // SAFETY: one byte is read into a local.
                let count = unsafe { libc::read(read, (&mut byte as *mut u8).cast(), 1) };
                let interrupted_read = count < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR);
                if count == 1 && byte == INTERRUPTED {
                    on_interrupt();
                } else if !interrupted_read {
                    // The stop byte, or the pipe failed.
                    return;
                }
            }
        });
        // SAFETY: sigaction is plain old data; the handler only performs async-signal-safe calls.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sigint as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGINT, &action, &mut previous) != 0 {
                stop(reader);
                return None;
            }
            Some(Self {
                previous,
                reader: Some(reader),
            })
        }
    }
}

/// Wakes the reader with the stop byte and waits for it. Interrupt bytes written before the
/// stop byte are consumed by this reader, so none is left for a later watch.
fn stop(reader: JoinHandle<()>) {
    let fd = WRITE_FD.load(Ordering::SeqCst);
    // SAFETY: the write end lives for the process lifetime.
    if unsafe { libc::write(fd, (&STOP as *const u8).cast(), 1) } == 1 {
        let _ = reader.join();
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: restores the disposition saved in start.
        unsafe { libc::sigaction(libc::SIGINT, &self.previous, std::ptr::null_mut()) };
        if let Some(reader) = self.reader.take() {
            stop(reader);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    fn current_handler() -> libc::sighandler_t {
        // SAFETY: a NULL new action only reads the current one.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGINT, std::ptr::null(), &mut current);
            current.sa_sigaction
        }
    }

    // Ctrl-C during the wait is reported (and does not end the process), and afterwards the
    // caller's own SIGINT disposition is back in place, so the module leaves no trace in sudo.
    #[test]
    fn sigint_is_reported_then_disposition_restored() {
        // Stand-in for the caller's disposition: ignore, as sudo effectively does here.
        // SAFETY: changes this test process's SIGINT disposition; restored at the end.
        let original = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
        let (sender, receiver) = channel();
        let watch = Watch::start(move || {
            let _ = sender.send(());
        })
        .unwrap();
        assert_eq!(
            current_handler(),
            on_sigint as *const () as libc::sighandler_t
        );
        // SAFETY: a process-directed SIGINT, handled by on_sigint.
        unsafe { libc::kill(libc::getpid(), libc::SIGINT) };
        assert!(receiver.recv_timeout(Duration::from_secs(5)).is_ok());
        drop(watch);
        assert_eq!(current_handler(), libc::SIG_IGN);
        // A second watch does not see the first watch's interrupt again.
        let (sender, receiver) = channel();
        let watch = Watch::start(move || {
            let _ = sender.send(());
        })
        .unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
        drop(watch);
        // SAFETY: restores the test harness's original disposition.
        unsafe { libc::signal(libc::SIGINT, original) };
    }
}
