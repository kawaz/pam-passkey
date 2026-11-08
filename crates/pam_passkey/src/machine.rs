//! The decision table of DR-0012 as a pure state machine. The driver in `authenticate`
//! feeds it what Touch ID and the helper report and performs the actions it returns.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    /// Started and not concluded (for Touch ID: a dialog is up or about to be).
    Running,
    /// Could not be used at all. Only this state counts towards `PAM_IGNORE`.
    Unavailable,
    /// Was used and did not succeed.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Touch ID cannot be used (`canEvaluatePolicy` false, or the euid could not be dropped).
    TouchUnavailable,
    TouchSucceeded,
    /// The 「詳細を確認」 fallback button (`LAErrorUserFallback`).
    TouchFallback,
    TouchCancelled,
    /// Biometry mismatch, lockout and every other end of the dialog.
    TouchFailed,
    /// The euid could not be returned to root after the evaluation.
    EuidNotRestored,
    RemoteUnavailable,
    RemotePassed,
    /// `pass: false`, a result for another request ID, malformed output, or exit without a result.
    RemoteFailed,
    /// The helper could not be given `open` / `reactivate`.
    OpenFailed,
    Expired,
    /// Ctrl-C (SIGINT) while waiting.
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Touch ID succeeded: the helper is told `finish` before returning.
    TouchSuccess,
    /// The helper reported the matching `result` with `pass: true`.
    RemoteSuccess,
    AuthErr,
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Wait,
    /// Show a new dialog, then send `open` and `reactivate` to the helper.
    Reshow,
    Finish(Outcome),
}

pub struct Machine {
    touch: Path,
    remote: Path,
}

impl Machine {
    pub fn new(touch_started: bool, remote_started: bool) -> Self {
        let state = |started| {
            if started {
                Path::Running
            } else {
                Path::Unavailable
            }
        };
        Self {
            touch: state(touch_started),
            remote: state(remote_started),
        }
    }

    /// The result when neither path could be started (both unavailable from the outset).
    pub fn initial(&self) -> Action {
        self.settle()
    }

    pub fn on(&mut self, input: Input) -> Action {
        match input {
            Input::TouchSucceeded => Action::Finish(Outcome::TouchSuccess),
            Input::RemotePassed => Action::Finish(Outcome::RemoteSuccess),
            Input::TouchCancelled
            | Input::Interrupted
            | Input::Expired
            | Input::EuidNotRestored
            | Input::OpenFailed => Action::Finish(Outcome::AuthErr),
            Input::TouchFallback => {
                if self.remote == Path::Running {
                    self.touch = Path::Running;
                    Action::Reshow
                } else {
                    Action::Finish(Outcome::AuthErr)
                }
            }
            Input::TouchUnavailable => self.end_touch(Path::Unavailable),
            Input::TouchFailed => self.end_touch(Path::Failed),
            Input::RemoteUnavailable => self.end_remote(Path::Unavailable),
            Input::RemoteFailed => self.end_remote(Path::Failed),
        }
    }

    fn end_touch(&mut self, to: Path) -> Action {
        if self.touch == Path::Running {
            self.touch = to;
        }
        self.settle()
    }

    fn end_remote(&mut self, to: Path) -> Action {
        // The first conclusion of the helper stands; its exit after `unavailable` is not a failure.
        if self.remote == Path::Running {
            self.remote = to;
        }
        self.settle()
    }

    fn settle(&self) -> Action {
        if self.touch == Path::Running || self.remote == Path::Running {
            Action::Wait
        } else if self.touch == Path::Unavailable && self.remote == Path::Unavailable {
            Action::Finish(Outcome::Ignore)
        } else {
            Action::Finish(Outcome::AuthErr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::{Finish, Reshow, Wait};
    use Input::*;
    use Outcome::*;

    fn run(touch: bool, remote: bool, inputs: &[Input]) -> Vec<Action> {
        let mut machine = Machine::new(touch, remote);
        inputs.iter().map(|input| machine.on(*input)).collect()
    }

    // Each test below is one row of the DR-0012 state table, named after the row.

    // Row: PAM_USER has no GUI session — no dialog, remote alone decides; IGNORE only if remote is unusable too.
    #[test]
    fn no_gui_session_waits_for_remote_alone() {
        assert_eq!(Machine::new(false, true).initial(), Wait);
        assert_eq!(run(false, true, &[RemotePassed]), [Finish(RemoteSuccess)]);
        assert_eq!(run(false, true, &[RemoteFailed]), [Finish(AuthErr)]);
        assert_eq!(run(false, true, &[Expired]), [Finish(AuthErr)]);
        assert_eq!(run(false, true, &[RemoteUnavailable]), [Finish(Ignore)]);
    }

    // Row: Touch ID cannot be evaluated — reported after start, the remote path keeps the request alive.
    #[test]
    fn touch_id_unusable_waits_for_remote() {
        assert_eq!(
            run(true, true, &[TouchUnavailable, RemotePassed]),
            [Wait, Finish(RemoteSuccess)]
        );
        assert_eq!(
            run(true, true, &[TouchUnavailable, RemoteFailed]),
            [Wait, Finish(AuthErr)]
        );
        assert_eq!(
            run(true, true, &[TouchUnavailable, RemoteUnavailable]),
            [Wait, Finish(Ignore)]
        );
        // The order of the two reports does not change the result.
        assert_eq!(
            run(true, true, &[RemoteUnavailable, TouchUnavailable]),
            [Wait, Finish(Ignore)]
        );
    }

    // Row: dialog cancelled — both stop even while the remote path could still succeed.
    #[test]
    fn cancel_stops_both() {
        assert_eq!(run(true, true, &[TouchCancelled]), [Finish(AuthErr)]);
        assert_eq!(
            run(true, true, &[RemoteUnavailable, TouchCancelled]),
            [Wait, Finish(AuthErr)]
        );
    }

    // Row: Touch ID fails while remote runs — only Touch ID ends; remote decides.
    #[test]
    fn touch_failure_leaves_remote_running() {
        assert_eq!(
            run(true, true, &[TouchFailed, RemotePassed]),
            [Wait, Finish(RemoteSuccess)]
        );
        assert_eq!(
            run(true, true, &[TouchFailed, RemoteFailed]),
            [Wait, Finish(AuthErr)]
        );
        assert_eq!(
            run(true, true, &[TouchFailed, Expired]),
            [Wait, Finish(AuthErr)]
        );
        // A used-and-failed Touch ID is not "unavailable", so an unusable remote gives AUTH_ERR.
        assert_eq!(
            run(true, true, &[TouchFailed, RemoteUnavailable]),
            [Wait, Finish(AuthErr)]
        );
    }

    // Row: 「詳細を確認」 — the dialog is shown again and either path can still succeed, repeatedly.
    #[test]
    fn fallback_reshows_while_remote_runs() {
        assert_eq!(
            run(true, true, &[TouchFallback, TouchSucceeded]),
            [Reshow, Finish(TouchSuccess)]
        );
        assert_eq!(
            run(true, true, &[TouchFallback, TouchFallback, RemotePassed]),
            [Reshow, Reshow, Finish(RemoteSuccess)]
        );
        assert_eq!(
            run(true, true, &[TouchFallback, RemoteFailed]),
            [Reshow, Wait]
        );
        assert_eq!(
            run(true, true, &[TouchFallback, Expired]),
            [Reshow, Finish(AuthErr)]
        );
    }

    // Row: 「詳細を確認」 when remote is unusable — both stop; also when the helper cannot take `open`.
    #[test]
    fn fallback_without_remote_stops_both() {
        assert_eq!(
            run(true, true, &[RemoteUnavailable, TouchFallback]),
            [Wait, Finish(AuthErr)]
        );
        assert_eq!(run(true, false, &[TouchFallback]), [Finish(AuthErr)]);
        assert_eq!(
            run(true, true, &[RemoteFailed, TouchFallback]),
            [Wait, Finish(AuthErr)]
        );
        assert_eq!(
            run(true, true, &[TouchFallback, OpenFailed]),
            [Reshow, Finish(AuthErr)]
        );
    }

    // Row: expiry — both stop regardless of what is still running.
    #[test]
    fn expiry_stops_both() {
        assert_eq!(run(true, true, &[Expired]), [Finish(AuthErr)]);
        assert_eq!(run(false, true, &[Expired]), [Finish(AuthErr)]);
        assert_eq!(run(true, false, &[Expired]), [Finish(AuthErr)]);
    }

    // Row: Ctrl-C — same as cancel: both stop, even with only one path running.
    #[test]
    fn interrupt_stops_both() {
        assert_eq!(run(true, true, &[Interrupted]), [Finish(AuthErr)]);
        assert_eq!(run(false, true, &[Interrupted]), [Finish(AuthErr)]);
        assert_eq!(
            run(true, true, &[TouchFallback, Interrupted]),
            [Reshow, Finish(AuthErr)]
        );
    }

    // Row: remote unusable (helper failed to start / unavailable) — Touch ID alone decides.
    #[test]
    fn unusable_remote_leaves_touch_id_alone() {
        assert_eq!(Machine::new(true, false).initial(), Wait);
        assert_eq!(run(true, false, &[TouchSucceeded]), [Finish(TouchSuccess)]);
        assert_eq!(run(true, false, &[TouchFailed]), [Finish(AuthErr)]);
        assert_eq!(run(true, false, &[TouchUnavailable]), [Finish(Ignore)]);
        assert_eq!(
            run(true, true, &[RemoteUnavailable, TouchSucceeded]),
            [Wait, Finish(TouchSuccess)]
        );
        assert_eq!(Machine::new(false, false).initial(), Finish(Ignore));
    }

    // Invariant (DR-0012 seteuid の順序): failing to return to root overrides a Touch ID success.
    #[test]
    fn unrestored_euid_is_auth_err() {
        assert_eq!(run(true, true, &[EuidNotRestored]), [Finish(AuthErr)]);
    }

    // Invariant (DR-0012 helper の成功判定): the helper's exit after `unavailable` must not turn
    // an unusable remote into a failed one, or Touch ID being unusable would give AUTH_ERR, not IGNORE.
    #[test]
    fn helper_exit_after_unavailable_keeps_it_unavailable() {
        assert_eq!(
            run(
                true,
                true,
                &[RemoteUnavailable, RemoteFailed, TouchUnavailable]
            ),
            [Wait, Wait, Finish(Ignore)]
        );
    }
}
