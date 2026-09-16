//! Opening a real PAM session, so logind registers the desktop.
//!
//! The authentication half already exists in `crate::pam`. This adds the
//! session half — `pam_setcred`, `pam_open_session`, `pam_getenvlist`,
//! `pam_close_session` — because `pam_systemd.so` is what creates
//! `/run/user/<uid>` (mode 0700, owned by the user) where the session's X
//! cookie lives.
//!
//! The handle must outlive the connection that created it: the desktop
//! survives disconnects, so the keeper process holds this, not the worker.

/// Environment PAM built for the session (`XDG_RUNTIME_DIR`, `XDG_SESSION_ID`, ...).
#[derive(Debug)]
pub(crate) struct PamEnv {
    pub(crate) vars: Vec<(String, String)>,
}

impl PamEnv {
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.vars.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub(crate) fn runtime_dir(&self) -> Option<&str> {
        self.get("XDG_RUNTIME_DIR")
    }
}

/// The PAM session lifecycle, behind a trait so the call order can be tested
/// without libpam present.
///
/// The order is the contract: authentication must precede the session, and
/// `pam_setcred` must precede `pam_open_session` — `pam_systemd` needs the
/// established credentials to register the logind session. Every failure path
/// must still reach `pam_end`, or the handle leaks for the life of the process.
pub(crate) trait PamSessionApi {
    /// Authenticate, then open a session. On any failure the handle is ended
    /// before returning, so a partial session never leaks.
    fn open(&mut self, user: &str, password: &str) -> Result<PamEnv, String>;
    /// Close the session and end the handle.
    fn close(&mut self) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct MockPam {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fail_at: Option<&'static str>,
    }

    impl PamSessionApi for MockPam {
        fn open(&mut self, _user: &str, _password: &str) -> Result<PamEnv, String> {
            for step in ["start", "authenticate", "acct_mgmt", "setcred", "open_session"] {
                self.calls.borrow_mut().push(step);
                if self.fail_at == Some(step) {
                    self.calls.borrow_mut().push("end");
                    return Err(format!("{step} failed"));
                }
            }
            Ok(PamEnv {
                vars: vec![
                    ("XDG_RUNTIME_DIR".to_owned(), "/run/user/1000".to_owned()),
                    ("XDG_SESSION_ID".to_owned(), "7".to_owned()),
                ],
            })
        }

        fn close(&mut self) -> Result<(), String> {
            self.calls.borrow_mut().push("close_session");
            self.calls.borrow_mut().push("end");
            Ok(())
        }
    }

    #[test]
    fn a_successful_session_runs_the_calls_in_order() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut pam = MockPam { calls: Rc::clone(&calls), fail_at: None };
        let env = pam.open("alice", "secret").expect("session opens");
        assert_eq!(
            *calls.borrow(),
            vec!["start", "authenticate", "acct_mgmt", "setcred", "open_session"],
            "authentication must precede the session, and setcred must precede open_session"
        );
        assert_eq!(env.runtime_dir(), Some("/run/user/1000"));
        assert_eq!(env.get("XDG_SESSION_ID"), Some("7"));
        assert_eq!(env.get("NOPE"), None);
    }

    #[test]
    fn a_failure_still_unwinds() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut pam = MockPam { calls: Rc::clone(&calls), fail_at: Some("open_session") };
        pam.open("alice", "secret").expect_err("open_session fails");
        assert_eq!(
            calls.borrow().last().copied(),
            Some("end"),
            "pam_end must run on the failure path or the handle leaks"
        );
    }

    #[test]
    fn close_runs_close_session_before_end() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut pam = MockPam { calls: Rc::clone(&calls), fail_at: None };
        pam.open("alice", "secret").expect("opens");
        calls.borrow_mut().clear();
        pam.close().expect("closes");
        assert_eq!(*calls.borrow(), vec!["close_session", "end"]);
    }
}
