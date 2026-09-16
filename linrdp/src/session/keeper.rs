//! Building the desktop's command line and environment.
//!
//! The keeper process owns a session: the PAM handle, the display lock and
//! the desktop processes. It outlives every connection, which is what makes
//! a reconnect land on the same desktop.

use super::privilege::UserIds;
use super::registry::SessionRecord;

#[derive(Debug)]
pub(crate) struct DesktopCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

/// The X server for one session.
///
/// `-auth` and the absence of `-ac` are the whole security boundary of the
/// session: without them any local user can read the screen and type into it.
pub(crate) fn xvfb_command(display: u16, xauthority: &str, size: (u16, u16)) -> DesktopCommand {
    let (w, h) = size;
    DesktopCommand {
        program: "Xvfb".to_owned(),
        args: vec![
            format!(":{display}"),
            "-screen".to_owned(),
            "0".to_owned(),
            format!("{w}x{h}x24"),
            "-auth".to_owned(),
            xauthority.to_owned(),
            "-nolisten".to_owned(),
            "tcp".to_owned(),
            "+extension".to_owned(),
            "DAMAGE".to_owned(),
            "+extension".to_owned(),
            "MIT-SHM".to_owned(),
            "+extension".to_owned(),
            "RANDR".to_owned(),
            "+extension".to_owned(),
            "XFIXES".to_owned(),
            "+extension".to_owned(),
            "XTEST".to_owned(),
        ],
    }
}

/// Environment for the desktop and for the worker that serves it.
pub(crate) fn session_env(rec: &SessionRecord, user: &UserIds) -> Vec<(String, String)> {
    vec![
        ("DISPLAY".to_owned(), format!(":{}", rec.display)),
        ("XAUTHORITY".to_owned(), rec.xauthority.clone()),
        ("XDG_RUNTIME_DIR".to_owned(), rec.runtime_dir.clone()),
        ("HOME".to_owned(), user.home.clone()),
        ("USER".to_owned(), user.name.clone()),
        ("LOGNAME".to_owned(), user.name.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::privilege::UserIds;
    use crate::session::registry::SessionRecord;

    #[test]
    fn xvfb_is_never_started_with_access_control_off() {
        let cmd = xvfb_command(42, "/run/user/1000/linrdp/Xauthority", (2880, 1800));
        assert_eq!(cmd.program, "Xvfb");
        assert!(
            !cmd.args.iter().any(|a| a == "-ac"),
            "-ac disables X access control: any local user could screenshot the \
             session and inject input. Never emit it. Got {:?}",
            cmd.args
        );
        assert!(cmd.args.iter().any(|a| a == ":42"), "display must be passed");
        let auth = cmd.args.windows(2).find(|w| w[0] == "-auth").expect("-auth is mandatory");
        assert_eq!(auth[1], "/run/user/1000/linrdp/Xauthority");
        assert!(
            cmd.args.iter().any(|a| a.starts_with("2880x1800x")),
            "screen geometry must be applied, got {:?}",
            cmd.args
        );
    }

    #[test]
    fn the_session_env_points_at_the_users_own_runtime_dir() {
        let rec = SessionRecord {
            user: "alice".to_owned(),
            display: 42,
            runtime_dir: "/run/user/1001".to_owned(),
            xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
        };
        let user = UserIds { uid: 1001, gid: 1001, name: "alice".to_owned(), home: "/home/alice".to_owned() };

        let env = session_env(&rec, &user);
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

        assert_eq!(get("DISPLAY"), Some(":42"));
        assert_eq!(get("XAUTHORITY"), Some("/run/user/1001/linrdp/Xauthority"));
        assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1001"));
        assert_eq!(get("HOME"), Some("/home/alice"));
        assert_eq!(get("USER"), Some("alice"));
        assert!(
            get("XAUTHORITY").is_some_and(|p| p.starts_with("/run/user/")),
            "the cookie must never be pointed at /tmp or a home directory"
        );
    }
}
