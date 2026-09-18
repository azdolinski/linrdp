//! Every command linrdp answers to, in one table.
//!
//! The same reason as [`config::meta`](crate::config::meta), learned the same
//! way: the usage text used to be a hand-written string, and the session that
//! added `service start|stop|restart|status` had to edit it by hand, write a
//! second list for the refusal message, and then a test to keep the two in
//! step. Three copies of one fact in two files. This is the one copy: the
//! tree, the group listing, the usage line and the "unknown command" refusal
//! are all rendered from here.
//!
//! Internal entry points are deliberately absent. `--keeper`,
//! `--capture-credential` and `--serve-fd` are how linrdp talks to itself; a
//! tree that lists them is an invitation to run them by hand.

/// What `linrdp` on its own does. Not in the table: it is the root the table
/// hangs from, and giving it an empty path would make every depth calculation
/// below special-case it.
pub(crate) const ROOT_SUMMARY: &str = "Serve every listener in the configuration";

pub(crate) struct Command {
    /// Dotted path. `service.start` is `linrdp service start`.
    pub(crate) path: &'static str,
    /// What follows the name in a usage line, if anything.
    pub(crate) args: Option<&'static str>,
    /// One line, in the imperative. It is what the tree prints beside the
    /// name, so it has to read at a glance and fit on a terminal.
    pub(crate) summary: &'static str,
}

/// In the order they are printed: the plain commands, then the groups with
/// their children under them. A group in the middle would push a `│` down the
/// left of everything after it for no reason.
pub(crate) const COMMANDS: &[Command] = &[
    Command {
        path: "doctor",
        args: Some("[<account>]"),
        summary: "Report what this machine, or one account, can do",
    },
    Command {
        path: "config",
        args: Some("[--print]"),
        summary: "Browse and edit the configuration",
    },
    Command {
        path: "debug",
        args: Some("[<level>]"),
        summary: "Run in the foreground with everything on screen (default: debug)",
    },
    Command {
        path: "tree",
        args: None,
        summary: "Show this command tree",
    },
    Command {
        path: "service",
        args: None,
        summary: "Install, remove and run the systemd unit",
    },
    Command {
        path: "service.install",
        args: None,
        summary: "Install the unit, the configuration and the credential capture",
    },
    Command {
        path: "service.uninstall",
        args: None,
        summary: "Remove what `service install` put there",
    },
    Command {
        path: "service.start",
        args: None,
        summary: "Start the service",
    },
    Command {
        path: "service.stop",
        args: None,
        summary: "Stop the service — running desktops survive it",
    },
    Command {
        path: "service.restart",
        args: None,
        summary: "Restart it, picking up a changed configuration",
    },
    Command {
        path: "service.status",
        args: None,
        summary: "What systemd says, plus the listeners in effect",
    },
    Command {
        path: "daemon",
        args: None,
        summary: "Run in the background on a machine without systemd",
    },
    Command {
        path: "daemon.start",
        args: None,
        summary: "Start the supervisor in the background",
    },
    Command {
        path: "daemon.stop",
        args: None,
        summary: "Stop it — sessions already open keep running",
    },
    Command {
        path: "daemon.status",
        args: None,
        summary: "Whether one is running here, and the listeners in effect",
    },
];

/// The table entry for a dotted path.
pub(crate) fn command(path: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.path == path)
}

/// The direct children of `path`; the top level when it is empty.
pub(crate) fn children(path: &str) -> Vec<&'static Command> {
    COMMANDS
        .iter()
        .filter(|c| parent_of(c.path) == path)
        .collect()
}

/// The last segment — what the operator actually types at this level.
pub(crate) fn leaf_name(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

/// Everything before the last segment, or "" at the top level.
fn parent_of(path: &str) -> &str {
    path.rsplit_once('.').map_or("", |(parent, _)| parent)
}

/// Whether `name` is a top-level command, for the dispatch in `main` — which
/// is what makes this table load-bearing rather than documentation. A command
/// missing from it is refused, not silently served.
pub(crate) fn is_a_top_level_command(name: &str) -> bool {
    children("").iter().any(|c| c.path == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command with no summary is a command nobody finds. This table is the
    /// only place the CLI is described, so an entry without one would print a
    /// blank line in the tree where the explanation belongs.
    #[test]
    fn every_command_is_summarised_in_one_imperative_line() {
        for c in COMMANDS {
            assert!(!c.summary.trim().is_empty(), "{} has no summary", c.path);
            assert!(!c.summary.ends_with('.'), "{}: the tree prints no full stops", c.path);
            assert!(!c.summary.contains('\n'), "{}: one line, it goes beside the name", c.path);
            let first = c.summary.chars().next().unwrap_or(' ');
            assert!(first.is_uppercase(), "{}: summaries start with a capital", c.path);
        }
    }

    /// A child whose parent is missing would be unreachable in the tree: the
    /// renderer walks down from the root, so it would simply never be printed
    /// — documented, and invisible.
    #[test]
    fn every_child_has_a_parent_in_the_table() {
        for c in COMMANDS {
            let parent = parent_of(c.path);
            if !parent.is_empty() {
                assert!(command(parent).is_some(), "{} has no parent entry", c.path);
            }
        }
    }

    #[test]
    fn no_path_is_listed_twice() {
        let mut seen: Vec<&str> = COMMANDS.iter().map(|c| c.path).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "a path appears twice in COMMANDS");
    }

    /// The table drives `service`'s dispatch as well as its help, so a verb
    /// that works but is not described — or is described but does not work —
    /// is a test failure rather than something an operator discovers.
    #[test]
    fn the_service_verbs_are_exactly_the_ones_service_accepts() {
        let mut described: Vec<&str> = children("service").iter().map(|c| leaf_name(c.path)).collect();
        let mut accepted: Vec<&str> = crate::service::VERBS.to_vec();
        described.sort_unstable();
        accepted.sort_unstable();
        assert_eq!(described, accepted, "the tree and `service` disagree about the verbs");
    }

    #[test]
    fn the_daemon_verbs_are_exactly_the_ones_daemon_accepts() {
        let mut described: Vec<&str> = children("daemon").iter().map(|c| leaf_name(c.path)).collect();
        let mut accepted: Vec<&str> = crate::daemon::VERBS.to_vec();
        described.sort_unstable();
        accepted.sort_unstable();
        assert_eq!(described, accepted, "the tree and `daemon` disagree about the verbs");
    }
}
