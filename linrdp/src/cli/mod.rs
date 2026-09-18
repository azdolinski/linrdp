//! `linrdp tree`, `linrdp --help`, and the group listing a bare `linrdp
//! service` prints.
//!
//! All three are the same drawing of [`meta::COMMANDS`] at a different root.
//! The prose below it is hand-written, because "what is this thing and how
//! does authentication work" is not a table.

pub(crate) mod meta;

use core::fmt::Write as _;

/// One printed line: the branch art, the name, and what it does.
struct Row {
    /// Box-drawing lead-in, already including every ancestor's continuation.
    stem: String,
    /// `install`, or `doctor [<account>]`.
    label: String,
    summary: String,
}

/// The whole tree, from `linrdp` down.
pub(crate) fn tree() -> String {
    draw("linrdp", "", meta::ROOT_SUMMARY)
}

/// One group's own listing — what `linrdp service` prints when it is given no
/// verb, and what a refused verb is shown alongside.
pub(crate) fn subtree(path: &str) -> String {
    let entry = meta::command(path);
    let mut label = format!("linrdp {}", path.replace('.', " "));
    if let Some(args) = entry.and_then(|c| c.args) {
        label.push(' ');
        label.push_str(args);
    }
    draw(&label, path, entry.map_or("", |c| c.summary))
}

/// `linrdp --help`: the tree, then the parts of the story a table cannot tell.
pub(crate) fn help() -> String {
    format!("{}\n{PROSE}", tree())
}

/// Let a closed pipe end this process instead of panicking in it.
///
/// Rust starts every program with SIGPIPE ignored, so a write to a pipe whose
/// reader has gone gives EPIPE — which `println!` turns into a panic and a
/// backtrace. `linrdp tree | head` ended in one.
///
/// Restoring the default disposition is the usual fix, and it is applied only
/// to the commands that print something and exit. Never to the server: a
/// worker writes to sockets, and on Linux a write to a connection the client
/// has closed raises SIGPIPE too. Killed by signal 13, a worker would lose a
/// session to a disconnection that its error path already handles.
pub(crate) fn die_quietly_on_a_closed_pipe() {
    // SAFETY: setting a signal disposition to SIG_DFL is async-signal-safe and
    // takes no memory.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

fn draw(root_label: &str, root_path: &str, root_summary: &str) -> String {
    let mut rows = vec![Row {
        stem: String::new(),
        label: root_label.to_owned(),
        summary: root_summary.to_owned(),
    }];
    collect(root_path, "", &mut rows);

    // Aligned on the widest label, so the summaries form a column. Computed
    // on the plain text: the colour below adds bytes and no width, and using
    // the coloured length here would ragged the column on a terminal and
    // nowhere else.
    let widest = rows
        .iter()
        .map(|row| row.stem.chars().count() + row.label.chars().count())
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for row in &rows {
        let width = row.stem.chars().count() + row.label.chars().count();
        let pad = " ".repeat(widest.saturating_sub(width) + 3);
        let _ = writeln!(out, "{}{}{pad}{}", row.stem, name(&row.label), row.summary);
    }
    out
}

/// Append `parent`'s children, and theirs, depth first.
fn collect(parent: &str, continuation: &str, rows: &mut Vec<Row>) {
    let children = meta::children(parent);
    for (n, child) in children.iter().enumerate() {
        let last = n + 1 == children.len();
        let label = match child.args {
            Some(args) => format!("{} {args}", meta::leaf_name(child.path)),
            None => meta::leaf_name(child.path).to_owned(),
        };
        rows.push(Row {
            stem: format!("{continuation}{} ", if last { "└──" } else { "├──" }),
            label,
            summary: child.summary.to_owned(),
        });
        // A child of a last child needs blank space where the parent's branch
        // would have continued; anything else draws a line to nowhere.
        collect(
            child.path,
            &format!("{continuation}{}", if last { "    " } else { "│   " }),
            rows,
        );
    }
}

/// Colour the command name, and only when somebody is looking at a terminal.
/// `console` decides that once, from stdout and `NO_COLOR` — the same rule the
/// log follows, for the same reason: `linrdp tree | less` must be readable.
fn name(label: &str) -> String {
    console::style(label).cyan().to_string()
}

const PROSE: &str = "\
Serves a real Linux desktop over RDP.

CONFIGURATION

Everything is in /etc/linrdp/config.yaml, and that file describes itself: every
key carries its meaning and every value its consequences, so `linrdp config` and
`less /etc/linrdp/config.yaml` answer the same questions. The systemd unit takes
no arguments and sets no environment; there is nowhere else for a setting to
hide.

  listeners       the addresses served, and how each one authenticates
                  (`auth: both | nla | system | greeter`)
  session         display range, pinned size, locking, the shared screen
  features        USB redirection, UDP transport, AVC444v2, Wayland capture
  tls             the certificate to serve, or none to keep a self-signed one
  log             level and destination

AUTHENTICATION

Whatever the listener offers, the password checked is the account's system
password. There is no linrdp password to set and no command that sets one.
CredSSP/NTLM does require the server to know the secret (MS-NLMP: it computes
the expected response from it), so linrdp learns each password from the
system's own authentication, the way Samba's pam_smbpass did — see
deploy/pam-capture, which `linrdp service install` wires up for you. Authenticate
once on this machine (su -, ssh, console) and RDP works from then on.

`linrdp doctor` reports whether that capture is wired and whose password it has
seen. `sudo linrdp doctor <account>` answers the narrower question the machine
report cannot: will this account work here?

OPTIONS

  --config <PATH>    read a configuration file other than /etc/linrdp/config.yaml
  --listener <ADDR>  serve just this one listener in this process, without
                     forking. Only for `session.console.enabled`: one process
                     cannot route per-user sessions. Use `linrdp debug` to
                     work on linrdp — it is the supervisor, just louder
  --serve-fd <N>     internal: serve the connection the supervisor handed over
";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command reaches the page. The tree is drawn by walking down from
    /// the root, so an entry the walk never reaches is documented in the table
    /// and invisible to the operator — which is worse than not writing it.
    #[test]
    fn every_command_in_the_table_appears_in_the_tree() {
        let drawn = tree();
        for c in meta::COMMANDS {
            assert!(
                drawn.contains(meta::leaf_name(c.path)),
                "{} is in the table but not in the tree:\n{drawn}",
                c.path
            );
            assert!(drawn.contains(c.summary), "{}'s summary is not printed", c.path);
        }
    }

    /// A child of the last group needs blank space under its parent, not a
    /// branch line: `│` under a `└──` draws a line to a sibling that is not
    /// there.
    #[test]
    fn the_last_group_does_not_draw_a_line_below_itself() {
        let drawn = tree();
        let lines: Vec<&str> = drawn.lines().collect();
        let last = lines
            .iter()
            .position(|line| line.starts_with("└──"))
            .expect("something is the last child of the root");
        assert!(last + 1 < lines.len(), "the last top-level entry is a group with children");
        for line in &lines[last + 1..] {
            assert!(
                !line.starts_with('│'),
                "a branch continues past the last group: {line}"
            );
        }
    }

    /// The help is the tree plus the prose, not a second description of the
    /// commands that can disagree with the first.
    #[test]
    fn the_help_carries_the_tree_rather_than_its_own_command_list() {
        let help = help();
        assert!(help.contains(&tree()), "the help does not contain the tree");
        assert!(help.contains("AUTHENTICATION"), "the prose is gone");
        assert!(
            !PROSE.contains("linrdp service install  "),
            "the prose has grown a command list of its own"
        );
    }

    /// A group prints its own subtree, rooted at itself — `linrdp service`
    /// showing the whole of linrdp would bury the six lines it was asked for.
    #[test]
    fn a_group_prints_only_what_is_under_it() {
        let drawn = subtree("service");
        assert!(drawn.contains("linrdp service"), "rooted at the group: {drawn}");
        assert!(drawn.contains("install"), "with its children: {drawn}");
        assert!(!drawn.contains("doctor"), "and nothing else: {drawn}");
    }
}
