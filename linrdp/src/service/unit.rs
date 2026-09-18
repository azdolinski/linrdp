//! The systemd unit, and the units it displaces.
//!
//! One unit, and its `ExecStart` carries nothing. That is the whole point of
//! the exercise: a setting that can live in a unit is a setting that lives in
//! two places, and the deployment this replaces had `--auth`, `--bind-addr`,
//! `--display-range` and three `Environment=` lines spread across two unit
//! files whose only difference was a port.

use std::path::{Path, PathBuf};

/// The one unit linrdp installs.
pub(crate) const UNIT_NAME: &str = "linrdp.service";

/// A unit that is about to stop applying, and what it used to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Displaced {
    pub(crate) name: String,
    pub(crate) exec_start: Option<String>,
}

/// The unit file linrdp writes.
pub(crate) fn body(binary: &Path) -> String {
    format!(
        "\
# Installed by `linrdp service install`. Everything linrdp does is configured
# in /etc/linrdp/config.yaml — deliberately nothing here: a setting that can
# live in a unit is a setting that lives in two places.
#
# `linrdp config` edits that file, and `linrdp doctor` reports what this
# machine will do with it.
[Unit]
Description=LinRDP — RDP server for Linux
Documentation=file://{config}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={binary}
# Root is needed to read /etc/shadow, open PAM sessions, and start each
# session's X server as its own user.
User=root
Restart=on-failure
RestartSec=2
# Sessions outlive the connection that created them and are owned by keeper
# processes re-parented to init; stopping this unit must not take the desktops
# with it.
KillMode=process

[Install]
WantedBy=multi-user.target
",
        config = crate::config::CONFIG_PATH,
        binary = binary.display(),
    )
}

/// The `linrdp*.service` files in `unit_dir` that do not start what this
/// build's unit would.
///
/// Read off disk rather than out of `systemctl show`, so it can be tested and
/// so it still answers on a machine where systemd is not running.
pub(crate) fn displaced(unit_dir: &Path, new_exec: &str) -> Vec<Displaced> {
    let Ok(entries) = std::fs::read_dir(unit_dir) else {
        return Vec::new();
    };
    let mut found: Vec<Displaced> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("linrdp") || !name.ends_with(".service") {
                return None;
            }
            let exec_start = std::fs::read_to_string(entry.path()).ok().and_then(|body| {
                body.lines()
                    .find_map(|line| line.trim().strip_prefix("ExecStart=").map(str::to_owned))
            });
            if exec_start.as_deref() == Some(new_exec) {
                return None; // already starts exactly this; nothing stops applying
            }
            Some(Displaced { name, exec_start })
        })
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// What to print about the units being taken out of service.
///
/// The old `ExecStart` goes in it on purpose. Removing these units silently
/// would leave an operator wondering why their second port, their pinned
/// screen size or their display range stopped applying; this is the list of
/// settings they now have to write into the configuration file.
pub(crate) fn describe_displaced(units: &[Displaced]) -> String {
    if units.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "These units are being removed. Anything their command line configured is now a key in \
         the configuration file — check it says what these said:\n",
    );
    for unit in units {
        out.push_str(&format!("  {}\n", unit.name));
        match &unit.exec_start {
            Some(exec) => out.push_str(&format!("      was: {exec}\n")),
            None => out.push_str("      (no ExecStart in the file)\n"),
        }
    }
    out
}

/// The path a unit file lives at.
pub(crate) fn path_in(unit_dir: &Path, name: &str) -> PathBuf {
    unit_dir.join(name)
}

/// Run one `systemctl` verb, reporting the failure rather than ignoring it.
///
/// Missing systemd is not an error: `install` is also run in containers and
/// build images where the files are what matter and nothing is started.
pub(crate) fn systemctl(args: &[&str]) -> Option<bool> {
    let (ok, said) = spoke_to_systemd(args)?;
    if !ok {
        tracing::debug!(args = ?args, stderr = %said, "systemctl reported a failure");
    }
    Some(ok)
}

/// The same call, with what systemd said about it.
///
/// `start` and `restart` are asked for by a person standing at a prompt, and
/// "it did not work" without systemd's own sentence sends them to the journal
/// to find out something systemctl already printed.
pub(crate) fn spoke_to_systemd(args: &[&str]) -> Option<(bool, String)> {
    let output = std::process::Command::new("systemctl").args(args).output().ok()?;
    let said = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Some((output.status.success(), said))
}

/// Run systemctl with this terminal's own stdout, for the one verb whose
/// output *is* the answer. Reformatting `systemctl status` would mean keeping
/// up with a format systemd owns, and losing the colour and the log tail that
/// make it worth reading.
pub(crate) fn systemctl_on_this_terminal(args: &[&str]) -> Option<bool> {
    let status = std::process::Command::new("systemctl").args(args).status().ok()?;
    Some(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("linrdp-unit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// The unit's whole job is to start the binary and get out of the way. A
    /// parameter or an Environment= line here would be a second place to
    /// configure the service, which is the arrangement being removed.
    #[test]
    fn the_unit_has_no_parameters_and_no_environment() {
        let body = body(Path::new("/usr/local/bin/linrdp"));
        let exec: Vec<&str> = body
            .lines()
            .filter_map(|line| line.strip_prefix("ExecStart="))
            .collect();
        assert_eq!(exec, vec!["/usr/local/bin/linrdp"], "no arguments at all");
        assert!(
            !body.lines().any(|line| line.starts_with("Environment=")),
            "no environment either:\n{body}"
        );
    }

    /// Sessions are owned by keepers re-parented to init and outlive the
    /// connection that made them. Without this, `systemctl stop` would take
    /// every desktop on the machine down with the listener.
    #[test]
    fn the_unit_does_not_take_the_desktops_down_with_it() {
        assert!(body(Path::new("/usr/local/bin/linrdp")).contains("KillMode=process"));
    }

    /// Removing a unit without saying what it used to start leaves the
    /// operator to work out for themselves why their second port vanished.
    #[test]
    fn displaced_units_are_reported_with_their_old_exec_start() {
        let dir = temp_dir("displaced");
        std::fs::write(
            dir.join("linrdp.service"),
            "[Service]\nExecStart=/usr/local/bin/linrdp --supervisor --bind-addr 0.0.0.0:3389\n",
        )
        .expect("seed");
        std::fs::write(
            dir.join("linrdp-alt-port.service"),
            "[Service]\nExecStart=/usr/local/bin/linrdp --supervisor --auth greeter --bind-addr 0.0.0.0:3390\n",
        )
        .expect("seed");
        std::fs::write(dir.join("unrelated.service"), "[Service]\nExecStart=/bin/true\n").expect("seed");

        let units = displaced(&dir, "/usr/local/bin/linrdp");
        assert_eq!(units.len(), 2, "only linrdp's own units: {units:?}");

        let text = describe_displaced(&units);
        assert!(text.contains("--auth greeter"), "the old settings are shown: {text}");
        assert!(text.contains("0.0.0.0:3390"), "including the port: {text}");
        assert!(
            !text.contains("unrelated"),
            "somebody else's unit is not touched: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Re-installing over a unit this build already wrote displaces nothing,
    /// so an upgrade does not report a settings change that did not happen.
    #[test]
    fn a_unit_that_already_starts_this_is_not_displaced() {
        let dir = temp_dir("same");
        std::fs::write(dir.join("linrdp.service"), body(Path::new("/usr/local/bin/linrdp"))).expect("seed");
        assert!(displaced(&dir, "/usr/local/bin/linrdp").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
