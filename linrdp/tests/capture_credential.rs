//! The credential-capture helper, run the way `pam_exec` runs it.
//!
//! This helper is wired into the *system* authentication stack, so it executes
//! on every `su`, `ssh`, console login and `sudo` on the machine. That gives it
//! two properties worth a test of their own, and they pull in opposite
//! directions:
//!
//! * it must **record** what it did, because "NLA silently never works" is
//!   otherwise indistinguishable from "the helper was never called"; and
//! * it must **never** write to stderr or stdout, because anything it prints
//!   lands on the terminal of every login on the machine.
//!
//! The obvious way to satisfy the first — hand the helper the server's normal
//! logging setup — breaks the second, which is why the second is tested here
//! rather than left to review.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The real binary, exactly as the PAM line names it.
const BINARY: &str = env!("CARGO_BIN_EXE_linrdp");

/// The account the fake `pam_exec` claims to have authenticated.
const ACCOUNT: &str = "capture-helper-test-account";

struct Outcome {
    stdout: String,
    stderr: String,
}

/// Run the helper against `config_path` with `pam_exec`'s environment.
///
/// stdin is closed rather than fed a password: an empty token is the one path
/// that reaches a log line without consulting PAM or `/etc/shadow`, so the
/// test says something about logging and nothing about this machine's accounts.
fn run_helper(config_path: &Path) -> Outcome {
    let output = Command::new(BINARY)
        .arg("--capture-credential")
        .arg("--config")
        .arg(config_path)
        .env("PAM_USER", ACCOUNT)
        .env("PAM_SERVICE", "su")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run the capture helper");

    // Part of the same contract: a helper that exits non-zero is a helper that
    // can lock someone out of their own machine.
    assert!(
        output.status.success(),
        "the helper must always exit zero, got {:?}",
        output.status
    );

    Outcome {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linrdp-capture-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn write_config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("config.yaml");
    std::fs::write(&path, body).expect("write config");
    path
}

/// A configuration that parses, with `log` filled in by the caller.
fn config_with_log(log: &str) -> String {
    format!("listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\nlog:\n{log}")
}

#[test]
fn the_helper_records_what_it_did_in_the_configured_log_file() {
    let dir = scratch("records");
    let log_file = dir.join("linrdp.log");
    let config = write_config(
        &dir,
        &config_with_log(&format!("  level: debug\n  file: {}\n", log_file.display())),
    );

    run_helper(&config);

    let recorded = std::fs::read_to_string(&log_file).unwrap_or_default();
    assert!(
        recorded.contains(ACCOUNT),
        "the helper ran but left no record naming the account it ran for; \
         {} holds {recorded:?}",
        log_file.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_helper_never_writes_to_a_terminal() {
    let dir = scratch("silent");

    // Every configuration below is one the server proper would comment on, out
    // loud, on stderr. On this path there is no terminal to comment to.
    let cases: Vec<(&str, PathBuf)> = vec![
        (
            "a log file it can open",
            write_config(
                &scratch("silent-ok"),
                &config_with_log(&format!("  level: debug\n  file: {}\n", dir.join("ok.log").display())),
            ),
        ),
        (
            "a log level that is not a filter",
            write_config(
                &scratch("silent-level"),
                &config_with_log("  level: \"not a filter!\"\n  file: /dev/null\n"),
            ),
        ),
        (
            "a log file it cannot open",
            write_config(
                &scratch("silent-unopenable"),
                &config_with_log("  level: debug\n  file: /proc/linrdp-no-such-dir/linrdp.log\n"),
            ),
        ),
        (
            "no log file at all",
            write_config(
                &scratch("silent-nofile"),
                &config_with_log("  level: debug\n  file: null\n"),
            ),
        ),
        (
            "a configuration that does not parse",
            write_config(&scratch("silent-broken"), "listeners: [ this is not: valid\n"),
        ),
        (
            "a configuration file that is not there",
            scratch("silent-missing").join("absent.yaml"),
        ),
    ];

    for (description, config) in cases {
        let outcome = run_helper(&config);
        assert!(
            outcome.stderr.is_empty(),
            "with {description}, the helper wrote to stderr: {:?}",
            outcome.stderr
        );
        assert!(
            outcome.stdout.is_empty(),
            "with {description}, the helper wrote to stdout: {:?}",
            outcome.stdout
        );
        if let Some(parent) = config.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
