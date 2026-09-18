//! Where linrdp's own output goes, and how loud it is.
//!
//! Two answers, and they are not the same kind of thing. The configuration's
//! `log` block is what this machine does every day. The override is what one
//! invocation asked for — `linrdp debug` — and it belongs to that command
//! rather than to the machine, so it is never written to the file and never
//! outlives the process that was typed.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::config;

/// Set by `linrdp debug`, read by everything that starts logging — including
/// the workers, which are told about it in their argv.
///
/// A process-wide cell for the same reason the configuration path is one: it
/// is a fact about how this process was invoked, settled before anything runs
/// and true for every part of it afterwards.
static OVERRIDE: OnceLock<String> = OnceLock::new();

/// Log at `filter` instead of what the configuration says, on the terminal.
pub(crate) fn set_override(filter: &str) {
    let _ = OVERRIDE.set(filter.to_owned());
}

/// The filter this invocation was asked for, if it was asked for one.
pub(crate) fn override_filter() -> Option<&'static str> {
    OVERRIDE.get().map(String::as_str)
}

/// Start logging as `log` asks.
///
/// The verbosity was `LINRDP_LOG` and the destination was `--log-file`; both
/// are `log.level` and `log.file` now, so that "why is this machine quiet?"
/// has one answer and it is in the same file as everything else.
/// Whether colour belongs on stderr.
///
/// Under the unit stderr is journald, not a terminal, and the escape codes go
/// into the journal as literal bytes — the same wart the log file carried
/// until it was written with `with_ansi(false)`. Run by hand, stderr is a
/// terminal and the colour is worth having.
pub(crate) fn stderr_is_a_terminal() -> bool {
    use std::io::IsTerminal as _;
    std::io::stderr().is_terminal()
}

pub(crate) fn setup(log: &config::Log) {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, fmt};

    // A malformed filter must not be the reason a server does not start.
    let filter = || {
        EnvFilter::try_new(&log.level).unwrap_or_else(|error| {
            eprintln!("linrdp: log.level `{}` is not a filter ({error}); using info", log.level);
            EnvFilter::new("info,ironrdp=warn")
        })
    };

    // `linrdp debug`: everything the operator asked for, on their terminal,
    // and nothing in the file. Appending a debug run to the machine's log
    // would leave somebody reading it later to work out which of two very
    // different things they are looking at — and a per-frame `trace` would
    // bury the day's records while they did.
    if let Some(filter) = override_filter() {
        let _ = fmt()
            .compact()
            .with_ansi(stderr_is_a_terminal())
            .with_env_filter(
                EnvFilter::try_new(filter).unwrap_or_else(|error| {
                    eprintln!("linrdp: `{filter}` is not a filter ({error}); using debug");
                    EnvFilter::new("debug")
                }),
            )
            .try_init();
        return;
    }

    let path = match &log.file {
        Some(path) => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            path.clone()
        }
        None => PathBuf::new(),
    };

    let file = if path.as_os_str().is_empty() {
        None
    } else {
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => Some(file),
            Err(error) => {
                eprintln!("linrdp: cannot open {} ({error}); logging to the terminal", path.display());
                None
            }
        }
    };

    match file {
        // A file AND the terminal — which, under the unit, is the journal.
        //
        // The file alone left `journalctl -u linrdp` and `systemctl status`
        // empty, which is the first place anyone looks and the worst possible
        // place to find nothing.
        //
        // The two carry different amounts on purpose. The file gets exactly
        // `log.level`; the journal gets the same filter capped at INFO, so
        // `debug` and `trace` — which log per frame — stay out of journald's
        // ring buffer. Duplicating those there would evict *other services'*
        // logs, a cost paid by the whole machine rather than by linrdp. The
        // cap only ever quietens: `log.level: warn` gives warn in both.
        Some(file) => {
            eprintln!("linrdp: logging to {} (and to the journal, at info)", path.display());
            let _ = tracing_subscriber::registry()
                // `log.level` governs everything...
                .with(filter())
                .with(
                    fmt::layer()
                        .compact()
                        // No escape codes in a file somebody will grep.
                        .with_ansi(false)
                        .with_writer(std::sync::Mutex::new(file)),
                )
                // ...and the journal is quietened further, never louder.
                .with(
                    fmt::layer()
                        .compact()
                        .with_ansi(stderr_is_a_terminal())
                        .with_writer(std::io::stderr)
                        .with_filter(LevelFilter::INFO),
                )
                .try_init();
        }
        // No file: the terminal is the whole log, and it gets everything that
        // was asked for — capping here would take `debug` away from the one
        // person who typed it.
        None => {
            let _ = fmt()
                .compact()
                .with_ansi(stderr_is_a_terminal())
                .with_env_filter(filter())
                .try_init();
        }
    }
}
