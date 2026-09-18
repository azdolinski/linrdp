//! What this binary is, for the report that opens with it.
//!
//! A version on its own does not identify a binary: `0.1.0` has been every
//! commit on this branch, and a bug report that names it names nothing. The
//! commit, the build profile and the day it was built are what turn "linrdp
//! is broken" into a thing that can be looked at.
//!
//! The three of them are read at build time by `build.rs`, which asks git and
//! writes down what it is told. A tree with no git to ask — a release
//! tarball, a vendored copy, a docker build that copied the sources in — still
//! builds, and says here only what it knows.

/// The package version, as `linrdp/Cargo.toml` declares it.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The commit, the profile and the day, in one line.
pub(crate) fn build() -> String {
    describe(
        env!("LINRDP_COMMIT"),
        env!("LINRDP_PROFILE"),
        env!("LINRDP_COMMIT_DATE"),
    )
}

/// The parts of a build that are knowable, in one line.
///
/// `unknown` is dropped rather than printed: it is what `build.rs` records
/// when there was nothing to ask, and a line reading "unknown, release,
/// unknown" spends three words saying one.
fn describe(commit: &str, profile: &str, date: &str) -> String {
    [commit, profile, date]
        .into_iter()
        .filter(|part| !part.is_empty() && *part != "unknown")
        .collect::<Vec<_>>()
        .join(", ")
}

/// What `linrdp version` prints.
pub(crate) fn version_line() -> String {
    line(VERSION, &build())
}

/// The name, the version, and the build in brackets after it — the shape
/// every other command-line program answers this question in.
fn line(version: &str, build: &str) -> String {
    if build.is_empty() {
        return format!("linrdp {version}");
    }
    format!("linrdp {version} ({build})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_line_carries_the_build_that_produced_it() {
        assert_eq!(
            line("0.1.0", "1b11b79, release, 2026-09-18"),
            "linrdp 0.1.0 (1b11b79, release, 2026-09-18)"
        );
    }

    /// With no git and no profile there is nothing to put in the brackets,
    /// and empty brackets are worse than none.
    #[test]
    fn a_build_that_knows_nothing_leaves_no_empty_brackets() {
        assert_eq!(line("0.1.0", ""), "linrdp 0.1.0");
    }

    #[test]
    fn a_build_out_of_a_git_checkout_names_the_commit_the_profile_and_the_day() {
        assert_eq!(
            describe("35a421b", "release", "2026-09-18"),
            "35a421b, release, 2026-09-18"
        );
    }

    /// A tarball, a vendored copy, a docker build that copied the sources in:
    /// there is no git to ask, and the report would otherwise read
    /// "unknown, release, unknown" — three words to say one.
    #[test]
    fn a_build_with_no_git_to_ask_says_only_what_it_knows() {
        assert_eq!(describe("unknown", "release", "unknown"), "release");
    }
}
