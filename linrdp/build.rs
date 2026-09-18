//! Record what this binary is being built from, for `linrdp doctor`.
//!
//! Three values, asked of git at build time: the commit, whether the tree had
//! uncommitted changes in it, and the day that commit was made. The build
//! profile comes from cargo. [`build_info`](src/build_info.rs) turns them into
//! the line the report opens with.
//!
//! Nothing here can fail a build. A source tree with no git in it still
//! compiles and says `unknown`, because a release tarball is a normal way to
//! receive this and refusing to build out of one would be absurd.

#![allow(clippy::print_stdout)]

use std::path::Path;
use std::process::Command;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());

    // What makes the recorded values go stale, and nothing else. Naming any
    // path at all turns off cargo's own default — "re-run when a file in the
    // package changes" — so the sources are named here too: an edit is what
    // makes a tree dirty, and a `-dirty` that only appeared after a commit
    // would be worse than none.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    if let Some(git_dir) = git(&dir, &["rev-parse", "--absolute-git-dir"]) {
        // HEAD moves on checkout, the ref it points at moves on commit, and
        // the index moves on `git add` — the three ways the answer changes
        // without a source file being touched.
        for file in ["HEAD", "index"] {
            let path = Path::new(&git_dir).join(file);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    let commit = match git(&dir, &["rev-parse", "--short=7", "HEAD"]) {
        // Tracked files only: an untracked scratch file in the tree is not a
        // change to what was built, and calling every working copy dirty
        // would make the mark mean nothing.
        Some(commit) => match git(&dir, &["status", "--porcelain", "--untracked-files=no"]) {
            Some(changes) if !changes.is_empty() => format!("{commit}-dirty"),
            _ => commit,
        },
        None => "unknown".to_owned(),
    };
    let date = git(&dir, &["log", "-1", "--format=%cs"]).unwrap_or_else(|| "unknown".to_owned());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());

    println!("cargo:rustc-env=LINRDP_COMMIT={commit}");
    println!("cargo:rustc-env=LINRDP_COMMIT_DATE={date}");
    println!("cargo:rustc-env=LINRDP_PROFILE={profile}");
}

/// What git says, or nothing at all — no git, no repository, and a git that
/// refuses to answer are the same answer here.
fn git(dir: &str, args: &[&str]) -> Option<String> {
    let output = Command::new("git").arg("-C").arg(dir).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
