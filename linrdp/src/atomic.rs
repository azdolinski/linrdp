//! Write a file all at once, or not at all.
//!
//! A temp sibling with the mode set at creation, then a rename over the
//! target: a reader never sees a half-written file, and one that is meant to
//! be private is never briefly world-readable. Lifted out of `sam` when the
//! configuration file needed the same guarantee at a different mode — the
//! store holds passwords and is 0600, the configuration holds none and is
//! 0644 so that `linrdp config` can show it to a non-root operator.

use std::path::Path;

/// Write `body` to `path` atomically, creating it with `mode`.
///
/// The temp name carries this process's pid so two writers of the same file do
/// not share one temp and race each other's rename. Whichever renames last
/// wins with identical content; nobody trips over a vanished temp.
pub(crate) fn write(path: &Path, body: &str, mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;

    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut file = {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(mode);
            }
            opts.open(&tmp)?
        };
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp); // best-effort: no stray temp on failure
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("linrdp-atomic-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// The configuration is read by `linrdp config` running as whoever is
    /// looking. At 0600 a non-root operator would get an empty read-only view
    /// for a reason that has nothing to do with what they asked.
    #[test]
    fn a_file_is_created_with_exactly_the_mode_asked_for() {
        let dir = temp_dir("mode");
        for mode in [0o600, 0o644] {
            let path = dir.join(format!("f{mode:o}"));
            write(&path, "body\n", mode).expect("written");
            let actual = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(actual, mode, "{}", path.display());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed write must not leave a temp file next to the target, where the
    /// next reader of the directory would find it.
    #[test]
    fn a_failed_write_leaves_no_temp_behind() {
        let dir = temp_dir("fail");
        let target = dir.join("subdir").join("nope");
        write(&target, "body\n", 0o600).expect_err("the parent does not exist");
        assert!(!dir.join("subdir").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
