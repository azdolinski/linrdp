//! The supervisor's runtime state directory.
//!
//! `/run` rather than `/tmp`: this is root's record of which user owns which
//! display, so no user may read or edit it. A home directory would be worse
//! than `/tmp` — a user could tamper with their own entry. `/run` is tmpfs,
//! cleared on boot, and the display locks in it are meaningless once the
//! processes holding them are gone.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::Context as _;

/// Where the supervisor keeps display locks and session records.
#[expect(dead_code, reason = "consumed by the display allocator in the next task")]
pub(crate) const STATE_DIR: &str = "/run/linrdp";

/// Create `base` if absent and enforce mode 0700 whether or not it existed.
pub(crate) fn ensure_state_dir(base: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(base).with_context(|| format!("create {}", base.display()))?;
    // Enforce rather than assume: the directory may have been created by an
    // older build, by a packaging script, or by hand.
    fs::set_permissions(base, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", base.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn state_dir_is_created_private_to_root() {
        let base = std::env::temp_dir().join(format!("linrdp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        ensure_state_dir(&base).expect("creates the directory");

        let mode = std::fs::metadata(&base).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state must not be readable by other users");

        ensure_state_dir(&base).expect("second call is a no-op");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_loose_mode_is_tightened() {
        let base = std::env::temp_dir().join(format!("linrdp-loose-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("pre-create");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).expect("loosen");

        ensure_state_dir(&base).expect("tightens");

        let mode = std::fs::metadata(&base).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "an inherited loose mode must be repaired, not trusted");

        let _ = std::fs::remove_dir_all(&base);
    }
}
