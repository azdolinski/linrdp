//! Race-free display-number allocation.
//!
//! `flock` on a file in the root-only state directory, held for the life of
//! the session. `/tmp/.X11-unix/X<n>` is deliberately NOT used: it is
//! world-writable, so an unprivileged user could pre-create entries and steer
//! which number the next session gets. The X socket still appears there
//! because X11 mandates it — what protects a session is the cookie, not the
//! path.

use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::ops::RangeInclusive;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// An exclusive claim on one X display number. The claim lasts as long as
/// this value: `flock` is released by the kernel when the fd closes, so a
/// crashed keeper cannot leak a number.
#[derive(Debug)]
pub(crate) struct DisplayLease {
    pub(crate) number: u16,
    base: PathBuf,
    /// Held purely for its `flock`; closing it releases the claim.
    _lock: File,
}

impl DisplayLease {
    /// `":42"` — the value for `$DISPLAY`.
    pub(crate) fn display_name(&self) -> String {
        format!(":{}", self.number)
    }

    /// Record which user this display belongs to, so a later worker can find
    /// an existing session for that user.
    pub(crate) fn record_owner(&self, user: &str) -> anyhow::Result<()> {
        let path = owner_path(&self.base, self.number);
        fs::write(&path, user).with_context(|| format!("write {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
        Ok(())
    }
}

impl Drop for DisplayLease {
    fn drop(&mut self) {
        // Best effort: the flock goes with the fd regardless.
        let _ = fs::remove_file(owner_path(&self.base, self.number));
    }
}

fn lock_path(base: &Path, number: u16) -> PathBuf {
    base.join(format!("display-{number}.lock"))
}

fn owner_path(base: &Path, number: u16) -> PathBuf {
    base.join(format!("display-{number}.owner"))
}

/// The user a display currently belongs to, if any.
pub(crate) fn owner_of(base: &Path, number: u16) -> Option<String> {
    let mut buf = String::new();
    File::open(owner_path(base, number)).ok()?.read_to_string(&mut buf).ok()?;
    let user = buf.trim().to_owned();
    (!user.is_empty()).then_some(user)
}

/// Claim the lowest free display number in `range`.
pub(crate) fn allocate(base: &Path, range: RangeInclusive<u16>) -> anyhow::Result<DisplayLease> {
    for number in range.clone() {
        let path = lock_path(base, number);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;

        // SAFETY: a valid open fd; LOCK_NB returns EWOULDBLOCK rather than
        // blocking when another holder has the lock.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        if locked {
            return Ok(DisplayLease {
                number,
                base: base.to_path_buf(),
                _lock: file,
            });
        }
    }
    anyhow::bail!("no free display in range {}-{}", range.start(), range.end())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("linrdp-alloc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        crate::session::runtime_dir::ensure_state_dir(&base).expect("state dir");
        base
    }

    #[test]
    fn two_leases_never_share_a_number() {
        let base = temp_base("distinct");
        let a = allocate(&base, 10..=12).expect("first lease");
        let b = allocate(&base, 10..=12).expect("second lease");
        assert_ne!(a.number, b.number, "a held lock must be skipped");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_released_number_is_reused() {
        let base = temp_base("reuse");
        let first = allocate(&base, 10..=10).expect("lease");
        let number = first.number;
        drop(first);
        let again = allocate(&base, 10..=10).expect("the number is free again");
        assert_eq!(again.number, number);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_exhausted_range_is_an_error_not_a_panic() {
        let base = temp_base("exhausted");
        let _held = allocate(&base, 10..=10).expect("lease");
        let err = allocate(&base, 10..=10).expect_err("range is full");
        assert!(err.to_string().contains("no free display"), "the error must say what ran out, got: {err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_owner_is_recorded_and_readable() {
        let base = temp_base("owner");
        let lease = allocate(&base, 10..=12).expect("lease");
        lease.record_owner("alice").expect("record");
        assert_eq!(owner_of(&base, lease.number).as_deref(), Some("alice"));
        assert_eq!(owner_of(&base, 99), None, "an unused display has no owner");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn display_name_is_the_x_form() {
        let base = temp_base("name");
        let lease = allocate(&base, 42..=42).expect("lease");
        assert_eq!(lease.display_name(), ":42");
        let _ = std::fs::remove_dir_all(&base);
    }
}
