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

    /// Give this claim to a child process without ever releasing it.
    ///
    /// `flock` belongs to the *open file description*, not to the process, so
    /// a descriptor inherited across `fork`/`exec` keeps the very same lock
    /// alive: the number stays claimed continuously from the moment the
    /// worker picked it to the moment the keeper's last copy closes.
    ///
    /// That continuity is the point. Probing for a free number and then
    /// dropping the claim so the keeper could take its own left a window in
    /// which two logins picked the same display; the loser's keeper then
    /// failed to lock it, while the loser's worker went on to read the
    /// winner's session record and bind to somebody else's desktop.
    ///
    /// Returns the raw descriptor and forgets the lease, so nothing here
    /// closes the file or removes the owner file the keeper is about to write.
    pub(crate) fn into_handoff_fd(self) -> std::os::fd::RawFd {
        let fd = self._lock.as_raw_fd();
        core::mem::forget(self);
        fd
    }

    /// Adopt a claim handed over on an inherited descriptor.
    ///
    /// Two things are checked, and the second one is the point.
    ///
    /// The descriptor must refer to **this display's** lock file — compared by
    /// device and inode against the path, not by taking the caller's word.
    /// `flock` alone cannot establish that: it succeeds on any lockable file,
    /// including one nobody was holding, so a probe that only locked would
    /// have accepted a descriptor pointing anywhere and left the real number
    /// free for somebody else.
    ///
    /// It must also already be locked. That cannot be tested from the process
    /// that holds it — `flock` on a descriptor whose open file description
    /// already has the lock succeeds and changes nothing, which is
    /// indistinguishable from taking it fresh — so what is checked instead is
    /// that *nobody else* can take it: a second, independent open of the same
    /// path must fail `LOCK_EX | LOCK_NB`. That is exactly the property the
    /// claim is supposed to have.
    ///
    /// Close-on-exec is restored immediately. The worker cleared it to hand the
    /// descriptor over, and the keeper then `fork`/`exec`s the X server and the
    /// desktop **as the session user**: without this, that desktop inherited an
    /// open descriptor for a root-owned lock file and could `flock(fd,
    /// LOCK_UN)` its own session's claim out from under a keeper that was still
    /// running, after which the allocator would hand the same display number to
    /// somebody else.
    pub(crate) fn adopt(base: &Path, number: u16, fd: std::os::fd::RawFd) -> anyhow::Result<Self> {
        use std::os::fd::FromRawFd as _;

        anyhow::ensure!(fd >= 0, "display lock descriptor {fd} is not a descriptor");
        // SAFETY: the parent dup2'd the lock file onto this descriptor
        // immediately before exec and nothing else in this process uses it.
        let file = unsafe { File::from_raw_fd(fd) };

        let path = lock_path(base, number);
        let expected = fs::metadata(&path)
            .with_context(|| format!("stat {}", path.display()))?;
        let got = file.metadata().context("stat the handed-over descriptor")?;
        use std::os::unix::fs::MetadataExt as _;
        anyhow::ensure!(
            got.dev() == expected.dev() && got.ino() == expected.ino(),
            "the descriptor handed over for display :{number} is not {}",
            path.display()
        );

        // Someone must already hold it, and from here that someone can only be
        // the open file description this descriptor names.
        let probe = OpenOptions::new().read(true).write(true).open(&path)
            .with_context(|| format!("open {} to verify the claim", path.display()))?;
        // SAFETY: a valid open fd; LOCK_NB returns EWOULDBLOCK rather than blocking.
        let free = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        drop(probe);
        anyhow::ensure!(
            !free,
            "display :{number} is not claimed by anyone — the descriptor handed over holds no lock"
        );

        // SAFETY: a descriptor this function owns.
        let flagged = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        anyhow::ensure!(
            flagged >= 0,
            "cannot close-on-exec the claim for display :{number}: {}",
            std::io::Error::last_os_error()
        );

        Ok(Self {
            number,
            base: base.to_path_buf(),
            _lock: file,
        })
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

    /// The claim must never lapse between the worker picking a number and the
    /// keeper owning it — that window is what let two logins land on one
    /// display.
    #[test]
    fn a_handed_over_claim_is_still_held_by_the_new_owner() {
        let base = temp_base("handoff");
        let lease = allocate(&base, 30..=30).expect("lease");
        let number = lease.number;
        let fd = lease.into_handoff_fd();

        assert!(
            allocate(&base, 30..=30).is_err(),
            "forgetting the lease must not release the lock the descriptor holds"
        );

        let adopted = DisplayLease::adopt(&base, number, fd).expect("the descriptor still holds the lock");
        assert_eq!(adopted.number, number);
        assert!(allocate(&base, 30..=30).is_err(), "the adopted lease still holds it");

        drop(adopted);
        allocate(&base, 30..=30).expect("closing the last copy frees the number");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A keeper must not serve a display on the word of a descriptor alone.
    ///
    /// `flock` succeeds on any lockable file, so a probe that only locked
    /// would accept a descriptor pointing anywhere — and leave the real
    /// number free for somebody else to claim.
    #[test]
    fn adopting_a_descriptor_that_is_not_this_displays_lock_is_refused() {
        let base = temp_base("adoptbad");
        assert!(
            DisplayLease::adopt(&base, 31, -1).is_err(),
            "a closed descriptor is not a claim"
        );

        // A real descriptor, lockable, on the wrong file.
        let plain = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(base.join("not-a-lock"))
            .expect("open");
        let stray = plain.as_raw_fd();
        core::mem::forget(plain);
        let err = DisplayLease::adopt(&base, 31, stray).expect_err("wrong file");
        assert!(
            format!("{err:#}").contains("display-31.lock"),
            "the refusal has to say which file it expected, got: {err:#}"
        );

        // The right file, but nobody is holding it: there was no handoff.
        let unheld = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path(&base, 32))
            .expect("open");
        let unheld_fd = unheld.as_raw_fd();
        core::mem::forget(unheld);
        let err = DisplayLease::adopt(&base, 32, unheld_fd).expect_err("no claim");
        assert!(
            format!("{err:#}").contains("not claimed"),
            "got: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The claim must not survive into the session's own processes.
    ///
    /// Regression, and a real one: the worker clears `FD_CLOEXEC` to hand the
    /// descriptor over, and the keeper then `fork`/`exec`s the X server and
    /// the desktop **as the session user**. With the flag left clear, that
    /// desktop inherited an open descriptor for a root-owned lock file — and
    /// the same open file description — so it could `flock(fd, LOCK_UN)` its
    /// own session's claim away while the keeper was still running, after
    /// which the allocator handed the number to somebody else.
    ///
    /// Checked through a real `exec`, because that is the only place the flag
    /// has any effect: moving the lease around inside one process would pass
    /// either way.
    #[test]
    fn an_adopted_claim_does_not_survive_into_the_sessions_processes() {
        let base = temp_base("cloexec");
        let lease = allocate(&base, 40..=40).expect("lease");
        let fd = lease.into_handoff_fd();
        let adopted = DisplayLease::adopt(&base, 40, fd).expect("adopt");

        let raw = adopted._lock.as_raw_fd();
        // SAFETY: a descriptor the lease owns.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed");
        assert!(
            flags & libc::FD_CLOEXEC != 0,
            "the claim must be close-on-exec once adopted"
        );

        let seen = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test -e /proc/self/fd/{raw}"))
            .status()
            .expect("run a child");
        assert!(
            !seen.success(),
            "an exec'd child must not inherit the display claim (fd {raw})"
        );

        drop(adopted);
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
