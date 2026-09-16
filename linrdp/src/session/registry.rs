//! Which user owns which display.
//!
//! One `key=value` file per display in the root-only state directory. The
//! files are a cache: the authority is the display lock (a live `flock`
//! means a live keeper) plus logind. A stale record for a display whose lock
//! is free is simply overwritten by the next allocation.

use std::fs;
use std::ops::RangeInclusive;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionRecord {
    pub(crate) user: String,
    pub(crate) display: u16,
    pub(crate) runtime_dir: String,
    pub(crate) xauthority: String,
    /// Whether the desktop is locked.
    ///
    /// Set when the last client disconnects, and on every supervisor start —
    /// a restart must never leave a desktop unlocked, because the process
    /// that could have locked it is exactly the one that went away.
    pub(crate) locked: bool,
}

pub(crate) fn record_path(base: &Path, display: u16) -> PathBuf {
    base.join(format!("display-{display}.session"))
}

pub(crate) fn write_record(base: &Path, rec: &SessionRecord) -> anyhow::Result<()> {
    let path = record_path(base, rec.display);
    let body = format!(
        "user={}\ndisplay={}\nruntime_dir={}\nxauthority={}\nlocked={}\n",
        rec.user, rec.display, rec.runtime_dir, rec.xauthority, rec.locked
    );
    fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

fn read_record(base: &Path, display: u16) -> Option<SessionRecord> {
    let body = fs::read_to_string(record_path(base, display)).ok()?;
    let field = |key: &str| -> Option<String> {
        let prefix = format!("{key}=");
        body.lines().find_map(|line| line.strip_prefix(&prefix)).map(str::to_owned)
    };
    Some(SessionRecord {
        user: field("user")?,
        display: field("display")?.parse().ok()?,
        runtime_dir: field("runtime_dir")?,
        xauthority: field("xauthority")?,
        // A record without the field predates it; treat it as locked, because
        // assuming unlocked is the unsafe direction.
        locked: field("locked").is_none_or(|v| v == "true"),
    })
}

/// One session record by display number.
pub(crate) fn read_one(base: &Path, display: u16) -> Option<SessionRecord> {
    read_record(base, display)
}

/// Remove a session record (the session is over).
pub(crate) fn forget_record(base: &Path, display: u16) -> anyhow::Result<()> {
    let path = record_path(base, display);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("remove {}", path.display()))),
    }
}

/// Mark every recorded session locked.
///
/// Run at supervisor start: whatever happened to the previous supervisor, the
/// desktops it left behind must not be reachable unlocked.
pub(crate) fn lock_all(base: &Path, range: RangeInclusive<u16>) -> usize {
    let mut locked = 0;
    for display in range {
        let Some(mut rec) = read_record(base, display) else {
            continue;
        };
        if rec.locked {
            continue;
        }
        rec.locked = true;
        if write_record(base, &rec).is_ok() {
            locked += 1;
        }
    }
    locked
}

/// Record a new lock state for one session.
pub(crate) fn set_locked(base: &Path, display: u16, locked: bool) -> anyhow::Result<()> {
    let Some(mut rec) = read_record(base, display) else {
        anyhow::bail!("no session recorded for :{display}");
    };
    rec.locked = locked;
    write_record(base, &rec)
}

/// The session belonging to `user`, if one is recorded in `range`.
pub(crate) fn find(base: &Path, user: &str, range: RangeInclusive<u16>) -> Option<SessionRecord> {
    range
        .into_iter()
        .filter_map(|display| read_record(base, display))
        .find(|rec| rec.user == user)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("linrdp-reg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        crate::session::runtime_dir::ensure_state_dir(&base).expect("state dir");
        base
    }

    fn sample(user: &str, display: u16) -> SessionRecord {
        SessionRecord {
            user: user.to_owned(),
            display,
            runtime_dir: format!("/run/user/{}", 1000 + u32::from(display)),
            xauthority: format!("/run/user/{}/linrdp/Xauthority", 1000 + u32::from(display)),
            locked: false,
        }
    }

    /// A restart must never leave a desktop reachable unlocked.
    #[test]
    fn every_session_is_locked_at_startup() {
        let base = temp_base("lockall");
        write_record(&base, &sample("alice", 11)).expect("write");
        write_record(&base, &sample("bob", 12)).expect("write");

        assert_eq!(lock_all(&base, 10..=20), 2, "both were unlocked");
        assert!(find(&base, "alice", 10..=20).expect("alice").locked);
        assert!(find(&base, "bob", 10..=20).expect("bob").locked);

        assert_eq!(lock_all(&base, 10..=20), 0, "already locked, nothing to do");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_lock_state_round_trips() {
        let base = temp_base("lockstate");
        write_record(&base, &sample("alice", 11)).expect("write");
        assert!(!find(&base, "alice", 10..=20).expect("found").locked);

        set_locked(&base, 11, true).expect("lock");
        assert!(find(&base, "alice", 10..=20).expect("found").locked);

        set_locked(&base, 11, false).expect("unlock");
        assert!(!find(&base, "alice", 10..=20).expect("found").locked);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Records written before the field existed must read as locked — the
    /// unsafe direction is to assume a desktop is free to walk into.
    #[test]
    fn a_record_without_the_field_reads_as_locked() {
        let base = temp_base("legacy");
        std::fs::write(
            record_path(&base, 13),
            "user=carol\ndisplay=13\nruntime_dir=/run/user/1013\nxauthority=/x\n",
        )
        .expect("legacy record");

        assert!(
            find(&base, "carol", 10..=20).expect("found").locked,
            "an unknown lock state must be treated as locked"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_users_session_is_found_again() {
        let base = temp_base("find");
        write_record(&base, &sample("alice", 11)).expect("write");
        let found = find(&base, "alice", 10..=20).expect("alice has a session");
        assert_eq!(found.display, 11);
        assert_eq!(found.runtime_dir, "/run/user/1011");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn another_user_gets_no_session() {
        let base = temp_base("other");
        write_record(&base, &sample("alice", 11)).expect("write");
        assert!(find(&base, "bob", 10..=20).is_none(), "bob must not land on alice's desktop");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_record_outside_the_range_is_ignored() {
        let base = temp_base("range");
        write_record(&base, &sample("alice", 50)).expect("write");
        assert!(find(&base, "alice", 10..=20).is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn records_round_trip_every_field() {
        let base = temp_base("roundtrip");
        let rec = sample("carol", 12);
        write_record(&base, &rec).expect("write");
        let found = find(&base, "carol", 10..=20).expect("found");
        assert_eq!(found.user, rec.user);
        assert_eq!(found.display, rec.display);
        assert_eq!(found.runtime_dir, rec.runtime_dir);
        assert_eq!(found.xauthority, rec.xauthority);
        let _ = std::fs::remove_dir_all(&base);
    }
}
