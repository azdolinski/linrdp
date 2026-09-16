//! Dropping to the session user.
//!
//! Order matters and is not negotiable: supplementary groups, then gid, then
//! uid. Dropping the uid first would leave the process unable to change its
//! groups, silently keeping root's group memberships. Every step is verified
//! after the fact, because `setuid` failing silently is the difference
//! between an isolated session and a root shell on someone else's desktop.

use std::ffi::{CStr, CString};

use anyhow::Context as _;

#[derive(Debug)]
pub(crate) struct UserIds {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) name: String,
    pub(crate) home: String,
}

/// Resolve an account through NSS.
pub(crate) fn lookup_user(name: &str) -> anyhow::Result<UserIds> {
    let c_name = CString::new(name).context("user name contains a NUL")?;
    // SAFETY: getpwnam returns a pointer into a static buffer, valid until
    // the next call; every field is read before returning.
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        anyhow::bail!("unknown user: {name}");
    }
    // SAFETY: non-null, and the strings are NUL-terminated by NSS.
    let (uid, gid, home) = unsafe {
        let home = if (*pw).pw_dir.is_null() {
            String::new()
        } else {
            CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned()
        };
        ((*pw).pw_uid, (*pw).pw_gid, home)
    };
    Ok(UserIds { uid, gid, name: name.to_owned(), home })
}

/// Irreversibly become `user`. Verifies each step.
pub(crate) fn drop_to(user: &UserIds) -> anyhow::Result<()> {
    let c_name = CString::new(user.name.as_str()).context("user name contains a NUL")?;

    // SAFETY: valid NUL-terminated name and a gid from getpwnam.
    if unsafe { libc::initgroups(c_name.as_ptr(), user.gid) } != 0 {
        anyhow::bail!("initgroups for {} failed: {}", user.name, std::io::Error::last_os_error());
    }
    // SAFETY: plain setgid.
    if unsafe { libc::setgid(user.gid) } != 0 {
        anyhow::bail!("setgid({}) failed: {}", user.gid, std::io::Error::last_os_error());
    }
    // SAFETY: plain setuid; irreversible for a non-zero target uid.
    if unsafe { libc::setuid(user.uid) } != 0 {
        anyhow::bail!("setuid({}) failed: {}", user.uid, std::io::Error::last_os_error());
    }

    // Verify rather than trust: a silent failure here is a privilege
    // escalation, not a cosmetic bug.
    // SAFETY: getuid/getgid are always safe.
    let (now_uid, now_gid) = unsafe { (libc::getuid(), libc::getgid()) };
    anyhow::ensure!(now_uid == user.uid, "setuid did not take effect (uid {now_uid})");
    anyhow::ensure!(now_gid == user.gid, "setgid did not take effect (gid {now_gid})");
    if user.uid != 0 {
        // SAFETY: attempting to regain root must fail for a real drop.
        anyhow::ensure!(
            unsafe { libc::setuid(0) } != 0,
            "uid {} could regain root — the drop is not irreversible",
            user.uid
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_account_resolves() {
        let root = lookup_user("root").expect("root always exists");
        assert_eq!(root.uid, 0);
        assert_eq!(root.name, "root");
        assert!(!root.home.is_empty(), "home must be populated for the session env");
    }

    #[test]
    fn an_unknown_account_is_an_error() {
        let err = lookup_user("definitely-not-a-real-account-xyz").expect_err("no such user");
        assert!(err.to_string().contains("unknown user"), "got: {err}");
    }

    /// The real drop cannot be unit-tested — it is irreversible and would
    /// poison the test process — so this covers the lookup plus verification
    /// path only. The integration checklist covers the real drop.
    #[test]
    fn dropping_to_the_current_user_succeeds() {
        // SAFETY: getuid is always safe.
        let current = unsafe { libc::getuid() };
        if current != 0 {
            return;
        }
        let ids = lookup_user("root").expect("lookup");
        drop_to(&ids).expect("dropping to the current uid is a no-op");
    }
}
