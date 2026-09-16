//! Per-session MIT-MAGIC-COOKIE.
//!
//! The cookie lives in `$XDG_RUNTIME_DIR/linrdp/Xauthority`, which
//! `pam_systemd` creates as mode 0700 owned by the user: tmpfs, so the
//! secret never reaches disk; per-boot, so it cannot outlive the session;
//! and independent of home-directory permissions or NFS.
//!
//! Xvfb is started with `-auth` pointing here and never with `-ac`. Without
//! this, any local user can screenshot the session and inject input.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use super::privilege::UserIds;

pub(crate) fn cookie_path(runtime_dir: &str) -> PathBuf {
    Path::new(runtime_dir).join("linrdp").join("Xauthority")
}

/// 16 secret bytes from the kernel CSPRNG.
pub(crate) fn random_cookie() -> anyhow::Result<[u8; 16]> {
    let mut cookie = [0u8; 16];
    let mut f = fs::File::open("/dev/urandom").context("open /dev/urandom")?;
    f.read_exact(&mut cookie).context("read cookie bytes")?;
    Ok(cookie)
}

/// One `.Xauthority` record: FamilyWild, no address, the display number as
/// text, `MIT-MAGIC-COOKIE-1`, and the 16 secret bytes. All lengths are
/// big-endian u16, per the Xau file format.
pub(crate) fn xauthority_entry(display: u16, cookie: &[u8; 16]) -> Vec<u8> {
    const NAME: &[u8] = b"MIT-MAGIC-COOKIE-1";
    let display_text = display.to_string();
    let mut out = Vec::with_capacity(46);
    out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // FamilyWild
    out.extend_from_slice(&0u16.to_be_bytes()); // address length
    out.extend_from_slice(&u16::try_from(display_text.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(display_text.as_bytes());
    out.extend_from_slice(&u16::try_from(NAME.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(NAME);
    out.extend_from_slice(&u16::try_from(cookie.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(cookie);
    out
}

/// Generate a fresh cookie and write it where only `owner` can read it.
pub(crate) fn write_cookie(runtime_dir: &str, display: u16, owner: &UserIds) -> anyhow::Result<PathBuf> {
    let path = cookie_path(runtime_dir);
    let dir = path.parent().context("cookie path has no parent")?;
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;

    let cookie = random_cookie()?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(&xauthority_entry(display, &cookie))
        .with_context(|| format!("write {}", path.display()))?;
    drop(file);

    // The keeper writes this as root before dropping privileges, so hand
    // ownership to the session user explicitly.
    chown_to(&path, owner)?;
    chown_to(dir, owner)?;
    Ok(path)
}

fn chown_to(path: &Path, owner: &UserIds) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).context("path NUL")?;
    // SAFETY: valid NUL-terminated path and ids from getpwnam.
    if unsafe { libc::chown(c_path.as_ptr(), owner.uid, owner.gid) } != 0 {
        anyhow::bail!("chown {} failed: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_is_a_well_formed_xauthority_record() {
        let cookie = [0xABu8; 16];
        let entry = xauthority_entry(42, &cookie);
        assert_eq!(&entry[0..2], &[0xFF, 0xFF], "family must be FamilyWild");
        assert_eq!(&entry[2..4], &[0x00, 0x00], "address length 0");
        assert_eq!(&entry[4..6], &[0x00, 0x02], "display number is 2 bytes of text");
        assert_eq!(&entry[6..8], b"42");
        assert_eq!(&entry[8..10], &[0x00, 0x12], "name length 18");
        assert_eq!(&entry[10..28], b"MIT-MAGIC-COOKIE-1");
        assert_eq!(&entry[28..30], &[0x00, 0x10], "cookie length 16");
        assert_eq!(&entry[30..46], &cookie);
        assert_eq!(entry.len(), 46);
    }

    #[test]
    fn a_one_digit_display_encodes() {
        assert_eq!(&xauthority_entry(7, &[0u8; 16])[4..7], &[0x00, 0x01, b'7']);
    }

    #[test]
    fn the_cookie_path_sits_under_the_runtime_dir() {
        assert_eq!(
            cookie_path("/run/user/1000"),
            std::path::Path::new("/run/user/1000/linrdp/Xauthority"),
            "the cookie belongs in the user's own 0700 tmpfs, never /tmp or $HOME"
        );
    }

    /// Two sessions must never share a secret.
    #[test]
    fn generated_cookies_differ() {
        let a = random_cookie().expect("cookie");
        let b = random_cookie().expect("cookie");
        assert_ne!(a, b, "a reused cookie lets one session authenticate to another");
        assert_ne!(a, [0u8; 16], "an all-zero cookie means /dev/urandom was not read");
    }
}
