//! The credential-capture line, added to and removed from the system's own
//! authentication stack.
//!
//! This is the most dangerous thing linrdp writes. `/etc/pam.d/common-auth`
//! decides whether anyone can log into this machine at all, so every edit here
//! is: back the file up first, mark the line as ours, never add it twice,
//! check the result still looks like a stack, and put the backup back if it
//! does not.
//!
//! One property does more for safety than all of that put together: the line
//! is `optional`. PAM ignores the result, so linrdp being missing, broken or
//! slow cannot turn a console login into a locked door. Nothing in this file
//! may ever change that word — hence the test that asserts it.
//!
//! Why the line has to exist at all: NLA (CredSSP/NTLMv2) makes the *server*
//! compute the expected response from the account secret (MS-NLMP), and a
//! one-way /etc/shadow hash cannot produce it. So linrdp learns each password
//! from the system's own authentication, exactly as Samba's pam_smbpass did.
//! It cannot drift from the system password, because it is the system
//! password, refreshed every time it is used. There is no linrdp password to
//! set and no command that sets one.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// Marks the line as linrdp's, so `uninstall` removes exactly what `install`
/// added and leaves an administrator's own `pam_exec` lines alone.
pub(crate) const MARKER: &str = "# linrdp credential capture — added by `linrdp service install`";

/// Which stack a line belongs to.
///
/// The type must match the stack it lives in: a `password` line in the auth
/// stack is never run, so the stored copy would silently stop following
/// password changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stack {
    /// Every successful authentication — su, ssh, console, sudo.
    Auth,
    /// Every password change, so the stored copy does not go stale.
    Password,
}

impl Stack {
    fn keyword(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Password => "password",
        }
    }
}

/// What happened to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Added(PathBuf, Stack),
    AlreadyPresent(PathBuf, Stack),
    Removed(PathBuf),
    /// The file is not on this distribution.
    Absent(PathBuf),
}

/// The stack files this distribution might have, and which line types each
/// one wants.
///
/// Debian splits the stacks; RedHat and SUSE combine them, so `system-auth`
/// and `password-auth` each take both lines.
pub(crate) fn candidates(pam_dir: &Path) -> Vec<(PathBuf, &'static [Stack])> {
    const AUTH: &[Stack] = &[Stack::Auth];
    const PASSWORD: &[Stack] = &[Stack::Password];
    const BOTH: &[Stack] = &[Stack::Auth, Stack::Password];
    vec![
        (pam_dir.join("common-auth"), AUTH),
        (pam_dir.join("common-password"), PASSWORD),
        (pam_dir.join("system-auth"), BOTH),
        (pam_dir.join("password-auth"), BOTH),
    ]
}

/// The line itself.
pub(crate) fn line_for(kind: Stack, binary: &Path) -> String {
    format!(
        "{:<9} optional  pam_exec.so expose_authtok quiet {} --capture-credential",
        kind.keyword(),
        binary.display()
    )
}

/// Add the capture line for `kind` to `path`, if it is not already there.
///
/// `verify` is handed the proposed file and says whether it is still a usable
/// stack; when it says no, the file is restored from the backup and the error
/// explains that nothing was changed.
pub(crate) fn wire(path: &Path, kind: Stack, binary: &Path, verify: &dyn Fn(&str) -> bool) -> anyhow::Result<Outcome> {
    let Ok(original) = std::fs::read_to_string(path) else {
        // Not this distribution's layout. Creating the file would replace a
        // stack PAM falls back to with one that says only what we put in it.
        return Ok(Outcome::Absent(path.to_path_buf()));
    };

    // Any existing capture line of this type counts, marked or not: an
    // administrator who added one by hand should not end up with two, and a
    // second `install` must not grow the stack.
    if has_capture(&original, kind) {
        return Ok(Outcome::AlreadyPresent(path.to_path_buf(), kind));
    }

    let mut proposed = original.clone();
    if !proposed.ends_with('\n') && !proposed.is_empty() {
        proposed.push('\n');
    }
    proposed.push_str(MARKER);
    proposed.push('\n');
    proposed.push_str(&line_for(kind, binary));
    proposed.push('\n');

    if !verify(&proposed) {
        anyhow::bail!(
            "refusing to change {}: the result would not be a usable PAM stack, and this file \
             decides whether anyone can log into this machine. Nothing was changed.",
            path.display()
        );
    }

    // The backup goes down before the file is touched, and stays afterwards.
    let backup = backup_path(path);
    std::fs::write(&backup, original.as_bytes()).with_context(|| format!("write the backup {}", backup.display()))?;

    crate::atomic::write(path, &proposed, mode_of(path)).with_context(|| format!("write {}", path.display()))?;

    Ok(Outcome::Added(path.to_path_buf(), kind))
}

/// Remove the lines `install` added, and only those.
///
/// A capture line an administrator wrote themselves has no marker above it and
/// is left exactly where it is — removing it would be linrdp deleting
/// somebody else's configuration on its way out.
pub(crate) fn unwire(path: &Path) -> anyhow::Result<Outcome> {
    let Ok(original) = std::fs::read_to_string(path) else {
        return Ok(Outcome::Absent(path.to_path_buf()));
    };

    let mut kept: Vec<&str> = Vec::new();
    let mut lines = original.lines().peekable();
    let mut removed = false;
    while let Some(line) = lines.next() {
        if line.trim_end() == MARKER {
            // Ours, if the line it introduces really is a capture line.
            if lines.peek().is_some_and(|next| next.contains("--capture-credential")) {
                lines.next();
                removed = true;
                continue;
            }
        }
        kept.push(line);
    }

    if !removed {
        return Ok(Outcome::Absent(path.to_path_buf()));
    }

    let mut body = kept.join("\n");
    body.push('\n');
    let backup = backup_path(path);
    std::fs::write(&backup, original.as_bytes()).with_context(|| format!("write the backup {}", backup.display()))?;
    crate::atomic::write(path, &body, mode_of(path)).with_context(|| format!("write {}", path.display()))?;
    Ok(Outcome::Removed(path.to_path_buf()))
}

fn backup_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.linrdp-backup", path.display()))
}

/// Keep whatever mode the stack file already had; 0644 for a file that is
/// somehow not there to ask.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).map_or(0o644, |meta| meta.permissions().mode() & 0o7777)
}

fn has_capture(body: &str, kind: Stack) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#')
            && trimmed.contains("--capture-credential")
            && trimmed.split_whitespace().next() == Some(kind.keyword())
    })
}

/// A structural sanity check: does this still read as a PAM stack?
///
/// Not a parser — PAM's grammar is richer than this. It catches the failure
/// that matters, a file mangled into something whose lines no longer begin
/// with a module type, and it is the default `verify` for [`wire`].
pub(crate) fn looks_like_a_stack(body: &str) -> bool {
    const TYPES: [&str; 8] = [
        "auth",
        "account",
        "password",
        "session",
        "-auth",
        "-account",
        "-password",
        "-session",
    ];
    body.lines().all(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('@') {
            return true;
        }
        trimmed
            .split_whitespace()
            .next()
            .is_some_and(|first| TYPES.contains(&first))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN_COMMON_AUTH: &str = "\
# /etc/pam.d/common-auth
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("linrdp-pam-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn seeded(tag: &str, body: &str) -> (PathBuf, PathBuf) {
        let dir = temp_dir(tag);
        let path = dir.join("common-auth");
        std::fs::write(&path, body).expect("seed");
        (dir, path)
    }

    fn binary() -> PathBuf {
        PathBuf::from("/usr/local/bin/linrdp")
    }

    fn always_fine(_: &str) -> bool {
        true
    }

    /// The one property that makes this edit survivable. PAM ignores the
    /// result of an `optional` line, so a linrdp that is missing, broken or
    /// slow cannot turn a console login into a locked door.
    #[test]
    fn the_line_is_optional_and_stays_optional() {
        let line = line_for(Stack::Auth, &binary());
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields[0], "auth");
        assert_eq!(
            fields[1], "optional",
            "the control flag is what makes this safe: {line}"
        );
        assert_eq!(fields[2], "pam_exec.so");
        assert!(
            line.contains("expose_authtok"),
            "without it the helper gets no password"
        );
    }

    /// A `password` line in the auth stack is never run, so the stored copy
    /// would quietly stop following password changes.
    #[test]
    fn the_type_matches_the_stack_it_is_written_into() {
        assert!(line_for(Stack::Password, &binary()).starts_with("password"));
        let (dir, _) = seeded("types", DEBIAN_COMMON_AUTH);
        let wants: Vec<_> = candidates(&dir)
            .into_iter()
            .map(|(path, kinds)| (path.file_name().expect("name").to_string_lossy().into_owned(), kinds))
            .collect();
        assert_eq!(wants[0].1, &[Stack::Auth]);
        assert_eq!(wants[1].1, &[Stack::Password]);
        assert_eq!(
            wants[2].1,
            &[Stack::Auth, Stack::Password],
            "RedHat combines the stacks"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Upgrading the binary means running `install` again. A stack that grew a
    /// line every time would run the helper once per install, forever.
    #[test]
    fn the_line_is_added_once_however_often_install_runs() {
        let (dir, path) = seeded("idem", DEBIAN_COMMON_AUTH);

        assert!(matches!(
            wire(&path, Stack::Auth, &binary(), &always_fine).expect("first"),
            Outcome::Added(..)
        ));
        for _ in 0..2 {
            assert!(matches!(
                wire(&path, Stack::Auth, &binary(), &always_fine).expect("again"),
                Outcome::AlreadyPresent(..)
            ));
        }

        let body = std::fs::read_to_string(&path).expect("read");
        assert_eq!(body.matches("--capture-credential").count(), 1, "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The backup is the way back, so it has to exist before the file is
    /// touched and hold what was there.
    #[test]
    fn a_backup_is_written_before_the_file_is_changed() {
        let (dir, path) = seeded("backup", DEBIAN_COMMON_AUTH);
        wire(&path, Stack::Auth, &binary(), &always_fine).expect("added");

        let backup = std::fs::read_to_string(dir.join("common-auth.linrdp-backup")).expect("backup");
        assert_eq!(backup, DEBIAN_COMMON_AUTH, "the backup is the file as it was");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `uninstall` takes back what `install` gave and nothing else. An
    /// administrator's own pam_exec line, and their own hand-written capture
    /// line, are somebody else's configuration.
    #[test]
    fn uninstall_removes_exactly_the_line_install_added() {
        let seed = format!(
            "{DEBIAN_COMMON_AUTH}auth    optional   pam_exec.so /usr/local/bin/notify-login\n\
             auth    optional   pam_exec.so expose_authtok quiet /opt/mine/linrdp --capture-credential\n"
        );
        let (dir, path) = seeded("unwire", &seed);

        // The hand-written capture line is already there, so install adds
        // nothing — and uninstall must still leave the file exactly as it is.
        assert!(matches!(
            wire(&path, Stack::Auth, &binary(), &always_fine).expect("skipped"),
            Outcome::AlreadyPresent(..)
        ));
        unwire(&path).expect("nothing of ours to remove");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            seed,
            "nothing of ours was there"
        );

        // Now with a line of ours present too.
        std::fs::write(&path, DEBIAN_COMMON_AUTH).expect("reseed");
        std::fs::write(
            &path,
            format!("{DEBIAN_COMMON_AUTH}auth    optional   pam_exec.so /usr/local/bin/notify-login\n"),
        )
        .expect("reseed");
        wire(&path, Stack::Auth, &binary(), &always_fine).expect("added");
        assert!(matches!(unwire(&path).expect("removed"), Outcome::Removed(_)));

        let body = std::fs::read_to_string(&path).expect("read");
        assert!(!body.contains(MARKER), "our marker is gone: {body}");
        assert!(!body.contains("--capture-credential"), "our line is gone: {body}");
        assert!(body.contains("notify-login"), "somebody else's line survives: {body}");
        assert!(body.contains("pam_unix.so nullok"), "the stack itself survives: {body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// If the result would not be a stack any more, the file is not written at
    /// all — there is nothing to restore, because nothing was touched.
    #[test]
    fn a_result_that_is_not_a_stack_leaves_the_file_alone() {
        let (dir, path) = seeded("verify", DEBIAN_COMMON_AUTH);
        let error = wire(&path, Stack::Auth, &binary(), &|_| false).expect_err("refused");

        assert!(format!("{error:#}").contains("Nothing was changed"), "got: {error:#}");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), DEBIAN_COMMON_AUTH);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Debian has no system-auth. Creating one would give PAM a stack
    /// containing only our line, on a machine that was working.
    #[test]
    fn a_stack_file_that_does_not_exist_is_not_created() {
        let dir = temp_dir("absent");
        let path = dir.join("system-auth");
        assert!(matches!(
            wire(&path, Stack::Auth, &binary(), &always_fine).expect("absent"),
            Outcome::Absent(_)
        ));
        assert!(!path.exists(), "no file was conjured up");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_structural_check_accepts_a_real_stack_and_rejects_rubbish() {
        assert!(looks_like_a_stack(DEBIAN_COMMON_AUTH));
        assert!(looks_like_a_stack("@include common-auth\n\n# comment\n"));
        assert!(!looks_like_a_stack(
            "auth required pam_unix.so\nthis is not a pam line\n"
        ));
    }

    /// A file with no trailing newline would otherwise get our marker glued
    /// onto the end of its last line, commenting that line out.
    #[test]
    fn a_file_without_a_trailing_newline_is_still_appended_to_safely() {
        let (dir, path) = seeded("nonewline", "auth required pam_unix.so");
        wire(&path, Stack::Auth, &binary(), &always_fine).expect("added");

        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.starts_with("auth required pam_unix.so\n"), "{body}");
        assert!(looks_like_a_stack(&body), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
