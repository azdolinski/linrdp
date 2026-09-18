//! `linrdp service install` and `linrdp service uninstall`.
//!
//! One command that leaves a machine able to serve RDP, and one that takes
//! back exactly what it put there. Between them they write four things: the
//! directories, the PAM service file, the configuration (only when it is not
//! there already), and one systemd unit — plus the credential-capture line in
//! the system's own authentication stack, which is the part that deserves the
//! care it gets in [`pam`].
//!
//! Every path is a field of [`Layout`] rather than a literal, so the whole of
//! this can be exercised against a temporary directory instead of against
//! /etc.

pub(crate) mod pam;
pub(crate) mod unit;

use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// Where everything goes.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// `/etc/linrdp`
    pub(crate) etc: PathBuf,
    /// `/etc/systemd/system`
    pub(crate) unit_dir: PathBuf,
    /// `/etc/pam.d`
    pub(crate) pam_dir: PathBuf,
    /// `/var/lib/linrdp`
    pub(crate) state: PathBuf,
    /// `/etc/linrdp/cert` — the self-signed identity linrdp keeps when
    /// `tls.cert` is unset. Made here so it exists, with the right mode,
    /// before the first connection makes one in a hurry.
    pub(crate) cert: PathBuf,
    /// `/var/log/linrdp`
    pub(crate) log: PathBuf,
    /// The binary the unit and the PAM line name.
    pub(crate) binary: PathBuf,
}

impl Layout {
    /// The real machine.
    fn system() -> Self {
        Self {
            etc: Path::new(crate::config::CONFIG_PATH)
                .parent()
                .unwrap_or(Path::new("/etc/linrdp"))
                .to_path_buf(),
            unit_dir: PathBuf::from("/etc/systemd/system"),
            pam_dir: PathBuf::from("/etc/pam.d"),
            state: PathBuf::from("/var/lib/linrdp"),
            cert: PathBuf::from(crate::tls::CERT_DIR),
            log: PathBuf::from("/var/log/linrdp"),
            // Where this very binary is running from, so the unit starts the
            // thing the operator just ran rather than one they may not have
            // installed yet.
            binary: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/linrdp")),
        }
    }

    fn config_file(&self) -> PathBuf {
        self.etc.join("config.yaml")
    }
}

/// The PAM service file each session opens. `pam_systemd` in it is what
/// creates /run/user/<uid>, which is where a session's X cookie lives.
const PAM_SERVICE: &str = "\
# PAM stack for linrdp sessions — installed by `linrdp service install`.
#
# pam_systemd is the point of this file: it registers the session with logind
# and creates /run/user/<uid> (mode 0700, owned by the user), which is where
# the session's X cookie lives. Without it there is no runtime directory to
# put the cookie in, and session creation fails saying so.
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_limits.so
session    required   pam_unix.so
session    optional   pam_systemd.so
";

/// `linrdp service <verb>`.
pub(crate) fn run(verb: Option<&str>) -> anyhow::Result<()> {
    let layout = Layout::system();
    match verb {
        Some("install") => install(&layout),
        Some("uninstall") => uninstall(&layout),
        Some(other) => anyhow::bail!("`linrdp service {other}` — expected `install` or `uninstall`"),
        None => anyhow::bail!("`linrdp service` expects `install` or `uninstall`"),
    }
}

fn install(layout: &Layout) -> anyhow::Result<()> {
    require_root("install")?;

    println!("linrdp service install");
    println!();

    // 1. Directories, with the modes enforced rather than assumed — they may
    //    have been made by an older build, a packaging script, or by hand.
    for dir in [&layout.etc, &layout.state, &layout.cert, &layout.log] {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    }
    harden(&layout.state, 0o700)?;
    // Not 0700: the certificate in it is meant to be copied to clients. The
    // private key beside it carries its own 0600 — see `tls::generate_into`.
    harden(&layout.cert, 0o755)?;
    println!(
        "  directories   {}, {}, {}, {}",
        layout.etc.display(),
        layout.state.display(),
        layout.cert.display(),
        layout.log.display()
    );

    // 2. The PAM service each session opens.
    let pam_service = layout.pam_dir.join("linrdp");
    if layout.pam_dir.is_dir() {
        crate::atomic::write(&pam_service, PAM_SERVICE, 0o644)
            .with_context(|| format!("write {}", pam_service.display()))?;
        println!("  PAM service   {}", pam_service.display());
    }

    // 3. The configuration — only when there is none. A re-install is how a
    //    binary upgrade is applied, and it must not touch what the operator
    //    has set.
    let config_file = layout.config_file();
    if ensure_config(&config_file)? {
        println!(
            "  config        {} (written, with every key described in it)",
            config_file.display()
        );
    } else {
        println!("  config        {} (left as it is)", config_file.display());
    }

    // A unit pointing into somebody's build directory works until the next
    // `cargo clean`, and then the machine stops serving RDP for a reason that
    // has nothing to do with linrdp. `current_exe` is right when the binary
    // has been installed first, as the README says; say so when it has not.
    if !is_a_system_path(&layout.binary) {
        println!();
        println!("  note          the unit will start {}", layout.binary.display());
        println!("                which is not a system location. Install the binary first:");
        println!("                  sudo install -m755 {} /usr/local/bin/linrdp", layout.binary.display());
        println!("                  sudo /usr/local/bin/linrdp service install");
        println!();
    }

    // 4. Units that are about to stop applying, named with what they started.
    let new_exec = layout.binary.display().to_string();
    let displaced = unit::displaced(&layout.unit_dir, &new_exec);
    for old in &displaced {
        unit::systemctl(&["disable", "--now", &old.name]);
        let path = unit::path_in(&layout.unit_dir, &old.name);
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }

    // 5. The one unit.
    let unit_path = unit::path_in(&layout.unit_dir, unit::UNIT_NAME);
    crate::atomic::write(&unit_path, &unit::body(&layout.binary), 0o644)
        .with_context(|| format!("write {}", unit_path.display()))?;
    println!("  unit          {}", unit_path.display());

    // 6. The credential capture. Last of the file writes, because it is the
    //    one that touches a stack this machine's own logins depend on.
    let mut wired = Vec::new();
    for (path, kinds) in pam::candidates(&layout.pam_dir) {
        for kind in kinds {
            match pam::wire(&path, *kind, &layout.binary, &pam::looks_like_a_stack)? {
                pam::Outcome::Added(path, _) => wired.push(format!("{} (added)", path.display())),
                pam::Outcome::AlreadyPresent(path, _) => {
                    wired.push(format!("{} (already wired)", path.display()));
                }
                pam::Outcome::Absent(_) | pam::Outcome::Removed(_) => {}
            }
        }
    }
    if wired.is_empty() {
        println!("  capture       no PAM stack found to wire — `linrdp doctor` will say so");
    } else {
        println!("  capture       {}", wired.join(", "));
    }

    // 7. Start it.
    unit::systemctl(&["daemon-reload"]);
    let started = unit::systemctl(&["enable", "--now", unit::UNIT_NAME]).unwrap_or(false);

    println!();
    if !displaced.is_empty() {
        println!("{}", unit::describe_displaced(&displaced));
    }
    if started {
        println!("linrdp is running. `linrdp doctor` reports what it can serve, and");
        println!("`linrdp config` edits {}.", config_file.display());
    } else {
        println!("Files are in place. systemd did not start the unit here — start it with:");
        println!("  systemctl enable --now {}", unit::UNIT_NAME);
    }
    println!();
    println!("The capture line is `optional`, so linrdp can never keep anyone out of this");
    println!("machine: PAM ignores its result. It exists because NLA makes the server compute");
    println!("the expected response from the account secret, which an /etc/shadow hash cannot");
    println!("do — so linrdp learns each password from the system's own authentication, the");
    println!("way Samba's pam_smbpass did. There is no linrdp password to set.");
    Ok(())
}

fn uninstall(layout: &Layout) -> anyhow::Result<()> {
    require_root("uninstall")?;

    println!("linrdp service uninstall");
    println!();

    unit::systemctl(&["disable", "--now", unit::UNIT_NAME]);
    let unit_path = unit::path_in(&layout.unit_dir, unit::UNIT_NAME);
    match std::fs::remove_file(&unit_path) {
        Ok(()) => println!("  unit          removed {}", unit_path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("  unit          {} was not there", unit_path.display());
        }
        Err(error) => return Err(error).with_context(|| format!("remove {}", unit_path.display())),
    }
    unit::systemctl(&["daemon-reload"]);

    let mut unwired = Vec::new();
    for (path, _) in pam::candidates(&layout.pam_dir) {
        if let pam::Outcome::Removed(path) = pam::unwire(&path)? {
            unwired.push(path.display().to_string());
        }
    }
    if unwired.is_empty() {
        println!("  capture       nothing of ours in the PAM stack");
    } else {
        println!("  capture       removed from {}", unwired.join(", "));
    }

    println!();
    println!("Left alone, because they are yours and not ours:");
    println!("  {}", layout.config_file().display());
    println!(
        "  {} (the TLS identity and the captured passwords)",
        layout.state.display()
    );
    println!("  {}", layout.log.display());
    Ok(())
}

/// Write the configuration, but only when there is none.
///
/// Returns whether it wrote one. A re-install is how a binary upgrade is
/// applied — `install` over the new binary, same machine — so this step has to
/// be the one that does nothing on every run but the first. Overwriting here
/// would silently reset every choice the operator has made.
fn ensure_config(path: &Path) -> anyhow::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    // Through the loader so that the file written is the same defaults the
    // service would have run with, rather than a second idea of them.
    let fresh = crate::config::load_or_default(path)?.config;
    crate::atomic::write(path, &crate::config::render(&fresh), 0o644)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

/// Whether this binary lives somewhere a service can rely on finding it.
fn is_a_system_path(binary: &Path) -> bool {
    const SYSTEM_DIRS: [&str; 5] = ["/usr/local/bin", "/usr/bin", "/usr/sbin", "/opt", "/bin"];
    SYSTEM_DIRS.iter().any(|dir| binary.starts_with(dir))
}

/// Writing to /etc and editing the PAM stack both need it, and failing at step
/// six with half the work done is worse than not starting.
fn require_root(verb: &str) -> anyhow::Result<()> {
    // SAFETY: geteuid takes no arguments, touches no memory and cannot fail.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        euid == 0,
        "`linrdp service {verb}` writes to /etc and /var, so it has to run as root: \
         try `sudo linrdp service {verb}`"
    );
    Ok(())
}

/// Create-or-enforce, the same way the runtime state directory does it: the
/// directory may predate this build.
fn harden(dir: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("set mode {mode:o} on {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The temporary tree a test layout lives under, remembered rather than
    /// recomputed: `cleanup` once walked one parent too far and aimed
    /// `remove_dir_all` at /tmp itself, which deleted other tests' fixtures
    /// out from under them mid-run.
    struct Fixture {
        root: PathBuf,
        layout: Layout,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(
                self.root.starts_with(std::env::temp_dir()) && self.root != std::env::temp_dir(),
                "refusing to remove {}",
                self.root.display()
            );
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("linrdp-svc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let layout = Layout {
            etc: root.join("etc/linrdp"),
            unit_dir: root.join("etc/systemd/system"),
            pam_dir: root.join("etc/pam.d"),
            state: root.join("var/lib/linrdp"),
            cert: root.join("etc/linrdp/cert"),
            log: root.join("var/log/linrdp"),
            binary: PathBuf::from("/usr/local/bin/linrdp"),
        };
        for dir in [
            &layout.etc,
            &layout.unit_dir,
            &layout.pam_dir,
            &layout.state,
            &layout.log,
        ] {
            std::fs::create_dir_all(dir).expect("temp layout");
        }
        Fixture { root, layout }
    }

    /// Re-running `install` is how a binary upgrade is applied. A configuration
    /// rewritten there would silently reset every choice the operator made.
    #[test]
    fn install_never_overwrites_an_existing_configuration() {
        let layout = &fixture("keepconfig").layout;
        let mine = "listeners:\n  - bind: 10.0.0.1:3389\n    auth: system\n";
        std::fs::write(layout.config_file(), mine).expect("seed");

        for _ in 0..2 {
            assert!(
                !ensure_config(&layout.config_file()).expect("no write"),
                "nothing written"
            );
        }
        assert_eq!(
            std::fs::read_to_string(layout.config_file()).expect("read"),
            mine,
            "byte for byte what the operator wrote"
        );
    }

    /// And on a machine that has none, it does write one.
    #[test]
    fn install_writes_a_configuration_when_there_is_none() {
        let layout = &fixture("newconfig").layout;
        assert!(ensure_config(&layout.config_file()).expect("written"));
        assert!(
            !ensure_config(&layout.config_file()).expect("second run"),
            "only the first time"
        );
        crate::config::load_strict(&layout.config_file()).expect("the service starts on it");
    }

    /// The file `install` writes on a fresh machine has to be one the service
    /// will actually start on, and one an operator can read to learn the keys.
    #[test]
    fn the_configuration_install_writes_is_valid_and_self_describing() {
        let layout = &fixture("freshconfig").layout;
        let fresh = crate::config::load_or_default(&layout.config_file())
            .expect("defaults")
            .config;
        let body = crate::config::render(&fresh);
        crate::atomic::write(&layout.config_file(), &body, 0o644).expect("write");

        let reloaded = crate::config::load_strict(&layout.config_file()).expect("starts on it");
        assert_eq!(reloaded, fresh);
        assert!(
            body.contains("# How a login is verified"),
            "the keys are described: {body}"
        );
    }

    /// A unit that starts a binary out of somebody's build directory works
    /// until the next `cargo clean`, and then the machine stops serving RDP
    /// for a reason that has nothing to do with linrdp.
    #[test]
    fn a_binary_outside_a_system_location_is_worth_a_word() {
        assert!(is_a_system_path(Path::new("/usr/local/bin/linrdp")));
        assert!(is_a_system_path(Path::new("/usr/bin/linrdp")));
        assert!(!is_a_system_path(Path::new("/home/user/src/linrdp/target/debug/linrdp")));
        assert!(!is_a_system_path(Path::new("/tmp/linrdp")));
    }

    /// The PAM service file is what gives a session its /run/user/<uid>, and
    /// pam_systemd is the line that does it.
    #[test]
    fn the_pam_service_registers_the_session_with_logind() {
        assert!(PAM_SERVICE.contains("pam_systemd.so"));
        assert!(pam::looks_like_a_stack(PAM_SERVICE));
    }

    /// Half an install is worse than none, so it refuses before the first
    /// write rather than at the PAM step with the unit already replaced.
    #[test]
    fn a_non_root_install_refuses_before_it_writes_anything() {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return; // running as root; the refusal cannot be provoked
        }
        let error = require_root("install").expect_err("refused");
        assert!(
            format!("{error:#}").contains("sudo linrdp service install"),
            "got: {error:#}"
        );
    }
}
