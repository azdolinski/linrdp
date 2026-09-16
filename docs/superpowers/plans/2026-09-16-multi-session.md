# Multi-session per-user desktops — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every RDP user gets their own desktop, running as their own Unix user, surviving disconnects and reconnects, with several users working at once.

**Architecture:** `linrdp` gains three roles in one binary. The *supervisor* binds 3389 and forks a child per connection — it never speaks RDP. The *worker* is today's linrdp serving exactly one connection; after CredSSP it finds or creates its user's session and drops to that user's uid. The *keeper* is one detached process per session that owns the PAM handle, the display lock and the desktop processes, so the desktop outlives every connection to it. Shared state lives in `/run/linrdp/` (root, 0700); per-user secrets live in `$XDG_RUNTIME_DIR`.

**Tech Stack:** Rust 2024, tokio, `libc` (fork/setuid/flock via FFI), libpam through the existing `dlopen` shim, logind via the existing `zbus` dependency, `pico_args` for flags.

**Spec:** `docs/superpowers/specs/2026-09-16-multi-session-design.md`

## Global Constraints

- Display range: 10–99 inclusive, overridable with `--display-range LOW-HIGH`.
- Supervisor state directory: `/run/linrdp`, mode 0700, owned by root. Never `/tmp`, never a home directory.
- Per-session Xauthority: `$XDG_RUNTIME_DIR/linrdp/Xauthority`, mode 0600, owned by the session user.
- Xvfb is **never** started with `-ac`. Every session uses a fresh MIT-MAGIC-COOKIE.
- The username that selects a desktop comes from the authenticated CredSSP identity. The X.224 `mstshash` cookie is never used for that decision.
- PAM service name: `linrdp`, stack at `/etc/pam.d/linrdp`, must include `pam_systemd.so` in its session group.
- The vendored `crates/ironrdp-server` is not modified by this plan.
- No new runtime dependencies: FFI goes through `libc` and the existing dlopen shim.

---

### Task 1: Runtime state directory

**Files:**
- Create: `linrdp/src/session/mod.rs`
- Create: `linrdp/src/session/runtime_dir.rs`
- Modify: `linrdp/src/main.rs` (add `mod session;` next to the other `mod` lines near line 13)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub(crate) const STATE_DIR: &str = "/run/linrdp";`, `pub(crate) fn ensure_state_dir(base: &Path) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing test**

Create `linrdp/src/session/runtime_dir.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_is_created_private_to_root() {
        let base = std::env::temp_dir().join(format!("linrdp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        ensure_state_dir(&base).expect("creates the directory");

        let mode = std::fs::metadata(&base).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state must not be readable by other users");

        // Idempotent: a second call on an existing directory succeeds.
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p linrdp runtime_dir`
Expected: FAIL — `cannot find function ensure_state_dir`.

- [ ] **Step 3: Write minimal implementation**

Above the test module in `linrdp/src/session/runtime_dir.rs`:

```rust
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
```

And in `linrdp/src/session/mod.rs`:

```rust
//! Multi-session support: per-user desktops with Windows RDP semantics.
//!
//! See `docs/superpowers/specs/2026-09-16-multi-session-design.md`.

pub(crate) mod runtime_dir;
```

Add `mod session;` to `linrdp/src/main.rs` alongside the other module declarations.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp runtime_dir`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/mod.rs linrdp/src/session/runtime_dir.rs linrdp/src/main.rs
git commit -m "session: root-only runtime state directory under /run"
```

---

### Task 2: Display allocator

**Files:**
- Create: `linrdp/src/session/display_alloc.rs`
- Modify: `linrdp/src/session/mod.rs` (add `pub(crate) mod display_alloc;`)

**Interfaces:**
- Consumes: `runtime_dir::ensure_state_dir`.
- Produces:
  - `pub(crate) struct DisplayLease { pub(crate) number: u16, /* holds the fd */ }`
  - `pub(crate) fn allocate(base: &Path, range: RangeInclusive<u16>) -> anyhow::Result<DisplayLease>`
  - `pub(crate) fn owner_of(base: &Path, number: u16) -> Option<String>`
  - `impl DisplayLease { pub(crate) fn record_owner(&self, user: &str) -> anyhow::Result<()>; pub(crate) fn display_name(&self) -> String /* ":42" */ }`
  - Dropping a `DisplayLease` releases the lock.

- [ ] **Step 1: Write the failing test**

```rust
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

        assert!(
            err.to_string().contains("no free display"),
            "the error must say what ran out, got: {err}"
        );
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp display_alloc`
Expected: FAIL — `cannot find function allocate`.

- [ ] **Step 3: Write minimal implementation**

```rust
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
    anyhow::bail!(
        "no free display in range {}-{}",
        range.start(),
        range.end()
    )
}
```

Add `pub(crate) mod display_alloc;` to `linrdp/src/session/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp display_alloc`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/display_alloc.rs linrdp/src/session/mod.rs
git commit -m "session: race-free display allocation via flock in /run/linrdp"
```

---

### Task 3: PAM session half

**Files:**
- Modify: `linrdp/src/pam.rs` (extend `PamApi`, add the session functions)
- Create: `linrdp/src/session/pam_session.rs`
- Modify: `linrdp/src/session/mod.rs`

**Interfaces:**
- Consumes: the existing `PamApi` / `load_pam()` in `linrdp/src/pam.rs`.
- Produces:
  - `pub(crate) trait PamSessionApi { fn open(&mut self, user: &str, password: &str) -> Result<PamEnv, String>; fn close(&mut self) -> Result<(), String>; }`
  - `pub(crate) struct PamEnv { pub(crate) vars: Vec<(String, String)> }`
  - `impl PamEnv { pub(crate) fn get(&self, key: &str) -> Option<&str>; pub(crate) fn runtime_dir(&self) -> Option<&str> }`
  - `pub(crate) struct PamSession` — RAII, closes the session on drop.
  - `pub(crate) fn open_session(user: &str, password: &str) -> anyhow::Result<PamSession>`

- [ ] **Step 1: Write the failing test**

In `linrdp/src/session/pam_session.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Records the PAM call sequence without touching libpam.
    #[derive(Default)]
    struct MockPam {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fail_at: Option<&'static str>,
    }

    impl PamSessionApi for MockPam {
        fn open(&mut self, _user: &str, _password: &str) -> Result<PamEnv, String> {
            for step in ["start", "authenticate", "acct_mgmt", "setcred", "open_session"] {
                self.calls.borrow_mut().push(step);
                if self.fail_at == Some(step) {
                    // Unwinding must still happen on the failure path.
                    self.calls.borrow_mut().push("end");
                    return Err(format!("{step} failed"));
                }
            }
            Ok(PamEnv {
                vars: vec![
                    ("XDG_RUNTIME_DIR".to_owned(), "/run/user/1000".to_owned()),
                    ("XDG_SESSION_ID".to_owned(), "7".to_owned()),
                ],
            })
        }

        fn close(&mut self) -> Result<(), String> {
            self.calls.borrow_mut().push("close_session");
            self.calls.borrow_mut().push("end");
            Ok(())
        }
    }

    #[test]
    fn a_successful_session_runs_the_calls_in_order() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut pam = MockPam { calls: Rc::clone(&calls), fail_at: None };

        let env = pam.open("alice", "secret").expect("session opens");

        assert_eq!(
            *calls.borrow(),
            vec!["start", "authenticate", "acct_mgmt", "setcred", "open_session"],
            "authentication must precede the session, and setcred must precede open_session"
        );
        assert_eq!(env.runtime_dir(), Some("/run/user/1000"));
        assert_eq!(env.get("XDG_SESSION_ID"), Some("7"));
        assert_eq!(env.get("NOPE"), None);
    }

    #[test]
    fn a_failure_still_unwinds() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut pam = MockPam { calls: Rc::clone(&calls), fail_at: Some("open_session") };

        pam.open("alice", "secret").expect_err("open_session fails");

        assert_eq!(
            calls.borrow().last().copied(),
            Some("end"),
            "pam_end must run on the failure path or the handle leaks"
        );
    }

    #[test]
    fn close_runs_close_session_before_end() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut pam = MockPam { calls: Rc::clone(&calls), fail_at: None };
        pam.open("alice", "secret").expect("opens");
        calls.borrow_mut().clear();

        pam.close().expect("closes");

        assert_eq!(*calls.borrow(), vec!["close_session", "end"]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp pam_session`
Expected: FAIL — `cannot find trait PamSessionApi`.

- [ ] **Step 3: Write minimal implementation**

First extend `PamApi` in `linrdp/src/pam.rs` — add these fields to the struct and load them in `load_pam()` with the existing `sym!` macro:

```rust
    pam_setcred: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_open_session: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_close_session: unsafe extern "C" fn(handle: *mut c_void, flags: c_int) -> c_int,
    pam_getenvlist: unsafe extern "C" fn(handle: *mut c_void) -> *mut *mut c_char,
```

```rust
            pam_setcred: sym!("pam_setcred"),
            pam_open_session: sym!("pam_open_session"),
            pam_close_session: sym!("pam_close_session"),
            pam_getenvlist: sym!("pam_getenvlist"),
```

Add the constants next to the existing ones:

```rust
const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_DELETE_CRED: c_int = 0x0004;
/// Session stack for linrdp; must include pam_systemd.so so logind registers
/// the session and creates /run/user/<uid>.
pub(crate) const PAM_SERVICE_LINRDP: &str = "linrdp";
```

Then `linrdp/src/session/pam_session.rs`:

```rust
//! Opening a real PAM session, so logind registers the desktop.
//!
//! The authentication half already exists in `crate::pam`. This adds the
//! session half — `pam_setcred`, `pam_open_session`, `pam_getenvlist`,
//! `pam_close_session` — because `pam_systemd.so` is what creates
//! `/run/user/<uid>` (mode 0700, owned by the user) where the session's X
//! cookie lives.
//!
//! The handle must outlive the connection that created it: the desktop
//! survives disconnects, so the keeper process holds this, not the worker.

/// Environment PAM built for the session (`XDG_RUNTIME_DIR`, `XDG_SESSION_ID`, …).
pub(crate) struct PamEnv {
    pub(crate) vars: Vec<(String, String)>,
}

impl PamEnv {
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn runtime_dir(&self) -> Option<&str> {
        self.get("XDG_RUNTIME_DIR")
    }
}

/// The PAM session lifecycle, behind a trait so the call order can be tested
/// without libpam present.
pub(crate) trait PamSessionApi {
    /// Authenticate, then open a session. On any failure the handle is ended
    /// before returning, so a partial session never leaks.
    fn open(&mut self, user: &str, password: &str) -> Result<PamEnv, String>;
    /// Close the session and end the handle.
    fn close(&mut self) -> Result<(), String>;
}
```

The libpam-backed implementation lands in Task 9, together with `session::create` which owns the handle; this task delivers the contract and its order guarantees.

Add `pub(crate) mod pam_session;` to `linrdp/src/session/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp pam_session`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/pam.rs linrdp/src/session/pam_session.rs linrdp/src/session/mod.rs
git commit -m "session: PAM session contract with ordered open/close"
```

---

### Task 4: Privilege drop

**Files:**
- Create: `linrdp/src/session/privilege.rs`
- Modify: `linrdp/src/session/mod.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub(crate) struct UserIds { pub(crate) uid: u32, pub(crate) gid: u32, pub(crate) name: String, pub(crate) home: String }`
  - `pub(crate) fn lookup_user(name: &str) -> anyhow::Result<UserIds>`
  - `pub(crate) fn drop_to(user: &UserIds) -> anyhow::Result<()>` — irreversible; verifies the drop took effect.

- [ ] **Step 1: Write the failing test**

```rust
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

    /// Dropping to uid 0 from uid 0 is a no-op that must still verify.
    /// The real drop cannot be unit-tested — it is irreversible and would
    /// poison the test process — so this covers the lookup + verification
    /// path only. The integration checklist covers the real drop.
    #[test]
    fn dropping_to_the_current_user_succeeds() {
        // SAFETY: getuid is always safe.
        let current = unsafe { libc::getuid() };
        let name = if current == 0 { "root" } else { return };
        let ids = lookup_user(name).expect("lookup");
        drop_to(&ids).expect("dropping to the current uid is a no-op");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp privilege`
Expected: FAIL — `cannot find function lookup_user`.

- [ ] **Step 3: Write minimal implementation**

```rust
//! Dropping to the session user.
//!
//! Order matters and is not negotiable: supplementary groups, then gid, then
//! uid. Dropping the uid first would leave the process unable to change its
//! groups, silently keeping root's group memberships. Every step is verified
//! after the fact, because `setuid` failing silently is the difference
//! between an isolated session and a root shell on someone else's desktop.

use std::ffi::{CStr, CString};

use anyhow::Context as _;

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
    Ok(UserIds {
        uid,
        gid,
        name: name.to_owned(),
        home,
    })
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
```

Add `pub(crate) mod privilege;` to `linrdp/src/session/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp privilege`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/privilege.rs linrdp/src/session/mod.rs
git commit -m "session: verified privilege drop to the session user"
```

---

### Task 5: Session record and lookup

**Files:**
- Create: `linrdp/src/session/registry.rs`
- Modify: `linrdp/src/session/mod.rs`

**Interfaces:**
- Consumes: `display_alloc::{allocate, owner_of, DisplayLease}`, `runtime_dir::STATE_DIR`.
- Produces:
  - `pub(crate) struct SessionRecord { pub(crate) user: String, pub(crate) display: u16, pub(crate) runtime_dir: String, pub(crate) xauthority: String }`
  - `pub(crate) fn find(base: &Path, user: &str, range: RangeInclusive<u16>) -> Option<SessionRecord>`
  - `pub(crate) fn record_path(base: &Path, display: u16) -> PathBuf`
  - `pub(crate) fn write_record(base: &Path, rec: &SessionRecord) -> anyhow::Result<()>`

Records are plain `key=value` lines — no new dependency, and trivially readable by an operator debugging a stuck session.

- [ ] **Step 1: Write the failing test**

```rust
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
        }
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp registry`
Expected: FAIL — `cannot find struct SessionRecord`.

- [ ] **Step 3: Write minimal implementation**

```rust
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

pub(crate) struct SessionRecord {
    pub(crate) user: String,
    pub(crate) display: u16,
    pub(crate) runtime_dir: String,
    pub(crate) xauthority: String,
}

pub(crate) fn record_path(base: &Path, display: u16) -> PathBuf {
    base.join(format!("display-{display}.session"))
}

pub(crate) fn write_record(base: &Path, rec: &SessionRecord) -> anyhow::Result<()> {
    let path = record_path(base, rec.display);
    let body = format!(
        "user={}\ndisplay={}\nruntime_dir={}\nxauthority={}\n",
        rec.user, rec.display, rec.runtime_dir, rec.xauthority
    );
    fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

fn read_record(base: &Path, display: u16) -> Option<SessionRecord> {
    let body = fs::read_to_string(record_path(base, display)).ok()?;
    let field = |key: &str| -> Option<String> {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}="))) 
            .map(str::to_owned)
    };
    Some(SessionRecord {
        user: field("user")?,
        display: field("display")?.parse().ok()?,
        runtime_dir: field("runtime_dir")?,
        xauthority: field("xauthority")?,
    })
}

/// The session belonging to `user`, if one is recorded in `range`.
pub(crate) fn find(base: &Path, user: &str, range: RangeInclusive<u16>) -> Option<SessionRecord> {
    range
        .into_iter()
        .filter_map(|display| read_record(base, display))
        .find(|rec| rec.user == user)
}
```

Add `pub(crate) mod registry;` to `linrdp/src/session/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp registry`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/registry.rs linrdp/src/session/mod.rs
git commit -m "session: per-display records mapping users to desktops"
```

---

### Task 6: X authority cookie

**Files:**
- Create: `linrdp/src/session/xauth.rs`
- Modify: `linrdp/src/session/mod.rs`

**Interfaces:**
- Consumes: `privilege::UserIds`.
- Produces:
  - `pub(crate) fn cookie_path(runtime_dir: &str) -> PathBuf`
  - `pub(crate) fn write_cookie(runtime_dir: &str, display: u16, owner: &UserIds) -> anyhow::Result<PathBuf>`
  - `pub(crate) fn xauthority_entry(display: u16, cookie: &[u8; 16]) -> Vec<u8>` — the on-disk `.Xauthority` binary record.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_is_a_well_formed_xauthority_record() {
        let cookie = [0xABu8; 16];
        let entry = xauthority_entry(42, &cookie);

        // family 0xFFFF (FamilyWild), empty address, display "42",
        // name "MIT-MAGIC-COOKIE-1", 16-byte cookie.
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
    fn a_two_digit_and_a_one_digit_display_both_encode() {
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp xauth`
Expected: FAIL — `cannot find function xauthority_entry`.

- [ ] **Step 3: Write minimal implementation**

```rust
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
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;

use super::privilege::UserIds;

pub(crate) fn cookie_path(runtime_dir: &str) -> PathBuf {
    Path::new(runtime_dir).join("linrdp").join("Xauthority")
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

    let mut cookie = [0u8; 16];
    fs::File::open("/dev/urandom")
        .context("open /dev/urandom")
        .and_then(|mut f| {
            use std::io::Read as _;
            f.read_exact(&mut cookie).context("read cookie bytes")
        })?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    file.write_all(&xauthority_entry(display, &cookie))
        .with_context(|| format!("write {}", path.display()))?;

    // The keeper writes this as root before dropping privileges, so hand
    // ownership to the session user explicitly.
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).context("path NUL")?;
    // SAFETY: valid NUL-terminated path and ids from getpwnam.
    if unsafe { libc::chown(c_path.as_ptr(), owner.uid, owner.gid) } != 0 {
        anyhow::bail!("chown {} failed: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(path)
}
```

Add `pub(crate) mod xauth;` to `linrdp/src/session/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp xauth`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/xauth.rs linrdp/src/session/mod.rs
git commit -m "session: per-session MIT-MAGIC-COOKIE in the user runtime dir"
```

---

### Task 7: Supervisor — fork per connection

**Files:**
- Create: `linrdp/src/supervisor.rs`
- Modify: `linrdp/src/main.rs` (add `mod supervisor;`, the `--supervisor` and `--display-range` flags, and the HELP text)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `pub(crate) fn parse_display_range(spec: &str) -> anyhow::Result<RangeInclusive<u16>>`
  - `pub(crate) fn run(bind: SocketAddr, worker_argv: Vec<String>) -> anyhow::Result<()>` — accept loop, fork per connection, reap children.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_range_parses() {
        let range = parse_display_range("10-99").expect("valid");
        assert_eq!(*range.start(), 10);
        assert_eq!(*range.end(), 99);
    }

    #[test]
    fn an_inverted_range_is_rejected() {
        let err = parse_display_range("99-10").expect_err("inverted");
        assert!(err.to_string().contains("LOW-HIGH"), "got: {err}");
    }

    #[test]
    fn display_zero_is_rejected() {
        // :0 is conventionally a physical seat; handing it out would collide
        // with a real console session.
        let err = parse_display_range("0-9").expect_err("zero");
        assert!(err.to_string().contains("must start at 1"), "got: {err}");
    }

    #[test]
    fn garbage_is_rejected() {
        parse_display_range("ten to ninety").expect_err("not a range");
        parse_display_range("10").expect_err("missing the dash");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp supervisor`
Expected: FAIL — `cannot find function parse_display_range`.

- [ ] **Step 3: Write minimal implementation**

```rust
//! The supervisor: accept, fork, reap. It never speaks RDP.
//!
//! Forking before any protocol runs is what removes the routing problem.
//! The child learns which desktop to serve from its own CredSSP exchange,
//! not from the client-supplied X.224 `mstshash` cookie — that field is
//! unauthenticated and must never decide whose desktop someone reaches.

use std::net::SocketAddr;
use std::ops::RangeInclusive;

use anyhow::Context as _;

/// Parse `--display-range LOW-HIGH`.
pub(crate) fn parse_display_range(spec: &str) -> anyhow::Result<RangeInclusive<u16>> {
    let Some((low, high)) = spec.split_once('-') else {
        anyhow::bail!("--display-range expects LOW-HIGH, e.g. 10-99");
    };
    let low: u16 = low.trim().parse().context("--display-range LOW")?;
    let high: u16 = high.trim().parse().context("--display-range HIGH")?;
    anyhow::ensure!(low >= 1, "--display-range must start at 1 or above (:0 is a physical seat)");
    anyhow::ensure!(low <= high, "--display-range expects LOW-HIGH with LOW <= HIGH");
    Ok(low..=high)
}
```

Then the accept loop in the same file:

```rust
/// Accept connections and fork a worker for each.
///
/// Uses a blocking listener deliberately: the supervisor has no async work,
/// and `fork` in a multi-threaded tokio runtime is a footgun — only the
/// calling thread survives in the child, so any runtime state is poisoned.
pub(crate) fn run(bind: SocketAddr, worker_argv: Vec<String>) -> anyhow::Result<()> {
    let listener = std::net::TcpListener::bind(bind).with_context(|| format!("bind {bind}"))?;
    tracing::info!(%bind, "supervisor listening — forking a worker per connection");

    // Reap children without blocking: a worker that exits must not become a
    // zombie, and the supervisor never waits on a specific child.
    // SAFETY: setting SIGCHLD to SIG_IGN is async-signal-safe and documented
    // on Linux to auto-reap.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };

    loop {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "accept failed");
                continue;
            }
        };

        // SAFETY: the parent is single-threaded here (no tokio runtime yet),
        // so the child inherits a consistent address space.
        match unsafe { libc::fork() } {
            -1 => tracing::error!(error = %std::io::Error::last_os_error(), "fork failed"),
            0 => {
                // Child: hand the accepted socket to the worker on fd 3 and
                // exec, so the worker is a clean process with a fresh runtime.
                crate::supervisor::exec_worker(stream, &worker_argv);
                // exec_worker never returns on success.
                std::process::exit(1);
            }
            pid => {
                tracing::debug!(%peer, pid, "forked worker");
                drop(stream); // the child owns it now
            }
        }
    }
}

/// Move `stream` to fd 3 and exec the worker binary with `--serve-fd 3`.
fn exec_worker(stream: std::net::TcpStream, argv: &[String]) {
    use std::os::fd::{AsRawFd as _, IntoRawFd as _};

    let fd = stream.into_raw_fd();
    // SAFETY: dup2 onto a fd the child does not otherwise use; CLOEXEC is
    // cleared by dup2, which is what lets the worker inherit it across exec.
    if unsafe { libc::dup2(fd, 3) } < 0 {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let Ok(exe_c) = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()) else { return };

    let mut args: Vec<std::ffi::CString> = vec![exe_c.clone()];
    for a in argv {
        if let Ok(c) = std::ffi::CString::new(a.as_str()) {
            args.push(c);
        }
    }
    args.push(std::ffi::CString::new("--serve-fd").expect("literal"));
    args.push(std::ffi::CString::new("3").expect("literal"));

    let mut ptrs: Vec<*const std::ffi::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: NUL-terminated argv built above; execv only returns on failure.
    unsafe { libc::execv(exe_c.as_ptr(), ptrs.as_ptr()) };
    let _ = fd;
}
```

In `linrdp/src/main.rs`, add `mod supervisor;`, parse the flags, and extend HELP:

```rust
    let supervisor_mode = args.contains("--supervisor");
    let display_range = match args.opt_value_from_str::<_, String>("--display-range")? {
        Some(spec) => supervisor::parse_display_range(&spec)?,
        None => 10..=99,
    };
```

HELP gains:

```
  --supervisor          accept on the bind address and fork one worker per
                        connection; each worker serves its user's own desktop
  --display-range L-H   X display numbers workers may allocate (default 10-99)
  --console             attach to $DISPLAY instead of a per-user session
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp supervisor`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/supervisor.rs linrdp/src/main.rs
git commit -m "supervisor: accept and fork a worker per connection"
```

---

### Task 8: Keeper — start a desktop and hold the session

**Files:**
- Create: `linrdp/src/session/keeper.rs`
- Modify: `linrdp/src/session/mod.rs`

**Interfaces:**
- Consumes: `display_alloc::allocate`, `xauth::write_cookie`, `privilege::{lookup_user, drop_to}`, `registry::write_record`, `pam_session::PamSessionApi`.
- Produces:
  - `pub(crate) struct DesktopCommand { pub(crate) program: String, pub(crate) args: Vec<String> }`
  - `pub(crate) fn xvfb_command(display: u16, xauthority: &str, size: (u16, u16)) -> DesktopCommand`
  - `pub(crate) fn session_env(rec: &registry::SessionRecord, user: &privilege::UserIds) -> Vec<(String, String)>`

The keeper process itself is wired in Task 9; this task delivers the command and environment construction, which is where the security-relevant mistakes live and which is testable without spawning anything.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::privilege::UserIds;
    use crate::session::registry::SessionRecord;

    #[test]
    fn xvfb_is_never_started_with_access_control_off() {
        let cmd = xvfb_command(42, "/run/user/1000/linrdp/Xauthority", (2880, 1800));

        assert_eq!(cmd.program, "Xvfb");
        assert!(
            !cmd.args.iter().any(|a| a == "-ac"),
            "-ac disables X access control: any local user could screenshot the \
             session and inject input. Never emit it. Got {:?}",
            cmd.args
        );
        assert!(cmd.args.iter().any(|a| a == ":42"), "display must be passed");
        let auth = cmd.args.windows(2).find(|w| w[0] == "-auth").expect("-auth is mandatory");
        assert_eq!(auth[1], "/run/user/1000/linrdp/Xauthority");
        assert!(
            cmd.args.iter().any(|a| a.starts_with("2880x1800x")),
            "screen geometry must be applied, got {:?}",
            cmd.args
        );
    }

    #[test]
    fn the_session_env_points_at_the_users_own_runtime_dir() {
        let rec = SessionRecord {
            user: "alice".to_owned(),
            display: 42,
            runtime_dir: "/run/user/1001".to_owned(),
            xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
        };
        let user = UserIds { uid: 1001, gid: 1001, name: "alice".to_owned(), home: "/home/alice".to_owned() };

        let env = session_env(&rec, &user);
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

        assert_eq!(get("DISPLAY"), Some(":42"));
        assert_eq!(get("XAUTHORITY"), Some("/run/user/1001/linrdp/Xauthority"));
        assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1001"));
        assert_eq!(get("HOME"), Some("/home/alice"));
        assert_eq!(get("USER"), Some("alice"));
        assert!(get("XAUTHORITY").is_some_and(|p| p.starts_with("/run/user/")),
            "the cookie must never be pointed at /tmp or $HOME");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp keeper`
Expected: FAIL — `cannot find function xvfb_command`.

- [ ] **Step 3: Write minimal implementation**

```rust
//! Building the desktop's command line and environment.
//!
//! The keeper process owns a session: the PAM handle, the display lock and
//! the desktop processes. It outlives every connection, which is what makes
//! a reconnect land on the same desktop.

use super::privilege::UserIds;
use super::registry::SessionRecord;

pub(crate) struct DesktopCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
}

/// The X server for one session.
///
/// `-auth` and the absence of `-ac` are the whole security boundary of the
/// session: without them any local user can read the screen and type into it.
pub(crate) fn xvfb_command(display: u16, xauthority: &str, size: (u16, u16)) -> DesktopCommand {
    let (w, h) = size;
    DesktopCommand {
        program: "Xvfb".to_owned(),
        args: vec![
            format!(":{display}"),
            "-screen".to_owned(),
            "0".to_owned(),
            format!("{w}x{h}x24"),
            "-auth".to_owned(),
            xauthority.to_owned(),
            "-nolisten".to_owned(),
            "tcp".to_owned(),
            "+extension".to_owned(),
            "DAMAGE".to_owned(),
            "+extension".to_owned(),
            "MIT-SHM".to_owned(),
            "+extension".to_owned(),
            "RANDR".to_owned(),
            "+extension".to_owned(),
            "XFIXES".to_owned(),
            "+extension".to_owned(),
            "XTEST".to_owned(),
        ],
    }
}

/// Environment for the desktop and for the worker that serves it.
pub(crate) fn session_env(rec: &SessionRecord, user: &UserIds) -> Vec<(String, String)> {
    vec![
        ("DISPLAY".to_owned(), format!(":{}", rec.display)),
        ("XAUTHORITY".to_owned(), rec.xauthority.clone()),
        ("XDG_RUNTIME_DIR".to_owned(), rec.runtime_dir.clone()),
        ("HOME".to_owned(), user.home.clone()),
        ("USER".to_owned(), user.name.clone()),
        ("LOGNAME".to_owned(), user.name.clone()),
    ]
}
```

Add `pub(crate) mod keeper;` to `linrdp/src/session/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp keeper`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/keeper.rs linrdp/src/session/mod.rs
git commit -m "session: desktop command and environment, never with -ac"
```

---

### Task 9: Worker attaches to its user's session

**Files:**
- Modify: `linrdp/src/main.rs` (serve one connection from `--serve-fd`, resolve the session after authentication)
- Modify: `linrdp/src/session/mod.rs` (add `attach_existing` and `create`)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `pub(crate) fn attach_existing(base: &Path, user: &str, range: RangeInclusive<u16>) -> Option<registry::SessionRecord>`
  - `pub(crate) fn create(base: &Path, user: &str, range: RangeInclusive<u16>, size: (u16, u16)) -> anyhow::Result<registry::SessionRecord>`

- [ ] **Step 1: Write the failing test**

In `linrdp/src/session/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("linrdp-attach-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        runtime_dir::ensure_state_dir(&base).expect("state dir");
        base
    }

    /// Reconnecting must land on the existing desktop, not a second one.
    #[test]
    fn a_second_attach_returns_the_same_display() {
        let base = temp_base("same");
        registry::write_record(
            &base,
            &registry::SessionRecord {
                user: "alice".to_owned(),
                display: 11,
                runtime_dir: "/run/user/1001".to_owned(),
                xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
            },
        )
        .expect("seed an existing session");

        let found = attach_existing(&base, "alice", 10..=20).expect("attaches");

        assert_eq!(found.display, 11, "a reconnect must not create a second desktop");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_user_without_a_session_gets_none() {
        let base = temp_base("none");
        assert!(attach_existing(&base, "bob", 10..=20).is_none());
        let _ = std::fs::remove_dir_all(&base);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp session::tests`
Expected: FAIL — `cannot find function attach_existing`.

- [ ] **Step 3: Write minimal implementation**

In `linrdp/src/session/mod.rs`:

```rust
use std::ops::RangeInclusive;
use std::path::Path;

/// The user's running session, if one is recorded.
pub(crate) fn attach_existing(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
) -> Option<registry::SessionRecord> {
    registry::find(base, user, range)
}
```

Then wire the worker path in `linrdp/src/main.rs`. After the credential validator confirms the username (the `ConnectionInfo` hook already fires with the authenticated identity), the worker resolves its session:

```rust
    // The desktop is chosen by the AUTHENTICATED identity. The X.224
    // mstshash cookie is never consulted: it is client-supplied and
    // unauthenticated, so trusting it would let anyone pick whose desktop
    // they land on.
    let session = match session::attach_existing(Path::new(session::runtime_dir::STATE_DIR), &authenticated_user, display_range.clone()) {
        Some(existing) => existing,
        None => session::create(Path::new(session::runtime_dir::STATE_DIR), &authenticated_user, display_range.clone(), desktop_size)?,
    };
    // SAFETY: single-threaded at this point in the worker.
    unsafe { std::env::set_var("DISPLAY", format!(":{}", session.display)) };
    unsafe { std::env::set_var("XAUTHORITY", &session.xauthority) };
```

And `create`, which composes Tasks 2, 3, 4, 6 and 8:

```rust
/// Build a new session for `user`: claim a display, open a PAM session so
/// logind creates the runtime dir, write the cookie there, start the X
/// server, and record the result.
///
/// The `DisplayLease` is deliberately leaked into the keeper: the flock must
/// outlive this function, because the session outlives the connection that
/// created it. Every early return drops the lease, which releases the claim —
/// that is what keeps a failed setup from stranding a display number.
pub(crate) fn create(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
    size: (u16, u16),
) -> anyhow::Result<registry::SessionRecord> {
    let ids = privilege::lookup_user(user)?;
    let lease = display_alloc::allocate(base, range)?;

    // PAM first: pam_systemd creates /run/user/<uid> (0700, user-owned),
    // and there is nowhere safe to put the cookie until it exists.
    let mut pam = pam_session::libpam_session();
    let env = pam
        .open(user, "")
        .map_err(|e| anyhow::anyhow!("pam_open_session for {user}: {e}"))?;
    let runtime_dir = env
        .runtime_dir()
        .context("PAM did not provide XDG_RUNTIME_DIR — is pam_systemd.so in /etc/pam.d/linrdp?")?
        .to_owned();

    let xauthority = xauth::write_cookie(&runtime_dir, lease.number, &ids)?;
    let rec = registry::SessionRecord {
        user: user.to_owned(),
        display: lease.number,
        runtime_dir,
        xauthority: xauthority.to_string_lossy().into_owned(),
    };

    let cmd = keeper::xvfb_command(rec.display, &rec.xauthority, size);
    let env_pairs = keeper::session_env(&rec, &ids);
    keeper::spawn_detached(&cmd, &env_pairs, &ids)
        .with_context(|| format!("start X server for {user} on :{}", rec.display))?;

    lease.record_owner(user)?;
    registry::write_record(base, &rec)?;
    // The keeper now owns the claim and the PAM handle for the session's life.
    core::mem::forget(lease);
    core::mem::forget(pam);
    Ok(rec)
}
```

`pam_session::libpam_session()` returns the libpam-backed `PamSessionApi`
implementation (the dlopen'd calls from Task 3), and
`keeper::spawn_detached(cmd, env, ids)` double-forks, applies `env`, drops
privileges with `privilege::drop_to(ids)` and execs — both are added here
alongside `create`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp`
Expected: PASS, whole suite.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/mod.rs linrdp/src/main.rs
git commit -m "worker: serve the authenticated user's own session"
```

---

### Task 10: Console mode and the PAM stack

**Files:**
- Create: `deploy/pam.d-linrdp` (installed to `/etc/pam.d/linrdp`)
- Modify: `linrdp/src/main.rs` (`--console` short-circuits session resolution)
- Modify: `deploy/linrdp.service`
- Modify: `README.md`

**Interfaces:**
- Consumes: the `--console` flag from Task 7.
- Produces: no new Rust interfaces.

- [ ] **Step 1: Write the failing test**

```rust
    /// --console must bypass session resolution entirely: it is the
    /// mstsc /admin equivalent and attaches to the shared display.
    #[test]
    fn console_mode_uses_the_ambient_display() {
        let base = temp_base("console");
        // Even with a recorded session for this user, console mode ignores it.
        registry::write_record(
            &base,
            &registry::SessionRecord {
                user: "alice".to_owned(),
                display: 11,
                runtime_dir: "/run/user/1001".to_owned(),
                xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
            },
        )
        .expect("seed");

        let resolved = resolve_display(&base, "alice", 10..=20, /* console */ true, ":99");

        assert_eq!(resolved, ":99", "console mode must not route to a per-user session");

        let resolved = resolve_display(&base, "alice", 10..=20, false, ":99");
        assert_eq!(resolved, ":11", "without console mode the user's own session wins");
        let _ = std::fs::remove_dir_all(&base);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p linrdp console_mode`
Expected: FAIL — `cannot find function resolve_display`.

- [ ] **Step 3: Write minimal implementation**

```rust
/// Which display this connection serves.
///
/// `console` is the `mstsc /admin` equivalent: attach to the ambient
/// `$DISPLAY` (the Selkies/VNC-shared screen) instead of a per-user session.
pub(crate) fn resolve_display(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
    console: bool,
    ambient: &str,
) -> String {
    if console {
        return ambient.to_owned();
    }
    match attach_existing(base, user, range) {
        Some(rec) => format!(":{}", rec.display),
        None => ambient.to_owned(),
    }
}
```

`deploy/pam.d-linrdp`:

```
# PAM stack for linrdp sessions. pam_systemd is what registers the session
# with logind and creates /run/user/<uid> (0700, user-owned) where the
# session's X cookie lives — without it there is no runtime dir to put the
# cookie in.
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_limits.so
session    required   pam_unix.so
session    optional   pam_systemd.so
```

README gains a "Multi-session" section documenting `--supervisor`,
`--display-range`, `--console`, and that `/etc/pam.d/linrdp` must exist.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp && cargo clippy -p linrdp --all-targets`
Expected: PASS, no clippy errors.

- [ ] **Step 5: Commit**

```bash
git add deploy/pam.d-linrdp deploy/linrdp.service linrdp/src/main.rs README.md
git commit -m "session: console mode for the shared display, PAM stack, docs"
```

---

### Task 11: Session teardown and stale-record reaping

**Files:**
- Modify: `linrdp/src/session/mod.rs`
- Modify: `linrdp/src/session/registry.rs`

**Interfaces:**
- Consumes: `display_alloc::allocate`, `registry::{record_path, find}`.
- Produces:
  - `pub(crate) fn is_stale(base: &Path, display: u16, range: RangeInclusive<u16>) -> bool`
  - `pub(crate) fn forget(base: &Path, display: u16) -> anyhow::Result<()>`

The spec requires that a session whose X server died is torn down and the
next connection gets a fresh one, and that a supervisor restart never
orphans a display. Both reduce to one question: is this record backed by a
live keeper? A free `flock` answers it — the kernel released the lock when
the keeper died.

- [ ] **Step 1: Write the failing test**

```rust
    /// A record whose display lock is free belongs to a dead keeper.
    #[test]
    fn a_record_without_a_live_lock_is_stale() {
        let base = temp_base("stale");
        registry::write_record(
            &base,
            &registry::SessionRecord {
                user: "alice".to_owned(),
                display: 11,
                runtime_dir: "/run/user/1001".to_owned(),
                xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
            },
        )
        .expect("seed");

        assert!(is_stale(&base, 11, 11..=11), "nobody holds the lock, so the keeper is gone");

        // While a lease is held, the same record is live.
        let _held = display_alloc::allocate(&base, 11..=11).expect("hold the lock");
        assert!(!is_stale(&base, 11, 11..=11), "a held lock means a live session");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Forgetting a dead session must free the number for reuse.
    #[test]
    fn forgetting_a_session_frees_the_display() {
        let base = temp_base("forget");
        registry::write_record(
            &base,
            &registry::SessionRecord {
                user: "alice".to_owned(),
                display: 11,
                runtime_dir: "/run/user/1001".to_owned(),
                xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
            },
        )
        .expect("seed");

        forget(&base, 11).expect("forget");

        assert!(attach_existing(&base, "alice", 10..=20).is_none(), "the record is gone");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A stale record must not send a reconnecting user to a dead desktop.
    #[test]
    fn attach_skips_a_stale_record() {
        let base = temp_base("skipstale");
        registry::write_record(
            &base,
            &registry::SessionRecord {
                user: "alice".to_owned(),
                display: 11,
                runtime_dir: "/run/user/1001".to_owned(),
                xauthority: "/run/user/1001/linrdp/Xauthority".to_owned(),
            },
        )
        .expect("seed");

        assert!(
            attach_live(&base, "alice", 10..=20).is_none(),
            "a record with no live keeper must not be attached to"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p linrdp session::tests`
Expected: FAIL — `cannot find function is_stale`.

- [ ] **Step 3: Write minimal implementation**

```rust
/// Whether the record for `display` is backed by a live keeper.
///
/// A free `flock` is proof the keeper is gone: the kernel drops the lock
/// when the holding process dies, so this survives crashes and a supervisor
/// restart without any bookkeeping of our own.
pub(crate) fn is_stale(base: &Path, display: u16, range: RangeInclusive<u16>) -> bool {
    let _ = range;
    match display_alloc::allocate(base, display..=display) {
        // We got the lock, so nobody was holding it.
        Ok(_lease) => true,
        Err(_) => false,
    }
}

/// Drop the record for a dead session so the number can be reused.
pub(crate) fn forget(base: &Path, display: u16) -> anyhow::Result<()> {
    let path = registry::record_path(base, display);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("remove {}", path.display()))),
    }
}

/// The user's session, but only if a keeper is still holding it.
pub(crate) fn attach_live(
    base: &Path,
    user: &str,
    range: RangeInclusive<u16>,
) -> Option<registry::SessionRecord> {
    let rec = attach_existing(base, user, range.clone())?;
    if is_stale(base, rec.display, range) {
        // The desktop died; clear the record so the next create() starts clean.
        let _ = forget(base, rec.display);
        return None;
    }
    Some(rec)
}
```

Change the worker in `linrdp/src/main.rs` to call `attach_live` rather than
`attach_existing`, so a reconnect never lands on a dead desktop.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p linrdp`
Expected: PASS, whole suite.

- [ ] **Step 5: Commit**

```bash
git add linrdp/src/session/mod.rs linrdp/src/session/registry.rs linrdp/src/main.rs
git commit -m "session: reap dead sessions so a reconnect never lands on one"
```

---

## Integration checklist (manual, on this host)

These cannot be unit-tested; run them after Task 10.

- [ ] Two different Unix accounts connect at once. Each sees its own desktop.
- [ ] `loginctl list-sessions` shows both, with the correct uids.
- [ ] `ls -ld /run/linrdp` is `drwx------ root root`.
- [ ] `ls -l /run/user/<uid>/linrdp/Xauthority` is `-rw------- <user> <user>`.
- [ ] `pgrep -a Xvfb` shows no `-ac` on any per-session server.
- [ ] From account B: `DISPLAY=:<A's display> xwd -root` **fails** (no cookie).
- [ ] `grep Uid /proc/<worker pid>/status` shows the session user, not 0.
- [ ] Disconnect and reconnect as the same user: the same windows are open.
- [ ] `systemctl restart linrdp` with a live session, then reconnect: still the same desktop.
- [ ] `--console` still reaches `:99` alongside Selkies and VNC.
- [ ] Kill a session's Xvfb: the next connection for that user creates a fresh session rather than failing.
