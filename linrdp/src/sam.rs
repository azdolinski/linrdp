//! NLA credentials store (SAM), MS-RDPBCGR 5.4.2 compliant.
//!
//! CredSSP/NLA authentication uses NTLMv2, which by the protocol's own math
//! (MS-NLMP) requires the server to know the account's secret (password or
//! NT hash) — a Windows server reads it from SAM. On Linux `/etc/shadow`
//! stores only a one-way hash (yescrypt), which NTLM cannot use.
//!
//! LinRDP therefore keeps its own SAM at `/var/lib/linrdp/sam`, mode 0600 and
//! root-owned — the same trust model as `/etc/shadow`.
//!
//! **At rest the passwords are encrypted, not cleartext.** Each is sealed with
//! AES-256-GCM under a key derived (HKDF-SHA256) from this host's identity —
//! DMI `product_uuid` plus `/etc/machine-id`, or `machine-id` alone when DMI is
//! absent. The account name is bound in as associated data, and the mode is
//! recorded per entry so a read reconstructs the right key.
//!
//! Be honest about what that buys. The file is already root-only, so this is
//! not a barrier against a local attacker who is already root — they read the
//! same machine identity the server does. What it does give, exactly as
//! Windows' LSA secrets do, is that the store holds no *readable* secret (no
//! casual, screenshot, backup or bug-report disclosure of the actual password)
//! and that the ciphertext is **machine-bound**: a file copied to another host
//! will not decrypt. If the host identity changes (board swap, VM clone), the
//! entries stop opening and are treated as absent — the next successful PAM
//! login re-learns them.
//!
//! Nothing here is ever provisioned by hand, and linrdp has no flag to do it
//! with. The only writer is the PAM capture (`--capture-credential`, see
//! `main::capture_credential`), which records a password the system itself
//! has just accepted. That is the whole point: the login uses the account's
//! system password and no other, so there is no second secret to set, rotate
//! or forget. An entry that did not come from a successful authentication
//! would be a password the system does not agree with.
//!
//! After CredSSP completes, the delegated credentials are additionally
//! verified against `/etc/shadow` (see `auth::ShadowValidator`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

const SAM_DIR: &str = "/var/lib/linrdp";
const SAM_FILE: &str = "/var/lib/linrdp/sam";
/// The file every writer of the store locks before reading it.
///
/// Separate from the store itself because the store is replaced by `rename`:
/// a lock taken on the old inode would mean nothing to the next writer, which
/// opens the new one. A fixed path nobody renames is what two processes can
/// agree on.
const SAM_LOCK: &str = "/var/lib/linrdp/sam.lock";

/// Current sealed-blob version. Bump when the wire format or cipher changes so
/// old entries can still be recognised (and refused) rather than misread.
const BLOB_VERSION: &str = "v1";
/// AES-GCM nonce length (96 bits, the standard for this mode).
const NONCE_LEN: usize = 12;

/// Which machine secret keyed a sealed blob. Recorded in the blob itself so a
/// read reconstructs the same key even if DMI availability flickers between
/// the write and the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyMode {
    /// HKDF over DMI `product_uuid` concatenated with `/etc/machine-id`.
    Dmi,
    /// HKDF over `/etc/machine-id` alone (DMI absent or empty).
    MachineId,
}

impl KeyMode {
    /// The single character that stands for this mode inside a blob.
    fn tag(self) -> char {
        match self {
            KeyMode::Dmi => 'd',
            KeyMode::MachineId => 'm',
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "d" => Some(KeyMode::Dmi),
            "m" => Some(KeyMode::MachineId),
            _ => None,
        }
    }
}

/// Seal `password` for `account` under `key`, producing a self-describing blob
/// `v1.<mode>.<base64url(nonce || ciphertext||tag)>`.
///
/// The account name is bound in as AES-GCM associated data, so a blob cannot be
/// lifted from one account's line and replayed under another's.
fn seal(key: &[u8; 32], mode: KeyMode, account: &str, password: &str) -> String {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS CSPRNG");
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: password.as_bytes(),
                aad: account.as_bytes(),
            },
        )
        .expect("AES-GCM encryption does not fail for valid inputs");

    let mut packed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);
    format!("{BLOB_VERSION}.{}.{}", mode.tag(), B64.encode(packed))
}

/// Recover the password from a sealed blob, deriving the key for the mode the
/// blob names via `key_for`. `None` for anything that is not a well-formed,
/// authentic `v1` blob for `account`.
fn open(blob: &str, account: &str, key_for: impl Fn(KeyMode) -> [u8; 32]) -> Option<String> {
    let mut parts = blob.splitn(3, '.');
    let (version, tag, body) = (parts.next()?, parts.next()?, parts.next()?);
    if version != BLOB_VERSION {
        return None;
    }
    let mode = KeyMode::from_tag(tag)?;
    let packed = B64.decode(body).ok()?;
    if packed.len() <= NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = packed.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce).ok()?;

    let key = key_for(mode);
    let cipher = Aes256Gcm::new((&key).into());
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: account.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(plaintext).ok()
}

/// First line of a sealed store. Its presence is what distinguishes a sealed
/// file from a legacy cleartext one: with a header every entry is a blob,
/// without one every entry is a bare `user:password`. A file-level marker
/// avoids guessing per line — a legacy password could itself start with `v1.`.
const SEAL_HEADER: &str = "#linrdp-sam v1";

/// Parse a store body into username→password, deriving keys for sealed entries
/// via `key_for`.
///
/// A body that begins with [`SEAL_HEADER`] is sealed: each entry is decrypted,
/// and one that will not open on this machine is dropped with a warning — it is
/// unusable for NLA and will be re-learned on the next successful PAM login. A
/// body without the header is legacy cleartext, read verbatim.
fn parse_body(body: &str, key_for: impl Fn(KeyMode) -> [u8; 32] + Copy) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut lines = body.lines();
    let sealed = matches!(lines.clone().next(), Some(first) if first == SEAL_HEADER);
    if sealed {
        lines.next(); // consume the header
    }
    for line in lines {
        let Some((user, rest)) = line.split_once(':') else {
            continue;
        };
        if user.is_empty() {
            continue;
        }
        if sealed {
            match open(rest, user, key_for) {
                Some(password) => {
                    map.insert(user.to_owned(), password);
                }
                None => tracing::warn!(
                    %user,
                    "a SAM entry could not be decrypted on this machine — ignoring it; \
                     the next successful PAM login will re-learn this account"
                ),
            }
        } else {
            map.insert(user.to_owned(), rest.to_owned());
        }
    }
    map
}

/// Render a username→password map as a sealed store body: the header followed
/// by one `user:blob` line per account, each sealed under `key`/`mode`.
fn render_body(map: &HashMap<String, String>, key: &[u8; 32], mode: KeyMode) -> String {
    let mut body = String::from(SEAL_HEADER);
    body.push('\n');
    for (user, password) in map {
        body.push_str(user);
        body.push(':');
        body.push_str(&seal(key, mode, user, password));
        body.push('\n');
    }
    body
}

/// Whether a store body still holds cleartext that should be migrated: any
/// non-empty body that does not begin with the sealed-file header.
fn body_has_legacy(body: &str) -> bool {
    !body.trim().is_empty() && body.lines().next() != Some(SEAL_HEADER)
}

/// HKDF salt and info. Neither is secret; they only separate this key from any
/// other use of the same machine identity. Baked into the format like the
/// blob version — changing either invalidates every existing blob.
const HKDF_SALT: &[u8] = b"linrdp-sam-v1";
const HKDF_INFO: &[u8] = b"sam-aes256gcm";

/// Stretch a machine-identity input into a 256-bit AES key via HKDF-SHA256.
fn derive_key(ikm: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// The sealing input and mode for a given identity: DMI `product_uuid`
/// concatenated with `machine_id` when the former is present, else the
/// `machine_id` alone. Inputs are trimmed so trailing newlines from the source
/// files do not change the key.
fn build_ikm(product_uuid: &str, machine_id: &str) -> (Vec<u8>, KeyMode) {
    let (pu, mid) = (product_uuid.trim(), machine_id.trim());
    if pu.is_empty() {
        (mid.as_bytes().to_vec(), KeyMode::MachineId)
    } else {
        (ikm_for_mode(pu, mid, KeyMode::Dmi), KeyMode::Dmi)
    }
}

/// Rebuild the sealing input for an explicit `mode` — the read-side counterpart
/// of [`build_ikm`], so a blob that names its mode opens with the same key it
/// was sealed under.
fn ikm_for_mode(product_uuid: &str, machine_id: &str, mode: KeyMode) -> Vec<u8> {
    let (pu, mid) = (product_uuid.trim(), machine_id.trim());
    match mode {
        KeyMode::Dmi => {
            let mut ikm = Vec::with_capacity(pu.len() + mid.len());
            ikm.extend_from_slice(pu.as_bytes());
            ikm.extend_from_slice(mid.as_bytes());
            ikm
        }
        KeyMode::MachineId => mid.as_bytes().to_vec(),
    }
}

pub(crate) fn sam_path() -> PathBuf {
    PathBuf::from(SAM_FILE)
}

/// Where this machine's identity is read from. `product_uuid` is root-only
/// (0400) and ties to the board/firmware; `machine-id` is always present on a
/// systemd host and stable across reboots.
const DMI_PRODUCT_UUID: &str = "/sys/class/dmi/id/product_uuid";
const MACHINE_ID: &str = "/etc/machine-id";

/// Read an identity file, trimmed; empty string when it is missing or
/// unreadable (a non-root read of `product_uuid`, a host without DMI).
fn read_id(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default().trim().to_owned()
}

/// The sealing input and mode for this machine right now.
fn machine_ikm() -> (Vec<u8>, KeyMode) {
    let (pu, mid) = (read_id(DMI_PRODUCT_UUID), read_id(MACHINE_ID));
    if pu.is_empty() && mid.is_empty() {
        tracing::error!(
            "no machine identity: neither DMI product_uuid nor /etc/machine-id is readable — \
             the SAM will still be encrypted, but the key is not bound to this host"
        );
    }
    build_ikm(&pu, &mid)
}

/// Derive the key for a blob's recorded `mode` from this machine's identity —
/// the read-side counterpart of [`machine_ikm`], passed to [`open`].
fn machine_key_for(mode: KeyMode) -> [u8; 32] {
    let (pu, mid) = (read_id(DMI_PRODUCT_UUID), read_id(MACHINE_ID));
    derive_key(&ikm_for_mode(&pu, &mid, mode))
}

/// Write `body` to `path` privately and atomically: a fresh 0600 temp file in
/// the same directory, then a rename over the target, so a reader never sees a
/// half-written store and the secrets never pass through a world-readable file.
///
/// The temp name carries this process's pid so two writers of the same store —
/// the two supervisors (port 3389 and 3390) migrating at once, say — do not
/// share one temp file and race each other's rename. Whichever renames last
/// wins with identical content; nobody trips over a vanished temp.
fn write_private(path: &Path, body: &str) -> std::io::Result<()> {
    crate::atomic::write(path, body, 0o600)
}

/// The usernames present in a store body, in file order, without decrypting
/// anything — usable on both sealed and legacy files.
fn parse_names(body: &str) -> Vec<String> {
    let mut lines = body.lines();
    if matches!(lines.clone().next(), Some(first) if first == SEAL_HEADER) {
        lines.next();
    }
    lines
        .filter_map(|line| line.split_once(':').map(|(u, _)| u))
        .filter(|u| !u.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Load the SAM into a username→password map, decrypting each entry with this
/// machine's key. Returns an empty map when the file does not exist yet.
pub(crate) fn load() -> std::io::Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(SAM_FILE)?;
    Ok(parse_body(&content, machine_key_for))
}

/// An exclusive claim on the store, held for a whole read–modify–write.
///
/// `flock` rather than anything of our own, for the same reason the display
/// allocator uses it: the kernel releases it when the holder dies, so a
/// crashed writer cannot wedge the store.
struct StoreLock {
    /// Held purely for its `flock`; closing it releases the claim.
    _file: std::fs::File,
}

impl StoreLock {
    /// Take the lock, waiting for whoever holds it.
    ///
    /// Blocking on purpose. The writers are PAM capture helpers, each of
    /// which runs once per login and holds this for the length of one small
    /// file rewrite; giving up instead would silently drop the password the
    /// login just proved, which is exactly the update that matters.
    fn acquire() -> std::io::Result<Self> {
        Self::at(Path::new(SAM_LOCK))
    }

    /// The mechanism itself, on a named file, so it can be exercised without
    /// writing to `/var/lib`.
    fn at(path: &Path) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        // SAFETY: a valid open fd; LOCK_EX without LOCK_NB waits its turn.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

/// Set (or update) one user's password in the SAM, sealed to this machine.
/// Creates the store with root-only permissions when missing.
///
/// The read, the change and the write are one locked step. They were three
/// unsynchronised ones, and two captures finishing together — two logins, or
/// one login on each of two listeners — each read the same map, each added
/// its own account, and whichever renamed last threw the other's entry away.
/// The atomic rename kept the file from ever being half-written; it could do
/// nothing about an update that was simply gone.
pub(crate) fn set_password(username: &str, password: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(SAM_DIR)?;
    let _lock = StoreLock::acquire()?;
    set_password_locked(username, password)
}

/// The read–modify–write itself, with the lock already held.
fn set_password_locked(username: &str, password: &str) -> std::io::Result<()> {
    let mut map = load().unwrap_or_default();
    map.insert(username.to_owned(), password.to_owned());

    let (ikm, mode) = machine_ikm();
    let body = render_body(&map, &derive_key(&ikm), mode);
    write_private(&sam_path(), &body)
}

/// The account names the SAM holds, sorted. Empty when the store is missing.
///
/// Names only, and never decrypted — the secrets stay in this module. Callers
/// want to report what is provisioned, never what the passwords are.
pub(crate) fn account_names() -> Vec<String> {
    let content = std::fs::read_to_string(SAM_FILE).unwrap_or_default();
    let mut names = parse_names(&content);
    names.sort();
    names
}

/// Look up one user's stored password (None = not provisioned / locked / not
/// decryptable on this machine).
pub(crate) fn lookup(username: &str) -> std::io::Result<Option<String>> {
    Ok(load()?.get(username).cloned())
}

/// Rewrite a legacy cleartext store in sealed form. A no-op when the file is
/// missing or already sealed, so it is safe to call unconditionally at startup.
pub(crate) fn migrate_plaintext() {
    // Cheap check first: the common case is a store that is already sealed,
    // or absent, and neither is worth taking the lock for.
    match std::fs::read_to_string(SAM_FILE) {
        Ok(content) if body_has_legacy(&content) => {}
        _ => return,
    }
    // Under the same lock as every other rewrite: two supervisors starting
    // together (port 3389 and 3390) both migrate, and without this the second
    // one's rewrite could land on top of a capture that happened in between.
    let _lock = match StoreLock::acquire() {
        Ok(lock) => lock,
        Err(error) => {
            tracing::warn!(%error, "could not lock the SAM to migrate it — leaving it as it is");
            return;
        }
    };
    let content = match std::fs::read_to_string(SAM_FILE) {
        Ok(content) => content,
        Err(_) => return, // missing or unreadable here — nothing to migrate
    };
    if !body_has_legacy(&content) {
        return; // somebody else migrated it while we waited for the lock
    }
    let map = parse_body(&content, machine_key_for); // legacy → cleartext
    let (ikm, mode) = machine_ikm();
    let body = render_body(&map, &derive_key(&ikm), mode);
    match write_private(&sam_path(), &body) {
        Ok(()) => tracing::info!(
            count = map.len(),
            "migrated the SAM to machine-bound encrypted storage"
        ),
        Err(error) => tracing::warn!(
            %error,
            "could not rewrite the SAM in encrypted form — leaving the existing file untouched"
        ),
    }
}

#[cfg(test)]
mod tests {
    /// Two writers must not be able to lose each other's update.
    ///
    /// Regression: `set_password` was an unsynchronised read–modify–write of
    /// the whole map. Two captures finishing together — two logins, or one on
    /// each of two listeners — each read the same state, each added its own
    /// account, and whichever renamed last discarded the other's entry. The
    /// atomic rename kept the file from ever being half-written; it could do
    /// nothing about an update that was simply gone.
    ///
    /// The store's own path is `/var/lib/linrdp`, which a test may not write,
    /// so this drives the lock the rewrite now runs under.
    #[test]
    fn the_store_lock_lets_only_one_writer_in_at_a_time() {
        let dir = std::env::temp_dir().join(format!("linrdp-samlock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let lock_path = dir.join("sam.lock");

        let inside = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let overlapped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let workers: Vec<_> = (0..4)
            .map(|_| {
                let (path, inside, overlapped) =
                    (lock_path.clone(), inside.clone(), overlapped.clone());
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        let _guard = StoreLock::at(&path).expect("lock");
                        if inside.fetch_add(1, core::sync::atomic::Ordering::SeqCst) != 0 {
                            overlapped.store(true, core::sync::atomic::Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                        inside.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }

        assert!(
            !overlapped.load(core::sync::atomic::Ordering::SeqCst),
            "two writers were inside the read-modify-write at once, which is how an update gets lost"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    // A fixed key so the crypto core can be exercised without touching /sys.
    const K: [u8; 32] = [7u8; 32];

    #[test]
    fn seal_then_open_round_trips() {
        let blob = seal(&K, KeyMode::MachineId, "alice", "hunter2");
        assert!(blob.starts_with("v1.m."), "blob carries version and mode: {blob}");
        assert!(!blob.contains("hunter2"), "the password must not appear in cleartext");

        let got = open(&blob, "alice", |_mode| K).expect("opens with the same key");
        assert_eq!(got, "hunter2");
    }

    #[test]
    fn a_blob_cannot_be_replayed_under_another_account() {
        let blob = seal(&K, KeyMode::MachineId, "alice", "hunter2");
        // Same key, wrong account: the AES-GCM tag over the account name fails.
        assert_eq!(open(&blob, "bob", |_mode| K), None);
    }

    #[test]
    fn a_wrong_key_does_not_open() {
        let blob = seal(&K, KeyMode::MachineId, "alice", "hunter2");
        let other = [9u8; 32];
        assert_eq!(open(&blob, "alice", |_mode| other), None);
    }

    #[test]
    fn the_dmi_mode_round_trips_and_is_tagged() {
        let blob = seal(&K, KeyMode::Dmi, "alice", "s3cret");
        assert!(blob.starts_with("v1.d."), "carries the dmi mode tag: {blob}");
        assert_eq!(open(&blob, "alice", |_mode| K).as_deref(), Some("s3cret"));
    }

    #[test]
    fn junk_and_legacy_lines_are_not_mistaken_for_blobs() {
        // Cleartext (legacy), wrong version, and corrupt base64 all decline.
        assert_eq!(open("hunter2", "alice", |_mode| K), None);
        let blob = seal(&K, KeyMode::MachineId, "alice", "hunter2");
        let bumped = blob.replacen("v1.", "v2.", 1);
        assert_eq!(open(&bumped, "alice", |_mode| K), None);
        assert_eq!(open("v1.m.!!!not-base64!!!", "alice", |_mode| K), None);
    }

    #[test]
    fn a_legacy_plaintext_body_is_read_as_is() {
        let map = parse_body("alice:hunter2\nbob:pw\n", |_mode| K);
        assert_eq!(map.get("alice").map(String::as_str), Some("hunter2"));
        assert_eq!(map.get("bob").map(String::as_str), Some("pw"));
    }

    #[test]
    fn a_sealed_body_round_trips_and_holds_no_cleartext() {
        let mut map = HashMap::new();
        map.insert("alice".to_owned(), "hunter2".to_owned());
        map.insert("bob".to_owned(), "s3cret".to_owned());

        let body = render_body(&map, &K, KeyMode::Dmi);
        assert!(!body.contains("hunter2") && !body.contains("s3cret"), "no cleartext: {body}");
        let mut lines = body.lines();
        assert_eq!(lines.next(), Some(SEAL_HEADER), "sealed files start with the header");
        assert!(lines.all(|l| l.contains(":v1.d.")), "every entry is a v1 dmi blob: {body}");

        assert_eq!(parse_body(&body, |_mode| K), map);
    }

    #[test]
    fn an_unopenable_sealed_line_is_dropped_not_kept() {
        let good = seal(&K, KeyMode::MachineId, "alice", "hunter2");
        let junk = B64.encode([0u8; NONCE_LEN + 4]); // valid shape, wrong bytes
        let body = format!("{SEAL_HEADER}\nalice:{good}\nbob:v1.m.{junk}\n");

        let map = parse_body(&body, |_mode| K);
        assert_eq!(map.get("alice").map(String::as_str), Some("hunter2"));
        assert!(!map.contains_key("bob"), "a sealed line that will not open is unusable and dropped");
    }

    #[test]
    fn write_private_is_atomic_private_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("linrdp-wp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("sam");

        write_private(&path, "hello\n").expect("writes");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\n");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        write_private(&path, "world\n").expect("overwrites in place");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "world\n");

        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(strays.is_empty(), "an atomic write leaves no temp sibling: {strays:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_are_listed_without_decrypting_either_format() {
        let sealed = format!(
            "{SEAL_HEADER}\nalice:{}\nbob:{}\n",
            seal(&K, KeyMode::Dmi, "alice", "x"),
            seal(&K, KeyMode::Dmi, "bob", "y"),
        );
        assert_eq!(parse_names(&sealed), vec!["alice".to_owned(), "bob".to_owned()]);
        assert_eq!(parse_names("carol:pw\nalice:pw2\n"), vec!["carol".to_owned(), "alice".to_owned()]);
        assert!(parse_names("").is_empty());
    }

    #[test]
    fn the_key_derivation_is_deterministic_and_separates_inputs() {
        assert_eq!(derive_key(b"abc"), derive_key(b"abc"), "same ikm, same key");
        assert_ne!(derive_key(b"abc"), derive_key(b"abd"), "a different ikm gives a different key");
    }

    #[test]
    fn ikm_prefers_dmi_and_falls_back_to_machine_id() {
        let (ikm, mode) = build_ikm(" UUID-123 \n", "mid-abc\n");
        assert_eq!(mode, KeyMode::Dmi);
        assert_eq!(ikm, b"UUID-123mid-abc", "dmi and machine-id are concatenated, trimmed");

        let (ikm, mode) = build_ikm("", "mid-abc");
        assert_eq!(mode, KeyMode::MachineId);
        assert_eq!(ikm, b"mid-abc", "empty dmi falls back to machine-id alone");
    }

    #[test]
    fn the_read_path_reconstructs_the_write_time_ikm() {
        // What build_ikm produced at write must be what ikm_for_mode rebuilds
        // at read for the recorded mode — otherwise sealed entries never open.
        let (w_ikm, mode) = build_ikm("uuid", "mid");
        assert_eq!(ikm_for_mode("uuid", "mid", mode), w_ikm);
        assert_eq!(ikm_for_mode("uuid", "mid", KeyMode::MachineId), b"mid");
    }

    #[test]
    fn a_legacy_password_that_looks_like_a_blob_is_still_read_verbatim() {
        // Without a file header the body is legacy cleartext, so a password
        // that happens to start with "v1." must not be mistaken for a blob.
        let map = parse_body("alice:v1.d.not-really-encrypted\n", |_mode| K);
        assert_eq!(map.get("alice").map(String::as_str), Some("v1.d.not-really-encrypted"));
    }

    #[test]
    fn legacy_bodies_are_flagged_for_migration_and_sealed_ones_are_not() {
        let mut map = HashMap::new();
        map.insert("alice".to_owned(), "hunter2".to_owned());

        assert!(body_has_legacy("alice:hunter2\n"), "cleartext must be migrated");
        assert!(body_has_legacy(&format!("alice:hunter2\nbob:{}\n", seal(&K, KeyMode::Dmi, "bob", "x"))),
            "a mix still has cleartext to migrate");
        assert!(!body_has_legacy(&render_body(&map, &K, KeyMode::Dmi)), "a fully sealed body is done");
        assert!(!body_has_legacy(""), "an empty store is nothing to migrate");
    }
}
