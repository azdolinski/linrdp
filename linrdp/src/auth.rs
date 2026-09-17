//! System authentication: verify a username/password pair against
//! `/etc/shadow` (SHA-512 / YESCRYPT / MD5 crypt), the same source SSH PAM
//! uses. Pure Rust — reads the shadow database directly; no external binaries.

use std::collections::HashMap;

use async_trait::async_trait;

use ironrdp_server::{CredentialDecision, CredentialValidationError, CredentialValidator, Credentials};

/// Validator backed by `/etc/shadow`, with the system PAM stack behind it.
///
/// This is the only authenticator that checks the account's **real** system
/// password. It runs on the TLS path, where the client sends its credentials
/// in the Client Info PDU after the channel is up, so the server never needs
/// to know the secret in advance.
pub(crate) struct ShadowValidator {
    /// Filled with the account this validator accepted, so the session router
    /// can create that user's desktop. Recorded only on success: the identity
    /// a session is built from must be one that was actually verified.
    pending: Option<std::sync::Arc<crate::session::router::PendingIdentity>>,
    /// `--auth greeter`: this validator does not decide anything, the logon
    /// screen does. A client that sends no credentials — or the wrong ones,
    /// which is what a client sends when it is just filling in the field its
    /// UI demands — must still reach the point where the screen can be drawn.
    /// Accepting here grants nothing: the gate is pointed at an X server with
    /// no session on it until the form itself authenticates.
    defer_to_greeter: bool,
}

impl ShadowValidator {
    pub(crate) fn new(pending: Option<std::sync::Arc<crate::session::router::PendingIdentity>>) -> Self {
        Self {
            pending,
            defer_to_greeter: false,
        }
    }

    /// Leave the decision to the logon screen that follows.
    pub(crate) fn deferring_to_greeter(mut self, defer: bool) -> Self {
        self.defer_to_greeter = defer;
        self
    }
}

/// What `/etc/shadow` holds for an account's password.
///
/// [`ShadowValidator::load_shadow`] cannot answer this: it drops every field
/// shorter than three characters, which is exactly the set that means
/// "locked" or "empty". A validator is right to treat those as "no verdict"
/// and fall through to PAM; a diagnostic has to name them, because a locked
/// account refuses every RDP login and no amount of configuration elsewhere
/// will change that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordState {
    /// A usable hash — PAM can authenticate this account.
    Set,
    /// Locked (`!`, `!!`, `*`): password authentication is refused outright.
    Locked,
    /// The password field is empty, which PAM refuses by default.
    Empty,
    /// Not in `/etc/shadow` at all — an NSS-only account (LDAP, SSSD), where
    /// PAM decides and shadow has no opinion to offer.
    Absent,
    /// `/etc/shadow` could not be read, so there is nothing to report.
    Unreadable,
}

/// What `/etc/shadow` says about `username`.
pub(crate) fn password_state(username: &str) -> PasswordState {
    match std::fs::read_to_string("/etc/shadow") {
        Ok(content) => classify_shadow(&content, username),
        Err(_) => PasswordState::Unreadable,
    }
}

/// Classify a shadow body directly, for tests in other modules.
#[cfg(test)]
pub(crate) fn classify_shadow_for_test(shadow: &str, username: &str) -> PasswordState {
    classify_shadow(shadow, username)
}

/// The classification itself, separated from the file so that every shape of
/// shadow entry can be tested without a machine that has one.
fn classify_shadow(shadow: &str, username: &str) -> PasswordState {
    for line in shadow.lines() {
        let mut parts = line.splitn(9, ':');
        let (Some(name), Some(field)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name != username {
            continue;
        }
        return if field.is_empty() {
            PasswordState::Empty
        } else if field.starts_with('!') || field.starts_with('*') {
            PasswordState::Locked
        } else {
            PasswordState::Set
        };
    }
    PasswordState::Absent
}

impl ShadowValidator {
    fn load_shadow() -> std::io::Result<HashMap<String, String>> {
        let content = std::fs::read_to_string("/etc/shadow")?;
        let mut map = HashMap::new();
        for line in content.lines() {
            let mut parts = line.splitn(9, ':');
            let name = parts.next().unwrap_or_default();
            let hash = parts.next().unwrap_or_default();
            if !name.is_empty() && hash.len() > 2 {
                map.insert(name.to_owned(), hash.to_owned());
            }
        }
        Ok(map)
    }
}

#[async_trait]
impl CredentialValidator for ShadowValidator {
    async fn validate(
        &self,
        credentials: &Credentials,
    ) -> Result<CredentialDecision, CredentialValidationError> {
        let username = credentials.username.clone();
        let username2 = username.clone();
        let password = credentials.password.clone();

        // Read + verify off the async path (file I/O + cost of the KDF).
        // The Ok(...) payload says whether PAM should be consulted as a
        // fallback: the shadow file is authoritative when it answers
        // definitively, but an unreadable file, an unknown user (SSSD/LDAP
        // accounts live outside /etc/shadow) or an unsupported hash scheme
        // is exactly the case the system PAM stack handles for us.
        let result = tokio::task::spawn_blocking(move || shadow_verdict(&username2, &password))
        .await
        .map_err(CredentialValidationError::new)?; // join error only

        // Greeter mode: never reject here. Record only what verified, so the
        // router can skip the form for a client that already sent something
        // correct, and show it to everyone else.
        if self.defer_to_greeter {
            if matches!(result, Ok(true)) {
                tracing::info!(%username, "credentials sent and verified — skipping the logon screen");
                self.accepted(&username, &credentials.password);
            } else {
                tracing::info!(%username, "no usable credentials — the logon screen will collect them");
            }
            return Ok(CredentialDecision::Accept);
        }

        match result {
            Ok(true) => {
                tracing::info!(%username, "authentication accepted");
                self.accepted(&username, &credentials.password);
                Ok(CredentialDecision::Accept)
            }
            Ok(false) => {
                tracing::warn!(%username, "authentication rejected");
                Ok(CredentialDecision::Reject)
            }

            Err(reason) if username.is_empty() => {
                // No username at all: the client connected without sending
                // credentials. That is what mstsc does on a non-NLA server —
                // it waits for a logon screen linrdp does not draw. Say so,
                // because "authentication rejected username=" reads like a
                // wrong password.
                let _ = reason;
                tracing::warn!(
                    "the client sent no credentials — without NLA it expects a server-drawn \
                     logon screen, which linrdp does not have. Use --auth nla (the default) \
                     for mstsc, or a client that sends credentials itself"
                );
                Ok(CredentialDecision::Reject)
            }
            Err(reason) => {
                // Shadow could not answer — fall back to the system PAM
                // stack (KRdp's primary path, our safety net). A PAM outage
                // is a backend error, not a rejection.
                let reason = reason.as_deref().unwrap_or("user not in /etc/shadow");
                tracing::info!(%username, %reason, "shadow lookup inconclusive - trying PAM");
                let (user, pass) = (username.clone(), credentials.password.clone());
                let pam = tokio::task::spawn_blocking(move || crate::pam::authenticate(&user, &pass))
                    .await
                    .map_err(CredentialValidationError::new)? // join error
                    .map_err(|e| CredentialValidationError::new(std::io::Error::other(e)))?;
                if pam {
                    tracing::info!(%username, "authentication accepted via PAM");
                    self.accepted(&username, &credentials.password);
                    Ok(CredentialDecision::Accept)
                } else {
                    tracing::warn!(%username, "authentication rejected (shadow+PAM)");
                    Ok(CredentialDecision::Reject)
                }
            }
        }
    }
}

impl ShadowValidator {
    /// Hand the verified account to the session router.
    fn accepted(&self, username: &str, password: &str) {
        if let Some(pending) = &self.pending {
            pending.record(username, password);
        }
    }
}

/// Verify `password` against the account's system password, blocking.
///
/// `/etc/shadow` first, then the system PAM stack for everything shadow
/// cannot answer for: an unreadable file, an account that lives in LDAP or
/// SSSD, or a hash scheme this build does not implement. `Err` means "no
/// verdict", never "wrong password".
///
/// The same core the RDP credential validator runs on, exposed so
/// provisioning can hold an NLA password to the system password it is
/// supposed to mirror.
pub(crate) fn verify_system_password(username: &str, password: &str) -> Result<bool, String> {
    match shadow_verdict(username, password) {
        Ok(verdict) => Ok(verdict),
        Err(reason) => {
            let reason = reason.unwrap_or_else(|| "user not in /etc/shadow".to_owned());
            tracing::debug!(%username, %reason, "shadow lookup inconclusive - trying PAM");
            crate::pam::authenticate(username, password).map_err(|e| format!("PAM: {e}"))
        }
    }
}

/// `/etc/shadow`'s verdict alone. `Err(reason)` = shadow cannot decide.
fn shadow_verdict(username: &str, password: &str) -> Result<bool, Option<String>> {
    let shadow = match ShadowValidator::load_shadow() {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                tracing::error!("cannot read /etc/shadow — run linrdp as root (or add CAP_DAC_READ_SEARCH)");
            }
            return Err(Some(format!("read /etc/shadow: {e}")));
        }
    };
    let Some(hash) = shadow.get(username) else {
        return Err(None); // unknown here — maybe known to PAM
    };
    if hash.starts_with('!') || hash.starts_with('*') {
        return Ok(false); // account locked / no password set
    }
    if !hash.contains('$') {
        // Pre-crypt or exotic entry pam_unix understands better.
        return Err(Some(format!("unparseable shadow hash: {hash:.8}...")));
    }
    let scheme = hash.trim_start_matches('$').split('$').next().unwrap_or_default();
    if !matches!(scheme, "1" | "5" | "6" | "y") {
        return Err(Some(format!("unsupported hash scheme ${scheme}$")));
    }
    Ok(verify_crypt(password, hash))
}

/// Verify `password` against an `/etc/shadow` hash (`$id$salt$hash`).
fn verify_crypt(password: &str, hash: &str) -> bool {
    let scheme = hash.trim_start_matches('$').split('$').next().unwrap_or_default();

    let verdict = match scheme {
        "1" | "5" | "6" => {
            // sha-crypt's check handles $5$/$6$ (and the legacy $1$ mapping onto
            // the same SHA-crypt verifier is intentionally not used; MD5 falls
            // back to the plain check below).
            if scheme == "1" {
                verify_md5(password, hash)
            } else {
                sha_crypt::sha512_check(password, hash).is_ok()
            }
        }
        "y" => use_yescrypt(password, hash),
        other => {
            tracing::warn!(scheme = other, "unsupported shadow hash scheme");
            false
        }
    };
    verdict
}

fn use_yescrypt(password: &str, hash: &str) -> bool {
    use yescrypt::password_hash::PasswordVerifier;
    match yescrypt::PasswordHashRef::new(hash) {
        Ok(h) => yescrypt::Yescrypt::default()
            .verify_password(password.as_bytes(), h)
            .is_ok(),
        Err(_) => false,
    }
}

/// Legacy MD5-crypt ($1$): minimal pure-Rust implementation of the FreeBSD
/// md5crypt algorithm (MD5-based iterated hash; standard, unmodified).
fn verify_md5(password: &str, hash: &str) -> bool {
    use md5::Context;

    let segs: Vec<&str> = hash.split('$').collect();
    // ["", "1", salt, digest]
    if segs.len() != 4 {
        return false;
    }
    let salt = segs[2];
    let expected = segs[3];
    let pw = password.as_bytes();
    let sl = salt.as_bytes();

    let mut h = Context::new();
    h.consume(pw);
    h.consume(b"$1$");
    h.consume(sl);

    let mut alt = Context::new();
    alt.consume(pw);
    alt.consume(sl);
    alt.consume(pw);
    let alt_digest = alt.compute().0;

    let mut pw_len = pw.len();
    while pw_len > 16 {
        h.consume(alt_digest);
        pw_len -= 16;
    }
    h.consume(&alt_digest[..pw_len]);

    let mut i = pw.len();
    while i > 0 {
        if i & 1 != 0 {
            h.consume([0u8]);
        } else {
            h.consume(&pw[..1]);
        }
        i >>= 1;
    }
    let mut digest = h.compute().0;

    for round in 0..1000 {
        let mut c = Context::new();
        if round & 1 != 0 {
            c.consume(pw);
        } else {
            c.consume(digest);
        }
        if round % 3 != 0 {
            c.consume(sl);
        }
        if round % 7 != 0 {
            c.consume(pw);
        }
        if round & 1 != 0 {
            c.consume(digest);
        } else {
            c.consume(pw);
        }
        digest = c.compute().0;
    }

    // md5crypt base64 alphabet with its specific output ordering.
    const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = String::new();
    let order = [
        [0usize, 6, 12],
        [1, 7, 13],
        [2, 8, 14],
        [3, 9, 15],
        [4, 10, 5],
    ];
    for grp in order {
        let (b0, b1, b2) = (digest[grp[0]] as u32, digest[grp[1]] as u32, digest[grp[2]] as u32);
        let mut w = (b2 << 16) | (b1 << 8) | b0;
        for _ in 0..4 {
            out.push(B64[(w & 0x3f) as usize] as char);
            w >>= 6;
        }
    }
    let mut w = digest[11] as u32;
    for _ in 0..2 {
        out.push(B64[(w & 0x3f) as usize] as char);
        w >>= 6;
    }
    constant_time_eq(out.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
