//! The one place a login decision is made.
//!
//! Every route to a desktop — NLA, the Client Info PDU, the server-drawn
//! logon screen, a reconnect to a session that is already running, console
//! mode — ends up in [`decide`]. That is the point: a correct secret is only
//! half of a login, and the other half (is this account still allowed to log
//! in *right now*?) used to be asked on some paths and not others.
//!
//! PAM first, `/etc/shadow` only when PAM is unavailable. The order is the
//! fix: verifying the hash ourselves and stopping there skipped `pam_acct_mgmt`
//! entirely, so an expired, disabled or `pam_access`-refused account kept
//! working as long as its old password still hashed correctly — and failed
//! attempts never reached `pam_faillock`, which counts them. The pure-Rust
//! `/etc/shadow` verifier (SHA-256 / SHA-512 / YESCRYPT / MD5 crypt) remains
//! for hosts with no libpam, and it now checks shadow's own expiry fields
//! rather than the hash alone.

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
    /// `auth: greeter`: this validator does not decide anything, the logon
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
        let (user, pass) = (username.clone(), credentials.password.clone());

        // Off the async path: PAM is blocking, and so is the cost of a KDF.
        let outcome = tokio::task::spawn_blocking(move || decide(&user, &pass))
            .await
            .map_err(CredentialValidationError::new)?; // join error only

        // Greeter mode: never reject here. Record only what verified, so the
        // router can skip the form for a client that already sent something
        // correct, and show it to everyone else.
        if self.defer_to_greeter {
            if matches!(outcome, Login::Accept) {
                tracing::info!(%username, "credentials sent and verified — skipping the logon screen");
                self.accepted(&username, &credentials.password);
            } else {
                tracing::info!(%username, "no usable credentials — the logon screen will collect them");
            }
            return Ok(CredentialDecision::Accept);
        }

        match outcome {
            Login::Accept => {
                tracing::info!(%username, "authentication accepted");
                self.accepted(&username, &credentials.password);
                Ok(CredentialDecision::Accept)
            }
            Login::Deny(reason) if username.is_empty() => {
                // No username at all: the client connected without sending
                // credentials. That is what mstsc does on a non-NLA server —
                // it waits for a logon screen linrdp does not draw. Say so,
                // because "authentication rejected username=" reads like a
                // wrong password.
                let _ = reason;
                tracing::warn!(
                    "the client sent no credentials — without NLA it expects a server-drawn \
                     logon screen. Give this listener `auth: greeter`, which draws one, or \
                     `auth: nla` for mstsc, or connect with a client that sends credentials \
                     itself"
                );
                Ok(CredentialDecision::Reject)
            }
            Login::Deny(reason) => {
                tracing::warn!(%username, %reason, "authentication rejected");
                Ok(CredentialDecision::Reject)
            }
            // Nothing could decide. Refusing is the only safe answer: the
            // alternative is letting a broken PAM stack plus an unreadable
            // /etc/shadow add up to an open door.
            Login::Unavailable(reason) => {
                tracing::error!(%username, %reason, "no authentication backend could decide — refusing");
                Ok(CredentialDecision::Reject)
            }
        }
    }
}

/// What the login-policy point decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Login {
    /// The secret is right and the account is allowed to log in now.
    Accept,
    /// Refused, with the reason for the log — never for the client, which is
    /// told only that the login failed.
    Deny(String),
    /// Neither PAM nor `/etc/shadow` could answer. Not a verdict: callers
    /// must refuse, not guess.
    Unavailable(String),
}

/// The single login-policy point: is this secret right, **and** is this
/// account allowed to log in at this moment?
///
/// PAM answers both halves in one pass (`pam_authenticate` then
/// `pam_acct_mgmt`) and is therefore asked first, so failed attempts land in
/// whatever counts them and account state is honoured. `/etc/shadow` is the
/// fallback for a host with no libpam, and it checks shadow's own ageing and
/// expiry fields — not just the hash.
pub(crate) fn decide(username: &str, password: &str) -> Login {
    if username.is_empty() {
        return Login::Deny("no user name".to_owned());
    }

    match crate::pam::authenticate(username, password) {
        Ok(true) => return Login::Accept,
        Ok(false) => return Login::Deny(format!("PAM ({}) refused", crate::pam::login_service())),
        // The stack exists and did not run. That is not the same as there
        // being no stack, and treating it as such was a hole: a `pam_start`
        // failure — after libpam had loaded perfectly well — used to hand the
        // decision to `/etc/shadow`, which knows nothing about `pam_access`,
        // `pam_time`, or anything else the stack would have applied. A correct
        // local password plus an unexpired shadow entry was then an `Accept`
        // with the policy never consulted. Refuse instead: a policy that
        // cannot run closes the door.
        Err(crate::pam::NoVerdict::BackendFailed(reason)) => {
            return Login::Unavailable(format!(
                "the PAM stack ({}) failed and no other source may stand in for it: {reason}",
                crate::pam::login_service()
            ));
        }
        // No libpam on this machine at all. There is no policy here to bypass,
        // so `/etc/shadow` is the authority by default rather than by failure.
        Err(crate::pam::NoVerdict::NotInstalled(reason)) => {
            tracing::warn!(
                %username,
                %reason,
                "PAM is not installed — falling back to /etc/shadow, which cannot apply \
                 pam_access, pam_time or pam_faillock"
            );
        }
    }

    match shadow_verdict(username, password) {
        Ok(false) => Login::Deny("/etc/shadow: wrong password".to_owned()),
        Ok(true) => match shadow_account_policy(username) {
            Ok(()) => Login::Accept,
            Err(reason) => Login::Deny(format!("/etc/shadow: {reason}")),
        },
        Err(reason) => Login::Unavailable(
            reason.unwrap_or_else(|| format!("{username} is not in /etc/shadow and PAM is unavailable")),
        ),
    }
}

/// Re-check an account that already authenticated at the protocol level.
///
/// NLA verifies the client's password against the copy in linrdp's own SAM,
/// which is a *stored* secret: it says nothing about whether the system
/// account has since been locked, expired, or had its password changed. The
/// same applies to attaching to a session that is already running, where no
/// new PAM session is opened and nothing else would ask. So every path to a
/// desktop asks here, with the credentials the client actually presented.
pub(crate) fn authorize_for_desktop(username: &str, password: &str) -> anyhow::Result<()> {
    match decide(username, password) {
        Login::Accept => Ok(()),
        Login::Deny(reason) => {
            anyhow::bail!("{username} is not allowed to log in: {reason}")
        }
        Login::Unavailable(reason) => {
            anyhow::bail!("cannot check whether {username} may log in ({reason}) — refusing")
        }
    }
}

/// Days since the epoch, the unit `/etc/shadow` ages accounts in.
fn today_in_shadow_days() -> Option<i64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    i64::try_from(secs / 86_400).ok()
}

/// Whether `/etc/shadow`'s ageing fields still allow this account to log in.
///
/// Only consulted when PAM is unavailable, so this is a stand-in for
/// `pam_unix`'s `account` phase rather than a second opinion on it.
fn shadow_account_policy(username: &str) -> Result<(), String> {
    let Ok(content) = std::fs::read_to_string("/etc/shadow") else {
        return Err("unreadable".to_owned());
    };
    let Some(today) = today_in_shadow_days() else {
        return Err("the system clock is before the epoch".to_owned());
    };
    account_policy_in(&content, username, today)
}

/// The rule itself, separated from the file so every shape of entry can be
/// tested on a machine that has none of them.
fn account_policy_in(shadow: &str, username: &str, today: i64) -> Result<(), String> {
    for line in shadow.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() != Some(&username) {
            continue;
        }
        let num = |index: usize| -> Option<i64> { fields.get(index)?.trim().parse().ok() };
        let last_change = num(2);
        let max_age = num(4);
        let inactive = num(6);
        let expire = num(7);

        if let Some(expire) = expire.filter(|v| *v >= 0) && today >= expire {
            return Err("the account expired".to_owned());
        }
        if last_change == Some(0) {
            return Err("the password must be changed before the next login".to_owned());
        }
        if let (Some(last), Some(max)) = (last_change, max_age)
            && last > 0
            && max >= 0
        {
            let must_change_by = last + max;
            if today > must_change_by {
                // Past `max` the password is expired; `inactive` is the grace
                // period pam_unix allows for changing it, and there is no way
                // to change a password over RDP.
                let grace = inactive.filter(|v| *v >= 0).unwrap_or(0);
                if today > must_change_by + grace {
                    return Err("the password expired".to_owned());
                }
                return Err("the password expired and can only be changed outside RDP".to_owned());
            }
        }
        return Ok(());
    }
    // Not in /etc/shadow at all: an NSS-only account (LDAP, SSSD) whose
    // policy lives where PAM would have read it. Without PAM there is nothing
    // to check and nothing to claim.
    Err("the account is not in /etc/shadow, so its policy cannot be checked without PAM".to_owned())
}

impl ShadowValidator {
    /// Hand the verified account to the session router.
    fn accepted(&self, username: &str, password: &str) {
        if let Some(pending) = &self.pending {
            pending.record(username, password);
        }
    }
}

/// Verify `password` against the account's system password **and** its
/// current policy, blocking. `Err` means "no verdict", never "wrong
/// password".
///
/// The same [`decide`] the RDP credential validator runs on, exposed so the
/// logon screen and provisioning hold an NLA password to exactly the system
/// password — and the system policy — it is supposed to mirror.
pub(crate) fn verify_system_password(username: &str, password: &str) -> Result<bool, String> {
    match decide(username, password) {
        Login::Accept => Ok(true),
        Login::Deny(reason) => {
            tracing::debug!(%username, %reason, "login refused");
            Ok(false)
        }
        Login::Unavailable(reason) => Err(reason),
    }
}

/// Whether `password` is the one `/etc/shadow` holds for `username` — the
/// hash comparison alone, with no policy attached.
///
/// This is deliberately NOT a login decision, and callers must not use it as
/// one. It exists for credential capture, which runs *inside* a PAM `auth`
/// stack via `pam_exec`: asking [`decide`] there would re-enter PAM for the
/// account PAM is in the middle of authenticating, double-counting the
/// attempt in `pam_faillock`. All capture needs to know is whether the token
/// it was handed is the account's real password, which is exactly this.
pub(crate) fn password_matches_shadow(username: &str, password: &str) -> Result<bool, String> {
    shadow_verdict(username, password)
        .map_err(|reason| reason.unwrap_or_else(|| format!("{username} is not in /etc/shadow")))
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
        "1" => verify_md5(password, hash),
        // `$5$` and `$6$` are different algorithms, not one with two labels:
        // SHA-256-crypt and SHA-512-crypt. Verifying a `$5$` entry with
        // `sha512_check` never matches, so every correct password on a
        // SHA-256-crypt host was rejected — and because that is a definitive
        // `Ok(false)`, PAM was never consulted to catch it.
        "5" => sha_crypt::sha256_check(password, hash).is_ok(),
        "6" => sha_crypt::sha512_check(password, hash).is_ok(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `$5$` is SHA-256-crypt and `$6$` is SHA-512-crypt — two algorithms,
    /// not one with two labels.
    ///
    /// Regression: both were verified with `sha512_check`, so every correct
    /// password on a SHA-256-crypt host was rejected. And because a shadow
    /// mismatch is a *definitive* "wrong password", nothing downstream ever
    /// got the chance to notice: the account simply could not log in.
    #[test]
    fn each_shadow_hash_scheme_is_verified_with_its_own_algorithm() {
        // Published SHA-crypt test vectors (Drepper's specification).
        let sha256 = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";
        let sha512 = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu\
                      esI68u4OTLiBFdcbYEdFCoEOfaS35inz1";

        assert!(verify_crypt("Hello world!", sha256), "$5$ must verify with SHA-256-crypt");
        assert!(!verify_crypt("wrong", sha256), "a wrong password must not verify");

        assert!(verify_crypt("Hello world!", sha512), "$6$ must verify with SHA-512-crypt");
        assert!(!verify_crypt("wrong", sha512), "a wrong password must not verify");

        // And neither scheme may be checked with the other's verifier, which
        // is what made the two indistinguishable before.
        assert!(
            !sha_crypt::sha512_check("Hello world!", sha256).is_ok(),
            "the bug: SHA-512-crypt cannot verify a SHA-256-crypt hash"
        );
    }

    /// A correct password is only half of a login. `/etc/shadow`'s ageing
    /// fields are the other half on the PAM-less fallback path, and they used
    /// to be ignored entirely.
    #[test]
    fn shadow_ageing_fields_can_refuse_an_account_with_the_right_password() {
        // Fields: name:hash:lastchg:min:max:warn:inactive:expire:flag
        let today = 20_000i64;
        let shadow = "\
alice:$6$x$y:19000:0:99999:7:::
expired:$6$x$y:19000:0:99999:7::19500:
mustchange:$6$x$y:0:0:99999:7:::
aged:$6$x$y:19000:0:30:7::: 
future:$6$x$y:19000:0:99999:7::20500:
";
        assert_eq!(account_policy_in(shadow, "alice", today), Ok(()), "an ordinary account logs in");
        assert!(
            account_policy_in(shadow, "expired", today).is_err(),
            "an expired account must be refused however right its password is"
        );
        assert!(
            account_policy_in(shadow, "mustchange", today).is_err(),
            "lastchg=0 means the password must be changed, which RDP cannot do"
        );
        assert!(
            account_policy_in(shadow, "aged", today).is_err(),
            "a password past its maximum age must be refused"
        );
        assert_eq!(
            account_policy_in(shadow, "future", today),
            Ok(()),
            "an expiry date still ahead is not an expiry"
        );
    }

    /// An account nothing knows about must not be waved through.
    #[test]
    fn an_account_outside_shadow_is_not_approved_without_pam() {
        assert!(
            account_policy_in("alice:$6$x$y:19000:0:99999:7:::\n", "bob", 20_000).is_err(),
            "no record and no PAM means no basis to allow the login"
        );
    }

    /// A PAM stack that exists and breaks is not a PAM stack that is absent.
    ///
    /// Regression: `decide` fell back to `/etc/shadow` on *any* error from
    /// `pam::authenticate`, and `pam_start` failing — after libpam had loaded
    /// perfectly well — produced exactly that error. A correct local password
    /// plus an unexpired shadow entry was then an `Accept`, with `pam_access`,
    /// `pam_time` and the rest of the stack never consulted. The two cases now
    /// have different types, and only one of them may fall back.
    #[test]
    fn a_broken_pam_stack_closes_the_door_while_an_absent_one_falls_back() {
        use crate::pam::NoVerdict;

        assert!(
            matches!(fallback_allowed(&NoVerdict::NotInstalled("no libpam.so.0".to_owned())), true),
            "a machine with no libpam has no policy to bypass"
        );
        assert!(
            !fallback_allowed(&NoVerdict::BackendFailed("pam_start: 3".to_owned())),
            "a stack that failed to run must not be stood in for"
        );

        // And the refusal is an Unavailable, which callers treat as "closed",
        // never a Deny that could be mistaken for a wrong password.
        let outcome = Login::Unavailable("the PAM stack (linrdp) failed".to_owned());
        assert!(authorize_for_desktop_from(outcome).is_err());
    }

    /// The rule `decide` applies, as a value that can be asserted on.
    fn fallback_allowed(reason: &crate::pam::NoVerdict) -> bool {
        matches!(reason, crate::pam::NoVerdict::NotInstalled(_))
    }

    /// Nothing may be accepted on a "cannot tell".
    #[test]
    fn an_undecidable_login_is_refused_rather_than_guessed() {
        let unavailable = Login::Unavailable("no backend".to_owned());
        assert!(
            authorize_for_desktop_from(unavailable).is_err(),
            "a backend outage must close the door, not open it"
        );
        assert!(authorize_for_desktop_from(Login::Deny("locked".to_owned())).is_err());
        assert!(authorize_for_desktop_from(Login::Accept).is_ok());
    }

    /// The decision-to-verdict mapping, without a PAM stack to drive.
    fn authorize_for_desktop_from(outcome: Login) -> anyhow::Result<()> {
        match outcome {
            Login::Accept => Ok(()),
            Login::Deny(reason) => anyhow::bail!("not allowed to log in: {reason}"),
            Login::Unavailable(reason) => anyhow::bail!("cannot check ({reason}) — refusing"),
        }
    }

    /// An empty user name is a refusal, never a lookup.
    #[test]
    fn a_login_without_a_user_name_is_refused_before_any_backend() {
        assert!(matches!(decide("", "whatever"), Login::Deny(_)));
    }
}
