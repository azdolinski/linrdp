//! System authentication: verify a username/password pair against
//! `/etc/shadow` (SHA-512 / YESCRYPT / MD5 crypt), the same source SSH PAM
//! uses. Pure Rust — reads the shadow database directly; no external binaries.

use std::collections::HashMap;

use async_trait::async_trait;

use ironrdp_server::{CredentialDecision, CredentialValidationError, CredentialValidator, Credentials};

/// Validator backed by `/etc/shadow`.
pub(crate) struct ShadowValidator;

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
        let result = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let shadow = match Self::load_shadow() {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    tracing::error!(
                        "cannot read /etc/shadow — run linrdp as root (or add CAP_DAC_READ_SEARCH). \
                         Without it user/password authentication cannot be verified."
                    );
                    return Ok(false);
                }
                Err(e) => return Err(format!("read /etc/shadow: {e}")),
            };
            let Some(hash) = shadow.get(&username2) else {
                return Ok(false); // unknown user — do not leak existence
            };
            if hash.starts_with('!') || hash.starts_with('*') {
                return Ok(false); // account locked / no password set
            }
            Ok(verify_crypt(&password, hash))
        })
        .await
        .map_err(CredentialValidationError::new)? // join error
        .map_err(|e| CredentialValidationError::new(std::io::Error::other(e)))?; // backend error

        if result {
            tracing::info!(%username, "authentication accepted");
            Ok(CredentialDecision::Accept)
        } else {
            tracing::warn!(%username, "authentication rejected");
            Ok(CredentialDecision::Reject)
        }
    }
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
