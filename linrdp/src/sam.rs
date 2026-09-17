//! NLA credentials store (SAM), MS-RDPBCGR 5.4.2 compliant.
//!
//! CredSSP/NLA authentication uses NTLMv2, which by the protocol's own math
//! (MS-NLMP) requires the server to know the account's secret (password or
//! NT hash) — a Windows server reads it from SAM. On Linux `/etc/shadow`
//! stores only a one-way hash (yescrypt), which NTLM cannot use.
//!
//! LinRDP therefore keeps its own SAM: `/var/lib/linrdp/sam` with
//! `username:password` entries, mode 0600, root-owned — the same trust model
//! as `/etc/shadow`.
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
use std::path::PathBuf;

const SAM_DIR: &str = "/var/lib/linrdp";
const SAM_FILE: &str = "/var/lib/linrdp/sam";

pub(crate) fn sam_path() -> PathBuf {
    PathBuf::from(SAM_FILE)
}

/// Load the SAM into a username→password map. Returns an empty map when the
/// file does not exist yet (no users provisioned).
pub(crate) fn load() -> std::io::Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(SAM_FILE)?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let Some((user, pass)) = line.split_once(':') else {
            continue;
        };
        if !user.is_empty() {
            map.insert(user.to_owned(), pass.to_owned());
        }
    }
    Ok(map)
}

/// Set (or update) one user's password in the SAM. Creates the store with
/// root-only permissions when missing.
pub(crate) fn set_password(username: &str, password: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(SAM_DIR)?;
    let mut map = load().unwrap_or_default();
    map.insert(username.to_owned(), password.to_owned());

    let mut body = String::new();
    for (u, p) in &map {
        body.push_str(u);
        body.push(':');
        body.push_str(p);
        body.push('\n');
    }
    let path = sam_path();
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// The account names the SAM holds, sorted. Empty when the store is missing.
///
/// Names only — the secrets stay in this module. Callers want to report what
/// is provisioned, never what the passwords are.
pub(crate) fn account_names() -> Vec<String> {
    let mut names: Vec<String> = load().unwrap_or_default().into_keys().collect();
    names.sort();
    names
}

/// Look up one user's stored password (None = not provisioned / locked).
pub(crate) fn lookup(username: &str) -> std::io::Result<Option<String>> {
    Ok(load()?.get(username).cloned())
}
