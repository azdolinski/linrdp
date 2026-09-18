//! TLS identity: load PEM cert/key from disk or generate a self-signed one
//! at startup (persisted for reuse so clients can pin the certificate).
//!
//! Stored in `/etc/linrdp/cert`, beside the configuration that names it — the
//! certificate is part of how this machine is set up, and an operator looking
//! for it looks where everything else about linrdp lives. The directory is
//! world-readable and the certificate with it, because copying it to a client
//! is the normal thing to do with it; the key beside it is 0600, the way
//! /etc/ssh holds a public host key and its private half in one place.
//!
//! The fresh certificate carries SANs for the machine's hostnames and
//! interface IPs so that, once imported into a client's trust store, it also
//! validates when connecting by raw IP (a bare CN never matches an IP).

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ironrdp_server::TlsIdentityCtx;

// Visible to `config::meta`, whose `tls.cert` / `tls.key` help promises these
// exact paths to anyone who leaves the keys unset. A test there compares the
// promise against these three.
pub(crate) const CERT_FILE: &str = "default.cert";
pub(crate) const KEY_FILE: &str = "default.key";
pub(crate) const CERT_DIR: &str = "/etc/linrdp/cert";

/// Where the generated pair lived before it moved in beside the config.
///
/// Named once, in a log line, rather than migrated. That key was written
/// 0644: carrying it into a directory whose whole promise is that the key is
/// private would launder a secret that may already have been read.
const LEGACY: [&str; 2] = ["/var/lib/linrdp/linrdp-cert.pem", "/var/lib/linrdp/linrdp-key.pem"];

/// Load the TLS identity the configuration names, or keep one of our own.
///
/// The two cases are deliberately not the same. `tls.cert`/`tls.key` unset
/// means "linrdp, look after this": load the pair in the certificate
/// directory, or generate one and persist it so a client that trusted it once
/// keeps trusting it. Setting them means the operator is naming a specific
/// identity, and a path that is not there is then a refusal to start — the
/// alternative is generating a fresh self-signed certificate under the
/// operator's chosen filename, which breaks pinning on every client at once
/// with nothing in any log to say why.
pub(crate) fn load_or_generate_identity(configured: &crate::config::Tls) -> anyhow::Result<TlsIdentityCtx> {
    if let (Some(cert), Some(key)) = (&configured.cert, &configured.key) {
        anyhow::ensure!(
            cert.exists() && key.exists(),
            "tls.cert / tls.key name a certificate that is not there ({} / {}). \
             They are only set when an identity is being provided, so linrdp will not \
             generate one over the top of them.",
            cert.display(),
            key.display()
        );
        return TlsIdentityCtx::init_from_paths(cert, key)
            .with_context(|| format!("the PEM identity at {} is invalid", cert.display()));
    }

    let (cert_path, key_path) = ensure_default_pair()?;
    TlsIdentityCtx::init_from_paths(&cert_path, &key_path).context("on-disk PEM identity invalid")
}

/// Generate the self-signed identity now, at supervisor start, if it is the
/// one that will be served.
///
/// Not left to the first connection. The certificate is a file the operator
/// copies to their clients, and it should be there to copy the moment the
/// service is up — rather than appearing only after somebody has already
/// connected once and been warned about an unknown certificate. A failure
/// here refuses the start: every connection would fail on it anyway, and a
/// supervisor that looks healthy while no client can complete a handshake is
/// the degraded start this service does not do.
pub(crate) fn ensure_default_identity(configured: &crate::config::Tls) -> anyhow::Result<()> {
    if configured.cert.is_some() || configured.key.is_some() {
        return Ok(()); // the operator named an identity; the worker loads it
    }
    ensure_default_pair().map(|_| ())
}

/// The pair in [`CERT_DIR`], generated if it is not there yet.
fn ensure_default_pair() -> anyhow::Result<(PathBuf, PathBuf)> {
    let dir = Path::new(CERT_DIR);
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    // Ours, already generated — done.
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }

    if LEGACY.iter().all(|p| Path::new(p).exists()) {
        tracing::warn!(
            old_cert = LEGACY[0],
            old_key = LEGACY[1],
            "an identity from the old layout is still on disk and is not reused: its key \
             was written world-readable, so it is not carried into a directory that \
             promises otherwise. Clients will see the new certificate once. Delete the old \
             pair, or name it in tls.cert / tls.key to go on using it."
        );
    }

    let pair = generate_into(dir)?;
    tracing::info!(
        cert = %pair.0.display(),
        key = %pair.1.display(),
        "generated self-signed TLS identity with IP SANs"
    );
    Ok(pair)
}

/// Generate a self-signed pair in `dir` and return the two paths.
///
/// Takes the directory so the modes it writes can be checked by a test rather
/// than by reading /etc after the fact. The key goes down 0600 at creation,
/// not 0644-then-chmod: `std::fs::write` obeys the umask, which under root's
/// usual 022 leaves a private key readable by every account on the machine
/// for as long as it takes to fix it — and nothing fixes it today.
fn generate_into(dir: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    // Enforced, not assumed: the directory may predate this build. Public,
    // because handing the certificate to a client is the point of having one.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", dir.display()))?;

    // SANs: hostnames plus every interface IP, so connecting by IP validates
    // after the cert is imported into the client's trust store.
    let dns = |name: &str| {
        rcgen::SanType::DnsName(
            name.parse()
                .unwrap_or_else(|_| "linrdp".parse().expect("valid IA5 fallback")),
        )
    };
    let mut sans = vec![
        dns("linrdp"),
        dns("localhost"),
        rcgen::SanType::IpAddress(IpAddr::from([127, 0, 0, 1])),
    ];
    if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
        if output.status.success() {
            for token in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if let Ok(ip) = token.parse::<IpAddr>() {
                    sans.push(rcgen::SanType::IpAddress(ip));
                }
            }
        }
    }

    let mut params = rcgen::CertificateParams::new(vec![]).context("cert params")?;
    params.subject_alt_names = sans;
    let key_pair = rcgen::KeyPair::generate().context("key generation")?;
    let cert = params.self_signed(&key_pair).context("self-signing")?;

    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    crate::atomic::write(&cert_path, &cert.pem(), 0o644)
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    crate::atomic::write(&key_path, &key_pair.serialize_pem(), 0o600)
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok((cert_path, key_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The private key must not be readable by other accounts. It was 0644
    /// under /var/lib/linrdp, saved only by that directory being 0700 — and
    /// the identity now lives in a directory that is deliberately not, so the
    /// file's own mode is the whole of the protection.
    #[test]
    fn the_generated_key_is_private_and_the_certificate_is_not() {
        let dir = std::env::temp_dir().join(format!("linrdp-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let (cert, key) = generate_into(&dir).expect("generates a pair");

        let mode = |p: &Path| {
            std::fs::metadata(p).expect("exists").permissions().mode() & 0o777
        };
        assert_eq!(mode(&key), 0o600, "the private key is readable by other accounts");
        assert_eq!(mode(&cert), 0o644, "the certificate is meant to be copied to clients");
        assert_eq!(mode(&dir), 0o755, "a 0700 directory would put the cert out of reach");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Generating twice must land on the same names, because the second call
    /// never happens: `load_or_generate_identity` reuses what is there, and a
    /// pair written under a different name each time would be a new identity
    /// on every restart — the pinning failure this module exists to avoid.
    #[test]
    fn the_pair_is_written_where_the_loader_looks_for_it() {
        let dir = std::env::temp_dir().join(format!("linrdp-tls-names-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let (cert, key) = generate_into(&dir).expect("generates a pair");

        assert_eq!(cert, dir.join(CERT_FILE));
        assert_eq!(key, dir.join(KEY_FILE));
        assert!(std::fs::read_to_string(&cert).expect("cert").contains("BEGIN CERTIFICATE"));
        assert!(std::fs::read_to_string(&key).expect("key").contains("PRIVATE KEY"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
