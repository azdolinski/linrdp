//! TLS identity: load PEM cert/key from disk or generate a self-signed one
//! at startup (persisted for reuse so clients can pin the certificate).
//!
//! Stored under `/var/lib/linrdp` (the service's state dir). The fresh
//! certificate carries SANs for the machine's hostnames and interface IPs so
//! that, once imported into a client's trust store, it also validates when
//! connecting by raw IP (a bare CN never matches an IP).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ironrdp_server::TlsIdentityCtx;

// Visible to `config::meta`, whose `tls.cert` / `tls.key` help promises these
// exact paths to anyone who leaves the keys unset. A test there compares the
// promise against these three.
pub(crate) const CERT_FILE: &str = "linrdp-cert.pem";
pub(crate) const KEY_FILE: &str = "linrdp-key.pem";
pub(crate) const STATE_DIR: &str = "/var/lib/linrdp";

/// Load the TLS identity the configuration names, or keep one of our own.
///
/// The two cases are deliberately not the same. `tls.cert`/`tls.key` unset
/// means "linrdp, look after this": load the pair in the state directory, or
/// generate one and persist it so a client that trusted it once keeps
/// trusting it. Setting them means the operator is naming a specific
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

    let cert_path = Path::new(STATE_DIR).join(CERT_FILE);
    let key_path = Path::new(STATE_DIR).join(KEY_FILE);

    // Fresh identity already in the state dir — done.
    if cert_path.exists() && key_path.exists() {
        return TlsIdentityCtx::init_from_paths(&cert_path, &key_path)
            .context("on-disk PEM identity invalid");
    }

    std::fs::create_dir_all(STATE_DIR).with_context(|| format!("mkdir {}", STATE_DIR))?;

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

    std::fs::write(&cert_path, cert.pem().as_bytes())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    std::fs::write(&key_path, key_pair.serialize_pem().as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    tracing::info!(cert = %cert_path.display(), key = %key_path.display(), "generated self-signed TLS identity with IP SANs");

    TlsIdentityCtx::init_from_paths(&cert_path, &key_path).context("freshly generated identity rejected")
}
