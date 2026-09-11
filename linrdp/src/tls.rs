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

const CERT_FILE: &str = "linrdp-cert.pem";
const KEY_FILE: &str = "linrdp-key.pem";
const STATE_DIR: &str = "/var/lib/linrdp";

/// Load the TLS identity from disk, migrating from the legacy location (the
/// build-time manifest dir) when present, or generate a fresh self-signed
/// pair persisted for reuse across runs.
pub(crate) fn load_or_generate_identity() -> anyhow::Result<TlsIdentityCtx> {
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
