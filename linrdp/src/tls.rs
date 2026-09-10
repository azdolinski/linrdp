//! TLS identity: load PEM cert/key from disk or generate a self-signed one
//! at startup (persisted for reuse so clients can pin the certificate).

use std::path::PathBuf;

use anyhow::Context as _;
use ironrdp_server::TlsIdentityCtx;

const CERT_FILE: &str = "linrdp-cert.pem";
const KEY_FILE: &str = "linrdp-key.pem";

/// Load the TLS identity from disk, or generate a fresh self-signed pair
/// (written to disk next to the crate manifest for reuse across runs).
pub(crate) fn load_or_generate_identity() -> anyhow::Result<TlsIdentityCtx> {
    let cert_path = cert_path();
    let key_path = key_path();

    if cert_path.exists() && key_path.exists() {
        return TlsIdentityCtx::init_from_paths(&cert_path, &key_path)
            .context("on-disk PEM identity invalid");
    }

    let cert =
        rcgen::generate_simple_self_signed(vec!["linrdp".to_owned()]).context("failed to generate self-signed cert")?;
    std::fs::write(&cert_path, cert.cert.pem().as_bytes())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem().as_bytes())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    tracing::info!(cert = %cert_path.display(), key = %key_path.display(), "generated self-signed TLS identity");

    TlsIdentityCtx::init_from_paths(&cert_path, &key_path).context("freshly generated identity rejected")
}

fn cert_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CERT_FILE)
}

fn key_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(KEY_FILE)
}
