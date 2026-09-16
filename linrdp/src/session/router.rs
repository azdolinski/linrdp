//! Routing an authenticated connection to its user's desktop.
//!
//! Where this hooks in matters, and the obvious place does not work.
//!
//! `CredentialValidator` looks right, but the acceptor only fills
//! `AcceptorResult.credentials` outside HYBRID/HYBRID_EX
//! (`ironrdp-acceptor/src/connection.rs`, the `!protocol.intersects(HYBRID…)`
//! guard): under NLA the credentials are consumed by CredSSP and never reach
//! the validator, which is skipped with "no credentials in AcceptorResult".
//!
//! So routing happens in two steps instead. The credential resolver — the
//! SAM lookup CredSSP performs — records the account being authenticated.
//! Then `on_connection_info`, which only fires once the whole acceptor
//! sequence including CredSSP has succeeded, turns that record into a
//! session. The identity therefore comes from the account CredSSP actually
//! verified, never from the X.224 `mstshash` cookie, which is unauthenticated.

use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The account CredSSP is authenticating, stashed by the credential resolver
/// for `on_connection_info` to consume once authentication has succeeded.
#[derive(Default)]
pub(crate) struct PendingIdentity {
    inner: Mutex<Option<(String, String)>>,
}

impl PendingIdentity {
    pub(crate) fn record(&self, user: &str, password: &str) {
        *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = Some((user.to_owned(), password.to_owned()));
    }

    fn take(&self) -> Option<(String, String)> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).take()
    }
}

/// Binds this worker to the authenticated user's desktop, then delegates to
/// the session-lifecycle handler underneath.
pub(crate) struct SessionRouter {
    inner: Box<dyn ironrdp_server::ConnectionHandler>,
    pending: Arc<PendingIdentity>,
    state_dir: PathBuf,
    range: RangeInclusive<u16>,
    /// `--console`: serve the ambient `$DISPLAY` (the shared screen) and
    /// create no per-user session at all.
    console: bool,
    desktop_size: (u16, u16),
}

impl SessionRouter {
    pub(crate) fn new(
        inner: Box<dyn ironrdp_server::ConnectionHandler>,
        pending: Arc<PendingIdentity>,
        state_dir: PathBuf,
        range: RangeInclusive<u16>,
        console: bool,
        desktop_size: (u16, u16),
    ) -> Self {
        Self { inner, pending, state_dir, range, console, desktop_size }
    }

    /// Resolve or create the session and point this process at it.
    fn bind_session(&self) -> anyhow::Result<()> {
        let Some((user, password)) = self.pending.take() else {
            anyhow::bail!("no authenticated identity recorded — cannot choose a desktop");
        };
        let rec = crate::session::attach_or_create(
            &self.state_dir,
            &user,
            &password,
            self.range.clone(),
            self.desktop_size,
        )?;
        // The gate, not the environment, is what the capture and input paths
        // trust. Binding also sets the environment for the subsystems that
        // start later and read it (clipboard, selection owner).
        crate::session::gate::bind(rec.display, &rec.xauthority, &rec.runtime_dir)?;
        tracing::info!(user, display = rec.display, "routed to the user's desktop");
        Ok(())
    }
}

impl ironrdp_server::ConnectionHandler for SessionRouter {
    fn on_accept(&mut self, peer: core::net::SocketAddr) -> bool {
        self.inner.on_accept(peer)
    }

    fn on_connection_info(&mut self, info: &ironrdp_server::ConnectionInfo) {
        if self.console {
            tracing::info!(
                display = %std::env::var("DISPLAY").unwrap_or_default(),
                "console mode — serving the shared display"
            );
        } else if let Err(error) = self.bind_session() {
            // Refusing beats falling back: a user whose session cannot start
            // must not silently land on the shared desktop. The worker exits,
            // which drops the connection with the reason in the log.
            tracing::error!(%error, "could not bind this connection to a desktop");
            std::process::exit(1);
        }
        self.inner.on_connection_info(info);
    }

    fn on_disconnected(
        &mut self,
        peer: core::net::SocketAddr,
        duration: core::time::Duration,
        error: Option<&ironrdp_server::ServerError>,
    ) -> ironrdp_server::PostConnectionAction {
        self.inner.on_disconnected(peer, duration, error)
    }
}
