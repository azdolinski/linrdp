//! Routing an authenticated connection to its user's desktop.
//!
//! The decision is made from the identity CredSSP verified, never from the
//! X.224 `mstshash` cookie the client supplies — that field is unauthenticated,
//! so trusting it would let anyone choose whose desktop they land on.
//!
//! It happens inside credential validation because that is the first point
//! where the username is known AND still earlier than any use of the display:
//! the worker's display factory connects lazily, so setting `$DISPLAY` here
//! decides which desktop the rest of the connection serves.

use std::ops::RangeInclusive;
use std::path::PathBuf;

use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_server::{CredentialDecision, CredentialValidationError, CredentialValidator};

/// Wraps the real validator and, on success, binds this worker to the
/// authenticated user's session.
pub(crate) struct SessionRouter {
    inner: std::sync::Arc<dyn CredentialValidator>,
    state_dir: PathBuf,
    range: RangeInclusive<u16>,
    /// `--console`: serve the ambient `$DISPLAY` (the shared screen) and
    /// create no per-user session at all.
    console: bool,
    desktop_size: (u16, u16),
}

impl SessionRouter {
    pub(crate) fn new(
        inner: std::sync::Arc<dyn CredentialValidator>,
        state_dir: PathBuf,
        range: RangeInclusive<u16>,
        console: bool,
        desktop_size: (u16, u16),
    ) -> Self {
        Self { inner, state_dir, range, console, desktop_size }
    }
}

#[async_trait::async_trait]
impl CredentialValidator for SessionRouter {
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        let decision = self.inner.validate(credentials).await?;
        if !matches!(decision, CredentialDecision::Accept) {
            return Ok(decision);
        }
        if self.console {
            tracing::info!(
                user = %credentials.username,
                display = %std::env::var("DISPLAY").unwrap_or_default(),
                "console mode — serving the shared display"
            );
            return Ok(decision);
        }

        let user = credentials.username.clone();
        let password = credentials.password.clone();
        let state_dir = self.state_dir.clone();
        let range = self.range.clone();
        let size = self.desktop_size;

        // Session setup forks, opens a PAM session and starts an X server —
        // all blocking, none of it safe on the async executor.
        let resolved = tokio::task::spawn_blocking(move || {
            crate::session::attach_or_create(&state_dir, &user, &password, range, size)
        })
        .await
        .map_err(|e| CredentialValidationError::new(std::io::Error::other(format!("session task: {e}"))))?;

        match resolved {
            Ok(rec) => {
                // SAFETY: the worker is still single-threaded with respect to
                // anything reading these — the display factory connects
                // lazily, on the first frame after this point.
                unsafe {
                    std::env::set_var("DISPLAY", format!(":{}", rec.display));
                    std::env::set_var("XAUTHORITY", &rec.xauthority);
                    std::env::set_var("XDG_RUNTIME_DIR", &rec.runtime_dir);
                }
                tracing::info!(user = %credentials.username, display = rec.display, "routed to the user's desktop");
                Ok(decision)
            }
            Err(error) => {
                // Refusing beats falling back to the shared desktop: a user
                // whose session cannot start must not silently land on
                // someone else's screen.
                tracing::error!(user = %credentials.username, %error, "could not start the user's session");
                Err(CredentialValidationError::new(std::io::Error::other(format!("session setup: {error:#}"))))
            }
        }
    }
}
