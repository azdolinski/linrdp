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
use anyhow::Context as _;
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

    /// Whether an identity was recorded, without consuming it.
    pub(crate) fn peek(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|(user, _)| user.clone())
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
    /// `--fixed-size`: pin every session's screen instead of following the
    /// connecting client.
    fixed_size: Option<(u16, u16)>,
    /// `--auth greeter`: the client sends no credentials, so the server draws
    /// a logon screen and collects them there.
    greeter: bool,
    /// The display this worker bound, so the disconnect path can lock it.
    /// A Cell because binding happens through `&self` inside the handler.
    bound_display: std::cell::Cell<Option<u16>>,
}

impl SessionRouter {
    pub(crate) fn new(
        inner: Box<dyn ironrdp_server::ConnectionHandler>,
        pending: Arc<PendingIdentity>,
        state_dir: PathBuf,
        range: RangeInclusive<u16>,
        console: bool,
        fixed_size: Option<(u16, u16)>,
        greeter: bool,
    ) -> Self {
        Self {
            inner,
            pending,
            state_dir,
            range,
            console,
            fixed_size,
            greeter,
            bound_display: std::cell::Cell::new(None),
        }
    }

    /// Start the logon screen and hand the session over once it succeeds.
    ///
    /// Returns as soon as the screen is up: the form runs on a thread of its
    /// own so the connection can start streaming it. Nothing of the user's is
    /// reachable until the form accepts — the gate is pointed at an X server
    /// that has no session on it.
    fn show_greeter(&self, client_size: (u16, u16)) -> anyhow::Result<()> {
        let greeter = crate::greeter::Greeter::start(&self.state_dir, self.range.clone(), client_size)?;
        crate::session::gate::bind_greeter(
            greeter.display,
            &greeter.xauthority,
            &greeter.runtime_dir,
            client_size,
        )?;

        let state_dir = self.state_dir.clone();
        let range = self.range.clone();
        let fixed_size = self.fixed_size;
        std::thread::Builder::new()
            .name("linrdp-greeter".to_owned())
            .spawn(move || {
                // `greeter` is moved in so its X server lives exactly as long
                // as the form, and is torn down by Drop on every path out.
                let greeter = greeter;
                let (conn, screen) = match crate::session::gate::connect() {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::error!(error = format!("{error:#}"), "logon screen: cannot connect to its X server");
                        return;
                    }
                };
                let verify = |user: &str, password: &str| {
                    crate::auth::verify_system_password(user, password).unwrap_or(false)
                };
                match crate::greeter::run_form(&conn, screen, &verify) {
                    Ok(Some((user, password))) => {
                        let size = fixed_size.unwrap_or(crate::session::SESSION_SCREEN_MAX);
                        match crate::session::attach_or_create(&state_dir, &user, &password, range, size) {
                            Ok(rec) => {
                                if let Err(error) = crate::session::gate::bind(
                                    rec.display,
                                    &rec.xauthority,
                                    &rec.runtime_dir,
                                    client_size,
                                ) {
                                    tracing::error!(error = format!("{error:#}"), "logon screen: handover refused");
                                    return;
                                }
                                if rec.locked && let Err(error) = crate::session::unlock(&state_dir, &rec) {
                                    tracing::warn!(error = format!("{error:#}"), "could not unlock the session");
                                }
                                tracing::info!(user, display = rec.display, "logon screen: handed over to the desktop");
                            }
                            Err(error) => {
                                tracing::error!(error = format!("{error:#}"), "logon screen: could not start the session");
                            }
                        }
                    }
                    Ok(None) => tracing::info!("logon screen: the client went away"),
                    Err(error) => tracing::error!(error = format!("{error:#}"), "logon screen failed"),
                }
            })
            .context("spawn the logon screen thread")?;
        Ok(())
    }

    /// Resolve or create the session and point this process at it.
    fn bind_session(&self, client_size: (u16, u16)) -> anyhow::Result<()> {
        let Some((user, password)) = self.pending.take() else {
            anyhow::bail!("no authenticated identity recorded — cannot choose a desktop");
        };
        self.bind_as(&user, &password, client_size)
    }

    /// Point this worker at `user`'s desktop. The caller has already verified
    /// them — through CredSSP, through the Client Info PDU, or at the logon
    /// screen.
    fn bind_as(&self, user: &str, password: &str, client_size: (u16, u16)) -> anyhow::Result<()> {
        let (user, password) = (user.to_owned(), password.to_owned());
        // A session's X server is created at the LARGEST desktop we serve,
        // not at this client's size: `-screen 0 WxH` is also Xvfb's RandR
        // maximum and cannot grow afterwards, so a session born at one
        // client's size could never fit the next one. The capture path scales
        // the screen down to `client_size` when it connects.
        // `--fixed-size` still wins when the operator pinned a geometry.
        let size = self.fixed_size.unwrap_or(crate::session::SESSION_SCREEN_MAX);
        let rec = crate::session::attach_or_create(&self.state_dir, &user, &password, self.range.clone(), size)?;
        // The gate, not the environment, is what the capture and input paths
        // trust. Binding also sets the environment for the subsystems that
        // start later and read it (clipboard, selection owner).
        crate::session::gate::bind(rec.display, &rec.xauthority, &rec.runtime_dir, client_size)?;
        // The user just proved who they are, so the desktop is theirs to see.
        // Unlocking is recorded rather than assumed, so a later disconnect —
        // or a supervisor restart — can put it back.
        if rec.locked {
            crate::session::unlock(&self.state_dir, &rec)?;
        }
        self.bound_display.set(Some(rec.display));
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
        } else if self.greeter {
            let size = (info.desktop_size.width, info.desktop_size.height);
            // A client that already sent credentials the validator verified
            // does not need to type them again.
            if self.pending.peek().is_some() {
                if let Err(error) = self.bind_session(size) {
                    tracing::error!(error = format!("{error:#}"), "could not bind this connection to a desktop");
                    std::process::exit(1);
                }
            } else if let Err(error) = self.show_greeter(size) {
                tracing::error!(error = format!("{error:#}"), "could not show the logon screen");
                std::process::exit(1);
            }
        } else if let Err(error) = self.bind_session((info.desktop_size.width, info.desktop_size.height)) {
            // Refusing beats falling back: a user whose session cannot start
            // must not silently land on the shared desktop. The worker exits,
            // which drops the connection with the reason in the log.
            // The whole chain, not just the outermost context: the cause is
            // the only part that says what actually went wrong.
            tracing::error!(error = format!("{error:#}"), "could not bind this connection to a desktop");
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
        // Lock on the way out. A desktop whose client is gone must not be
        // walked into by the next connection, which is the whole point of
        // sessions that outlive their connections.
        if let Some(bound) = self.bound_display.get() {
            if let Err(error) = crate::session::lock(&self.state_dir, bound) {
                tracing::error!(display = bound, %error, "could not lock the session on disconnect");
            } else {
                tracing::info!(display = bound, "session locked on disconnect");
            }
        }
        self.inner.on_disconnected(peer, duration, error)
    }
}
