//! Session lifecycle integration — the KRdp SessionController pattern, in
//! Rust: when the last RDP client disconnects, lock the local logind session
//! (`org.freedesktop.login1.Session.Lock`); when a client (re)connects,
//! unlock it. Optionally switch to the greeter (`SwitchToGreeter`) when a
//! client takes over, for setups where linrdp owns the whole seat.
//!
//! The goal is the same as KRdp's: a remote-desktop session must never leave
//! the desktop physically unlocked after the remote side hangs up.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ironrdp_server::{ConnectionHandler, ConnectionInfo, PostConnectionAction, ServerError};
use tokio::sync::Mutex as AsyncMutex;

use core::net::SocketAddr;

const LOGIN1_SERVICE: &str = "org.freedesktop.login1";
const LOGIN1_SESSION_PATH: &str = "/org/freedesktop/login1/session/auto";
const LOGIN1_SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const DISPLAY_MANAGER_SERVICE: &str = "org.freedesktop.DisplayManager";
const DISPLAY_MANAGER_SEAT_PATH: &str = "/org/freedesktop/DisplayManager/Seat0";
const DISPLAY_MANAGER_SEAT_IFACE: &str = "org.freedesktop.DisplayManager.Seat";

/// Give up on a D-Bus call after this long — connection teardown must not
/// wait on a stuck system bus.
const DBUS_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Connection lifecycle controller (KRdp `SessionController` equivalent).
///
/// Counts authenticated connections; on 0↔1 transitions it drives the local
/// session's lock state over D-Bus. D-Bus work is spawned so the connection
/// loop never blocks on the system bus.
pub(crate) struct SessionController {
    inner: Arc<ControllerInner>,
}

pub(crate) struct ControllerInner {
    /// Authenticated connections currently active.
    active: AtomicUsize,
    /// `session.lock_on_disconnect`: unlock on first connect, lock when last leaves.
    lock_session: bool,
    /// `session.switch_to_greeter`: flip the seat to the greeter when the first
    /// client connects (for "linrdp owns the seat" setups, mirroring KRdp's
    /// RemoteAccess mode).
    switch_to_greeter: bool,
    /// Serialize the spawned D-Bus tasks so unlock/lock cannot race when
    /// connections churn quickly.
    dbus_serial: AsyncMutex<()>,
}

impl SessionController {
    pub(crate) fn new(lock_session: bool, switch_to_greeter: bool) -> Self {
        Self {
            inner: Arc::new(ControllerInner {
                active: AtomicUsize::new(0),
                lock_session,
                switch_to_greeter,
                dbus_serial: AsyncMutex::new(()),
            }),
        }
    }
}

impl ConnectionHandler for SessionController {
    fn on_accept(&mut self, _peer: SocketAddr) -> bool {
        true
    }

    /// After credentials are validated: on the first active client, bring
    /// the local session to the remote user (unlock; optionally greeter
    /// switch so the local console shows the login screen instead).
    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        let before = self.inner.active.fetch_add(1, Ordering::AcqRel);
        if before != 0 {
            return; // a client is already active — session already usable
        }
        tracing::info!(
            keyboard_layout = info.keyboard_layout,
            "first client connected - taking over the session"
        );

        if self.inner.switch_to_greeter {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let _guard = inner.dbus_serial.lock().await;
                if let Err(error) = switch_to_greeter().await {
                    tracing::warn!(%error, "could not switch to greeter");
                }
            });
        }
        if self.inner.lock_session {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let _guard = inner.dbus_serial.lock().await;
                if let Err(error) = set_session_lock(false).await {
                    tracing::warn!(%error, "could not unlock the logind session");
                }
            });
        }
    }

    /// Connection ended: when the last client leaves, lock the session so
    /// the desktop is never left physically unlocked after remote access.
    fn on_disconnected(
        &mut self,
        peer: SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
    ) -> PostConnectionAction {
        // `on_connection_info` only counts connections that reached the
        // ConnectionInfo stage, but `on_disconnected` fires for every
        // connection — including mstsc's probe, which dies mid-CredSSP with a
        // BrokenPipe on every single attempt. A plain `fetch_sub` wrapped the
        // counter (observed: remaining=18446744073709551614), after which
        // `after == 0` was never true again and `session.lock_on_disconnect` would leave
        // the desktop unlocked forever. Saturate at zero instead.
        let after = self
            .inner
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(1)))
            .unwrap_or(0)
            .saturating_sub(1);
        tracing::info!(
            %peer,
            ?duration,
            had_error = error.is_some(),
            remaining = after,
            "client disconnected"
        );
        if after == 0 && self.inner.lock_session {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let _guard = inner.dbus_serial.lock().await;
                if let Err(error) = set_session_lock(true).await {
                    tracing::warn!(%error, "could not lock the logind session");
                }
            });
        }
        PostConnectionAction::Continue
    }
}

/// `org.freedesktop.login1.Session.Lock` / `.Unlock` on the calling
/// session (`session/auto` resolves to the caller's own session).
async fn set_session_lock(lock: bool) -> Result<(), String> {
    let method = if lock { "Lock" } else { "Unlock" };
    call_system_dbus(LOGIN1_SERVICE, LOGIN1_SESSION_PATH, LOGIN1_SESSION_IFACE, method).await
}

/// `org.freedesktop.DisplayManager.Seat.SwitchToGreeter` — flips the seat
/// to the display manager's greeter (SDDM/GDM).
async fn switch_to_greeter() -> Result<(), String> {
    call_system_dbus(
        DISPLAY_MANAGER_SERVICE,
        DISPLAY_MANAGER_SEAT_PATH,
        DISPLAY_MANAGER_SEAT_IFACE,
        "SwitchToGreeter",
    )
    .await
}

async fn call_system_dbus(service: &str, path: &str, iface: &str, method: &str) -> Result<(), String> {
    let (service, path, iface, method) = (
        service.to_owned(),
        path.to_owned(),
        iface.to_owned(),
        method.to_owned(),
    );
    let label = format!("{iface}.{method}");
    let timeout_label = label.clone();
    tokio::time::timeout(DBUS_CALL_TIMEOUT, async move {
        let connection = zbus::Connection::system().await.map_err(|e| format!("system bus: {e}"))?;
        connection
            .call_method(Some(service), path, Some(iface), method, &())
            .await
            .map_err(|e| format!("{label}: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|_| format!("D-Bus call {timeout_label} timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "192.168.1.1:49386".parse().expect("valid addr")
    }

    /// mstsc opens a probe connection that dies mid-CredSSP on every attempt,
    /// so `on_disconnected` runs without a matching `on_connection_info`.
    /// A plain `fetch_sub` wrapped the counter to u64::MAX-ish, after which
    /// the "last client left" transition never fired again and
    /// `session.lock_on_disconnect` left the desktop unlocked.
    #[test]
    fn disconnect_without_a_counted_connect_keeps_the_counter_at_zero() {
        let mut ctl = SessionController::new(false, false);

        ctl.on_disconnected(peer(), Duration::from_secs(3), None);

        assert_eq!(
            ctl.inner.active.load(Ordering::Acquire),
            0,
            "the counter must not underflow"
        );
    }

    /// And a real session still drives the 0 -> 1 -> 0 transition, even after
    /// the probe connections above have churned through.
    #[test]
    fn counter_still_tracks_real_sessions_after_probe_churn() {
        let mut ctl = SessionController::new(false, false);

        for _ in 0..3 {
            ctl.on_disconnected(peer(), Duration::from_secs(3), None);
        }
        ctl.on_connection_info(&ConnectionInfo::new(
            0x0415,
            ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
            String::new(),
            ironrdp_connector::DesktopSize {
                width: 1920,
                height: 1080,
            },
        ));
        assert_eq!(ctl.inner.active.load(Ordering::Acquire), 1);

        ctl.on_disconnected(peer(), Duration::from_secs(60), None);
        assert_eq!(
            ctl.inner.active.load(Ordering::Acquire),
            0,
            "the last real client must bring the counter back to zero"
        );
    }
}
