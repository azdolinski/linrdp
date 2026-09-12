//! xdg-desktop-portal client (RemoteDesktop + ScreenCast) over the session
//! bus — the Rust port of KRdp's `PortalSession`, using zbus.
//!
//! Handshake (all requests follow the portal Request/Response pattern on
//! per-call object paths):
//!
//! 1. `RemoteDesktop.CreateSession` → session handle
//! 2. `RemoteDesktop.SelectDevices` (keyboard+pointer+touch, persist until
//!    revoked so later sessions can restore)
//! 3. `ScreenCast.SelectSources` (monitor, cursor **embedded** in frames —
//!    simpler than KRdp's metadata mode and the cursor is then visible
//!    without a pointer-update channel)
//! 4. `RemoteDesktop.Start` → devices + streams (node id, size, mapping id)
//!    + restore token (persisted for future runs)
//! 5. `ScreenCast.OpenPipeWireRemote` → capture fd
//! 6. `RemoteDesktop.ConnectToEIS` → libei fd (absent on older portals —
//!    input is then unavailable and only capture works)

use std::collections::HashMap;
use std::time::Duration;

use zbus::zvariant::{OwnedValue, Value};
use futures_util::StreamExt;
use zbus::{Connection, MatchRule, MessageStream};

const PORTAL_SERVICE: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const REMOTE_DESKTOP_IFACE: &str = "org.freedesktop.portal.RemoteDesktop";
const SCREENCAST_IFACE: &str = "org.freedesktop.portal.ScreenCast";
const REQUEST_IFACE: &str = "org.freedesktop.portal.Request";

/// A portal interaction that never completes is a hung desktop — cap waits.
const PORTAL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// One screencast stream as returned by `Start`.
#[derive(Debug, Clone)]
pub(crate) struct PortalStream {
    pub(crate) node_id: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) mapping_id: Option<String>,
}

/// Everything the server needs after the portal handshake.
pub(crate) struct PortalHandles {
    pub(crate) stream: PortalStream,
    /// fd of the PipeWire remote (ownership moves into the capture).
    pub(crate) pipewire_fd: std::os::fd::OwnedFd,
    /// fd of the EIS connection for libei, when the portal supports it.
    pub(crate) eis_fd: Option<std::os::fd::OwnedFd>,
}

pub(crate) struct PortalSession {
    connection: Connection,
    session_path: String,
    token_seq: u32,
}

impl PortalSession {
    /// Full handshake; returns the capture/input handles. The restore token
    /// from a previous run (if any) suppresses the interactive permission
    /// dialog on portals that support restoring.
    pub(crate) async fn connect(restore_token: Option<&str>) -> anyhow::Result<PortalHandles> {
        let connection = Connection::session().await.map_err(|e| anyhow::anyhow!("session bus: {e}"))?;
        let mut session = Self {
            connection,
            session_path: String::new(),
            token_seq: 0,
        };

        session.create_session().await?;
        session.select_devices(restore_token).await?;
        let stream = session.select_sources_and_start().await?;
        session.persist_restore_token().await;

        let pipewire_fd = session
            .call_fd(SCREENCAST_IFACE, "OpenPipeWireRemote", HashMap::new())
            .await
            .map_err(|e| anyhow::anyhow!("OpenPipeWireRemote: {e}"))?;
        // Absent on older portals: capture still works, input does not.
        let eis_fd = session
            .call_fd(REMOTE_DESKTOP_IFACE, "ConnectToEIS", HashMap::new())
            .await
            .ok();

        Ok(PortalHandles {
            stream,
            pipewire_fd,
            eis_fd,
        })
    }

    fn next_tokens(&mut self) -> (String, String) {
        self.token_seq += 1;
        (
            format!("linrdp{}", self.token_seq),
            format!("linrdp-session{}", self.token_seq),
        )
    }

    async fn create_session(&mut self) -> anyhow::Result<()> {
        let (handle_token, session_token) = self.next_tokens();
        let mut options = make_options(&handle_token);
        options.insert("session_handle_token", Value::Str(session_token.as_str().into()));

        let request = self
            .call_object_path(REMOTE_DESKTOP_IFACE, "CreateSession", options)
            .await?;
        let response = self.wait_response(&request).await?;
        let session_handle = response
            .get("session_handle")
            .and_then(value_to_string)
            .ok_or_else(|| anyhow::anyhow!("portal returned no session_handle"))?;
        tracing::info!(%session_handle, "portal session created");
        self.session_path = session_handle;
        Ok(())
    }

    async fn select_devices(&mut self, restore_token: Option<&str>) -> anyhow::Result<()> {
        let (handle_token, _) = self.next_tokens();
        let mut options = make_options(&handle_token);
        // 7 = keyboard(1) | pointer(2) | touch(4); 2 = persist until revoked.
        options.insert("types", Value::U32(7));
        options.insert("persist_mode", Value::U32(2));
        if let Some(token) = restore_token {
            options.insert("restore_token", Value::Str(token.into()));
        }

        let request = self
            .call_object_path(REMOTE_DESKTOP_IFACE, "SelectDevices", options)
            .await?;
        self.wait_ok(&request).await
    }

    /// ScreenCast.SelectSources + RemoteAccess.Start, returning the first stream.
    async fn select_sources_and_start(&mut self) -> anyhow::Result<PortalStream> {
        let (handle_token, _) = self.next_tokens();
        let mut source_options = make_options(&handle_token);
        // Monitor capture; cursor mode 2 = embedded (composited into frames).
        source_options.insert("types", Value::U32(1));
        source_options.insert("cursor_mode", Value::U32(2));
        let request = self
            .call_object_path(SCREENCAST_IFACE, "SelectSources", source_options)
            .await?;
        self.wait_ok(&request).await?;

        let (handle_token, _) = self.next_tokens();
        let start_options = make_options(&handle_token);
        let request = self
            .call_object_path(REMOTE_DESKTOP_IFACE, "Start", start_options)
            .await?;
        let response = self.wait_response(&request).await?;

        let devices = response
            .get("devices")
            .and_then(value_to_u32)
            .unwrap_or(0);
        if devices == 0 {
            anyhow::bail!("portal granted no input devices");
        }

        // streams: a(ua{sv}) — take the first (single-monitor sessions).
        let streams_value = response
            .get("streams")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("portal returned no screencast streams"))?;
        let streams: Vec<(u32, HashMap<String, OwnedValue>)> = streams_value
            .try_into()
            .map_err(|e| anyhow::anyhow!("portal streams decode: {e}"))?;
        let (node_id, props) = streams
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("portal returned an empty stream list"))?;

        let (mut width, mut height) = (0u32, 0u32);
        if let Some(size) = props.get("size").and_then(|v| v.downcast_ref::<(i32, i32)>().ok()) {
            (width, height) = (size.0.unsigned_abs(), size.1.unsigned_abs());
        }
        let mapping_id = props.get("mapping_id").and_then(value_to_string_owned);

        // Keep the restore token for the next run.
        if let Some(token) = response.get("restore_token").and_then(value_to_string_owned) {
            if std::fs::create_dir_all("/var/lib/linrdp").is_ok() {
                let _ = std::fs::write("/var/lib/linrdp/portal-restore-token", token);
            }
        }

        tracing::info!(node_id, width, height, "portal screencast stream selected");
        Ok(PortalStream {
            node_id,
            width,
            height,
            mapping_id,
        })
    }

    async fn persist_restore_token(&self) {
        // handled in select_sources_and_start (single write, no extra round trip)
        let _ = &self.session_path;
    }

    async fn call_object_path(
        &self,
        interface: &str,
        method: &str,
        options: HashMap<&str, Value<'_>>,
    ) -> anyhow::Result<String> {
        let reply = self
            .connection
            .call_method(
                Some(PORTAL_SERVICE),
                PORTAL_PATH,
                Some(interface),
                method,
                &(self.session_path.clone(), options),
            )
            .await
            .map_err(|e| anyhow::anyhow!("{method}: {e}"))?;
        let path: zbus::zvariant::OwnedObjectPath = reply
            .body()
            .deserialize()
            .map_err(|e| anyhow::anyhow!("{method} reply: {e}"))?;
        Ok(path.to_string())
    }

    /// Methods that reply with an fd directly (OpenPipeWireRemote,
    /// ConnectToEIS) — the fd argument is the session path only.
    async fn call_fd(
        &self,
        interface: &str,
        method: &str,
        options: HashMap<&str, Value<'_>>,
    ) -> anyhow::Result<std::os::fd::OwnedFd> {
        let reply = self
            .connection
            .call_method(
                Some(PORTAL_SERVICE),
                PORTAL_PATH,
                Some(interface),
                method,
                &(self.session_path.clone(), options),
            )
            .await
            .map_err(|e| anyhow::anyhow!("{method}: {e}"))?;
        let fd: zbus::zvariant::OwnedFd = reply
            .body()
            .deserialize()
            .map_err(|e| anyhow::anyhow!("{method} reply: {e}"))?;
        Ok(fd.into())
    }

    /// Wait for `org.freedesktop.portal.Request::Response` on `request_path`.
    /// Response is `(u, a{sv})`; response 0 = success.
    async fn wait_response(&self, request_path: &str) -> anyhow::Result<HashMap<String, OwnedValue>> {
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(PORTAL_SERVICE)?
            .interface(REQUEST_IFACE)?
            .path(request_path)?
            .member("Response")?
            .build();
        let mut stream = MessageStream::for_match_rule(rule, &self.connection, None).await?;

        let message = tokio::time::timeout(PORTAL_RESPONSE_TIMEOUT, stream.next())
            .await
            .map_err(|_| anyhow::anyhow!("portal Response on {request_path} timed out (permission dialog open?)"))?
            .ok_or_else(|| anyhow::anyhow!("portal request stream closed"))?;
        let body = message.map_err(|e| anyhow::anyhow!("portal signal: {e}"))?;
        let (status, result): (u32, HashMap<String, OwnedValue>) = body
            .body()
            .deserialize()
            .map_err(|e| anyhow::anyhow!("portal Response body: {e}"))?;
        match status {
            0 => Ok(result),
            1 => anyhow::bail!("portal request cancelled by the user"),
            other => anyhow::bail!("portal request failed with status {other}"),
        }
    }

    async fn wait_ok(&self, request_path: &str) -> anyhow::Result<()> {
        self.wait_response(request_path).await.map(|_| ())
    }
}

fn make_options<'a>(handle_token: &'a str) -> HashMap<&'a str, Value<'a>> {
    let mut map = HashMap::new();
    map.insert("handle_token", Value::Str(handle_token.into()));
    map
}

fn value_to_string(value: &OwnedValue) -> Option<String> {
    value.downcast_ref::<String>().ok().map(|s| s.to_owned())
}

fn value_to_string_owned(value: &OwnedValue) -> Option<String> {
    value_to_string(value)
}

fn value_to_u32(value: &OwnedValue) -> Option<u32> {
    value.downcast_ref::<u32>().ok()
}
