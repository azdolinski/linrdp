//! EGFX (MS-RDPEGFX) integration glue for the linrdp binary.
//!
//! The ironrdp crates ship a complete server-side graphics pipeline
//! (`ironrdp_egfx::server::GraphicsPipelineServer`) and an
//! `ironrdp-server` bridge (`GfxDvcBridge`, `ServerEvent::Egfx`); what was
//! missing is the binary-side wiring done here:
//!
//! - a [`GfxSession`] shared between the DVC side (capability negotiation,
//!   frame acks) and the display loop (frame producer, see `gfx_display.rs`),
//! - a [`LinrdpGfxFactory`] the server calls when a client opens the
//!   "Microsoft::Windows::RDS::Graphics" dynamic virtual channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_server::{
    EgfxServerMessage, GfxDvcBridge, GfxServerFactory, GfxServerHandle, ServerEvent, ServerEventSender,
};
use ironrdp_svc::ChannelFlags;
use tokio::sync::mpsc;

/// State shared between the DVC side and the display loop.
pub(crate) struct GfxSession {
    /// The per-connection pipeline server, published by the factory when the
    /// server attaches the DVC. `None` until a connection is set up.
    handle: Mutex<Option<GfxServerHandle>>,
    /// Set once capability negotiation completes; the display loop switches
    /// from the legacy bitmap path to EGFX frames when this is true.
    ready: AtomicBool,
    /// Whether this client advertised `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL`
    /// (MS-RDPEGFX 1.5). Reported by `ironrdp-server` once the acceptor
    /// sequence completes, before the display loop produces its first frame.
    /// `false` — the default, and the state before the report arrives — means
    /// the display loop must never hold frames waiting for EGFX.
    client_supports_egfx: AtomicBool,
    /// Set when the graphics channel is gone for this connection: the client
    /// refused its creation (MS-RDPEDYC 3.3.3.2) or closed it mid-session.
    /// Either way no capability negotiation will follow, so the display loop
    /// stops waiting and starts sending legacy bitmap updates.
    ///
    /// Deliberately separate from clearing `handle`: `drain_and_send` needs
    /// the handle to stay alive, and clearing it by pointer on reconnect
    /// would race with the next connection publishing its own.
    /// `build_server_with_handle` resets this alongside `ready`.
    unavailable: AtomicBool,
    /// Server event channel (set via [`ServerEventSender`]), used to ship
    /// drained EGFX PDUs to the wire.
    sender: Mutex<Option<mpsc::UnboundedSender<ServerEvent>>>,
}

impl GfxSession {
    pub(crate) fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            ready: AtomicBool::new(false),
            client_supports_egfx: AtomicBool::new(false),
            unavailable: AtomicBool::new(false),
            sender: Mutex::new(None),
        }
    }

    /// The current connection's pipeline server, if attached.
    pub(crate) fn handle(&self) -> Option<GfxServerHandle> {
        self.handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    pub(crate) fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Whether the client advertised graphics-pipeline support (MS-RDPEGFX 1.5).
    pub(crate) fn client_supports_egfx(&self) -> bool {
        self.client_supports_egfx.load(Ordering::Relaxed)
    }

    /// Whether the graphics channel is known not to be coming for this
    /// connection — refused at creation, or closed.
    pub(crate) fn unavailable(&self) -> bool {
        self.unavailable.load(Ordering::Relaxed)
    }

    /// Drain the pipeline server's output queue and ship it to the wire via
    /// the server event loop. Returns the drained byte count (for stats).
    pub(crate) fn drain_and_send(&self, handle: &GfxServerHandle) -> usize {
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Read under the same lock as the drain: the server loop drops the
        // batch if the pipeline has been reset since (MS-RDPEGFX 3.2.5.18).
        let generation = server.generation();
        let drained = server.drain_output();
        let bytes = drained.iter().map(|m| m.size()).sum();
        let Some(channel_id) = server.channel_id() else {
            return 0; // channel not started yet — nothing to send on
        };
        drop(server);

        let Ok(messages) = ironrdp_dvc::encode_dvc_messages(channel_id, drained, ChannelFlags::SHOW_PROTOCOL) else {
            return 0;
        };
        let guard = self.sender.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sender) = guard.as_ref() {
            let _ = sender.send(ServerEvent::Egfx(EgfxServerMessage::SendMessages {
                messages,
                generation,
            }));
        }
        bytes
    }
}

struct LinrdpGfxHandler {
    session: Arc<GfxSession>,
}

impl GraphicsPipelineHandler for LinrdpGfxHandler {
    fn capabilities_advertise(&mut self, pdu: &ironrdp_egfx::pdu::CapabilitiesAdvertisePdu) {
        tracing::info!(?pdu, "EGFX: client advertised graphics capabilities");
    }

    fn on_ready(&mut self, negotiated: &ironrdp_egfx::pdu::CapabilitySet) {
        tracing::info!(?negotiated, "EGFX ready — display switches to the graphics pipeline");
        // Already ready = mid-session re-advertise (client decoder recovery).
        // The pipeline server has already reset itself per MS-RDPEGFX
        // 3.2.5.18, so our surface is gone: the display loop notices that on
        // its next tick (`get_surface` returns None) and rebuilds the whole
        // sequence — ResetGraphics, CreateSurface, MapSurfaceToOutput, full
        // repaint. Nothing to do here beyond the log.
        if self.session.ready.swap(true, Ordering::Relaxed) {
            tracing::info!("EGFX re-advertised mid-session — pipeline state reset, surface will be rebuilt");
        }
    }

    fn on_close(&mut self) {
        tracing::info!("EGFX closed — display falls back to the legacy bitmap path");
        self.session.ready.store(false, Ordering::Relaxed);
        // Until this was set the message above was a lie: the display loop
        // gates on `handle()`, which stays `Some` for the life of the
        // connection, so a closed or refused channel left it holding frames
        // forever instead of falling back to anything.
        self.session.unavailable.store(true, Ordering::Relaxed);
    }
}

/// Attaches the EGFX dynamic virtual channel to the server.
pub(crate) struct LinrdpGfxFactory {
    session: Arc<GfxSession>,
}

impl LinrdpGfxFactory {
    pub(crate) fn new(session: Arc<GfxSession>) -> Self {
        Self { session }
    }
}

impl ServerEventSender for LinrdpGfxFactory {
    fn set_sender(&mut self, sender: mpsc::UnboundedSender<ServerEvent>) {
        *self.session.sender.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sender);
    }
}

impl GfxServerFactory for LinrdpGfxFactory {
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        Box::new(LinrdpGfxHandler {
            session: Arc::clone(&self.session),
        })
    }

    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let server = GraphicsPipelineServer::new(Box::new(LinrdpGfxHandler {
            session: Arc::clone(&self.session),
        }));
        let handle: GfxServerHandle = Arc::new(Mutex::new(server));
        // New connection: reset the switch state. The display loop detects
        // the new handle by pointer identity and re-creates its surface.
        self.session.ready.store(false, Ordering::Relaxed);
        self.session.unavailable.store(false, Ordering::Relaxed);
        *self.session.handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&handle));
        Some((GfxDvcBridge::new(Arc::clone(&handle)), handle))
    }

    fn on_client_graphics_support(&self, supported: bool) {
        if !supported {
            tracing::info!(
                "client did not advertise the graphics pipeline (MS-RDPEGFX 1.5) — display stays on legacy bitmaps"
            );
        }
        self.session.client_supports_egfx.store(supported, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused or closed graphics channel has to be distinguishable from one
    /// that is still negotiating. Before this, `on_close` only cleared `ready`
    /// — which was already false — so the display loop saw no change at all
    /// and held every frame for the rest of the session.
    #[test]
    fn a_closed_channel_marks_egfx_unavailable() {
        let session = Arc::new(GfxSession::new());
        assert!(!session.unavailable(), "a fresh session has not given up on EGFX");

        let mut handler = LinrdpGfxHandler {
            session: Arc::clone(&session),
        };
        handler.on_close();

        assert!(session.unavailable());
        assert!(!session.ready());
    }

    /// The next connection in this process must not inherit the previous
    /// client's verdict: `GfxSession` outlives a single connection.
    #[test]
    fn a_new_connection_clears_the_previous_verdict() {
        let session = Arc::new(GfxSession::new());
        LinrdpGfxHandler {
            session: Arc::clone(&session),
        }
        .on_close();
        assert!(session.unavailable());

        let factory = LinrdpGfxFactory::new(Arc::clone(&session));
        let built = factory.build_server_with_handle();

        assert!(built.is_some());
        assert!(!session.unavailable(), "a new connection starts EGFX negotiation afresh");
        assert!(!session.ready());
    }

    /// MS-RDPEGFX 1.5 is the only pre-channel signal, so the default must be
    /// the safe one: assume no EGFX until the client says otherwise.
    #[test]
    fn graphics_support_defaults_to_absent_and_follows_the_advertised_flag() {
        let session = Arc::new(GfxSession::new());
        assert!(!session.client_supports_egfx());

        let factory = LinrdpGfxFactory::new(Arc::clone(&session));
        factory.on_client_graphics_support(true);
        assert!(session.client_supports_egfx());

        factory.on_client_graphics_support(false);
        assert!(!session.client_supports_egfx());
    }
}
