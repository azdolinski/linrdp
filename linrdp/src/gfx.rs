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
    /// Set when the client re-advertises caps mid-session (decoder recovery):
    /// the display loop's next frame must be a forced IDR so the confused
    /// decoder can resync. The surface itself is never touched.
    force_idr: AtomicBool,
    /// Server event channel (set via [`ServerEventSender`]), used to ship
    /// drained EGFX PDUs to the wire.
    sender: Mutex<Option<mpsc::UnboundedSender<ServerEvent>>>,
}

impl GfxSession {
    pub(crate) fn new() -> Self {
        Self {
            handle: Mutex::new(None),
            ready: AtomicBool::new(false),
            force_idr: AtomicBool::new(false),
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

    /// Take the pending decoder-resync request (set by a mid-session caps
    /// re-advertise), if any.
    pub(crate) fn take_force_idr(&self) -> bool {
        self.force_idr.swap(false, Ordering::Relaxed)
    }

    /// Drain the pipeline server's output queue and ship it to the wire via
    /// the server event loop. Returns the drained byte count (for stats).
    pub(crate) fn drain_and_send(&self, handle: &GfxServerHandle) -> usize {
        let mut server = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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
            let _ = sender.send(ServerEvent::Egfx(EgfxServerMessage::SendMessages { messages }));
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
        // Already ready = mid-session re-advertise (mstsc decoder recovery):
        // request a forced IDR on the next frame so the decoder can resync.
        if self.session.ready.swap(true, Ordering::Relaxed) {
            tracing::info!("EGFX re-advertised mid-session — forcing an IDR on the next frame");
            self.session.force_idr.store(true, Ordering::Relaxed);
        }
    }

    fn on_close(&mut self) {
        tracing::info!("EGFX closed — display falls back to the legacy bitmap path");
        self.session.ready.store(false, Ordering::Relaxed);
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
        *self.session.handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(&handle));
        Some((GfxDvcBridge::new(Arc::clone(&handle)), handle))
    }
}
