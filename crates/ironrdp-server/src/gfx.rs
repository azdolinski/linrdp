//! EGFX (Graphics Pipeline Extension) server integration.
//!
//! Provides the bridge between `ironrdp-egfx`'s `GraphicsPipelineServer` and
//! `ironrdp-server`'s `RdpServer`, enabling H.264 video streaming via DVC.
//!
//! The bridge pattern (`GfxDvcBridge`) wraps an `Arc<Mutex<GraphicsPipelineServer>>`
//! so the display handler can call `send_avc420_frame()` proactively while the
//! DVC infrastructure handles client messages (capability negotiation, frame acks).

use std::sync::{Arc, Mutex};

use ironrdp_core::impl_as_any;
use ironrdp_dvc::{DvcMessage, DvcProcessor, DvcServerProcessor};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_pdu::PduResult;
use ironrdp_svc::SvcMessage;

use crate::server::ServerEventSender;

/// Shared handle to a `GraphicsPipelineServer`.
///
/// Uses `std::sync::Mutex` (not tokio) because `DvcProcessor` trait methods
/// are synchronous and cannot hold async locks.
pub type GfxServerHandle = Arc<Mutex<GraphicsPipelineServer>>;

/// Factory for creating EGFX graphics pipeline handlers.
///
/// Implements `ServerEventSender` so the factory can signal the server event loop
/// when EGFX frames are ready to be drained and sent.
pub trait GfxServerFactory: ServerEventSender + Send {
    /// Create a handler for EGFX callbacks (caps negotiation, frame acks).
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler>;

    /// Create a bridge and shared server handle for proactive frame sending.
    ///
    /// When returning `Some`, the bridge is registered with DrdynvcServer for
    /// client messages, and the handle is available for direct frame submission.
    /// Returns `None` by default, falling back to `build_gfx_handler()`.
    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        None
    }

    /// Whether this client advertised support for the graphics pipeline.
    ///
    /// [MS-RDPEGFX] 1.5 makes this the protocol's own answer to "does this
    /// client do EGFX": a client implementing the extension MUST set
    /// `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (0x0100) in the
    /// `earlyCapabilityFlags` field of its Client Core Data ([MS-RDPBCGR]
    /// 2.2.1.3.2). The flag arrives in the GCC Conference Create Request,
    /// long before any dynamic channel exists.
    ///
    /// Called once per connection, after the acceptor sequence completes and
    /// before any display update is produced. The EGFX channel is attached
    /// either way — the static channel set is consumed before this flag is
    /// known — so `false` does not mean no Create Request was sent; it means
    /// nothing should ever *wait* on that channel opening.
    ///
    /// [MS-RDPEGFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    fn on_client_graphics_support(&self, _supported: bool) {}
}

/// DVC bridge wrapping a shared `GraphicsPipelineServer`.
///
/// Delegates all `DvcProcessor` methods to the inner server through a mutex,
/// enabling shared access from both the DVC layer and the display handler.
pub struct GfxDvcBridge {
    inner: GfxServerHandle,
}

impl GfxDvcBridge {
    pub fn new(server: GfxServerHandle) -> Self {
        Self { inner: server }
    }

    pub fn server(&self) -> &GfxServerHandle {
        &self.inner
    }
}

impl_as_any!(GfxDvcBridge);

impl DvcProcessor for GfxDvcBridge {
    fn channel_name(&self) -> &str {
        ironrdp_egfx::CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.inner
            .lock()
            .expect("GfxServerHandle mutex poisoned")
            .start(channel_id)
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        self.inner
            .lock()
            .expect("GfxServerHandle mutex poisoned")
            .process(channel_id, payload)
    }

    fn close(&mut self, channel_id: u32) {
        self.inner
            .lock()
            .expect("GfxServerHandle mutex poisoned")
            .close(channel_id)
    }
}

impl DvcServerProcessor for GfxDvcBridge {}

/// Message for routing EGFX PDUs to the wire via `ServerEvent`.
#[derive(Debug)]
pub enum EgfxServerMessage {
    /// Pre-encoded DVC messages from `GraphicsPipelineServer::drain_output()`.
    ///
    /// `generation` is `GraphicsPipelineServer::generation()`, read under the
    /// same lock as the drain. The messages go out only while the connection's
    /// pipeline is still in that generation. Output drained before a
    /// mid-session CapsAdvertise, before the channel closed, or on an earlier
    /// connection is dropped (MS-RDPEGFX 3.2.5.18).
    SendMessages { messages: Vec<SvcMessage>, generation: u64 },
}

impl core::fmt::Display for EgfxServerMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SendMessages { messages, generation } => {
                write!(f, "SendMessages(count={}, generation={generation})", messages.len())
            }
        }
    }
}
