use core::fmt;
use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
#[cfg(feature = "usb")]
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Instant;

use ironrdp_acceptor::{Acceptor, AcceptorResult, BeginResult, DesktopSize};
use ironrdp_async::Framed;
use ironrdp_cliprdr::CliprdrServer;
use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_core::{decode, encode_vec, impl_as_any};
use ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout;
use ironrdp_displaycontrol::server::{DisplayControlHandler, DisplayControlServer};
use ironrdp_dvc as dvc;
#[cfg(feature = "usb")]
use ironrdp_dvc::DynamicChannelId;
use ironrdp_error::ResultExt as _;
#[cfg(feature = "usb")]
use ironrdp_pdu::PduError;
use ironrdp_pdu::codecs::rfx::Quant;
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::InputEventPdu;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
use ironrdp_pdu::mcs::{SendDataIndication, SendDataRequest};
use ironrdp_pdu::rdp::capability_sets::{
    BitmapCodecs, CapabilitySet, CmdFlags, CodecProperty, EntropyBits, GeneralExtraFlags, LargePointerSupportFlags,
};
pub use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_pdu::rdp::headers::{ServerDeactivateAll, ShareControlPdu};
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::{Action, PduResult, decode_err, mcs, nego, rdp};
use ironrdp_rdpdr as rdpdr;
use ironrdp_rdpsnd as rdpsnd;
use ironrdp_svc::{ChannelFlags, StaticChannelId, StaticChannelSet, SvcMessage, SvcProcessor, server_encode_svc_messages};
use ironrdp_tokio::{FramedRead, FramedWrite, TokioFramed, split_tokio_framed, unsplit_tokio_framed};
use rand::RngCore as _;
use rdpdr::server::{RdpdrServer, RdpdrServerMessage};
use rdpsnd::server::{RdpsndServer, RdpsndServerMessage};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};

use crate::autodetect::{AutoDetectManager, AutoDetectOutcome, RttSnapshot};
use crate::clipboard::CliprdrServerFactory;
use crate::display::{DisplayUpdate, RdpServerDisplay};
use crate::echo::{EchoDvcBridge, EchoServerHandle, EchoServerMessage, build_echo_request};
use crate::encoder::{UpdateEncoder, UpdateEncoderCodecs};
use crate::error::{ServerError, ServerErrorExt as _, ServerErrorKind, ServerResult};
#[cfg(feature = "egfx")]
use crate::gfx::{EgfxServerMessage, GfxServerFactory};
use crate::handler::RdpServerInputHandler;
use crate::heartbeat::HeartbeatConfig;
use crate::rdpei::RdpeiServerFactory;
#[cfg(feature = "usb")]
use crate::urbdrc::{
    DeviceFactory, ServerDeviceIoReq, ServerUsbDevice, UrbdrcDeviceServerMessage, UrbdrcServerMessage,
    UsbControlHandle, UsbDeviceHandle,
};
use crate::{RdpdrServerFactory, SoundServerFactory, builder, capabilities};
#[cfg(feature = "usb")]
use ironrdp_rdpeusb::{InterfaceAlloc, server::UrbdrcControlServer, server::UrbdrcDeviceServer};

/// TCP listen backlog size for the RDP server socket.
const LISTENER_BACKLOG: u32 = 1024;
const AUTO_RECONNECT_COOKIE_UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Largest update payload carried in a single slow-path Share Data PDU
/// (MS-RDPBCGR 2.2.9.1.1): the TPKT ceiling (65535) minus the Share Data
/// Header (18), a pointer update's messageType and padding (4) and X.224/MCS
/// framing overhead. Slow-path has no fragmentation, so bigger updates are
/// dropped with a warning rather than corrupted.
const MAX_SLOWPATH_UPDATE_SIZE: usize = 65_400;

/// Largest uncompressed bitmap tile encoded for a slow-path client. The
/// encoder splits damage into tiles of at most this many bytes of 32-bpp
/// pixels, so that a compressed tile, which can come out slightly larger than
/// its pixels, still fits [`MAX_SLOWPATH_UPDATE_SIZE`].
const SLOWPATH_TILE_BYTES: u32 = 48 * 1024;

/// How long a single [`ironrdp_acceptor::accept_finalize`] pass may take before
/// the connection is dropped.
///
/// A client can complete the whole security handshake — X.224, TLS, and CredSSP
/// where applicable — and then stop producing PDUs, leaving the server blocked
/// on a socket read with no timeout. Because `RdpServer` serves one connection
/// at a time, that connection then holds the server indefinitely: the socket
/// stays ESTABLISHED with both TCP queues empty, and nothing tears it down.
/// This has been observed in the field against a real client, which completed
/// MCS Connect, Erect Domain, Attach User and every channel join and then never
/// sent its Client Info PDU; the connection sat there for 45 minutes.
///
/// Generous on purpose: a healthy finalize is sub-second, and even over a slow
/// mobile link with heavy retransmits the whole pass stays within a few
/// seconds. A false timeout is cheap — the connection is dropped and the client
/// reconnects (immediately, if it holds an auto-reconnect cookie).
const FINALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// Monotonic milliseconds since first use, for feeding the auto-detect state machine.
///
/// The clock lives here, in the I/O driver, rather than inside [`AutoDetectManager`]:
/// the state machine takes timestamps as arguments so it stays free of ambient time.
/// Only differences are meaningful, so the epoch is arbitrary.
fn monotonic_now_ms() -> u64 {
    static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(EPOCH.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Action to take after a client disconnects.
///
/// Returned by [`ConnectionHandler::on_disconnected`] to control whether
/// the server continues accepting new connections or shuts down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostConnectionAction {
    /// Continue accepting new connections.
    Continue,
    /// Stop the accept loop and return from [`RdpServer::run`].
    Stop,
}

/// Per-connection metadata captured during connection setup, made available to
/// [`ConnectionHandler::on_connection_info`] once the connection is established.
///
/// These are GCC Client Core Data fields (MS-RDPBCGR 2.2.1.3.2) that the acceptor
/// captures but has no use for itself; embedders that want to act on them (for
/// example, selecting a server-side keyboard layout matching the client) can do
/// so here without reaching into the acceptor's internals.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectionInfo {
    /// See [`ironrdp_acceptor::AcceptorResult::keyboard_layout`].
    pub keyboard_layout: u32,
    /// See [`ironrdp_acceptor::AcceptorResult::keyboard_type`].
    pub keyboard_type: ironrdp_pdu::gcc::KeyboardType,
    /// See [`ironrdp_acceptor::AcceptorResult::ime_file_name`].
    pub ime_file_name: String,
    /// See [`ironrdp_acceptor::AcceptorResult::desktop_size`].
    pub desktop_size: ironrdp_connector::DesktopSize,
    /// See [`ironrdp_acceptor::AcceptorResult::client_cluster`].
    pub client_cluster: Option<ironrdp_pdu::gcc::ClientClusterData>,
}

impl ConnectionInfo {
    /// Builds a `ConnectionInfo` directly, for downstream `ConnectionHandler` implementations
    /// that want to exercise [`ConnectionHandler::on_connection_info`] in their own unit tests
    /// without going through a live connection. `#[non_exhaustive]` blocks struct-literal
    /// construction outside this crate, so a constructor is the only way to do that.
    pub fn new(
        keyboard_layout: u32,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType,
        ime_file_name: String,
        desktop_size: ironrdp_connector::DesktopSize,
    ) -> Self {
        Self {
            keyboard_layout,
            keyboard_type,
            ime_file_name,
            desktop_size,
            client_cluster: None,
        }
    }

    /// The same, with Client Cluster Data — for tests of console routing.
    #[must_use]
    pub fn with_client_cluster(mut self, cluster: Option<ironrdp_pdu::gcc::ClientClusterData>) -> Self {
        self.client_cluster = cluster;
        self
    }

    /// Whether the client asked for the console session (`mstsc /admin`):
    /// Client Cluster Data with `REDIRECTED_SESSIONID_FIELD_VALID` naming
    /// session 0, the console's.
    pub fn requests_console(&self) -> bool {
        self.client_cluster.as_ref().is_some_and(|cluster| {
            cluster
                .flags
                .contains(ironrdp_pdu::gcc::RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID)
                && cluster.redirected_session_id == 0
        })
    }
}

#[cfg(test)]
mod connection_info_tests {
    use ironrdp_pdu::gcc::{ClientClusterData, RedirectionFlags, RedirectionVersion};

    use super::ConnectionInfo;

    fn info(flags: RedirectionFlags, session: u32) -> ConnectionInfo {
        ConnectionInfo::new(
            0,
            ironrdp_pdu::gcc::KeyboardType(0),
            String::new(),
            ironrdp_connector::DesktopSize { width: 1, height: 1 },
        )
        .with_client_cluster(Some(ClientClusterData {
            flags,
            redirection_version: RedirectionVersion::V4,
            redirected_session_id: session,
        }))
    }

    /// What mstsc sends with and without `/admin`, as logged live:
    /// flags 0x3 (`/admin`) and 0x1.
    #[test]
    fn admin_is_a_request_for_session_zero() {
        let admin = RedirectionFlags::REDIRECTION_SUPPORTED | RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID;
        assert!(info(admin, 0).requests_console());
        assert!(!info(RedirectionFlags::REDIRECTION_SUPPORTED, 0).requests_console());
        // A redirect to some other session is not the console.
        assert!(!info(admin, 7).requests_console());
        let none = ConnectionInfo::new(
            0,
            ironrdp_pdu::gcc::KeyboardType(0),
            String::new(),
            ironrdp_connector::DesktopSize { width: 1, height: 1 },
        );
        assert!(!none.requests_console());
    }
}

/// Hooks for connection lifecycle events.
///
/// Implement this trait to add pre-accept filtering (rate limiting,
/// IP allowlists), post-disconnect logic (cleanup, session validity
/// checks, metrics), and to observe per-connection metadata once a
/// connection is established.
///
/// All methods have default implementations that accept all connections
/// and continue unconditionally.
///
/// [`Self::on_accept`] is called only from [`RdpServer::run`]'s own accept
/// loop, because only that loop does the accepting.
///
/// [`Self::on_connection_info`] and [`Self::on_disconnected`] are called from
/// every code path that runs a connection, including
/// [`RdpServer::run_connection`] and [`RdpServer::run_connection_with`].
/// `on_disconnected` was once `run`-only, and that made it unusable for its
/// main purpose: an embedder that forks a process per connection and calls
/// `run_connection` never reached its own teardown at all, so whatever it did
/// there — releasing a session, locking a desktop, restoring a console — did
/// not happen. Exactly one dispatch per connection: `run` calls
/// `run_connection_inner` directly and dispatches itself, so nothing is
/// doubled.
///
/// Embedders outside `run` have no accepted address to report, so
/// `on_disconnected` receives whatever [`RdpServer::set_peer_addr`] was told,
/// and an unspecified address when it was told nothing.
pub trait ConnectionHandler: Send {
    /// Called after `accept()` returns but before `run_connection()`.
    ///
    /// Return `false` to reject the connection (the TCP stream is dropped).
    fn on_accept(&mut self, peer: SocketAddr) -> bool {
        let _ = peer;
        true
    }

    /// Called once per connection, after credential and auto-reconnect
    /// validation succeed and before the session loop starts.
    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        let _ = info;
    }

    /// Called after `run_connection()` completes (successfully or with error).
    ///
    /// `duration` is the wall-clock time the connection was active.
    /// `error` is `Some` if the connection ended with an error.
    fn on_disconnected(
        &mut self,
        peer: SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
    ) -> PostConnectionAction {
        let _ = (peer, duration, error);
        PostConnectionAction::Continue
    }
}

/// Outcome of a successful [`CredentialValidator::validate`] call.
///
/// A rejection from a working validator is not an error: the validator did
/// its job and decided the credentials do not authenticate. Backend failures
/// (LDAP unreachable, PAM transport broken, database connection lost) are
/// reported via [`CredentialValidationError`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialDecision {
    /// Credentials accepted; the connection proceeds.
    Accept,
    /// Credentials rejected; the connection is closed.
    Reject,
}

/// Error returned by a [`CredentialValidator`] when the validator backend
/// itself fails (rather than the credentials being invalid).
///
/// Wraps any [`core::error::Error`] from the backend (LDAP/PAM/DB/etc.) so
/// the trait does not require a particular error library in implementors or
/// consumers.
#[derive(Debug)]
pub struct CredentialValidationError {
    source: Box<dyn core::error::Error + Send + Sync>,
}

impl CredentialValidationError {
    /// Wrap a backend error as a credential-validation failure.
    pub fn new<E>(source: E) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for CredentialValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credential validator backend failure")
    }
}

impl core::error::Error for CredentialValidationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&*self.source)
    }
}

/// Server-side credential validator for TLS-mode connections.
///
/// Called during connection setup when the server receives client credentials
/// via `ClientInfoPdu`. Not used for CredSSP/Hybrid connections (those use
/// pre-loaded credentials for NTLM challenge-response).
///
/// Implement this trait to validate credentials against external systems
/// (PAM, LDAP, database, etc.). For blocking backends, wrap the call in
/// `tokio::task::spawn_blocking` to avoid stalling the async runtime.
///
/// # Example
///
/// ```ignore
/// use ironrdp_server::{CredentialDecision, CredentialValidationError, CredentialValidator, Credentials};
///
/// struct StaticValidator {
///     expected_user: String,
///     expected_password: String,
/// }
///
/// #[async_trait::async_trait]
/// impl CredentialValidator for StaticValidator {
///     async fn validate(
///         &self,
///         creds: &Credentials,
///     ) -> Result<CredentialDecision, CredentialValidationError> {
///         if creds.username == self.expected_user && creds.password == self.expected_password {
///             Ok(CredentialDecision::Accept)
///         } else {
///             Ok(CredentialDecision::Reject)
///         }
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait CredentialValidator: Send + Sync {
    /// Validate credentials received from the client.
    ///
    /// Return `Ok(CredentialDecision::Accept)` to permit the connection,
    /// `Ok(CredentialDecision::Reject)` to refuse it. Return
    /// `Err(CredentialValidationError::new(_))` only when the validator
    /// itself could not produce a decision (backend system error).
    ///
    /// Implementors backed by blocking systems (PAM, libldap, a synchronous
    /// database driver) should offload the work, for example with
    /// `tokio::task::spawn_blocking`, so the returned future does not stall the
    /// caller's executor. Native-async backends can simply `.await`.
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError>;
}

/// A built-in [`CredentialValidator`] that accepts exactly one fixed set of credentials.
///
/// This is the validation-policy equivalent of the acceptor's pre-loaded
/// exact-match: it keeps the common "one known account" case a one-liner while
/// going through the same hook as PAM, LDAP, or database-backed validators.
pub struct ExactMatchCredentialValidator {
    expected: Credentials,
}

impl ExactMatchCredentialValidator {
    /// Build a validator that accepts only `expected` and rejects everything else.
    pub fn new(expected: Credentials) -> Self {
        Self { expected }
    }
}

#[async_trait::async_trait]
impl CredentialValidator for ExactMatchCredentialValidator {
    async fn validate(&self, credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
        if credentials == &self.expected {
            Ok(CredentialDecision::Accept)
        } else {
            Ok(CredentialDecision::Reject)
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct RdpServerOptions {
    pub addr: SocketAddr,
    pub security: RdpServerSecurity,
    pub codecs: BitmapCodecs,
    pub max_request_size: u32,
    /// When `Some`, the server sends a Server Initiate Multitransport Request
    /// PDU (MS-RDPBCGR 2.2.15.1) on the I/O channel right after the connection
    /// sequence completes, asking the client to establish a sideband RDP-UDP
    /// transport (MS-RDPEMT). The `request_id` + `security_cookie` pair is
    /// generated by the embedder, which is also responsible for running the
    /// UDP listener (`ironrdp-rdpeudp-tokio::accept_udp`) that validates them.
    ///
    /// The request is only sent when the client announced both
    /// `TRANSPORT_TYPE_UDP_FECR` and `SOFT_SYNC_TCP_TO_UDP` in its GCC
    /// MultiTransportChannelData: dynamic channels move to the tunnel only by
    /// Soft-Sync (MS-RDPEDYC 3.1.5.3).
    pub multitransport: Option<MultiTransportRequest>,
    /// When `Some(max)`, each connection's acceptor adopts the desktop size the
    /// client requests in its Client Core Data (instead of the size reported by
    /// the display handler), negotiating that size from the start without a
    /// Deactivation-Reactivation resize. The request is clamped per dimension to
    /// `max` so an untrusted client can't drive the framebuffer/encoder
    /// allocation past that ceiling. `None` (the default) always enforces the
    /// server-provided size. Set via
    /// [`RdpServerBuilder::with_honor_client_desktop_size`](crate::RdpServerBuilder::with_honor_client_desktop_size).
    pub honor_client_desktop_size: Option<DesktopSize>,
    /// When `true`, a new connection accepted while [`RdpServer::run`] is
    /// already serving another one PREEMPTS it: once the newcomer has
    /// **completed authentication**, the existing connection is told why it is
    /// going away and dropped, and the newcomer is served in its place.
    ///
    /// [`RdpServer`] serves one connection at a time. By default a second
    /// connection accepted while one is live is left unserved in the OS listen
    /// backlog — from that client's point of view, a silent hang until the
    /// first session ends. That is `ironrdp-server`'s pre-existing behaviour,
    /// kept as the default so an embedder that already relies on it is not
    /// surprised by upgrading; it does not suit a server backing a single
    /// specific session (e.g. mirroring one desktop), where a newly connecting
    /// client should replace a stale or abandoned one.
    ///
    /// # Security — what a candidate must clear, per mode
    ///
    /// Evicting a live session is disruptive, so a candidate runs the FULL
    /// negotiation — and, under [`RdpServerSecurity::Hybrid`], CredSSP/NLA —
    /// before the live session is touched at all. A candidate that fails at any
    /// step leaves the live session untouched.
    ///
    /// How strong that bar actually is depends entirely on the security mode,
    /// because only `Hybrid` authenticates the *client* before the point a
    /// candidate reaches. **Read this table before enabling the option:**
    ///
    /// | Security mode | Bar to preempt | Guarantee |
    /// |---|---|---|
    /// | [`Hybrid`](RdpServerSecurity::Hybrid) | CredSSP/NLA succeeds | an unauthenticated peer can never evict |
    /// | [`Tls`](RdpServerSecurity::Tls) | a TLS handshake — which authenticates the *server* to the client, not the reverse | **none against an unauthenticated peer**: any peer that can reach the port clears it, and a [`CredentialValidator`] does not run until finalization |
    /// | [`None`](RdpServerSecurity::None) | a well-formed X.224 Connection Request | **none**: this mode authenticates nothing |
    ///
    /// So under `Tls` and `None` an unauthenticated peer CAN evict an
    /// authenticated session, repeatedly — the anti-storm cooldown bars the
    /// victim, never the attacker. A warning is logged at startup in that case.
    /// If you need takeover to be authentication-gated, use `Hybrid`; if you
    /// must enable it under another mode, restrict who may attempt one with
    /// [`ConnectionHandler::on_accept`].
    ///
    /// Candidates are additionally gated through
    /// [`ConnectionHandler::on_accept`] *before* they are allowed to
    /// negotiate, so an IP allowlist or rate limiter bounds who may even
    /// attempt a takeover. It does NOT bound how long one admitted candidate
    /// can occupy the (single) negotiation slot before another is even
    /// considered — see the limitation documented on
    /// `CANDIDATE_NEGOTIATION_TIMEOUT`.
    ///
    /// Defaults to `false` (queue-behind, the pre-existing behaviour). Set via
    /// [`RdpServerBuilder::with_preempt_existing_session`](crate::RdpServerBuilder::with_preempt_existing_session).
    pub preempt_existing_session: bool,
    /// Quantization values the RemoteFX encoder uses once selected. Defaults
    /// to [`Quant::default`], the same values Windows RDP servers send. Set
    /// via
    /// [`RdpServerBuilder::with_remotefx_quant`](crate::RdpServerBuilder::with_remotefx_quant).
    pub remotefx_quant: Quant,
    /// Preferred RemoteFX entropy coder. If the client's advertised
    /// TS_RFX_ICAP array includes it, the server uses it; otherwise the
    /// server falls back to whichever coder the client offered first.
    /// `None` (the default) always uses whichever coder is offered first,
    /// since [MS-RDPRFX] 3.1.5.1 has the server arbitrarily pick one
    /// supported TS_RFX_ICAP element rather than rank the array as a
    /// preference order. Set via
    /// [`RdpServerBuilder::with_remotefx_entropy_coder`](crate::RdpServerBuilder::with_remotefx_entropy_coder).
    ///
    /// [MS-RDPRFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx/
    pub remotefx_entropy_coder: Option<EntropyBits>,
}

impl RdpServerOptions {
    /// Default [MultifragmentUpdate] max reassembly buffer size (8 MB).
    ///
    /// Advertised to the client during capability exchange as the largest
    /// reassembled Fast-Path Update the server can accept.
    /// Values that are too large cause certain clients (notably mstsc)
    /// to reject the connection.
    ///
    /// [MultifragmentUpdate]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/01717954-716a-424d-af35-28fb2b86df89
    pub(crate) const DEFAULT_MAX_REQUEST_SIZE: u32 = 8 * 1024 * 1024;

    fn has_image_remote_fx(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::ImageRemoteFx(_)))
    }

    fn has_remote_fx(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::RemoteFx(_)))
    }

    #[cfg(feature = "qoi")]
    fn has_qoi(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::Qoi))
    }

    #[cfg(feature = "qoiz")]
    fn has_qoiz(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::QoiZ))
    }

    #[cfg(feature = "nscodec")]
    fn has_nscodec(&self) -> bool {
        self.codecs
            .0
            .iter()
            .any(|codec| matches!(codec.property, CodecProperty::NsCodec(_)))
    }
}

/// Picks a RemoteFX entropy coder out of the client's advertised TS_RFX_ICAP
/// array. Returns `preferred` if the client offered it, otherwise the first
/// coder the client offered. Returns `None` if `offered` is empty.
pub fn pick_remotefx_entropy_coder(
    preferred: Option<EntropyBits>,
    offered: impl Iterator<Item = EntropyBits>,
) -> Option<EntropyBits> {
    let mut first = None;

    for entropy_bits in offered {
        if first.is_none() {
            first = Some(entropy_bits);
        }

        if preferred == Some(entropy_bits) {
            return Some(entropy_bits);
        }
    }

    first
}

#[derive(Clone)]
pub enum RdpServerSecurity {
    None,
    Tls(TlsAcceptor),
    /// Used for both hybrid + hybrid-ex.
    Hybrid((TlsAcceptor, Vec<u8>)),
    /// Advertise TLS *and* CredSSP, and let each client take the strongest it
    /// supports (MS-RDPBCGR 5.4.5.1 negotiation).
    ///
    /// A client that offers HYBRID gets NLA and proves itself before the
    /// session exists; one that offers only SSL gets TLS and sends its
    /// credentials in the Client Info PDU instead. Without this, a port has to
    /// pick one, and a client that cannot speak that one is simply refused —
    /// mstsc on a TLS-only port sends no credentials at all and reports
    /// 0x904.
    HybridOrTls((TlsAcceptor, Vec<u8>)),
}

impl RdpServerSecurity {
    pub fn flag(&self) -> nego::SecurityProtocol {
        match self {
            RdpServerSecurity::None => nego::SecurityProtocol::empty(),
            RdpServerSecurity::Tls(_) => nego::SecurityProtocol::SSL,
            RdpServerSecurity::Hybrid(_) => nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX,
            RdpServerSecurity::HybridOrTls(_) => {
                nego::SecurityProtocol::SSL | nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX
            }
        }
    }
}

struct AInputHandler {
    handler: Arc<Mutex<Box<dyn RdpServerInputHandler>>>,
}

impl_as_any!(AInputHandler);

impl dvc::DvcProcessor for AInputHandler {
    fn channel_name(&self) -> &str {
        ironrdp_ainput::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<dvc::DvcMessage>> {
        use ironrdp_ainput::{ServerPdu, VersionPdu};

        let pdu = ServerPdu::Version(VersionPdu::default());

        Ok(vec![Box::new(pdu)])
    }

    fn close(&mut self, _channel_id: u32) {}

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<dvc::DvcMessage>> {
        use ironrdp_ainput::ClientPdu;

        match decode(payload).map_err(|e| decode_err!(e))? {
            ClientPdu::Mouse(pdu) => {
                let handler = Arc::clone(&self.handler);
                task::spawn_blocking(move || {
                    handler.blocking_lock().mouse(pdu.into());
                });
            }
        }

        Ok(Vec::new())
    }
}

impl dvc::DvcServerProcessor for AInputHandler {}

struct DisplayControlBackend {
    display: Arc<Mutex<Box<dyn RdpServerDisplay>>>,
}

impl DisplayControlBackend {
    fn new(display: Arc<Mutex<Box<dyn RdpServerDisplay>>>) -> Self {
        Self { display }
    }
}

impl DisplayControlHandler for DisplayControlBackend {
    fn monitor_layout(&self, layout: DisplayControlMonitorLayout) {
        let display = Arc::clone(&self.display);
        task::spawn_blocking(move || display.blocking_lock().request_layout(layout));
    }
}

#[cfg(feature = "usb")]
struct ServerUsbManager {
    factory: Box<dyn DeviceFactory>,
    comp_iface_alloc: InterfaceAlloc,
    router: HashMap<DynamicChannelId, Arc<ServerUsbDevice>>,
}

#[cfg(feature = "usb")]
impl ServerUsbManager {
    fn new(inner: Box<dyn DeviceFactory>) -> Self {
        Self {
            factory: inner,
            comp_iface_alloc: InterfaceAlloc::default(),
            router: HashMap::new(),
        }
    }
}

/// Selects who performs the TLS handshake for a connection accepted via
/// [`RdpServer::run_connection_with`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TransportTls {
    /// IronRDP performs the TLS accept on the stream (standard TCP+TLS).
    Managed,
    /// The stream is already past TLS, terminated by a lower layer (e.g. a WSS
    /// terminator). IronRDP skips the TLS handshake. The caller MUST guarantee
    /// the transport is already encrypted; see the preconditions on
    /// [`RdpServer::run_connection_with`].
    AlreadyDone,
}

/// RDP Server
///
/// A server is created to listen for connections.
/// After the connection sequence is finalized using the provided security mechanism, the server can:
///  - receive display updates from a [`RdpServerDisplay`] and forward them to the client
///  - receive input events from a client and forward them to an [`RdpServerInputHandler`]
///
/// # Example
///
/// ```
/// use ironrdp_server::{RdpServer, RdpServerInputHandler, RdpServerDisplay, RdpServerDisplayUpdates};
///
///# use ironrdp_server::{DisplayUpdate, DesktopSize, KeyboardEvent, MouseEvent, ServerResult};
///# use tokio_rustls::TlsAcceptor;
///# struct NoopInputHandler;
///# impl RdpServerInputHandler for NoopInputHandler {
///#     fn keyboard(&mut self, _: KeyboardEvent) {}
///#     fn mouse(&mut self, _: MouseEvent) {}
///# }
///# struct NoopDisplay;
///# #[async_trait::async_trait]
///# impl RdpServerDisplay for NoopDisplay {
///#     async fn size(&mut self) -> DesktopSize {
///#         todo!()
///#     }
///#     async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
///#         todo!()
///#     }
///# }
///# async fn stub() -> ServerResult<()> {
/// fn make_tls_acceptor() -> TlsAcceptor {
///    /* snip */
///#    todo!()
/// }
///
/// fn make_input_handler() -> impl RdpServerInputHandler {
///    /* snip */
///#    NoopInputHandler
/// }
///
/// fn make_display_handler() -> impl RdpServerDisplay {
///    /* snip */
///#    NoopDisplay
/// }
///
/// let tls_acceptor = make_tls_acceptor();
/// let input_handler = make_input_handler();
/// let display_handler = make_display_handler();
///
/// let mut server = RdpServer::builder()
///     .with_addr(([127, 0, 0, 1], 3389))
///     .with_tls(tls_acceptor)
///     .with_input_handler(input_handler)
///     .with_display_handler(display_handler)
///     .build();
///
/// server.run().await;
/// Ok(())
///# }
/// ```
/// Embedder-supplied parameters for the Server Initiate Multitransport
/// Request PDU (MS-RDPBCGR 2.2.15.1).
///
/// The pair binds the TCP session to the sideband UDP transport: the client
/// echoes both in its Tunnel Create Request over UDP (MS-RDPEMT), where the
/// server's `accept_udp` validates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiTransportRequest {
    pub request_id: u32,
    pub security_cookie: [u8; 16],
}

pub struct RdpServer {
    opts: RdpServerOptions,
    // FIXME: replace with a channel and poll/process the handler?
    handler: Arc<Mutex<Box<dyn RdpServerInputHandler>>>,
    display: Arc<Mutex<Box<dyn RdpServerDisplay>>>,
    static_channels: StaticChannelSet,
    static_channel_factories: Vec<Box<dyn StaticChannelFactory>>,
    dynamic_channel_attachers: Vec<Box<dyn FnMut(&mut dvc::DrdynvcServer) + Send>>,
    sound_factory: Option<Box<dyn SoundServerFactory>>,
    cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
    rdpei_factory: Option<Box<dyn RdpeiServerFactory>>,
    rdpdr_factory: Option<Box<dyn RdpdrServerFactory>>,
    echo_handle: EchoServerHandle,
    #[cfg(feature = "egfx")]
    gfx_factory: Option<Box<dyn GfxServerFactory>>,
    #[cfg(feature = "egfx")]
    gfx_handle: Option<crate::gfx::GfxServerHandle>,
    #[cfg(feature = "usb")]
    usb_man: Option<ServerUsbManager>,
    ev_sender: mpsc::UnboundedSender<ServerEvent>,
    ev_receiver: Arc<Mutex<mpsc::UnboundedReceiver<ServerEvent>>>,
    creds: Option<Credentials>,
    credential_validator: Option<Arc<dyn CredentialValidator>>,
    credential_resolver: Option<std::sync::Arc<dyn Fn(&str) -> std::io::Result<Credentials> + Send + Sync>>,
    enable_ainput: bool,
    /// What the Display Control channel advertises (MS-RDPEDISP 2.2.2.1);
    /// `None` keeps `DisplayControlServer`'s default.
    display_control_caps: Option<ironrdp_displaycontrol::pdu::DisplayControlCapabilities>,
    /// Who is on the other end, for embedders that accepted the connection
    /// themselves and then handed the stream to
    /// [`Self::run_connection`](RdpServer::run_connection). `run`'s own loop
    /// knows this from `accept` and does not consult it.
    peer_addr: Option<SocketAddr>,
    /// How long a connection may take to get from the first byte to a
    /// finished handshake, if the embedder set a deadline.
    ///
    /// Nothing in the negotiation has a deadline of its own: it waits for the
    /// client's first PDU, then for a TLS handshake, then for CredSSP, each
    /// for as long as the client likes. A client that connects and says
    /// nothing therefore held its connection — and, for embedders that fork
    /// per connection, its process — indefinitely. The timeouts that do exist
    /// (preemption candidate, finalize) all start after this.
    handshake_timeout: Option<Duration>,
    local_addr: Option<SocketAddr>,
    autodetect: Option<AutoDetectManager>,
    /// Sender half of the UDP multitransport tunnel, installed by
    /// [`ServerEvent::SoftSyncToUdp`] once the embedder's RDP-UDP accept
    /// completed. `None` = no tunnel (all DVC traffic stays on TCP).
    udp_tunnel_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Whether the client has confirmed the multitransport tunnel with a
    /// successful Initiate Multitransport Response (MS-RDPBCGR 2.2.15.2).
    ///
    /// MS-RDPEDYC 3.3.5.3.1: the Soft-Sync Request MUST NOT be sent before
    /// that response. The RDP-UDP handshake usually completes first, and
    /// sending Soft-Sync then — which this server did on every connection —
    /// is mostly tolerated by mstsc, but not when it lands while the EGFX
    /// channel is being set up: mstsc then resets the TCP connection
    /// (`write dvc messages: Connection reset by peer`, 0.46 s into the
    /// session, reproduced against a GNOME session on 2026-09-23).
    multitransport_confirmed: bool,
    /// The requestId of the Initiate Multitransport Request this connection
    /// sent, if it sent one. MS-RDPBCGR 2.2.15.2: the response's requestId
    /// "MUST contain the ID that was sent to the client"; a response carrying
    /// any other confirms nothing.
    multitransport_request_id: Option<u32>,
    /// A tunnel that came up before the client confirmed it: Soft-Sync waits
    /// here until the response arrives.
    pending_soft_sync: Option<mpsc::Sender<Vec<u8>>>,
    heartbeat: Option<HeartbeatConfig>,
    /// Whether the client set RNS_UD_CS_SUPPORT_ERRINFO_PDU in its Client
    /// Core Data `earlyCapabilityFlags`. MS-RDPBCGR 3.3.5.7.1: the Set Error
    /// Info PDU MUST NOT be sent to a client that did not set it.
    client_supports_errinfo: bool,
    /// Whether the client set RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT: it
    /// "supports network characteristics detection using the structures and
    /// PDUs described in section 2.2.14" (MS-RDPBCGR 2.2.1.3.2). Auto-detect
    /// requests go only to such a client.
    client_supports_autodetect: bool,
    /// Whether the client advertised FASTPATH_OUTPUT_SUPPORTED (2.2.7.1.1).
    /// When it did not, display updates fall back to slow-path Share Data
    /// Update PDUs (MS-RDPBCGR 2.2.9.1.1) instead of failing the session.
    client_fastpath_output: bool,
    /// Whether the CURRENT disconnect was initiated by the client (Shutdown
    /// Request PDU or MCS Disconnect Provider Ultimatum). Server-initiated
    /// teardowns send their own Ultimatum (MS-RDPBCGR 3.3.5.6); echoing one
    /// back at a client that is already leaving would be noise.
    client_initiated_disconnect: bool,
    connection_handler: Option<Box<dyn ConnectionHandler>>,
    /// Anti-storm net for [`RdpServerOptions::preempt_existing_session`]: the
    /// peer most recently EVICTED by a takeover, and when it last tried to
    /// come back.
    ///
    /// Telling the loser why it was evicted (see
    /// [`ServerEvent::EvictedByOtherConnection`]) is the real fix for the
    /// eviction loop, but whether a client honours it is client-dependent.
    /// This bounds the damage if one doesn't: a just-evicted peer may not
    /// immediately re-preempt, and each refused attempt RE-ARMS the window, so
    /// an automatic reconnect storm can never win the session back, while a
    /// human who closes the client and reconnects still can. Keyed on source
    /// IP, since the source port changes on every reconnect. Cleared once a
    /// session ends on its own terms rather than being replaced.
    recently_evicted: Option<EvictedPeer>,
    /// True while the client has sent `SuppressOutput { desktop_rect: None }`
    /// — the standard RDP "I don't need display updates right now" signal
    /// (mstsc raises it on window minimize). Cleared on
    /// `SuppressOutput { Some(rect) }` or `RefreshRectangle` (sent on
    /// refocus). Exposed via [`Self::display_suppressed_handle`] so display
    /// backends can hold a clone and skip frame emission while it's set —
    /// without this, a server keeps streaming high-bitrate
    /// EGFX/H.264 frames into a minimized client, which accumulates them
    /// and locks up its input dispatch for seconds on refocus while it
    /// chews through the backlog.
    display_suppressed: Arc<AtomicBool>,

    /// Latest NetworkAutoDetect round-trip time in milliseconds, or `u32::MAX`
    /// until the first measurement (and while auto-detect is disabled). Updated
    /// on each RTT Measure Response when auto-detect is enabled (see
    /// [`Self::enable_autodetect`]). Exposed via [`Self::autodetect_rtt_handle`]
    /// so display backends can read a fresh, frame-traffic-independent network
    /// RTT for flow control.
    autodetect_rtt: Arc<AtomicU32>,

    /// Session-lifetime lowest RTT in milliseconds (`baseRTT` per MS-RDPBCGR
    /// 2.2.14.1.5), or `u32::MAX` until the first measurement. Unlike
    /// [`Self::autodetect_rtt`], this never rises: it is the floor over the
    /// whole session, not a sliding-window figure, which is what makes
    /// `averageRTT - baseRTT` a queueing-delay signal rather than two
    /// unrelated latency numbers. Updated at the same point as
    /// [`Self::autodetect_rtt`]. Exposed via
    /// [`Self::autodetect_baseline_rtt_handle`].
    autodetect_baseline_rtt: Arc<AtomicU32>,

    /// Latest NetworkAutoDetect measured bandwidth in kilobits per second, or
    /// `u32::MAX` until the first measurement completes (and while auto-detect
    /// is disabled). Updated whenever a Bandwidth Measure Results response is
    /// processed, same trigger point as [`Self::autodetect_rtt`]. Exposed via
    /// [`Self::autodetect_bandwidth_handle`]: without it, the server can tell
    /// the *client* its measured bandwidth over the wire but has no way to
    /// tell the embedder, which the connect-time figure carried to the client
    /// alone does not fix.
    autodetect_bandwidth: Arc<AtomicU32>,

    /// Client-advertised `pointerCacheSize` (MS-RDPBCGR 2.2.7.1.5), or `0`
    /// until capability exchange (and for clients that do not advertise the
    /// New Pointer Update at all). Display backends that manage a
    /// `CachedPointer` slot LRU need this bound; the `UpdateEncoder` keeps
    /// its own copy and drops pointer updates that exceed it, so a backend
    /// reading a stale larger value only wastes slots, never breaks the
    /// client. Exposed via [`Self::pointer_cache_handle`].
    negotiated_pointer_cache: Arc<AtomicU16>,

    /// Frame Acknowledge accounting (MS-RDPBCGR 2.2.2.3), shared between the
    /// display loop (paces frame emission on the client's presentation rate)
    /// and the slow-path input handler (records incoming Frame Acknowledge
    /// PDUs).
    frame_ack_state: Arc<FrameAckState>,

    /// Client-advertised `maxUnackFrameCount` (MS-RDPBCGR 2.2.7.2.11). Zero
    /// (or no Frame Acknowledge capability set at all) means the client does
    /// not ack frames — pacing must stay off in that case, or the display
    /// loop would deadlock waiting for acks that never arrive.
    frame_ack_limit: u32,

    /// Optional Server Auto-Reconnect Cookie (MS-RDPBCGR 2.2.4.2
    /// `ARC_SC_PRIVATE_PACKET`). When `Some`, the server validates a returning
    /// `ARC_CS_PRIVATE_PACKET`, replaces its random after every connection, and
    /// sends hourly updates to the active client. This requires TLS or Hybrid
    /// security, which provides the all-zero client random required for Enhanced
    /// RDP Security. `None` (the default) disables automatic reconnection.
    /// Configure it on the builder
    /// ([`RdpServer::builder`]) via `with_auto_reconnect_cookie`, or after
    /// construction via [`Self::set_auto_reconnect_cookie`].
    auto_reconnect_cookie: Option<rdp::session_info::ServerAutoReconnect>,
    /// The cookie replaced by the current one, accepted until the next rotation.
    ///
    /// A successful socket write does not prove the client received the
    /// replacement. Retaining one previous value lets a client that disconnects
    /// during that window reconnect with the last cookie it knows.
    previous_auto_reconnect_cookie: Option<rdp::session_info::ServerAutoReconnect>,
    /// Tracks whether the current cookie has reached a client. Subsequent
    /// connections and hourly updates replace it with a new random.
    auto_reconnect_sent: bool,
}

/// Cloneable handle for updating the Server Auto-Reconnect Cookie while
/// [`RdpServer::run`] owns the server.
#[derive(Clone)]
pub struct AutoReconnectCookieHandle {
    sender: mpsc::UnboundedSender<ServerEvent>,
}

impl AutoReconnectCookieHandle {
    /// Queue a replacement cookie for the active client or the next connection.
    ///
    /// The change takes effect only after the server handles this event. `None`
    /// then disables auto-reconnect and invalidates every cookie currently held
    /// by the server.
    #[expect(
        clippy::result_large_err,
        reason = "SendError<ServerEvent> hands the whole event back on a closed channel; ServerEvent's size is \
                  driven by its largest per-channel payload (RdpdrServerMessage), not by anything this method does"
    )]
    pub fn set(
        &self,
        cookie: Option<rdp::session_info::ServerAutoReconnect>,
    ) -> Result<(), mpsc::error::SendError<ServerEvent>> {
        self.sender.send(ServerEvent::SetAutoReconnectCookie(cookie))
    }
}

/// Cloneable handle for gracefully disconnecting the active client with a
/// `ServerSetErrorInfo` PDU (MS-RDPBCGR 2.2.5.1) while [`RdpServer::run`]
/// owns the server.
#[derive(Clone)]
pub struct ErrorInfoDisconnectHandle {
    sender: mpsc::UnboundedSender<ServerEvent>,
}

impl ErrorInfoDisconnectHandle {
    /// Send `error` to the client via a `ServerSetErrorInfoPdu`, then close the
    /// connection.
    ///
    /// The disconnect takes effect only after the server handles this event.
    /// Unlike [`ServerEvent::Quit`], the client is told why: it decodes the
    /// PDU and can surface `error` to the user before the connection drops.
    #[expect(
        clippy::result_large_err,
        reason = "SendError<ServerEvent> hands the whole event back on a closed channel; ServerEvent's size is \
                  driven by its largest per-channel payload (RdpdrServerMessage), not by anything this method does"
    )]
    pub fn disconnect(&self, error: ErrorInfo) -> Result<(), mpsc::error::SendError<ServerEvent>> {
        self.sender.send(ServerEvent::Disconnect(error))
    }
}

pub enum ServerEvent {
    Quit(String),
    /// End this connection because an authenticated candidate is taking the
    /// session over — a preemption, not a plain quit.
    ///
    /// Unlike [`Self::Quit`], this sends a Server Set Error Info PDU carrying
    /// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (MS-RDPBCGR 2.2.5.1.1 — the
    /// code real Windows RDS uses for a session takeover) before
    /// disconnecting. That distinction is load-bearing rather than cosmetic
    /// whenever a Server Auto-Reconnect Cookie is in play: a client dropped
    /// with no explanation auto-reconnects a second later, re-preempts the
    /// client that replaced it, and the two ping-pong indefinitely. Telling
    /// the loser WHY it was disconnected is what makes it stay away.
    ///
    /// A more general version of the same PDU/mechanism exists as
    /// [`Self::Disconnect`] (upstream, `ErrorInfoDisconnectHandle`) for an
    /// embedder-chosen [`ErrorInfo`]; this variant stays separate because its
    /// reason is fixed (always `DisconnectedByOtherconnection`) and it is
    /// wired specifically to the preemption race, not exposed as a public
    /// handle.
    EvictedByOtherConnection,
    /// Disconnect the active client with a `ServerSetErrorInfoPdu` carrying
    /// the given reason. See [`ErrorInfoDisconnectHandle::disconnect`].
    Disconnect(ErrorInfo),
    Clipboard(ClipboardMessage),
    Rdpsnd(RdpsndServerMessage),
    Rdpdr(RdpdrServerMessage),
    Echo(EchoServerMessage),
    SetCredentials(Credentials),
    /// Replace or clear the Server Auto-Reconnect Cookie.
    SetAutoReconnectCookie(Option<rdp::session_info::ServerAutoReconnect>),
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    #[cfg(feature = "egfx")]
    Egfx(EgfxServerMessage),
    /// Trigger an RTT measurement probe (requires auto-detect enabled).
    AutoDetectRttRequest,
    #[cfg(feature = "usb")]
    Usb(UrbdrcServerMessage),
    /// Bind an established RDP-UDP multitransport tunnel (MS-RDPEMT) to this
    /// session: the server answers by sending a DVC Soft-Sync request moving
    /// every open dynamic channel to the tunnel
    /// ([MS-RDPEMT] soft-sync; `DrdynvcServer::request_reliable_udp`).
    /// `to_tunnel` carries unframed DVC PDUs the session wants transmitted
    /// over the UDP tunnel — the embedder pumps it into its `UdpTransport`.
    SoftSyncToUdp {
        to_tunnel: mpsc::Sender<Vec<u8>>,
    },
    /// A DVC frame received over the UDP tunnel (unframed DVC PDU bytes from
    /// the embedder's `UdpTransport::recv()`). Fed into the DRDYNVC
    /// processor's tunnel path; responses go back through `SoftSyncToUdp`'s
    /// `to_tunnel` sender.
    UdpTunnelData(Vec<u8>),
    /// Open a dynamic virtual channel from the server side while the session
    /// runs (MS-RDPEDYC 2.2.2.1).
    ///
    /// The Create Request goes out only once the DVC capability exchange has
    /// finished (2.2.1); a channel opened earlier waits for it. `reply`, if
    /// given, receives the ID assigned to the channel — the handle for
    /// [`Self::CloseDynamicChannel`] — or `None` when this connection has no
    /// DRDYNVC channel to open it on.
    OpenDynamicChannel {
        processor: Box<dyn dvc::DvcServerProcessor>,
        reply: Option<oneshot::Sender<Option<u32>>>,
    },
    /// Close a dynamic virtual channel opened with
    /// [`Self::OpenDynamicChannel`] (MS-RDPEDYC 2.2.4, 3.3.5.2).
    CloseDynamicChannel {
        channel_id: u32,
    },
}

/// Creates a fresh static-channel processor for each accepted RDP connection.
///
/// Factories are invoked before the Basic Settings Exchange so their channels
/// participate in GCC static-channel negotiation.
pub trait StaticChannelFactory: Send {
    /// Attaches the connection-local static-channel processor to `acceptor`.
    fn attach(&self, acceptor: &mut Acceptor);
}

impl fmt::Debug for ServerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quit(reason) => f.debug_tuple("Quit").field(reason).finish(),
            Self::EvictedByOtherConnection => f.write_str("EvictedByOtherConnection"),
            Self::Disconnect(error) => f.debug_tuple("Disconnect").field(error).finish(),
            Self::Clipboard(..) => f.write_str("Clipboard(..)"),
            Self::Rdpsnd(..) => f.write_str("Rdpsnd(..)"),
            Self::Rdpdr(..) => f.write_str("Rdpdr(..)"),
            Self::Echo(..) => f.write_str("Echo(..)"),
            Self::SetCredentials(..) => f.write_str("SetCredentials(..)"),
            Self::SetAutoReconnectCookie(Some(..)) => f.write_str("SetAutoReconnectCookie(Some(..))"),
            Self::SetAutoReconnectCookie(None) => f.write_str("SetAutoReconnectCookie(None)"),
            Self::GetLocalAddr(..) => f.write_str("GetLocalAddr(..)"),
            #[cfg(feature = "egfx")]
            Self::Egfx(..) => f.write_str("Egfx(..)"),
            #[cfg(feature = "usb")]
            Self::Usb(..) => f.write_str("Usb(..)"),
            Self::SoftSyncToUdp { .. } => f.write_str("SoftSyncToUdp { .. }"),
            Self::UdpTunnelData(data) => f.debug_tuple("UdpTunnelData").field(&data.len()).finish(),
            Self::AutoDetectRttRequest => f.write_str("AutoDetectRttRequest"),
            Self::OpenDynamicChannel { processor, .. } => f
                .debug_struct("OpenDynamicChannel")
                .field("channel_name", &processor.channel_name())
                .finish_non_exhaustive(),
            Self::CloseDynamicChannel { channel_id } => f
                .debug_struct("CloseDynamicChannel")
                .field("channel_id", channel_id)
                .finish(),
        }
    }
}

pub trait ServerEventSender {
    fn set_sender(&mut self, sender: mpsc::UnboundedSender<ServerEvent>);
}

impl ServerEvent {
    pub fn create_channel() -> (mpsc::UnboundedSender<Self>, mpsc::UnboundedReceiver<Self>) {
        mpsc::unbounded_channel()
    }
}

/// The in-flight [`negotiate_candidate`] call for a candidate connection, or a
/// never-resolving placeholder while none is being negotiated. Borrows the
/// [`NegotiationContext`] the race built.
type PreemptProbe<'ctx> =
    core::pin::Pin<Box<dyn Future<Output = Option<(Box<NegotiatedCandidate>, SocketAddr)>> + 'ctx>>;

/// What resolved first while a session was live, under
/// [`RdpServerOptions::preempt_existing_session`]: the session itself ending, a
/// new inbound connection, or the verdict on a [`PreemptProbe`] being
/// negotiated. The race's `select!` yields one of these and must not
/// otherwise mutate the probe slot, whose futures it still borrows.
enum PreemptRace {
    Ended(ServerResult<()>),
    Accepted(std::io::Result<(TcpStream, SocketAddr)>),
    Probed(Option<(Box<NegotiatedCandidate>, SocketAddr)>),
}

#[derive(Debug, PartialEq)]
enum RunState {
    Continue,
    Disconnect,
    DeactivationReactivation { desktop_size: DesktopSize },
}

/// Which transport a connection ended up on after
/// [`negotiate_and_authenticate`], carrying the framed stream in the shape the
/// finalize step needs. The three variants exist to preserve the three
/// pre-existing finalize behaviours exactly.
enum NegotiatedTransport<S> {
    /// Never upgraded ([`RdpServerSecurity::None`]): finalize without a
    /// stream shutdown, matching the old `BeginResult::Continue` arm.
    Continued(TokioFramed<S>),
    /// Upgraded in-band by us ([`TransportTls::Managed`]).
    Tls(Box<TokioFramed<tokio_rustls::server::TlsStream<S>>>),
    /// Already past TLS at a lower layer ([`TransportTls::AlreadyDone`]).
    Offloaded(TokioFramed<S>),
}

/// A freshly built [`Acceptor`], paired with the exact [`RdpServerSecurity`]
/// it was constructed from.
///
/// Negotiation needs both together: [`Acceptor::new`] takes `security.flag()`
/// up front, and the TLS-upgrade step later needs the full `security` value
/// again (for the [`TlsAcceptor`] and, under Hybrid, the CredSSP public key).
/// Threading `security` and `acceptor` as independent parameters — which an
/// earlier revision of this refactor did — turns that pairing into a
/// caller-enforced precondition: nothing stops a future caller from passing
/// an `Acceptor` built from a *different* `RdpServerSecurity`, and the
/// failure mode is a panic on a server connection path
/// (`RdpServerSecurity::None => unreachable!()`, below). The single
/// constructor here makes the pairing a construction-time guarantee instead:
/// there is no way to reach [`Self::negotiate_and_authenticate`] with a
/// mismatched pair, because there is no way to build a `PendingConnection`
/// without going through [`Self::new`], which ties them together atomically.
///
/// Owns a cloned `RdpServerSecurity` rather than borrowing `&self.opts.security`
/// — `RdpServerSecurity` is a cheap `Clone` (its `TlsAcceptor` is an `Arc`
/// underneath) — deliberately: a caller in `run_connection_with` needs `&mut
/// self` (for `attach_channels`) while a live `PendingConnection` is still in
/// scope, which a borrowed `security` would conflict with for as long as the
/// pending connection exists.
struct PendingConnection {
    security: RdpServerSecurity,
    acceptor: Acceptor,
}

impl PendingConnection {
    fn new(
        security: RdpServerSecurity,
        desktop_size: DesktopSize,
        capabilities: Vec<CapabilitySet>,
        creds: Option<Credentials>,
        honor_client_desktop_size: Option<DesktopSize>,
        credential_resolver: Option<std::sync::Arc<dyn Fn(&str) -> std::io::Result<Credentials> + Send + Sync>>,
    enable_ainput: bool,
    multitransport: bool,
    ) -> Self {
        let mut acceptor = Acceptor::new_with_resolver(security.flag(), desktop_size, capabilities, creds, credential_resolver);
        acceptor.set_honor_client_desktop_size(honor_client_desktop_size);
        // TS_UD_SC_MULTITRANSPORT (2.2.1.4.6): announce the UDP/FECR transport
        // whenever the embedder configured multitransport — 3.3.5.8 requires
        // the announcement before bootstrapping it.
        acceptor.set_multitransport_announce(multitransport);
        Self { security, acceptor }
    }

    /// Mutable access to the acceptor for the one thing that must happen
    /// before negotiation: attaching static/dynamic channels. Negotiation
    /// itself (`negotiate_and_authenticate`) owns the acceptor from here on,
    /// so this is only available pre-negotiation.
    fn acceptor_mut(&mut self) -> &mut Acceptor {
        &mut self.acceptor
    }

    /// Negotiate `stream` and, where the security mode provides it,
    /// AUTHENTICATE it — everything up to (but not including)
    /// `accept_finalize`.
    ///
    /// Consumes `self` rather than taking `&mut self`, so it can be driven
    /// without holding a mutable borrow of the whole server for the
    /// duration — a future caller (a preempting connection negotiating
    /// concurrently with the live one) needs exactly that.
    ///
    /// `Ok(None)` means the TLS handshake failed and was already logged — the
    /// caller should abandon the connection quietly rather than treat it as a
    /// connection error (preserving the pre-existing `return Ok(())` behaviour).
    async fn negotiate_and_authenticate<S>(
        self,
        stream: S,
        tls: TransportTls,
    ) -> ServerResult<Option<NegotiatedConnection<S>>>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        let PendingConnection { security, mut acceptor } = self;
        let security = &security;
        let framed = TokioFramed::new(stream);

        let res = ironrdp_acceptor::accept_begin(framed, &mut acceptor)
            .await
            .map_err_kind("accept_begin failed", ServerErrorKind::Connector)?;

        match res {
            // The only thing that varies between the two modes is who performs
            // the TLS handshake; everything past it is `complete_security_upgrade`.
            BeginResult::ShouldUpgrade(stream) => match tls {
                TransportTls::Managed => {
                    // `RdpServerSecurity::None` can never reach this arm: `Self::new`
                    // built `acceptor` from THIS `security` via `security.flag()`,
                    // which is empty only for `None`, and `accept_begin` yields
                    // `ShouldUpgrade` only when the negotiated flags are non-empty
                    // -- `None` always yields `Continue` instead (the arm below).
                    let tls_acceptor = match security {
                        RdpServerSecurity::Tls(acceptor) => acceptor,
                        RdpServerSecurity::Hybrid((acceptor, _))
                        | RdpServerSecurity::HybridOrTls((acceptor, _)) => acceptor,
                        RdpServerSecurity::None => unreachable!(),
                    };
                    let accept = match tls_acceptor.accept(stream).await {
                        Ok(accept) => accept,
                        Err(e) => {
                            warn!("Failed to TLS accept: {}", e);
                            return Ok(None);
                        }
                    };
                    let mut framed = TokioFramed::new(accept);
                    complete_security_upgrade(security, &mut framed, &mut acceptor).await?;
                    Ok(Some(NegotiatedConnection {
                        transport: NegotiatedTransport::Tls(Box::new(framed)),
                        acceptor,
                    }))
                }
                // The stream is already past TLS (terminated at a lower
                // layer, e.g. a WSS terminator); do NOT call
                // tls_acceptor.accept on it.
                TransportTls::AlreadyDone => {
                    let mut framed = TokioFramed::new(stream);
                    complete_security_upgrade(security, &mut framed, &mut acceptor).await?;
                    Ok(Some(NegotiatedConnection {
                        transport: NegotiatedTransport::Offloaded(framed),
                        acceptor,
                    }))
                }
            },

            BeginResult::Continue(framed) => Ok(Some(NegotiatedConnection {
                transport: NegotiatedTransport::Continued(framed),
                acceptor,
            })),
        }
    }
}

/// The result of [`PendingConnection::negotiate_and_authenticate`]: the
/// [`NegotiatedTransport`] it landed on, bundled with the same [`Acceptor`]
/// that negotiated it (rather than the caller tracking the two as separate
/// values, which is how this looked before `PendingConnection` existed).
struct NegotiatedConnection<S> {
    transport: NegotiatedTransport<S>,
    acceptor: Acceptor,
}

/// Advance a stream that is now past the security upgrade: mark the acceptor
/// accordingly and, under [`RdpServerSecurity::Hybrid`], run the CredSSP
/// exchange.
///
/// Generic over the stream so both [`TransportTls`] modes can call this one
/// definition of the exchange (the two differ only in what the framed stream
/// wraps) — restoring, not introducing, the single-call-site property the
/// pre-existing `finalize_after_upgrade` already had for the same two arms
/// before this refactor split negotiation out of it. The actual reason this
/// exists as its own function is [`negotiate_and_authenticate`]'s: a future
/// caller (a preempting connection negotiating without holding `&mut self`)
/// needs the CredSSP step available from a plain function it can drive
/// itself, not bundled into a `&mut self` method.
async fn complete_security_upgrade<S>(
    security: &RdpServerSecurity,
    framed: &mut TokioFramed<S>,
    acceptor: &mut Acceptor,
) -> ServerResult<()>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    acceptor.mark_security_upgrade_as_done();

    // Whether CredSSP runs is decided by what was NEGOTIATED, not by what the
    // server was configured to offer: under `HybridOrTls` the same server
    // serves NLA clients and TLS-only ones, and the acceptor's state already
    // reflects which of the two this connection chose.
    let pub_key = match security {
        RdpServerSecurity::Hybrid((_, key)) | RdpServerSecurity::HybridOrTls((_, key)) => Some(key),
        RdpServerSecurity::Tls(_) | RdpServerSecurity::None => None,
    };
    if let Some(pub_key) = pub_key.filter(|_| acceptor.should_perform_credssp()) {
        // Generic streams don't expose peer address. Use a neutral
        // placeholder; it's unclear whether CredSSP/NTLM actually
        // uses this value in practice.
        let client_name = "rdp-client".to_owned();

        ironrdp_acceptor::accept_credssp(
            framed,
            acceptor,
            &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
            client_name.into(),
            pub_key.clone(),
            None,
        )
        .await
        .map_err_kind("accept_credssp", ServerErrorKind::Connector)?;
    }

    Ok(())
}

/// How long an evicted session gets to send its
/// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` and wind down on its own before
/// it is cancelled outright. Short, because the preempting client is already
/// authenticated and waiting and a half-dead peer must not stall the takeover;
/// exceeding it is not an error, it just degrades to an abrupt drop.
const EVICTION_GRACE: Duration = Duration::from_millis(750);

/// How long a candidate gets to complete negotiation and authentication before
/// it is abandoned.
///
/// This bound is load-bearing, not a tidiness measure: `negotiate_candidate`
/// blocks on socket reads, so without it a peer that completes the TCP
/// handshake and then sends NOTHING parks the probe forever — which stalls
/// accepts for the rest of the session (the accept arm is gated on `!probing`)
/// and, once the live session ends, hangs the whole accept loop on the handoff
/// await with no way left to observe [`ServerEvent::Quit`]. Generous enough for
/// TLS + CredSSP over a slow link, which is sub-second on a healthy one.
///
/// # Known limitation: one candidate is negotiated at a time
///
/// `run()`'s race holds a SINGLE probe slot (`probe`/`probing`), so a peer
/// that has already cleared [`ConnectionHandler::on_accept`] and then merely
/// STALLS its handshake (a well-formed X.224 Connection Request, then
/// silence before TLS — `on_accept` cannot see this in advance, since it
/// already returned `true` for this peer) occupies the slot for up to this
/// whole timeout, during which the accept arm is gated off and no OTHER
/// candidate — including a legitimate one — can even begin negotiating. The
/// live session itself is unaffected either way (this only withholds
/// PREEMPTION, never breaks it), and it is not a regression against master's
/// queue-behind default. But it means `on_accept` bounds who may ATTEMPT a
/// takeover, not how long one attempt can hold up every other. Closing this
/// properly needs a small pool of concurrent probe slots rather than one;
/// not done here.
const CANDIDATE_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the accept loop will wait, AFTER the live session has ended, for a
/// candidate that is still mid-negotiation.
///
/// Deliberately short and separate from [`CANDIDATE_NEGOTIATION_TIMEOUT`]:
/// while this wait is in progress the loop is servicing nothing — no accepts,
/// no [`ServerEvent`]s, not even [`ServerEvent::Quit`] — so it is the window in
/// which an unauthenticated peer can make the server look hung. A candidate
/// that cannot finish within it is dropped and simply reconnects; holding the
/// whole listener for it is the worse trade.
const CANDIDATE_HANDOFF_GRACE: Duration = Duration::from_millis(750);

/// How long a just-evicted peer is barred from preempting its way back in —
/// see [`RdpServer::recently_evicted`].
const REPREEMPT_COOLDOWN: Duration = Duration::from_secs(5);

/// Absolute cap on that bar, measured from the eviction itself.
///
/// [`refuse_reconnect_from_evicted`] re-arms its window on every refused
/// attempt, which is what stops an auto-reconnect storm from winning the
/// session back. Left uncapped that also permanently locks out the feature's
/// own headline case — a client whose link dropped, whose stale session is
/// still live, and which is auto-reconnecting to reclaim it. Past this cap the
/// bar lifts even under a continuing storm; by then the evicted peer has had
/// its `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (the real fix for the loop),
/// and this heuristic has served its purpose as a backstop.
const REPREEMPT_MAX_LOCKOUT: Duration = Duration::from_secs(30);

/// Does this security mode authenticate the CLIENT before a candidate reaches
/// the point where it could evict the live session?
///
/// Only [`RdpServerSecurity::Hybrid`] does: CredSSP/NLA runs inside
/// [`negotiate_candidate`]. A `Tls` handshake authenticates the *server* to the
/// client, not the reverse, and any peer that can reach the port completes one;
/// `None` authenticates nothing. Under those two, preemption's bar is therefore
/// NOT authentication — see the security section on
/// [`RdpServerOptions::preempt_existing_session`], and the startup warning in
/// [`RdpServer::run`].
fn authenticates_before_eviction(security: &RdpServerSecurity) -> bool {
    matches!(security, RdpServerSecurity::Hybrid(_))
}

/// A peer barred from preempting straight back after being evicted, and when
/// that bar started — see [`refuse_reconnect_from_evicted`].
#[derive(Debug, Clone, Copy)]
struct EvictedPeer {
    ip: IpAddr,
    /// When the eviction happened; bounds the lockout via [`REPREEMPT_MAX_LOCKOUT`].
    evicted_at: Instant,
    /// Most recent refused attempt; re-armed to throttle a reconnect storm.
    last_try: Instant,
}

/// Should this candidate be refused because it is the peer that was just
/// evicted, bouncing straight back to retake the session?
///
/// Each refused attempt RE-ARMS the window, so a client auto-reconnecting on a
/// ~1 s cadence keeps resetting its own cooldown and cannot immediately win the
/// session back, while a human who closes the client and reconnects — a gap
/// beyond `cooldown` — still can.
///
/// The re-arm is bounded by `max_lockout` from the eviction, so a peer that
/// keeps retrying is eventually let back in rather than barred forever. Without
/// that cap this locks out exactly the case the feature exists for: a client
/// whose network dropped, auto-reconnecting to reclaim its own stale session.
///
/// Keyed on source IP, because the source port changes on every reconnect. The
/// cost is that two clients behind one NAT briefly share a bar; the cap bounds
/// how long that lasts.
fn refuse_reconnect_from_evicted(
    recently_evicted: &mut Option<EvictedPeer>,
    peer: IpAddr,
    now: Instant,
    cooldown: Duration,
    max_lockout: Duration,
) -> bool {
    match recently_evicted {
        Some(evicted) if evicted.ip == peer => {
            let within_cooldown = now.duration_since(evicted.last_try) < cooldown;
            let within_cap = now.duration_since(evicted.evicted_at) < max_lockout;
            let refuse = within_cooldown && within_cap;
            if refuse {
                evicted.last_try = now;
            }
            refuse
        }
        _ => false,
    }
}

/// A cheap, cloned snapshot of everything a preempting candidate needs to
/// negotiate, so it can do so WITHOUT `&mut self` and therefore concurrently
/// with the live connection's borrow. Built per race via
/// [`RdpServer::negotiation_context`].
///
/// Deliberately does NOT carry the channel factories: a candidate builds no
/// backends, because it may never be served (see the note in
/// [`negotiate_candidate`]). Only the winner does, in
/// [`RdpServer::serve_negotiated`], from `self`.
struct NegotiationContext {
    opts: RdpServerOptions,
    creds: Option<Credentials>,
    credential_resolver: Option<std::sync::Arc<dyn Fn(&str) -> std::io::Result<Credentials> + Send + Sync>>,
    enable_ainput: bool,
    display: Arc<Mutex<Box<dyn RdpServerDisplay>>>,
}

/// A candidate that has negotiated AND authenticated, and so has earned the
/// right to evict the live session. Everything needed to resume at
/// finalization, which [`RdpServer::serve_negotiated`] does once it wins --
/// just [`PendingConnection::negotiate_and_authenticate`]'s own result type,
/// named for what it means in this context.
type NegotiatedCandidate = NegotiatedConnection<TcpStream>;

/// Negotiate and authenticate a candidate connection against a cloned `ctx`,
/// touching no `&mut self` — which is what lets this run inside
/// [`RdpServer::run`]'s preemption race, concurrently with the live
/// connection.
///
/// Returns `Some` only once the candidate has genuinely earned the session:
/// negotiation completed and, where the security mode provides it,
/// authentication succeeded (see the table on
/// [`RdpServerOptions::preempt_existing_session`]). On any failure — a
/// malformed or non-RDP handshake, TLS rejected, CredSSP rejected — returns
/// `None` and the live session is left completely undisturbed.
async fn negotiate_candidate(
    ctx: &NegotiationContext,
    stream: TcpStream,
    peer: SocketAddr,
) -> Option<(Box<NegotiatedCandidate>, SocketAddr)> {
    let size = ctx.display.lock().await.size().await;
    let capabilities = capabilities::capabilities(&ctx.opts, size);
    let pending = PendingConnection::new(
        ctx.opts.security.clone(),
        size,
        capabilities,
        ctx.creds.clone(),
        ctx.opts.honor_client_desktop_size,
        ctx.credential_resolver.clone(),
        ctx.enable_ainput,
        ctx.opts.multitransport.is_some(),
    );

    // NOTE: deliberately NO channel attachment here. Building the cliprdr /
    // sound / gfx backends means running user-supplied factories for a peer
    // that has not authenticated yet — a port scan would construct and tear
    // down backends alongside the live session's, and those factories may claim
    // exclusive OS resources (an audio capture device, clipboard ownership).
    // The winner attaches its own channels in `RdpServer::serve_negotiated`,
    // which is still before `accept_finalize` — the acceptor does not consume
    // the static channel set until it processes the MCS Connect Initial, which
    // happens there, not in `accept_begin`.

    match pending.negotiate_and_authenticate(stream, TransportTls::Managed).await {
        Ok(Some(negotiated)) => {
            debug!(?peer, "candidate authenticated -- eligible to preempt the live session");
            Some((Box::new(negotiated), peer))
        }
        Ok(None) => {
            debug!(
                ?peer,
                "candidate TLS handshake failed -- not preempting the live session"
            );
            None
        }
        Err(error) => {
            debug!(
                ?peer,
                %error,
                "candidate did not negotiate/authenticate -- not preempting the live session"
            );
            None
        }
    }
}

/// [`negotiate_candidate`] under a hard deadline.
///
/// The negotiation blocks on socket reads from an as-yet-unauthenticated peer,
/// so it MUST NOT be awaited unbounded anywhere in the accept loop: a peer that
/// connects and then says nothing would otherwise stall accepts for the rest of
/// the session and hang the loop outright once the session ended. Timing out is
/// treated exactly like a failed negotiation — the candidate is dropped and the
/// live session is untouched.
async fn negotiate_candidate_bounded(
    ctx: &NegotiationContext,
    stream: TcpStream,
    peer: SocketAddr,
) -> Option<(Box<NegotiatedCandidate>, SocketAddr)> {
    match tokio::time::timeout(CANDIDATE_NEGOTIATION_TIMEOUT, negotiate_candidate(ctx, stream, peer)).await {
        Ok(candidate) => candidate,
        Err(_) => {
            debug!(
                ?peer,
                timeout = ?CANDIDATE_NEGOTIATION_TIMEOUT,
                "candidate did not finish negotiating in time -- abandoning it, the live session is untouched"
            );
            None
        }
    }
}

impl RdpServer {
    #[expect(
        clippy::too_many_arguments,
        reason = "called via the builder; positional parameters are an internal detail"
    )]
    pub(crate) fn new(
        opts: RdpServerOptions,
        handler: Box<dyn RdpServerInputHandler>,
        display: Box<dyn RdpServerDisplay>,
        static_channel_factories: Vec<Box<dyn StaticChannelFactory>>,
    dynamic_channel_attachers: Vec<Box<dyn FnMut(&mut dvc::DrdynvcServer) + Send>>,
        mut sound_factory: Option<Box<dyn SoundServerFactory>>,
        mut cliprdr_factory: Option<Box<dyn CliprdrServerFactory>>,
        mut rdpei_factory: Option<Box<dyn RdpeiServerFactory>>,
        mut rdpdr_factory: Option<Box<dyn RdpdrServerFactory>>,
        connection_handler: Option<Box<dyn ConnectionHandler>>,
        credential_resolver: Option<std::sync::Arc<dyn Fn(&str) -> std::io::Result<Credentials> + Send + Sync>>,
    enable_ainput: bool,
        #[cfg(feature = "egfx")] mut gfx_factory: Option<Box<dyn GfxServerFactory>>,
        display_suppressed: Option<Arc<AtomicBool>>,
        #[cfg(feature = "usb")] usb_factory: Option<Box<dyn DeviceFactory>>,
        autodetect_rtt: Option<Arc<AtomicU32>>,
        autodetect_baseline_rtt: Option<Arc<AtomicU32>>,
        autodetect_bandwidth: Option<Arc<AtomicU32>>,
        pointer_cache: Option<Arc<AtomicU16>>,
    ) -> Self {
        let (ev_sender, ev_receiver) = ServerEvent::create_channel();
        if let Some(cliprdr) = cliprdr_factory.as_mut() {
            cliprdr.set_sender(ev_sender.clone());
        }
        if let Some(snd) = sound_factory.as_mut() {
            snd.set_sender(ev_sender.clone());
        }
        if let Some(rdpei) = rdpei_factory.as_mut() {
            rdpei.set_sender(ev_sender.clone());
        }
        if let Some(rdpdr) = rdpdr_factory.as_mut() {
            rdpdr.set_sender(ev_sender.clone());
        }
        #[cfg(feature = "egfx")]
        if let Some(gfx) = gfx_factory.as_mut() {
            gfx.set_sender(ev_sender.clone());
        }

        Self {
            opts,
            handler: Arc::new(Mutex::new(handler)),
            display: Arc::new(Mutex::new(display)),
            static_channels: StaticChannelSet::new(),
            static_channel_factories,
            dynamic_channel_attachers,
            sound_factory,
            cliprdr_factory,
            rdpei_factory,
            rdpdr_factory,
            echo_handle: EchoServerHandle::new(ev_sender.clone()),
            #[cfg(feature = "egfx")]
            gfx_factory,
            #[cfg(feature = "egfx")]
            gfx_handle: None,
            #[cfg(feature = "usb")]
            usb_man: usb_factory.map(ServerUsbManager::new),
            ev_sender,
            ev_receiver: Arc::new(Mutex::new(ev_receiver)),
            creds: None,
            credential_resolver,
            enable_ainput,
            display_control_caps: None,
            peer_addr: None,
            // The embedder sets this; the library keeps its previous
            // behaviour (wait forever) unless it does.
            handshake_timeout: None,
            credential_validator: None,
            local_addr: None,
            autodetect: None,
            udp_tunnel_tx: None,
            multitransport_confirmed: false,
            multitransport_request_id: None,
            pending_soft_sync: None,
            heartbeat: None,
            client_supports_errinfo: false,
            client_supports_autodetect: false,
            client_fastpath_output: true,
            client_initiated_disconnect: false,
            connection_handler,
            recently_evicted: None,
            display_suppressed: display_suppressed.unwrap_or_else(|| Arc::new(AtomicBool::new(false))),
            autodetect_rtt: {
                // Reset to the sentinel: an injected handle must not expose a stale value before the first measurement.
                let handle = autodetect_rtt.unwrap_or_else(|| Arc::new(AtomicU32::new(u32::MAX)));
                handle.store(u32::MAX, Ordering::Relaxed);
                handle
            },
            autodetect_baseline_rtt: {
                let handle = autodetect_baseline_rtt.unwrap_or_else(|| Arc::new(AtomicU32::new(u32::MAX)));
                handle.store(u32::MAX, Ordering::Relaxed);
                handle
            },
            autodetect_bandwidth: {
                let handle = autodetect_bandwidth.unwrap_or_else(|| Arc::new(AtomicU32::new(u32::MAX)));
                handle.store(u32::MAX, Ordering::Relaxed);
                handle
            },
            negotiated_pointer_cache: {
                let handle = pointer_cache.unwrap_or_else(|| Arc::new(AtomicU16::new(0)));
                handle.store(0, Ordering::Relaxed);
                handle
            },
            frame_ack_state: Arc::default(),
            frame_ack_limit: 0,
            auto_reconnect_cookie: None,
            previous_auto_reconnect_cookie: None,
            auto_reconnect_sent: false,
        }
    }

    pub fn builder() -> builder::RdpServerBuilder<builder::WantsAddr> {
        builder::RdpServerBuilder::new()
    }

    /// Set or clear the credential validator for TLS-mode connections.
    ///
    /// When set, credentials received from the client during
    /// `SecureSettingsExchange` are validated through this callback before
    /// the session is established. If the validator returns
    /// [`CredentialDecision::Reject`] (or a [`CredentialValidationError`]),
    /// the connection is rejected. Passing `None` clears any previously
    /// configured validator.
    ///
    /// A valid Server Auto-Reconnect Cookie bypasses this validator. Applications
    /// that must validate every connection should leave automatic reconnection
    /// disabled.
    ///
    /// Most callers should configure the validator at construction time via
    /// the builder's `with_credential_validator` method
    /// ([`RdpServer::builder`]); this setter exists for dynamic
    /// post-construction reconfiguration.
    ///
    /// Not used for CredSSP/Hybrid connections (those use pre-loaded credentials).
    pub fn set_credential_validator(&mut self, validator: Option<Arc<dyn CredentialValidator>>) {
        self.credential_validator = validator;
    }

    /// What the Display Control channel tells clients about the layouts they
    /// may request (MS-RDPEDISP 2.2.2.1): the monitor count and the area the
    /// display can really take. Layouts beyond them are not applied.
    pub fn set_display_control_capabilities(
        &mut self,
        capabilities: ironrdp_displaycontrol::pdu::DisplayControlCapabilities,
    ) {
        self.display_control_caps = Some(capabilities);
    }

    /// Set or clear the Server Auto-Reconnect Cookie (MS-RDPBCGR 2.2.4.2
    /// `ARC_SC_PRIVATE_PACKET`) handed to the client during logon.
    ///
    /// When set to `Some`, the server sends a Save Session Info PDU carrying the
    /// cookie right after activation. It verifies the returned
    /// `ARC_CS_PRIVATE_PACKET` using the HMAC-MD5 verifier required by
    /// MS-RDPBCGR 5.5, replaces the random after every accepted connection, and
    /// sends an update every hour. Automatic reconnection requires TLS or Hybrid
    /// security, which provides the all-zero client random required for Enhanced
    /// RDP Security. The [`ServerAutoReconnect`] `logon_id` identifies the
    /// session; the server generates replacement randoms with a CSPRNG.
    ///
    /// Pass `None` (the default) to send no cookie.
    ///
    /// Most callers should configure this at construction time via the builder
    /// ([`RdpServer::builder`])'s `with_auto_reconnect_cookie`. To replace a
    /// cookie while [`Self::run`] owns the server, use
    /// [`Self::auto_reconnect_cookie_handle`].
    ///
    /// [`ServerAutoReconnect`]: ironrdp_pdu::rdp::session_info::ServerAutoReconnect
    pub fn set_auto_reconnect_cookie(&mut self, cookie: Option<rdp::session_info::ServerAutoReconnect>) {
        self.auto_reconnect_cookie = cookie;
        self.previous_auto_reconnect_cookie = None;
        self.auto_reconnect_sent = false;
    }

    /// Returns a handle for replacing the cookie while [`Self::run`] owns this
    /// server.
    pub fn auto_reconnect_cookie_handle(&self) -> AutoReconnectCookieHandle {
        AutoReconnectCookieHandle {
            sender: self.ev_sender.clone(),
        }
    }

    /// Returns a handle for gracefully disconnecting the active client with a
    /// `ServerSetErrorInfo` PDU while [`Self::run`] owns this server.
    pub fn error_info_disconnect_handle(&self) -> ErrorInfoDisconnectHandle {
        ErrorInfoDisconnectHandle {
            sender: self.ev_sender.clone(),
        }
    }

    fn supports_auto_reconnect(&self) -> bool {
        matches!(
            &self.opts.security,
            RdpServerSecurity::Tls(_) | RdpServerSecurity::Hybrid(_)
        )
    }

    fn verify_auto_reconnect_cookie(&self, reconnect: &rdp::client_info::ClientAutoReconnect) -> bool {
        if !self.supports_auto_reconnect() {
            return false;
        }

        [&self.auto_reconnect_cookie, &self.previous_auto_reconnect_cookie]
            .into_iter()
            .flatten()
            .any(|cookie| reconnect.verify(cookie))
    }

    fn generate_auto_reconnect_cookie(logon_id: u32) -> rdp::session_info::ServerAutoReconnect {
        let mut random_bits = [0; 16];
        rand::rng().fill_bytes(&mut random_bits);

        rdp::session_info::ServerAutoReconnect { logon_id, random_bits }
    }

    fn next_auto_reconnect_cookie(&self) -> Option<rdp::session_info::ServerAutoReconnect> {
        if !self.supports_auto_reconnect() {
            return None;
        }

        let cookie = self.auto_reconnect_cookie.as_ref()?;

        if self.auto_reconnect_sent {
            Some(Self::generate_auto_reconnect_cookie(cookie.logon_id))
        } else {
            Some(cookie.clone())
        }
    }

    fn commit_auto_reconnect_rotation(&mut self, cookie: rdp::session_info::ServerAutoReconnect) {
        if self.auto_reconnect_sent {
            self.previous_auto_reconnect_cookie = self.auto_reconnect_cookie.replace(cookie);
        } else {
            self.auto_reconnect_cookie = Some(cookie);
        }
        self.auto_reconnect_sent = true;
    }

    /// (vendored, divergence 23) Invalidate whatever ARC cookie belongs to
    /// the session that is about to be EVICTED, without disabling
    /// auto-reconnect for the server going forward.
    ///
    /// MS-RDPBCGR 5.5 requires a session's auto-reconnect cookie to be
    /// invalidated once a different client's session begins. This crate
    /// already demotes the outgoing cookie into `previous_auto_reconnect_
    /// cookie` on every normal rotation (`commit_auto_reconnect_rotation`) --
    /// a network-timing tolerance for the common case of a lost Save Session
    /// Info PDU -- which means an EVICTED peer's cookie stays valid for one
    /// more rotation. Since `verify_auto_reconnect_cookie` accepts either
    /// slot, and a client presenting a valid ARC cookie skips
    /// `credential_validator` (see `client_accepted`), an evicted peer could
    /// silently resume without a real re-authorization check -- and, because
    /// re-authenticating via ARC needs no user interaction, do so reliably
    /// the moment `REPREEMPT_MAX_LOCKOUT` lifts.
    ///
    /// Rotates to a FRESH cookie under the SAME `logon_id` (so the server
    /// keeps issuing cookies to whoever connects next -- a normal rotation
    /// does the same) but with new random bits, which is what actually
    /// invalidates the old one: `ClientAutoReconnect::verify` HMACs against
    /// `random_bits`, not `logon_id` alone. `previous_auto_reconnect_cookie`
    /// is discarded outright here rather than demoted into, since the whole
    /// point is that the evicted party's cookie must not remain valid even
    /// for one more attempt.
    ///
    /// MUST NOT set `auto_reconnect_cookie` to `None`:
    /// `next_auto_reconnect_cookie` treats `None` as "auto-reconnect is not
    /// configured" and stops issuing cookies to EVERY future connection, not
    /// just this one -- silently disabling the feature server-wide for the
    /// rest of the process (see `next_auto_reconnect_cookie`'s early
    /// `self.auto_reconnect_cookie.as_ref()?`). No-op if auto-reconnect isn't
    /// configured at all.
    fn invalidate_auto_reconnect_cookie_on_eviction(&mut self) {
        if let Some(current) = self.auto_reconnect_cookie.as_ref() {
            self.auto_reconnect_cookie = Some(Self::generate_auto_reconnect_cookie(current.logon_id));
        }
        self.previous_auto_reconnect_cookie = None;
    }
    async fn send_auto_reconnect_cookie(
        cookie: rdp::session_info::ServerAutoReconnect,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let pdu = rdp::headers::ShareDataPdu::SaveSessionInfo(rdp::session_info::SaveSessionInfoPdu {
            info_type: rdp::session_info::InfoType::LogonExtended,
            info_data: rdp::session_info::InfoData::LogonExtended(rdp::session_info::LogonInfoExtended {
                present_fields_flags: rdp::session_info::LogonExFlags::AUTO_RECONNECT_COOKIE,
                auto_reconnect: Some(cookie),
                errors_info: None,
            }),
        });
        let data = encode_share_data_pdu(pdu, user_channel_id, io_channel_id, user_channel_id)?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| ServerError::io("send auto-reconnect cookie", e))?;
        debug!("Sent Server Auto-Reconnect Cookie (Save Session Info PDU)");

        Ok(())
    }

    async fn send_next_auto_reconnect_cookie(
        &mut self,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let Some(cookie) = self.next_auto_reconnect_cookie() else {
            return Ok(());
        };

        Self::send_auto_reconnect_cookie(cookie.clone(), writer, io_channel_id, user_channel_id).await?;
        self.commit_auto_reconnect_rotation(cookie);

        Ok(())
    }

    async fn rotate_auto_reconnect_cookie(
        &mut self,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        if !self.supports_auto_reconnect() {
            return Ok(());
        }

        let Some(cookie) = self.auto_reconnect_cookie.as_ref() else {
            return Ok(());
        };
        let cookie = Self::generate_auto_reconnect_cookie(cookie.logon_id);

        Self::send_auto_reconnect_cookie(cookie.clone(), writer, io_channel_id, user_channel_id).await?;
        self.commit_auto_reconnect_rotation(cookie);

        Ok(())
    }

    async fn update_auto_reconnect_cookie(
        &mut self,
        cookie: Option<rdp::session_info::ServerAutoReconnect>,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let Some(cookie) = cookie else {
            self.set_auto_reconnect_cookie(None);
            return Ok(());
        };

        if !self.supports_auto_reconnect() {
            self.set_auto_reconnect_cookie(Some(cookie));
            return Ok(());
        }

        Self::send_auto_reconnect_cookie(cookie.clone(), writer, io_channel_id, user_channel_id).await?;
        self.auto_reconnect_cookie = Some(cookie);
        self.previous_auto_reconnect_cookie = None;
        self.auto_reconnect_sent = true;

        Ok(())
    }

    /// Say who is on the other end of a stream this server did not accept.
    ///
    /// Only affects what [`ConnectionHandler::on_disconnected`] is told;
    /// nothing in the protocol consults it. An embedder that forks per
    /// connection knows the peer from its own `accept` and is the only one who
    /// can pass it on.
    pub fn set_peer_addr(&mut self, peer: Option<SocketAddr>) {
        self.peer_addr = peer;
    }

    /// Bound how long a connection may spend before it is authenticated.
    ///
    /// Covers everything from the first byte to the end of the acceptor
    /// sequence: the X.224 exchange, the TLS handshake and CredSSP. A
    /// connection that has not finished by then is dropped. `None` (the
    /// default) waits forever, which is what let silent clients accumulate.
    ///
    /// Applies to connections started after this call.
    pub fn set_handshake_timeout(&mut self, timeout: Option<Duration>) {
        self.handshake_timeout = timeout;
    }

    /// Replace the multitransport request parameters (see
    /// [`RdpServerOptions::multitransport`]). `None` disables the TCP-side
    /// bootstrap PDU for connections accepted afterwards.
    pub fn set_multitransport(&mut self, request: Option<MultiTransportRequest>) {
        self.opts.multitransport = request;
    }

    pub fn event_sender(&self) -> &mpsc::UnboundedSender<ServerEvent> {
        &self.ev_sender
    }

    #[cfg(feature = "usb")]
    fn remove_usb_device(&mut self, dvc_id: DynamicChannelId) {
        let Some(usb_man) = self.usb_man.as_mut() else {
            warn!("Missing USB device factory");
            return;
        };

        let Some(device) = usb_man.router.remove(&dvc_id) else {
            trace!(dvc_id, "Closed USB device is absent from request router");
            return;
        };

        // Set the terminal state before failing waiters: a woken PendingRequest
        // must not enqueue CANCEL_REQUEST for a removed DVC. The pending map is
        // shared, so dropping the router entry no longer drops it.
        device.mark_closed();
        let pending_requests = device.drain_pending();
        debug!(
            dvc_id,
            pending_requests, "Removed closed USB device from request router"
        );
    }

    /// Returns the shared "display suppressed" flag — `true` while the
    /// connected client has sent `SuppressOutput { desktop_rect: None }`
    /// (e.g., mstsc minimized).
    ///
    /// Display backends should hold a clone of this `Arc` and skip frame
    /// emission while it's set, so the client doesn't accumulate a backlog
    /// of frames it can't present until refocus. Cleared by the per-
    /// connection PDU handler on `SuppressOutput { Some(rect) }` or
    /// `RefreshRectangle`.
    ///
    /// **Caveat:** some clients (notably mstsc) send
    /// `SuppressOutput { desktop_rect: None }` during their connect
    /// handshake *before* their display surface is fully initialized; a
    /// backend that honors the flag blindly will block that first frame
    /// and leave the client with a half-initialized surface that doesn't
    /// recover on un-suppress (visible as a frozen desktop on first
    /// connect). Backends are advised to defer acting on the flag until
    /// after the first frame has been delivered to the client, and to
    /// debounce transient flaps (some clients pulse this PDU under wire
    /// pressure on heavy CPU/IO loads) — e.g., only engage the gate once
    /// the flag has been steady-`true` for ~1 s.
    ///
    /// The display backend typically needs to share this flag with the
    /// server before any client connects (so the same `Arc` is read by
    /// the backend's polling thread and written by the per-connection
    /// PDU handler). To inject the shared instance at construction time,
    /// use [`RdpServerBuilder::with_display_suppressed_handle`](crate::RdpServerBuilder::with_display_suppressed_handle).
    ///
    /// [crate::RdpServerBuilder]: crate::RdpServerBuilder
    pub fn display_suppressed_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.display_suppressed)
    }

    /// Returns a handle to the latest NetworkAutoDetect RTT in milliseconds
    /// (`u32::MAX` until the first measurement, and while auto-detect is
    /// disabled). The server updates it on each RTT Measure Response; backends
    /// clone the handle to read a fresh network RTT for flow control. Inject a
    /// shared instance at construction with
    /// [`RdpServerBuilder::with_autodetect_rtt_handle`](crate::RdpServerBuilder::with_autodetect_rtt_handle).
    pub fn autodetect_rtt_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.autodetect_rtt)
    }

    /// Returns a handle to the session-lifetime lowest RTT in milliseconds
    /// (`baseRTT` per MS-RDPBCGR 2.2.14.1.5; `u32::MAX` until the first
    /// measurement, and while auto-detect is disabled). Unlike
    /// [`Self::autodetect_rtt_handle`], this figure never rises: pair it with
    /// that handle's average to derive queueing delay
    /// (`averageRTT - baseRTT`), which `autodetect_rtt_handle` alone cannot
    /// give since its figure is a sliding-window value that rises as low
    /// samples age out. Inject a shared instance at construction with
    /// [`RdpServerBuilder::with_autodetect_baseline_rtt_handle`](crate::RdpServerBuilder::with_autodetect_baseline_rtt_handle).
    pub fn autodetect_baseline_rtt_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.autodetect_baseline_rtt)
    }

    /// Returns a handle to the latest NetworkAutoDetect measured bandwidth in
    /// kilobits per second (`u32::MAX` until the first measurement completes,
    /// and while auto-detect is disabled). The server updates it whenever a
    /// Bandwidth Measure Results response completes a measurement; backends
    /// clone the handle to read the figure the server also reports to the
    /// client on the wire. Inject a shared instance at construction with
    /// [`RdpServerBuilder::with_autodetect_bandwidth_handle`](crate::RdpServerBuilder::with_autodetect_bandwidth_handle).
    pub fn autodetect_bandwidth_handle(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.autodetect_bandwidth)
    }

    /// Returns the shared ECHO server handle for runtime probe requests and RTT measurements.
    pub fn echo_handle(&self) -> &EchoServerHandle {
        &self.echo_handle
    }

    /// Enable protocol-level auto-detect ([MS-RDPBCGR 2.2.14]).
    ///
    /// Auto-detect uses lightweight Share Data PDUs on the IO channel,
    /// separate from the ECHO DVC. It supports bandwidth measurement
    /// in addition to RTT and works even when DVC is unavailable.
    ///
    /// Probes go only to clients that advertise
    /// `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT` (MS-RDPBCGR 2.2.1.3.2).
    ///
    /// Send probes via [`ServerEvent::AutoDetectRttRequest`] and
    /// query results with [`rtt_snapshot()`](Self::rtt_snapshot).
    pub fn enable_autodetect(&mut self) {
        self.autodetect = Some(AutoDetectManager::new());
    }

    /// Enable periodic Server Heartbeat PDUs (MS-RDPBCGR 2.2.16.1).
    ///
    /// Heartbeats ride the MCS message channel, so they are only emitted
    /// when the client requested one AND advertised
    /// `RNS_UD_CS_SUPPORT_HEARTBEAT_PDU` in its early capability flags, and,
    /// per the spec's idle-only SHOULD, only when no other PDU went out
    /// during the previous heartbeat interval.
    pub fn enable_heartbeat(&mut self, config: HeartbeatConfig) {
        self.heartbeat = Some(config);
    }

    /// Get the latest auto-detect RTT snapshot.
    ///
    /// Returns `None` if auto-detect is not enabled or no measurements
    /// have been received yet.
    pub fn rtt_snapshot(&self) -> Option<RttSnapshot> {
        self.autodetect.as_ref().and_then(|ad| ad.snapshot())
    }

    /// The client's advertised `pointerCacheSize` (MS-RDPBCGR 2.2.7.1.5),
    /// or `0` before capability exchange / for clients without New Pointer
    /// Update support. Display backends bound this to size a
    /// `CachedPointer` LRU; changes only with a new client connection.
    pub fn pointer_cache_handle(&self) -> Arc<AtomicU16> {
        Arc::clone(&self.negotiated_pointer_cache)
    }

    /// Returns the shared EGFX server handle for proactive frame submission.
    ///
    /// Available after `build_server_with_handle()` returns `Some` during
    /// channel setup. Display handlers use this to call
    /// `send_avc420_frame()` / `send_avc444_frame()` and then signal the
    /// event loop via `ServerEvent::Egfx`.
    #[cfg(feature = "egfx")]
    pub fn gfx_handle(&self) -> Option<&crate::gfx::GfxServerHandle> {
        self.gfx_handle.as_ref()
    }

    /// Whether EGFX output drained in `generation` is still wanted by this
    /// connection's pipeline (see `GraphicsPipelineServer::generation`).
    ///
    /// The pipeline resets while this loop processes a mid-session
    /// CapsAdvertise and writes the new CapsConfirm straight away. Batches
    /// the display thread drained before that are already queued as events
    /// and would follow the confirm. MS-RDPEGFX 3.2.5.18: the client has
    /// "disregarded all the messages sent by the server prior to
    /// RDPGFX_CAPS_CONFIRM_PDU", so these batches address surfaces it no
    /// longer has.
    #[cfg(feature = "egfx")]
    fn egfx_output_is_current(&self, generation: u64) -> bool {
        self.gfx_handle.as_ref().is_some_and(|handle| {
            handle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .generation()
                == generation
        })
    }

    fn attach_channels(&mut self, acceptor: &mut Acceptor) {
        if let Some(cliprdr_factory) = self.cliprdr_factory.as_deref() {
            let backend = cliprdr_factory.build_cliprdr_backend();

            let cliprdr = CliprdrServer::new(backend);

            acceptor.attach_static_channel(cliprdr);
        }

        if let Some(factory) = self.sound_factory.as_deref() {
            let backend = factory.build_backend();

            acceptor.attach_static_channel(RdpsndServer::new(backend));
        }

        if let Some(factory) = self.rdpdr_factory.as_deref() {
            let backend = factory.build_backend();

            acceptor.attach_static_channel(RdpdrServer::new(backend));
        }

        let dcs_backend = DisplayControlBackend::new(Arc::clone(&self.display));
        let dvc = dvc::DrdynvcServer::new();
        let dvc = if self.enable_ainput {
            dvc.with_dynamic_channel(AInputHandler {
                handler: Arc::clone(&self.handler),
            })
        } else {
            dvc
        };
        let display_control = DisplayControlServer::new(Box::new(dcs_backend));
        let display_control = match self.display_control_caps.clone() {
            Some(capabilities) => display_control.with_capabilities(capabilities),
            None => display_control,
        };
        let dvc = dvc.with_dynamic_channel(display_control);

        let dvc = {
            let echo_handle = self.echo_handle.clone();
            dvc.with_dynamic_channel(EchoDvcBridge::new(echo_handle))
        };

        let mut dvc = if let Some(factory) = self.rdpei_factory.as_deref() {
            dvc.with_dynamic_channel(factory.build_server())
        } else {
            dvc
        };

        for attacher in &mut self.dynamic_channel_attachers {
            attacher(&mut dvc);
        }

        #[cfg(feature = "egfx")]
        let dvc = {
            let mut dvc = dvc;
            if let Some(gfx_factory) = self.gfx_factory.as_deref() {
                if let Some((bridge, handle)) = gfx_factory.build_server_with_handle() {
                    self.gfx_handle = Some(handle);
                    dvc = dvc.with_dynamic_channel(bridge);
                } else {
                    let handler = gfx_factory.build_gfx_handler();
                    let gfx_server = ironrdp_egfx::server::GraphicsPipelineServer::new(handler);
                    dvc = dvc.with_dynamic_channel(gfx_server);
                }
            }
            dvc
        };

        #[cfg(feature = "usb")]
        let dvc = {
            let mut dvc = dvc;
            if self.usb_man.is_some() {
                dvc = dvc.with_dynamic_channel(UrbdrcControlServer::new(Box::new(UsbControlHandle::new(
                    self.ev_sender.clone(),
                ))));
            }
            dvc
        };

        acceptor.attach_static_channel(dvc);

        for factory in &self.static_channel_factories {
            factory.attach(acceptor);
        }
    }

    /// Drop every event still queued on the server-global channel that
    /// belongs to the SESSION just replaced, keeping only the small set of
    /// lifecycle/control events meant to survive across connections.
    ///
    /// Called immediately before serving a preemption winner. The channel is
    /// shared across every connection the server ever serves and is read by
    /// whichever connection drains it next -- so any event the outgoing
    /// session produced but never got around to consuming (its OWN eviction
    /// notice, a queued clipboard message, an RDPSND wave, an EGFX frame)
    /// would otherwise be delivered to its replacement. That is at best stale
    /// (an audio wave from a session that no longer exists) and at worst a
    /// real leak (the previous peer's clipboard content, handed unprompted to
    /// the client that just replaced it).
    ///
    /// An ALLOWLIST of what to KEEP, not a denylist of `EvictedByOtherConnection`
    /// alone, and deliberately so: this mirrors what `run()`'s own top-level
    /// select already does when NOTHING is being served (only `Quit` /
    /// `GetLocalAddr` / `SetCredentials` / `SetAutoReconnectCookie` are
    /// meaningful there; everything else falls into its `ev => debug!("Unexpected
    /// event")` catch-all and is discarded). A new per-session `ServerEvent`
    /// variant is excluded here by default, instead of silently leaking across
    /// a takeover boundary until someone remembers to add it to a denylist.
    async fn discard_stale_session_events(&mut self) {
        use tokio::sync::mpsc::error::TryRecvError;

        let ev_receiver = Arc::clone(&self.ev_receiver);
        let mut ev_receiver = ev_receiver.lock().await;

        // Collect first, re-send after: re-sending during the drain would push
        // events onto the back of the same queue we are draining.
        let mut keep = Vec::new();
        let mut discarded = 0usize;
        loop {
            match ev_receiver.try_recv() {
                Ok(
                    event @ (ServerEvent::Quit(_)
                    | ServerEvent::GetLocalAddr(_)
                    | ServerEvent::SetCredentials(_)
                    | ServerEvent::SetAutoReconnectCookie(_)),
                ) => keep.push(event),
                Ok(_other) => discarded += 1,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }

        if discarded > 0 {
            debug!(
                discarded,
                "dropped per-session events the replaced session never consumed -- they must not reach its replacement"
            );
        }

        for event in keep {
            let _ = self.ev_sender.send(event);
        }
    }

    /// Build the cheap, cloned snapshot a preempting candidate negotiates
    /// against — see [`NegotiationContext`].
    fn negotiation_context(&self) -> NegotiationContext {
        NegotiationContext {
            opts: self.opts.clone(),
            creds: self.creds.clone(),
            credential_resolver: self.credential_resolver.clone(),
            enable_ainput: self.enable_ainput,
            display: Arc::clone(&self.display),
        }
    }

    /// Serve a candidate that already won the preemption race: negotiation and
    /// authentication are done, so this is where its channel backends are
    /// finally built (see the body comment below for why only now) before
    /// handing off to the same finalization the normal path uses. From here
    /// on, a preemption winner is indistinguishable from a normally-accepted
    /// connection.
    async fn serve_negotiated(&mut self, candidate: Box<NegotiatedCandidate>) -> ServerResult<()> {
        self.display_suppressed.store(false, Ordering::Relaxed);
        self.client_initiated_disconnect = false;

        let mut candidate = candidate;
        // Only NOW build the channel backends: this connection has
        // authenticated and is about to be served, so the factories run
        // exactly once per served session, as they always have. Still ahead of
        // `accept_finalize`, which is where the acceptor first consumes the
        // static channel set (the MCS Connect Initial); `accept_begin`, already
        // done, stops at the security-upgrade gate before that.
        self.attach_channels(&mut candidate.acceptor);

        self.finalize_negotiated(*candidate).await
    }

    /// Run a single RDP connection over `stream`, performing the
    /// IronRDP-managed TLS handshake on `ShouldUpgrade` (standard TCP+TLS).
    ///
    /// Socket options on `stream` are the caller's to set. In particular RDP
    /// is a stream of small, latency-sensitive writes, so a TCP stream should
    /// have `TCP_NODELAY` set; [`RdpServer::run`] does that for the
    /// connections it accepts itself.
    ///
    /// Equivalent to [`run_connection_with`](Self::run_connection_with) with
    /// [`TransportTls::Managed`].
    pub async fn run_connection<S>(&mut self, stream: S) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        self.run_connection_with(stream, TransportTls::Managed).await
    }

    /// Run a single RDP connection over `stream`, choosing who performs the TLS
    /// handshake with `tls`.
    ///
    /// Socket options on `stream` are the caller's to set; see
    /// [`run_connection`](Self::run_connection).
    ///
    /// With [`TransportTls::Managed`], IronRDP performs the TLS accept on
    /// `ShouldUpgrade`, exactly as [`run_connection`](Self::run_connection).
    ///
    /// With [`TransportTls::AlreadyDone`], the caller's `stream` has ALREADY
    /// been transport-encrypted at a lower layer that the embedder owns
    /// (typically a WSS terminator in the same process, or a TLS stream the
    /// embedder accepted up front), so IronRDP skips the TLS handshake and
    /// advances the state machine via [`Acceptor::mark_security_upgrade_as_done`].
    /// Everything past the handshake, including the optional Hybrid CredSSP
    /// exchange and finalization, is identical to the managed path.
    ///
    /// # Use case for [`TransportTls::AlreadyDone`]
    ///
    /// This mode decouples transport encryption from the RDP security-upgrade
    /// step. It is for ironrdp-server endpoints that terminate transport
    /// encryption themselves before the RDP state machine runs — for example a
    /// server that accepts WSS directly, or one fronted by an in-process TLS
    /// terminator — and therefore must not perform a second, inner TLS
    /// handshake when the X.224 negotiation selects `PROTOCOL_SSL`.
    ///
    /// This is distinct from a [RDCleanPath] proxy deployment (e.g.
    /// Devolutions Gateway), where the proxy performs a real TLS handshake with
    /// a *separate* backend RDP server and relays that server's certificate
    /// chain to the client. In that topology the backend server owns its own
    /// TLS and uses [`TransportTls::Managed`]; this mode does not apply to it.
    /// RDCleanPath is relevant here only as one client-side mechanism (see
    /// precondition 2) for telling a client not to expect an inner handshake.
    ///
    /// # Preconditions for [`TransportTls::AlreadyDone`] (caller MUST guarantee)
    ///
    /// 1. The `stream` is already transport-encrypted by another layer
    ///    (WSS, in-process, etc.). Passing a plain TCP stream here exposes
    ///    RDP traffic in plaintext on the wire.
    ///
    /// 2. The connecting client must not expect an inner TLS handshake on this
    ///    stream. Vanilla RDP clients (mstsc, xfreerdp) negotiate TLS from the
    ///    X.224 `selectedProtocol` and have no concept of "TLS already done at a
    ///    lower layer": they will hang or fail, and must use
    ///    [`TransportTls::Managed`]. Arranging for a client to skip the inner
    ///    handshake is the embedder's responsibility; RDCleanPath is one such
    ///    mechanism, but this method does not depend on it.
    ///
    /// 3. If `self.opts.security` is [`RdpServerSecurity::Hybrid`], two things
    ///    must hold. First, the client must support CredSSP over this
    ///    transport; the SPNEGO exchange itself is transport-independent
    ///    (CredSSP carries its own crypto via TSRequest), so it runs the same
    ///    as on the managed path. Second, and less obvious: the CredSSP
    ///    server-public-key confirmation (`pubKeyAuth`, per MS-CSSP) binds to
    ///    the certificate the client validated at the lower transport layer,
    ///    not to anything IronRDP does here. So the public key configured in
    ///    [`RdpServerSecurity::Hybrid`] MUST be the public key of the
    ///    certificate that lower layer (e.g. the WSS terminator) presented to
    ///    the client, otherwise the client's `pubKeyAuth` check fails and
    ///    Hybrid is rejected. This is the embedder's responsibility; it does
    ///    not hold automatically. In practice it means terminating transport
    ///    TLS with the same certificate configured for Hybrid.
    ///
    /// [RDCleanPath]: https://docs.rs/ironrdp-rdcleanpath
    ///
    /// # Wire-level invariant
    ///
    /// This method does NOT alter the X.224 negotiation. The acceptor still
    /// advertises whatever `SecurityProtocol` it was constructed with, and the
    /// connecting client still negotiates as normal. The only behaviour change
    /// under [`TransportTls::AlreadyDone`] is that after the negotiation reaches
    /// the security-upgrade gate, no TLS handshake is performed on the byte
    /// stream, because the caller's stream is already past TLS at a lower layer.
    pub async fn run_connection_with<S>(&mut self, stream: S, tls: TransportTls) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        let started = std::time::Instant::now();
        let result = self.run_connection_inner(stream, tls).await;

        // The static channels belong to the connection that negotiated them,
        // and their backends own real resources: an rdpsnd handler is stopped
        // through `Drop`, so an audio backend keeps capturing until the set is
        // replaced. `run` cleared the set itself, which left embedders driving
        // connections through this method with the previous session's backends
        // still live until the next client attached new ones.
        self.static_channels = StaticChannelSet::new();

        // The connection is over, so whatever the embedder does at the end of
        // one has to happen here. This used to fire only in `run`'s accept
        // loop, which meant an embedder that forks a process per connection —
        // and therefore calls this method, not `run` — never reached its own
        // teardown: no session released, no desktop locked, no console
        // restored. `run` does not route through this method (it calls
        // `run_connection_inner` and dispatches itself), so this is not a
        // second dispatch for it.
        if let Some(ref mut handler) = self.connection_handler {
            let peer = self
                .peer_addr
                .unwrap_or_else(|| SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED), 0));
            // The return value steers `run`'s loop, and there is no loop here:
            // this method serves one connection and the caller decides what
            // comes next.
            let _ = handler.on_disconnected(peer, started.elapsed(), result.as_ref().err());
        }

        result
    }

    async fn run_connection_inner<S>(&mut self, stream: S, tls: TransportTls) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin,
    {
        // Per-connection state must start fresh: if the previous client
        // disconnected while it had sent `SuppressOutput { None }` (e.g.,
        // closed the mstsc window while minimized so the matching resume
        // PDU never arrived), the flag would still read `true` here and the
        // display backend would silently drop frames for the entire new
        // session until/unless the new client happens to send a
        // `RefreshRectangle` or `SuppressOutput { Some(rect) }`. Resetting
        // here also covers backends that share an externally-created Arc via
        // `set_display_suppressed_handle()`.
        self.display_suppressed.store(false, Ordering::Relaxed);
        self.client_initiated_disconnect = false;

        let size = self.display.lock().await.size().await;
        let capabilities = capabilities::capabilities(&self.opts, size);
        let mut pending = PendingConnection::new(
            self.opts.security.clone(),
            size,
            capabilities,
            self.creds.clone(),
            self.opts.honor_client_desktop_size,
            self.credential_resolver.clone(),
            self.enable_ainput,
            self.opts.multitransport.is_some(),
        );

        self.attach_channels(pending.acceptor_mut());

        // The whole pre-authentication phase under one deadline. Putting it
        // here, around `negotiate_and_authenticate`, is the point: the waits
        // inside it — for the client's first PDU, for TLS, for CredSSP — have
        // no deadlines of their own, and the timeouts further down the
        // connection all begin only once this has returned.
        let negotiated = match self.handshake_timeout {
            Some(limit) => match tokio::time::timeout(limit, pending.negotiate_and_authenticate(stream, tls)).await {
                Ok(result) => result?,
                Err(_elapsed) => {
                    warn!(?limit, "client did not finish the handshake in time — dropping it");
                    return Err(ServerError::reason(
                        "handshake",
                        "the client did not finish negotiating before the deadline",
                    ));
                }
            },
            None => pending.negotiate_and_authenticate(stream, tls).await?,
        };
        let Some(negotiated) = negotiated else {
            return Ok(());
        };

        self.finalize_negotiated(negotiated).await
    }

    /// Finalize a connection that has already negotiated (and, under Hybrid,
    /// authenticated) via [`PendingConnection::negotiate_and_authenticate`].
    /// Dispatches on which [`NegotiatedTransport`] variant it got: `Continued`
    /// (no security upgrade happened, [`RdpServerSecurity::None`]) goes
    /// straight to `accept_finalize` with no stream to shut down, while `Tls`
    /// / `Offloaded` route through [`Self::finalize_and_shutdown`] for the
    /// extra shutdown step — these three paths are NOT structurally identical
    /// past this point, only past the handshake `negotiate_and_authenticate`
    /// itself covers.
    async fn finalize_negotiated<S>(&mut self, negotiated: NegotiatedConnection<S>) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        let NegotiatedConnection { transport, acceptor } = negotiated;
        match transport {
            // No security upgrade happened, so there is no TLS session to shut
            // down — matches the pre-existing `BeginResult::Continue` arm.
            NegotiatedTransport::Continued(framed) => {
                self.accept_finalize(framed, acceptor).await?;
            }
            NegotiatedTransport::Tls(framed) => {
                self.finalize_and_shutdown(*framed, acceptor, "TLS connection").await?;
            }
            NegotiatedTransport::Offloaded(framed) => {
                self.finalize_and_shutdown(framed, acceptor, "TLS-offloaded stream")
                    .await?;
            }
        }

        Ok(())
    }

    /// Finalize an upgraded stream and shut it down afterwards. The
    /// negotiation and authentication that used to precede this now live in
    /// [`negotiate_and_authenticate`], which the preemption candidate path
    /// shares.
    async fn finalize_and_shutdown<S>(
        &mut self,
        framed: TokioFramed<S>,
        acceptor: Acceptor,
        shutdown_label: &str,
    ) -> ServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        // No mark_security_upgrade_as_done / CredSSP here: this refactor moved
        // both into `complete_security_upgrade`, called from
        // `PendingConnection::negotiate_and_authenticate` before this function
        // ever runs -- upstream's un-refactored equivalent still does that
        // work at this point, since it has no separate negotiation step.
        let framed = self.accept_finalize(framed, acceptor).await?;
        debug!("Shutting down {}", shutdown_label);
        let (mut inner, _) = framed.into_inner();
        if let Err(e) = inner.shutdown().await {
            debug!(?e, "{} shutdown error", shutdown_label);
        }

        Ok(())
    }

    pub async fn run(&mut self) -> ServerResult<()> {
        // Create socket with control over options before binding.
        // Using TcpSocket instead of TcpListener::bind() allows setting
        // SO_REUSEADDR and IPv6 dual-stack mode.
        let socket = match self.opts.addr {
            SocketAddr::V4(_) => TcpSocket::new_v4().map_err(|e| ServerError::io("create IPv4 socket", e))?,
            SocketAddr::V6(_) => {
                // IPv6 socket: on Linux, dual-stack is the default
                // (net.ipv6.bindv6only=0), so IPv4 clients connect as
                // IPv4-mapped addresses (::ffff:x.x.x.x). On platforms
                // where IPV6_V6ONLY defaults to 1 (Windows, some BSDs),
                // only IPv6 clients will be accepted and a separate IPv4
                // listener would be needed.
                TcpSocket::new_v6().map_err(|e| ServerError::io("create IPv6 socket", e))?
            }
        };

        // SO_REUSEADDR prevents EADDRINUSE when restarting the server while
        // the previous socket is still in TIME_WAIT. Only set on Unix;
        // on Windows SO_REUSEADDR has different semantics that allow a
        // second process to bind the same port, which is a security risk.
        #[cfg(unix)]
        socket
            .set_reuseaddr(true)
            .map_err(|e| ServerError::io("set SO_REUSEADDR", e))?;

        socket
            .bind(self.opts.addr)
            .map_err(|e| ServerError::io("bind listen address", e))?;

        let listener = socket
            .listen(LISTENER_BACKLOG)
            .map_err(|e| ServerError::io("start listener", e))?;
        let local_addr = listener.local_addr().map_err(|e| ServerError::io("local_addr", e))?;

        debug!("Listening for connections on {local_addr}");
        self.local_addr = Some(local_addr);

        // A candidate that wins a preemption race has ALREADY cleared
        // `on_accept` and fully authenticated by the time it lands here, so it
        // carries a negotiated candidate rather than a raw stream: the next
        // iteration resumes it at finalization, with no second `on_accept`
        // call (that hook is stateful for rate limiters) and no renegotiation.
        let mut pending: Option<(Box<NegotiatedCandidate>, SocketAddr)> = None;

        let preempt_enabled = self.opts.preempt_existing_session;
        // Say so out loud: under these modes the bar to evict a live session is
        // NOT authentication, whatever the option's name suggests. Restrict who
        // may even attempt a takeover with `ConnectionHandler::on_accept`.
        if preempt_enabled && !authenticates_before_eviction(&self.opts.security) {
            warn!(
                "preempt_existing_session is enabled under a security mode that does not authenticate the client \
                 before it could evict the live session: any peer able to complete the handshake can take the \
                 session over. Use RdpServerSecurity::Hybrid (CredSSP/NLA) for an authentication-gated takeover, or \
                 gate candidates with ConnectionHandler::on_accept."
            );
        }

        loop {
            enum Entry {
                Fresh(TcpStream, SocketAddr),
                Negotiated(Box<NegotiatedCandidate>, SocketAddr),
            }

            let entry = match pending.take() {
                Some((candidate, peer)) => {
                    // The eviction event is queued on the server-global channel
                    // but consumed by whichever connection happens to drain it.
                    // If the incumbent was too wedged to take it within
                    // `EVICTION_GRACE` (very plausibly the case — being wedged
                    // is why it was evicted), it is still queued now, and the
                    // WINNER's `client_loop` would drain it and disconnect
                    // itself, reporting a bogus
                    // `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` to the client
                    // that just took the session over. Discard any such
                    // leftover before serving it; every other event is put back
                    // in order.
                    self.discard_stale_session_events().await;
                    Entry::Negotiated(candidate, peer)
                }
                None => {
                    let ev_receiver = Arc::clone(&self.ev_receiver);
                    let mut ev_receiver = ev_receiver.lock().await;
                    let accepted = tokio::select! {
                        Some(event) = ev_receiver.recv() => {
                            match event {
                                ServerEvent::Quit(reason) => {
                                    debug!("Got quit event {reason}");
                                    break;
                                }
                                ServerEvent::GetLocalAddr(tx) => {
                                    let _ = tx.send(self.local_addr);
                                }
                                ServerEvent::SetCredentials(creds) => {
                                    self.set_credentials(Some(creds));
                                }
                                ServerEvent::SetAutoReconnectCookie(cookie) => {
                                    self.set_auto_reconnect_cookie(cookie);
                                }
                                // Routine at the 70 ms probe cadence while no
                                // client is connected; logging it at debug
                                // would flood the log 14 lines/s.
                                ServerEvent::AutoDetectRttRequest => {}
                                ev => {
                                    debug!("Unexpected event {:?}", ev);
                                }
                            }
                            continue;
                        },
                        Ok((stream, peer)) = listener.accept() => {
                            drop(ev_receiver);
                            // RDP output is small writes the peer is waiting
                            // on: a frame, a pointer update, a channel PDU.
                            // Nagle holds the trailing partial segment of each
                            // until the previous is acknowledged, which
                            // against a peer using delayed acknowledgements is
                            // dead time on every one. Not worth refusing a
                            // connection over, though.
                            if let Err(error) = stream.set_nodelay(true) {
                                warn!(?peer, %error, "Failed to set TCP_NODELAY; interactive latency may suffer");
                            }
                            (stream, peer)
                        },
                        else => break,
                    };
                    Entry::Fresh(accepted.0, accepted.1)
                }
            };

            let peer = match &entry {
                Entry::Fresh(_, peer) | Entry::Negotiated(_, peer) => *peer,
            };
            debug!(?peer, "Received connection");

            // A `Negotiated` winner already passed `on_accept` as a candidate,
            // inside the race below — its negotiation would not even have
            // started otherwise. Re-running it here would double-count for a
            // stateful handler (a rate limiter's window, an audit record).
            let accepted = matches!(entry, Entry::Negotiated(..))
                || self.connection_handler.as_mut().is_none_or(|h| h.on_accept(peer));

            if !accepted {
                debug!(?peer, "Connection rejected by handler");
                if let Entry::Fresh(stream, _) = entry {
                    drop(stream);
                }
                continue;
            }

            let started = tokio::time::Instant::now();

            let (result, preempted_by) = if preempt_enabled {
                // Serve this connection while still accepting: a newcomer that
                // clears `on_accept` AND fully authenticates
                // (`negotiate_candidate`) takes over, instead of queuing behind
                // the live session. Cancelling `conn` runs the same
                // per-connection teardown a client-side disconnect does.
                //
                // `conn` borrows `self` for the whole race, so the candidate's
                // `on_accept` and its negotiation work from clones taken here.
                let handler = self.connection_handler.take();
                let ctx = self.negotiation_context();
                let ev_sender = self.ev_sender.clone();
                let mut recently_evicted = self.recently_evicted.take();

                let outcome = {
                    // Uses the anyhow-returning inner method, not the public
                    // `run_connection` (`ServerResult`-returning as of
                    // upstream's typed-error migration, #1242): `conn`'s
                    // declared `Result<()>` (anyhow) must match
                    // `serve_negotiated`'s return type across both match
                    // arms, and `on_disconnected` below still expects
                    // `Option<&anyhow::Error>` -- the same reason upstream's
                    // own accept loop bypasses the public wrapper too.
                    let mut conn: core::pin::Pin<Box<dyn Future<Output = ServerResult<()>> + '_>> = match entry {
                        Entry::Fresh(stream, _) => Box::pin(self.run_connection_inner(stream, TransportTls::Managed)),
                        Entry::Negotiated(candidate, _) => Box::pin(self.serve_negotiated(candidate)),
                    };
                    let mut probe: PreemptProbe<'_> = Box::pin(core::future::pending());
                    let mut handler = handler;
                    let mut probing = false;

                    loop {
                        // This `select!` must only YIELD — never mutate
                        // `probe`, whose futures it still borrows.
                        let race = tokio::select! {
                            res = &mut conn => PreemptRace::Ended(res),
                            accepted = listener.accept(), if !probing => PreemptRace::Accepted(accepted),
                            candidate = &mut probe => PreemptRace::Probed(candidate),
                        };

                        match race {
                            // The session ended on its own. A candidate still
                            // negotiating is NOT discarded — that would reset a
                            // legitimate client that happened to connect just
                            // as the old session ended; finish it and serve it
                            // next if it authenticates.
                            PreemptRace::Ended(res) => {
                                if probing {
                                    // BOUNDED: nothing else is being serviced
                                    // during this await, so a candidate that
                                    // is not nearly done is dropped rather
                                    // than allowed to stall the listener.
                                    pending = match tokio::time::timeout(CANDIDATE_HANDOFF_GRACE, &mut probe).await {
                                        Ok(candidate) => candidate,
                                        Err(_) => {
                                            debug!(
                                                "a candidate was still negotiating when the session ended -- \
                                                 dropping it rather than stalling the accept loop; it can reconnect"
                                            );
                                            None
                                        }
                                    };
                                }
                                break (res, None, handler, recently_evicted);
                            }
                            PreemptRace::Accepted(Ok((next_stream, next_peer))) => {
                                // Same reason as the primary accept above: RDP
                                // is small latency-sensitive writes, so a
                                // candidate that goes on to win the race and
                                // become the live session needs this too, not
                                // just the one accept path upstream's own
                                // (non-preemption) loop happens to have.
                                if let Err(error) = next_stream.set_nodelay(true) {
                                    warn!(
                                        ?next_peer,
                                        %error,
                                        "Failed to set TCP_NODELAY on a candidate; interactive latency may suffer"
                                    );
                                }
                                // A peer evicted moments ago may not bounce
                                // straight back and retake the session; each
                                // attempt re-arms the window, so a reconnect
                                // storm can never win. See `recently_evicted`.
                                let bounced_back = refuse_reconnect_from_evicted(
                                    &mut recently_evicted,
                                    next_peer.ip(),
                                    Instant::now(),
                                    REPREEMPT_COOLDOWN,
                                    REPREEMPT_MAX_LOCKOUT,
                                );
                                // Gate the candidate through `on_accept` BEFORE
                                // it may negotiate, and so before it can
                                // preempt anything: otherwise a candidate the
                                // rate limiter would reject could still evict
                                // the live session and only be rejected
                                // afterwards, once the damage was done.
                                let candidate_accepted =
                                    !bounced_back && handler.as_mut().is_none_or(|h| h.on_accept(next_peer));

                                if candidate_accepted {
                                    probing = true;
                                    // BOUNDED: see `CANDIDATE_NEGOTIATION_TIMEOUT`.
                                    // An unbounded probe is a remote hang of
                                    // the whole accept loop.
                                    probe = Box::pin(negotiate_candidate_bounded(&ctx, next_stream, next_peer));
                                } else if bounced_back {
                                    info!(
                                        ?next_peer,
                                        "ignoring a reconnect from the peer just evicted -- it is \
                                         auto-reconnecting into the session that replaced it"
                                    );
                                    drop(next_stream);
                                } else {
                                    debug!(?next_peer, "candidate rejected by handler while a session was live");
                                    drop(next_stream);
                                }
                            }
                            PreemptRace::Accepted(Err(error)) => {
                                warn!(?error, "accept failed while a session was live");
                            }
                            PreemptRace::Probed(candidate) => {
                                probing = false;
                                probe = Box::pin(core::future::pending());
                                // `negotiate_candidate` already logged the
                                // reason when it declines, so there is nothing
                                // to do in the `None` case.
                                if let Some((candidate, new_peer)) = candidate {
                                    info!(
                                        old_peer = ?peer,
                                        ?new_peer,
                                        "an authenticated client connected -- evicting the existing session"
                                    );
                                    let _ = ev_sender.send(ServerEvent::EvictedByOtherConnection);
                                    let now = Instant::now();
                                    recently_evicted = Some(EvictedPeer {
                                        ip: peer.ip(),
                                        evicted_at: now,
                                        last_try: now,
                                    });
                                    // Let the incumbent observe the event and
                                    // put the reason on the wire before it
                                    // goes; bounded, so a wedged peer cannot
                                    // stall the takeover.
                                    match tokio::time::timeout(EVICTION_GRACE, &mut conn).await {
                                        Ok(res) => {
                                            break (res, Some((candidate, new_peer)), handler, recently_evicted);
                                        }
                                        Err(_) => {
                                            debug!(old_peer = ?peer, "evicted session did not wind down in time");
                                            break (Ok(()), Some((candidate, new_peer)), handler, recently_evicted);
                                        }
                                    }
                                }
                            }
                        }
                    }
                };

                let (result, preempted_by, handler, evicted) = outcome;
                self.connection_handler = handler;
                // Only remember an eviction that actually replaced this
                // session; a session that ended on its own terms leaves nobody
                // barred from connecting.
                self.recently_evicted = if preempted_by.is_some() { evicted } else { None };
                if preempted_by.is_some() {
                    // Can't do this INSIDE the race above: `conn` (built from
                    // `self.run_connection`/`self.serve_negotiated`) borrows
                    // `self` mutably for the whole race, so no other &mut self
                    // call is possible there. `self` is free again here, and
                    // the ~750ms EVICTION_GRACE this waited through is
                    // immaterial to what this closes -- a real ARC reconnect
                    // takes far longer than that to occur.
                    self.invalidate_auto_reconnect_cookie_on_eviction();
                }
                (result, preempted_by)
            } else {
                let result = match entry {
                    // Same anyhow-vs-ServerResult reasoning as the preemption
                    // branch above.
                    Entry::Fresh(stream, _) => self.run_connection_inner(stream, TransportTls::Managed).await,
                    // Unreachable in practice: `pending` is only ever populated
                    // by the preemption branch above.
                    Entry::Negotiated(candidate, _) => self.serve_negotiated(candidate).await,
                };
                (result, None)
            };
            let duration = started.elapsed();

            if let Some((candidate, new_peer)) = preempted_by {
                pending = Some((candidate, new_peer));
            }

            if let Err(ref error) = result {
                error!(?error, "Connection error");
            }

            // NOT redundant with `run_connection_with`'s own reset (added
            // upstream, #1721) despite resetting the same field: a preemption
            // winner reaches this point via `serve_negotiated`, which never
            // calls `run_connection`/`run_connection_with` at all -- so this
            // is the only reset that path gets. Removing this because
            // `run_connection_with` "already handles it" would silently
            // reintroduce #1721's leak (channel backends, e.g. rdpsnd's audio
            // capture, held open until the next client) for every preemption
            // takeover.
            self.static_channels = StaticChannelSet::new();

            if let Some(ref mut handler) = self.connection_handler {
                let action = handler.on_disconnected(peer, duration, result.as_ref().err());
                if action == PostConnectionAction::Stop {
                    debug!(?peer, "Handler requested stop after disconnect");
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn get_svc_processor<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.static_channels
            .get_by_type_mut::<T>()
            .and_then(|svc| svc.channel_processor_downcast_mut())
    }

    pub fn get_channel_id_by_type<T: SvcProcessor + 'static>(&self) -> Option<StaticChannelId> {
        self.static_channels.get_channel_id_by_type::<T>()
    }

    /// Write DVC (DRDYNVC) messages: unframed through the UDP tunnel once the
    /// client's Soft-Sync response confirmed the migration, otherwise framed
    /// on the TCP drdynvc channel.
    /// Bind the UDP tunnel and ask the client (via TCP DVC Soft-Sync) to move
    /// every open dynamic channel to it.
    async fn soft_sync(
        &mut self,
        to_tunnel: mpsc::Sender<Vec<u8>>,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
            warn!("Soft-sync requested but DRDYNVC channel is gone; ignoring");
            return Ok(());
        };
        let ids = drdynvc.open_channel_ids();
        if ids.is_empty() {
            // The client can confirm the tunnel before it has opened a single
            // dynamic channel. Dropping the Soft-Sync then left the whole
            // connection on TCP; keep it until a channel is open instead.
            debug!("Soft-sync ready but no dynamic channel is open yet; waiting for one");
            self.pending_soft_sync = Some(to_tunnel);
            return Ok(());
        }
        let request = drdynvc
            .request_reliable_udp(ids.clone())
            .map_err_kind("request reliable udp", ServerErrorKind::Pdu)?;
        self.udp_tunnel_tx = Some(to_tunnel);
        info!(channels = ?ids, "Sending DVC Soft-Sync request (TCP→UDP migration)");
        self.write_dvc_messages(vec![request], writer, user_channel_id).await
    }

    /// Record the client's Initiate Multitransport Response.
    fn on_multitransport_response(&mut self, request_id: u32, hr_response: u32) {
        if self.multitransport_request_id != Some(request_id) {
            warn!(
                request_id,
                sent = ?self.multitransport_request_id,
                "Multitransport Response for a request this connection did not send; ignoring"
            );
            return;
        }
        if hr_response == 0 {
            self.multitransport_confirmed = true;
        } else {
            // The client could not bring the tunnel up: everything stays on
            // TCP, and a tunnel we built anyway is not to be used.
            warn!(hr_response = format!("{hr_response:#010X}"), "client refused the multitransport tunnel");
            self.pending_soft_sync = None;
        }
    }

    /// Send a Soft-Sync that was waiting for the client's confirmation.
    async fn resume_soft_sync(&mut self, writer: &mut impl FramedWrite, user_channel_id: u16) -> ServerResult<()> {
        if self.multitransport_confirmed
            && let Some(to_tunnel) = self.pending_soft_sync.take()
        {
            self.soft_sync(to_tunnel, writer, user_channel_id).await?;
        }
        Ok(())
    }

    async fn write_dvc_messages(
        &mut self,
        messages: Vec<SvcMessage>,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
    ) -> ServerResult<()> {
        let tunneled = self.udp_tunnel_tx.is_some()
            && self
                .get_svc_processor::<dvc::DrdynvcServer>()
                .is_some_and(|d: &mut dvc::DrdynvcServer| d.soft_sync_response_received());
        if tunneled {
            self.send_to_tunnel(messages)?;
        } else {
            let channel_id = self
                .get_channel_id_by_type::<dvc::DrdynvcServer>()
                .ok_or_else(|| ServerError::channel("DRDYNVC channel not found"))?;
            let data =
                server_encode_svc_messages(messages, channel_id, user_channel_id).map_err(ServerError::encode)?;
            writer
                .write_all(&data)
                .await
                .map_err(|e| ServerError::io("write dvc messages", e))?;
        }
        Ok(())
    }

    /// Encode DVC messages unframed and hand them to the UDP tunnel pump.
    fn send_to_tunnel(&self, messages: Vec<SvcMessage>) -> ServerResult<()> {
        let Some(tx) = self.udp_tunnel_tx.as_ref() else {
            return Err(ServerError::custom("udp tunnel", std::io::Error::other("no tunnel installed")));
        };
        for msg in messages {
            let bytes = msg.encode_unframed_pdu().map_err(ServerError::encode)?;
            if tx.try_send(bytes).is_err() {
                warn!("UDP tunnel write queue full; dropping DVC message");
            }
        }
        Ok(())
    }

    async fn dispatch_pdu(
        &mut self,
        action: Action,
        bytes: bytes::BytesMut,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
    ) -> ServerResult<RunState> {
        match action {
            Action::FastPath => {
                let input = decode(&bytes).map_err(ServerError::decode)?;
                self.handle_fastpath(input).await;
            }

            Action::X224 => {
                if self
                    .handle_x224(writer, io_channel_id, user_channel_id, message_channel_id, &bytes)
                    .await?
                {
                    debug!("Got disconnect request");
                    return Ok(RunState::Disconnect);
                }
            }
        }

        Ok(RunState::Continue)
    }

    async fn dispatch_display_update(
        update: DisplayUpdate,
        writer: &mut impl FramedWrite,
        user_channel_id: u16,
        io_channel_id: u16,
        fastpath_output: bool,
        buffer: &mut Vec<u8>,
        mut encoder: UpdateEncoder,
        budget: &mut DisplayBudget,
    ) -> ServerResult<(RunState, UpdateEncoder)> {
        if let DisplayUpdate::Resize(desktop_size) = update {
            debug!(?desktop_size, "Display resize");
            encoder.set_desktop_size(desktop_size);
            deactivate_all(io_channel_id, user_channel_id, writer).await?;
            return Ok((RunState::DeactivationReactivation { desktop_size }, encoder));
        }

        let mut encoder_iter = encoder.update(update);
        loop {
            let Some(fragmenter) = encoder_iter.next().await else {
                break;
            };

            let mut fragmenter = fragmenter?;

            if !fastpath_output {
                // MS-RDPBCGR 2.2.9.1.1: slow-path graphics and pointer
                // updates, one Share Data PDU each. Slow-path has no
                // fragmentation, so an update larger than what fits in a
                // single MCS PDU is dropped (with a warning) rather than
                // corrupted.
                let code = fragmenter.update_code();
                let payload = fragmenter.payload();
                if payload.len() > MAX_SLOWPATH_UPDATE_SIZE {
                    warn!(
                        size = payload.len(),
                        max = MAX_SLOWPATH_UPDATE_SIZE,
                        update_code = code.as_u8(),
                        "slow-path update too large for one PDU; dropping"
                    );
                    continue;
                }
                let Some(pdu) = slow_path_update(code, payload) else {
                    warn!(update_code = code.as_u8(), "update has no slow-path form; dropping");
                    continue;
                };
                let data = encode_share_data_pdu(pdu, io_channel_id, io_channel_id, user_channel_id)?;
                budget.acquire(data.len()).await;
                writer
                    .write_all(&data)
                    .await
                    .map_err(|e| ServerError::io("failed to write slow-path update", e))?;
                continue;
            }

            if fragmenter.size_hint() > buffer.len() {
                buffer.resize(fragmenter.size_hint(), 0);
            }

            while let Some(len) = fragmenter.next(buffer) {
                // Bandwidth shaping (MS-RDPBCGR 2.2.14): pace bitmap bytes to
                // the link bandwidth the auto-detect probes measured, so a
                // full-screen video can't saturate the shared TCP transport
                // and starve audio/input behind it.
                budget.acquire(len).await;
                writer
                    .write_all(&buffer[..len])
                    .await
                    .map_err(|e| ServerError::io("failed to write display update", e))?;
            }
        }

        Ok((RunState::Continue, encoder))
    }

    async fn dispatch_server_events(
        &mut self,
        events: &mut Vec<ServerEvent>,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
    ) -> ServerResult<RunState> {
        // NOTE: waves are no longer shed here. The old WAVE_KEEP drop broke
        // two invariants the app-side flow control relies on: a wave dropped
        // after the handler counted it in-flight is never confirmed (wedging
        // the counter until the self-heal timeout), and skipping a wave
        // desyncs any block-number-based confirm matching (MS-RDPEA
        // 2.2.3.8). Backlog control belongs where the backlog is measured —
        // the sound handler drops waves based on the client's held-time
        // reports before they ever reach this loop.
        let mut wave_skip: usize = 0;
        for event in events.drain(..) {
            trace!(?event, "Dispatching");
            match event {
                ServerEvent::Quit(reason) => {
                    debug!("Got quit event: {reason}");
                    return Ok(RunState::Disconnect);
                }
                // Session takeover: tell the client WHY it is being
                // disconnected before dropping it, so it does not read this as
                // an unexpected drop and auto-reconnect (which ping-pongs
                // against the preempting client — see the variant's docs).
                ServerEvent::EvictedByOtherConnection => {
                    debug!("evicting this connection -- another client took the session over");
                    // MS-RDPBCGR 3.3.5.7.1: the Set Error Info PDU MUST NOT
                    // be sent to a client that did not set
                    // RNS_UD_CS_SUPPORT_ERRINFO_PDU in its Client Core Data
                    // `earlyCapabilityFlags` (tracked in
                    // `self.client_supports_errinfo`).
                    if !self.client_supports_errinfo {
                        debug!("client did not announce SUPPORT_ERRINFO_PDU; skipping the eviction reason");
                        return Ok(RunState::Disconnect);
                    }
                    let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                        ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::DisconnectedByOtherconnection),
                    ));
                    // Best-effort: if the evicted peer's socket is already
                    // half-dead the write fails, which is fine — it is leaving
                    // either way, and the caller falls back to cancelling it.
                    // pduSource=0, not user_channel_id -- MS-RDPBCGR 2.2.5.1.1
                    // requires it for TS_SET_ERROR_INFO_PDU specifically.
                    match encode_share_data_pdu(pdu, 0, io_channel_id, user_channel_id) {
                        Ok(bytes) => {
                            if let Err(error) = writer.write_all(&bytes).await {
                                debug!(%error, "could not send the eviction reason; disconnecting anyway");
                            }
                        }
                        Err(error) => {
                            warn!(%error, "could not encode the eviction reason; disconnecting anyway");
                        }
                    }
                    return Ok(RunState::Disconnect);
                }
                ServerEvent::Disconnect(error) => {
                    debug!(?error, "Got disconnect event");
                    // MS-RDPBCGR 3.3.5.7.1: MUST NOT send the Set Error Info
                    // PDU to a client that did not set
                    // RNS_UD_CS_SUPPORT_ERRINFO_PDU.
                    if !self.client_supports_errinfo {
                        debug!("client did not announce SUPPORT_ERRINFO_PDU; disconnecting without a reason PDU");
                        return Ok(RunState::Disconnect);
                    }
                    let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(error));
                    // pduSource=0, not user_channel_id -- same MS-RDPBCGR
                    // 2.2.5.1.1 requirement as the EvictedByOtherConnection
                    // arm above; upstream's original call here (before this
                    // merge) predated that parameter and used
                    // user_channel_id, which this fixes to match.
                    let data = encode_share_data_pdu(pdu, 0, io_channel_id, user_channel_id)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("send server set error info", e))?;
                    return Ok(RunState::Disconnect);
                }
                ServerEvent::GetLocalAddr(tx) => {
                    let _ = tx.send(self.local_addr);
                }
                ServerEvent::SetCredentials(creds) => {
                    self.set_credentials(Some(creds));
                }
                ServerEvent::SetAutoReconnectCookie(cookie) => {
                    self.update_auto_reconnect_cookie(cookie, writer, io_channel_id, user_channel_id)
                        .await?;
                }
                ServerEvent::Rdpsnd(s) => {
                    let Some(rdpsnd) = self.get_svc_processor::<RdpsndServer>() else {
                        warn!("No rdpsnd channel, dropping event");
                        continue;
                    };
                    let msgs = match s {
                        RdpsndServerMessage::Wave(data, ts) => {
                            if wave_skip > 0 {
                                wave_skip -= 1;
                                debug!("Dropping stale wave");
                                continue;
                            }
                            rdpsnd.wave(data, ts)
                        }
                        RdpsndServerMessage::SetVolume { left, right } => rdpsnd.set_volume(left, right),
                        RdpsndServerMessage::Close => rdpsnd.close(),
                        RdpsndServerMessage::Error(error) => {
                            error!(?error, "Handling rdpsnd event");
                            continue;
                        }
                    }
                    .map_err_kind("failed to send rdpsnd event", ServerErrorKind::Pdu)?;
                    let channel_id = self
                        .get_channel_id_by_type::<RdpsndServer>()
                        .ok_or_else(|| ServerError::channel("SVC channel not found"))?;
                    let data = server_encode_svc_messages(msgs.into(), channel_id, user_channel_id)
                        .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::SoftSyncToUdp { to_tunnel } => {
                    if self.multitransport_confirmed {
                        self.soft_sync(to_tunnel, writer, user_channel_id).await?;
                    } else {
                        info!("RDP-UDP tunnel ready before the client confirmed it; deferring Soft-Sync");
                        self.pending_soft_sync = Some(to_tunnel);
                    }
                }
                ServerEvent::OpenDynamicChannel { processor, reply } => {
                    let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
                        warn!(
                            channel_name = processor.channel_name(),
                            "no DRDYNVC channel on this connection; cannot open a dynamic channel"
                        );
                        if let Some(reply) = reply {
                            let _ = reply.send(None);
                        }
                        continue;
                    };
                    let channel_name = processor.channel_name().to_owned();
                    let (channel_id, request) = drdynvc
                        .create_channel_boxed(processor)
                        .map_err_kind("create dynamic channel", ServerErrorKind::Pdu)?;
                    debug!(%channel_name, channel_id, deferred = request.is_none(), "opening a dynamic channel");
                    if let Some(reply) = reply {
                        let _ = reply.send(Some(channel_id));
                    }
                    if let Some(request) = request {
                        self.write_dvc_messages(vec![request], writer, user_channel_id).await?;
                    }
                }
                ServerEvent::CloseDynamicChannel { channel_id } => {
                    let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
                        continue;
                    };
                    debug!(channel_id, "closing a dynamic channel");
                    if let Some(close) = drdynvc.close_channel(channel_id) {
                        self.write_dvc_messages(vec![close], writer, user_channel_id).await?;
                    }
                }
                ServerEvent::UdpTunnelData(frame) => {
                    let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
                        warn!("Tunnel data but DRDYNVC channel is gone; dropping");
                        continue;
                    };
                    let responses = drdynvc
                        .process_tunnel(&frame)
                        .map_err_kind("process tunnel data", ServerErrorKind::Pdu)?;
                    // Responses to tunneled data always go back through the
                    // tunnel — the client no longer reads these channels on TCP.
                    if !responses.is_empty() {
                        self.send_to_tunnel(responses)?;
                    }
                }
                ServerEvent::Rdpdr(msg) => {
                    let Some(rdpdr) = self.get_svc_processor::<RdpdrServer>() else {
                        warn!("No rdpdr channel, dropping event");
                        continue;
                    };
                    let msgs = match msg {
                        RdpdrServerMessage::Create {
                            device_id,
                            path,
                            desired_access,
                            create_disposition,
                            create_options,
                        } => rdpdr.drive_create(device_id, path, desired_access, create_disposition, create_options),
                        RdpdrServerMessage::Read {
                            device_id,
                            file_id,
                            length,
                            offset,
                        } => rdpdr.drive_read(device_id, file_id, length, offset),
                        RdpdrServerMessage::Write {
                            device_id,
                            file_id,
                            data,
                            offset,
                        } => rdpdr.drive_write(device_id, file_id, data, offset),
                        RdpdrServerMessage::Close { device_id, file_id } => rdpdr.drive_close(device_id, file_id),
                        RdpdrServerMessage::FlushBuffers { device_id, file_id } => {
                            rdpdr.drive_flush_buffers(device_id, file_id)
                        }
                        RdpdrServerMessage::QueryInformation {
                            device_id,
                            file_id,
                            info_class,
                        } => rdpdr.drive_query_information(device_id, file_id, info_class),
                        RdpdrServerMessage::SetInformation {
                            device_id,
                            file_id,
                            set_buffer,
                        } => rdpdr.drive_set_information(device_id, file_id, set_buffer),
                        RdpdrServerMessage::QueryDirectory {
                            device_id,
                            file_id,
                            info_class,
                            path,
                            initial_query,
                        } => rdpdr.drive_query_directory(device_id, file_id, info_class, path, initial_query),
                        RdpdrServerMessage::NotifyChangeDirectory {
                            device_id,
                            file_id,
                            watch_tree,
                            completion_filter,
                        } => rdpdr.drive_notify_change_directory(device_id, file_id, watch_tree, completion_filter),
                        RdpdrServerMessage::QueryVolumeInformation {
                            device_id,
                            file_id,
                            fs_info_class,
                        } => rdpdr.drive_query_volume_information(device_id, file_id, fs_info_class),
                        RdpdrServerMessage::LockControl {
                            device_id,
                            file_id,
                            operation,
                            wait,
                            locks,
                        } => rdpdr.drive_lock_control(device_id, file_id, operation, wait, locks),
                        RdpdrServerMessage::QuerySecurity {
                            device_id,
                            file_id,
                            security_information,
                        } => rdpdr.drive_query_security(device_id, file_id, security_information),
                        RdpdrServerMessage::SetSecurity {
                            device_id,
                            file_id,
                            security_information,
                            security_descriptor,
                        } => rdpdr.drive_set_security(device_id, file_id, security_information, security_descriptor),
                        RdpdrServerMessage::DeviceControl {
                            device_id,
                            file_id,
                            io_control_code,
                            input_buffer,
                            output_buffer_length,
                        } => rdpdr.drive_device_control(
                            device_id,
                            file_id,
                            io_control_code,
                            input_buffer,
                            output_buffer_length,
                        ),
                    }
                    .map_err_kind("failed to send rdpdr event", ServerErrorKind::Pdu)?;
                    let channel_id = self
                        .get_channel_id_by_type::<RdpdrServer>()
                        .ok_or_else(|| ServerError::channel("SVC channel not found"))?;
                    let data =
                        server_encode_svc_messages(msgs, channel_id, user_channel_id).map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::Clipboard(c) => {
                    let Some(cliprdr) = self.get_svc_processor::<CliprdrServer>() else {
                        warn!("No clipboard channel, dropping event");
                        continue;
                    };
                    let msgs = match c {
                        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
                        ClipboardMessage::SendInitiateFileCopy(files) => cliprdr.initiate_file_copy(files),
                        ClipboardMessage::SendFormatData(data) => cliprdr.submit_format_data(data),
                        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format),
                        ClipboardMessage::SendFileContentsRequest(request) => cliprdr.request_file_contents(request),
                        ClipboardMessage::SendFileContentsResponse(response) => cliprdr.submit_file_contents(response),
                        ClipboardMessage::Error(error) => {
                            error!(?error, "Handling clipboard event");
                            continue;
                        }
                    }
                    .map_err_kind("failed to send clipboard event", ServerErrorKind::Pdu)?;
                    let channel_id = self
                        .get_channel_id_by_type::<CliprdrServer>()
                        .ok_or_else(|| ServerError::channel("SVC channel not found"))?;
                    let data = server_encode_svc_messages(msgs.into(), channel_id, user_channel_id)
                        .map_err(ServerError::encode)?;
                    writer
                        .write_all(&data)
                        .await
                        .map_err(|e| ServerError::io("write_all", e))?;
                }
                ServerEvent::Echo(msg) => match msg {
                    EchoServerMessage::SendRequest { payload } => {
                        let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
                            warn!("No drdynvc channel, dropping ECHO request");
                            continue;
                        };

                        let Some(echo_channel_id) = drdynvc.get_channel_id_by_type::<EchoDvcBridge>() else {
                            warn!("No ECHO dynamic channel, dropping ECHO request");
                            continue;
                        };

                        if !drdynvc.is_channel_opened(echo_channel_id) {
                            warn!("ECHO dynamic channel not yet opened, dropping ECHO request");
                            continue;
                        }

                        self.echo_handle.on_request_sent(&payload);

                        let request = build_echo_request(payload)?;
                        let messages =
                            dvc::encode_dvc_messages(echo_channel_id, vec![request], ChannelFlags::SHOW_PROTOCOL)
                                .map_err(ServerError::encode)?;

                        self.write_dvc_messages(messages, writer, user_channel_id).await?;
                    }
                },
                #[cfg(feature = "usb")]
                ServerEvent::Usb(msg) => match msg {
                    UrbdrcServerMessage::AddChan => {
                        let create_dvc_msg = {
                            use crate::urbdrc::UsbRedirServer;

                            let Some(usb_man) = self.usb_man.as_mut() else {
                                warn!("Missing USB device factory");
                                continue;
                            };
                            let Some(drdynvc) = self
                                .static_channels
                                .get_by_type_mut::<dvc::DrdynvcServer>()
                                .and_then(|svc| svc.channel_processor_downcast_mut::<dvc::DrdynvcServer>())
                            else {
                                warn!("No drdynvc channel, dropping URBDRC request");
                                continue;
                            };

                            let Some(comp_iface) = usb_man.comp_iface_alloc.alloc() else {
                                warn!("Run out of URBDRC interface IDs");
                                continue;
                            };

                            let Some(device_backend) = usb_man.factory.create_device() else {
                                warn!("Failed to create USB device backend");
                                continue;
                            };

                            drdynvc
                                .create_channel_with(|dvc_id| {
                                    let handle = UsbDeviceHandle::new(self.ev_sender.clone(), dvc_id);
                                    if usb_man.router.insert(dvc_id, handle.device()).is_some() {
                                        warn!(dvc_id = dvc_id, "Replacing USB device pending-request map");
                                    }
                                    Ok::<_, PduError>(
                                        UrbdrcDeviceServer::new(
                                            Box::new(UsbRedirServer::new(device_backend, handle)),
                                            comp_iface,
                                        )
                                        .expect("interface ID allocated by InterfaceAlloc must be valid"),
                                    )
                                })
                                .map_err_kind("create URBDRC device channel", ServerErrorKind::Pdu)?
                        };

                        // `None`: the capability exchange is still running, and
                        // the request goes out with its answer.
                        if let Some(create_dvc_msg) = create_dvc_msg {
                            self.write_dvc_messages(vec![create_dvc_msg], writer, user_channel_id)
                                .await?;
                        }
                    }
                    UrbdrcServerMessage::Device { dvc_id, dev_msg } => {
                        let Some(device) = self
                            .usb_man
                            .as_ref()
                            .and_then(|usb_man| usb_man.router.get(&dvc_id))
                            .map(Arc::clone)
                        else {
                            warn!(dvc_id, "Missing USB device state");
                            continue;
                        };

                        // Handle checks are an early rejection for callers. This event-loop check
                        // is authoritative because a request may already be queued when retract or
                        // channel close changes the shared lifecycle state.
                        if !device.is_open() {
                            trace!(dvc_id, "Dropping request for closing or closed USB device");
                            continue;
                        }

                        let Some(drdynvc) = self.get_svc_processor::<dvc::DrdynvcServer>() else {
                            warn!("No drdynvc channel, dropping URBDRC request");
                            continue;
                        };

                        let Some(mut dvc) = drdynvc.dvc_by_id_mut::<UrbdrcDeviceServer>(dvc_id) else {
                            warn!(dvc_id, "USB dynamic channel ID mismatch");
                            continue;
                        };
                        let processor = dvc.processor_mut();

                        let (dvc_msgs, close_dev) = match dev_msg {
                            UrbdrcDeviceServerMessage::QueryDeviceText { text_type, locale_id } => {
                                let text = processor
                                    .query_device_text(text_type, locale_id)
                                    .map_err_kind("query USB device text", ServerErrorKind::Pdu)?;
                                (vec![text], false)
                            }
                            UrbdrcDeviceServerMessage::IoReq { data, tx } => {
                                if tx.is_closed() {
                                    continue;
                                }

                                let request = match data {
                                    ServerDeviceIoReq::IoControl(packet) => processor.io_control(packet),
                                    ServerDeviceIoReq::InternalIoControl(packet) => {
                                        processor.internal_io_control(packet)
                                    }
                                    ServerDeviceIoReq::TransferOut(packet) => processor.transfer_out(packet),
                                    ServerDeviceIoReq::TransferIn(packet) => processor.transfer_in(packet),
                                }
                                .map_err_kind("USB I/O request", ServerErrorKind::Pdu)?;

                                let pending = request
                                    .expects_completion
                                    .then(|| device.register_pending(request.request_id));

                                // Reply before the write so the caller owns cancel-on-drop as early
                                // as possible. A CANCEL_REQUEST it enqueues in response lands in a
                                // later batch, so it cannot overtake this request on the wire.
                                if tx.send(pending).is_err() && request.expects_completion {
                                    trace!(dvc_id, "USB I/O request receiver dropped");
                                    device.forget_pending(request.request_id);
                                    processor.abandon_unsent(request);
                                    (Vec::new(), false)
                                } else {
                                    (vec![request.message], false)
                                }
                            }
                            UrbdrcDeviceServerMessage::Retract(reason) => {
                                let request = processor
                                    .retract_device(reason)
                                    .map_err_kind("retract USB device", ServerErrorKind::Pdu)?;
                                device.mark_retracting();
                                (vec![request], true)
                            }
                            UrbdrcDeviceServerMessage::CancelRequest(request_id) => {
                                if !device.is_pending(request_id) {
                                    trace!(dvc_id, request_id, "USB I/O request is no longer pending");
                                    continue;
                                }

                                let request = processor
                                    .cancel_request(request_id)
                                    .map_err_kind("cancel USB I/O request", ServerErrorKind::Pdu)?;

                                (vec![request], false)
                            }
                        };

                        let mut messages = dvc::encode_dvc_messages(dvc_id, dvc_msgs, ChannelFlags::SHOW_PROTOCOL)
                            .map_err(ServerError::encode)?;

                        if close_dev {
                            let close_message = self
                                .get_svc_processor::<dvc::DrdynvcServer>()
                                .and_then(|drdynvc| drdynvc.close_channel(dvc_id))
                                .ok_or_else(|| {
                                    ServerError::channel("URBDRC dynamic channel disappeared before close")
                                })?;
                            self.remove_usb_device(dvc_id);
                            messages.push(close_message);
                        }

                        self.write_dvc_messages(messages, writer, user_channel_id).await?;
                    }
                    UrbdrcServerMessage::DeviceClosed { dvc_id } => {
                        self.remove_usb_device(dvc_id);
                    }
                },
                #[cfg(feature = "egfx")]
                ServerEvent::Egfx(msg) => match msg {
                    EgfxServerMessage::SendMessages { messages, generation } => {
                        if self.egfx_output_is_current(generation) {
                            self.write_dvc_messages(messages, writer, user_channel_id).await?;
                        } else {
                            debug!(
                                generation,
                                count = messages.len(),
                                "Dropping EGFX output drained before a pipeline reset or close"
                            );
                        }
                    }
                },
                ServerEvent::AutoDetectRttRequest => {
                    // Auto-detect requests ride the MCS message channel
                    // ([MS-RDPBCGR] 2.2.14.3). With none negotiated (the client
                    // did not request it), there is nowhere to send them, and
                    // a client without RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT
                    // does not take them at all.
                    if self.client_supports_autodetect
                        && let (Some(ad), Some(message_channel_id)) = (self.autodetect.as_mut(), message_channel_id)
                    {
                        let now_ms = monotonic_now_ms();
                        ad.expire_stale_probes(now_ms, crate::autodetect::RTT_PROBE_MAX_AGE_MS);
                        let request = ad.send_rtt_request(now_ms);
                        let data = encode_autodetect_request(request, message_channel_id, user_channel_id)?;
                        writer
                            .write_all(&data)
                            .await
                            .map_err(|e| ServerError::io("write_all", e))?;

                        // No Network Characteristics Result here: [MS-RDPBCGR]
                        // 1.3.9 lists it among the main-connection messages of
                        // Connect-Time Auto-Detection only. During Continuous
                        // Auto-Detection it travels over sideband channels.

                        // Periodically measure bandwidth: Start on one tick, Stop several
                        // ticks later, with ordinary traffic in between counted by the
                        // client, then a Bandwidth Measure Results PDU in reply.
                        if let Some(pdu) = ad.build_bandwidth_measure() {
                            let data = encode_autodetect_request(pdu, message_channel_id, user_channel_id)?;
                            writer
                                .write_all(&data)
                                .await
                                .map_err(|e| ServerError::io("write_all", e))?;
                        }
                    }
                }
            }
        }

        Ok(RunState::Continue)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "private per-connection entry point; the parameters are the connection's negotiated identifiers"
    )]
    async fn client_loop<R, W>(
        &mut self,
        reader: &mut Framed<R>,
        writer: &mut Framed<W>,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        client_supports_heartbeat: bool,
        mut encoder: UpdateEncoder,
    ) -> ServerResult<RunState>
    where
        R: FramedRead,
        W: FramedWrite,
    {
        debug!("Starting client loop");
        let heartbeat = if client_supports_heartbeat {
            self.heartbeat
        } else {
            None
        };
        let mut display_updates = self.display.lock().await.updates().await?;
        let display_bandwidth = Arc::clone(&self.autodetect_bandwidth);
        let frame_ack_state = Arc::clone(&self.frame_ack_state);
        let frame_ack_limit = self.frame_ack_limit;
        let mut writer = SharedWriter::new(writer);
        let mut display_writer = writer.clone();
        let mut event_writer = writer.clone();
        let mut auto_reconnect_writer = writer.clone();
        let mut heartbeat_writer = writer.clone();
        let write_counter = writer.write_counter();
        let ev_receiver = Arc::clone(&self.ev_receiver);
        let client_fastpath_output = self.client_fastpath_output;
        let s = Rc::new(Mutex::new(self));

        let this = Rc::clone(&s);
        let dispatch_pdu = async move {
            loop {
                let (action, bytes) = reader.read_pdu().await.map_err(|e| ServerError::io("read pdu", e))?;
                // D8: per-PDU lock-acquisition + dispatch timing. The `this`
                // mutex is shared with dispatch_events; when an outbound
                // event batch is in flight, this lock wait is the latency
                // that a FrameAcknowledge sees before it reaches its
                // handler. Log when the dispatch itself or the lock wait
                // exceeds 50ms.
                let pdu_len = bytes.len();
                let lock_start = Instant::now();
                let mut this = this.lock().await;
                let lock_wait_ms = u64::try_from(lock_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                let dispatch_start = Instant::now();
                let result = this
                    .dispatch_pdu(
                        action,
                        bytes,
                        &mut writer,
                        io_channel_id,
                        user_channel_id,
                        message_channel_id,
                    )
                    .await?;
                let dispatch_ms = u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                if lock_wait_ms >= 50 {
                    tracing::warn!(
                        pdu_len,
                        lock_wait_ms,
                        dispatch_ms,
                        "dispatch_pdu delayed acquiring this.lock, contended with outbound batch (dispatch_events/dispatch_display)"
                    );
                } else if dispatch_ms >= 50 {
                    tracing::warn!(
                        pdu_len,
                        lock_wait_ms,
                        dispatch_ms,
                        "dispatch_pdu ran long after acquiring this.lock immediately, handler or runtime stall, not lock contention"
                    );
                } else {
                    tracing::debug!(pdu_len, lock_wait_ms, dispatch_ms, "dispatch_pdu");
                }

                match result {
                    RunState::Continue => continue,
                    state => break Ok(state),
                }
            }
        };

        let dispatch_display = async move {
            let mut buffer = vec![0u8; 4096];
            let mut budget = DisplayBudget::new(Arc::clone(&display_bandwidth));
            // Latched off after the first overdue ack: a client whose acks
            // don't track our frame ids (observed with mstsc on the legacy
            // path — the ack watermark never advanced) would otherwise stall
            // the display to one frame per FRAME_ACK_TIMEOUT forever.
            let mut frame_ack_pacing = frame_ack_limit > 0;

            loop {
                match display_updates.next_update().await {
                    Ok(Some(update)) => {
                        if frame_ack_pacing && matches!(update, DisplayUpdate::Bitmap(_)) {
                            // MS-RDPBCGR 2.2.2.3: the client presents frames
                            // at its own pace (maxUnackFrameCount) and acks
                            // each presented frame. Waiting here — instead of
                            // queueing the next grab — is what keeps live
                            // video latency bounded: a queued frame is stale
                            // the moment the client gets to it. Pointer and
                            // other small updates bypass the gate entirely.
                            let deadline = Instant::now() + FRAME_ACK_TIMEOUT;
                            while frame_ack_state.unacked() >= frame_ack_limit {
                                if Instant::now() >= deadline {
                                    warn!(
                                        unacked = frame_ack_state.unacked(),
                                        "frame ack overdue — disabling frame-ack pacing for this session"
                                    );
                                    frame_ack_pacing = false;
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(4)).await;
                            }
                        }
                        let frames_before = encoder.frame_counter();
                        match Self::dispatch_display_update(
                            update,
                            &mut display_writer,
                            user_channel_id,
                            io_channel_id,
                            client_fastpath_output,
                            &mut buffer,
                            encoder,
                            &mut budget,
                        )
                        .await?
                        {
                            (RunState::Continue, enc) => {
                                // A frame marker group went out when the
                                // encoder's id counter advanced — publish it
                                // as the pacing "sent" watermark.
                                if enc.frame_counter() != frames_before {
                                    frame_ack_state.sent.store(enc.frame_counter(), Ordering::Relaxed);
                                }
                                encoder = enc;
                                continue;
                            }
                            (state, _) => {
                                break Ok(state);
                            }
                        }
                    }
                    Ok(None) => {
                        break Ok(RunState::Disconnect);
                    }
                    Err(error) => {
                        warn!(error = format!("{error:#}"), "next_updated failed");
                    }
                }
            }
        };

        let this = Rc::clone(&s);
        let mut ev_receiver = ev_receiver.lock().await;
        let dispatch_events = async move {
            let mut events = Vec::with_capacity(100);
            loop {
                let nevents = ev_receiver.recv_many(&mut events, 100).await;
                if nevents == 0 {
                    debug!("No sever events.. stopping");
                    break Ok(RunState::Disconnect);
                }
                while let Ok(ev) = ev_receiver.try_recv() {
                    events.push(ev);
                }

                // D7: per-batch dispatch_events timing. The events Vec can
                // grow up to 100+ entries; dispatch_server_events holds the
                // `this` mutex AND the SharedWriter mutex for the full
                // batch. Log batch size + total dispatch time so operators
                // can see when an event batch ties up both locks.
                let batch_size = events.len();
                let lock_start = Instant::now();
                let mut this = this.lock().await;
                let lock_wait_ms = u64::try_from(lock_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                let dispatch_start = Instant::now();
                let result = this
                    .dispatch_server_events(
                        &mut events,
                        &mut event_writer,
                        io_channel_id,
                        user_channel_id,
                        message_channel_id,
                    )
                    .await?;
                let dispatch_ms = u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                if lock_wait_ms >= 50 || dispatch_ms >= 100 {
                    tracing::warn!(
                        batch_size,
                        lock_wait_ms,
                        dispatch_ms,
                        "dispatch_events batch stalled, long write or lock contention"
                    );
                } else if batch_size > 1 {
                    tracing::debug!(batch_size, lock_wait_ms, dispatch_ms, "dispatch_events batch");
                }

                match result {
                    RunState::Continue => continue,
                    state => break Ok(state),
                }
            }
        };

        let this = Rc::clone(&s);
        let refresh_auto_reconnect_cookie = async move {
            let mut interval = tokio::time::interval(AUTO_RECONNECT_COOKIE_UPDATE_INTERVAL);
            interval.tick().await;

            loop {
                interval.tick().await;
                let mut this = this.lock().await;
                this.rotate_auto_reconnect_cookie(&mut auto_reconnect_writer, io_channel_id, user_channel_id)
                    .await?;
            }
        };

        let send_heartbeats = async move {
            let (Some(config), Some(message_channel_id)) = (heartbeat, message_channel_id) else {
                return core::future::pending::<ServerResult<RunState>>().await;
            };
            // 2.2.16.1: `period` is in seconds. A zero period is meaningless
            // (and would panic tokio's interval), so it is bumped to one.
            let period = Duration::from_secs(u64::from(config.period_secs.max(1)));
            let mut interval = tokio::time::interval(period);
            // A stalled write (TCP back-pressure) can hold this future past
            // several tick deadlines; Burst (the default) would then fire the
            // missed ticks back-to-back and emit a run of consecutive
            // heartbeats on an otherwise idle link. Skip fires at the next
            // period boundary instead.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // first tick completes immediately; real waits start below

            let mut writes_at_last_tick = write_counter.load(Ordering::Relaxed);
            loop {
                interval.tick().await;
                let writes_now = write_counter.load(Ordering::Relaxed);
                if writes_now != writes_at_last_tick {
                    // 2.2.16.1: heartbeats SHOULD only be sent when no other
                    // PDU went out in the interval; ordinary traffic doubles
                    // as the liveness signal.
                    writes_at_last_tick = writes_now;
                    continue;
                }
                let data = encode_heartbeat(&config, message_channel_id, user_channel_id)?;
                heartbeat_writer
                    .write_all(&data)
                    .await
                    .map_err(|e| ServerError::io("send heartbeat", e))?;
                // Re-read so the heartbeat's own write does not read as
                // foreign traffic on the next tick.
                writes_at_last_tick = write_counter.load(Ordering::Relaxed);
            }
        };

        let state = tokio::select!(
            state = dispatch_pdu => state,
            state = dispatch_display => state,
            state = dispatch_events => state,
            state = refresh_auto_reconnect_cookie => state,
            state = send_heartbeats => state,
        );

        debug!("End of client loop: {state:?}");
        state
    }

    async fn client_accepted<R, W>(
        &mut self,
        reader: &mut Framed<R>,
        writer: &mut Framed<W>,
        result: AcceptorResult,
    ) -> ServerResult<RunState>
    where
        R: FramedRead,
        W: FramedWrite,
    {
        debug!("Client accepted");

        // MS-RDPBCGR 3.3.5.7.1: whether this client takes the Set Error Info
        // PDU that announces a refusal below. `self.client_supports_errinfo`
        // is set only further down, and until then describes the previous
        // connection.
        let client_supports_errinfo = result
            .client_early_capability_flags
            .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU);

        // MS-RDPBCGR 3.3.5.3.11: "If logon with the cookie fails, the
        // credentials supplied in the Client Info PDU SHOULD be used" (5.5,
        // step 6). A cookie that does not verify makes this an ordinary logon,
        // with every check an ordinary logon gets.
        let is_auto_reconnect = match result.auto_reconnect.as_ref() {
            Some(reconnect) if self.verify_auto_reconnect_cookie(reconnect) => {
                debug!("Auto-reconnect cookie validation accepted");
                true
            }
            Some(_) => {
                warn!("Auto-reconnect cookie validation rejected; logging on with the Client Info credentials");
                false
            }
            None => false,
        };

        // Validate credentials if a validator is configured. The validator runs here, in the
        // async server layer, rather than in the sans-I/O acceptor, because real validators
        // (PAM/LDAP/DB) are I/O-bound. On rejection, deny with a ServerSetErrorInfoPdu before
        // closing, matching the acceptor's exact-match denial path.
        if !is_auto_reconnect && let Some(validator) = self.credential_validator.clone() {
            if let Some(creds) = &result.credentials {
                match validator.validate(creds).await {
                    Ok(CredentialDecision::Accept) => {
                        debug!("Credential validation accepted");
                    }
                    Ok(CredentialDecision::Reject) => {
                        warn!("Credential validation rejected");
                        send_access_denied(
                            result.io_channel_id,
                            result.user_channel_id,
                            client_supports_errinfo,
                            writer,
                        )
                        .await?;
                        return Err(ServerError::reason("credential validation", "rejected by validator"));
                    }
                    Err(e) => {
                        error!(error = %e, "Credential validator backend error");
                        send_access_denied(
                            result.io_channel_id,
                            result.user_channel_id,
                            client_supports_errinfo,
                            writer,
                        )
                        .await?;
                        return Err(ServerError::custom("credential validation", e));
                    }
                }
            } else {
                debug!("Skipping credential validation (no credentials in AcceptorResult)");
            }
        }

        if !result.reactivation
            && let Some(ref mut handler) = self.connection_handler
        {
            handler.on_connection_info(&ConnectionInfo {
                keyboard_layout: result.keyboard_layout,
                keyboard_type: result.keyboard_type,
                ime_file_name: result.ime_file_name.clone(),
                desktop_size: result.desktop_size,
                client_cluster: result.client_cluster.clone(),
            });
        }

        if !result.input_events.is_empty() {
            debug!("Handling input event backlog from acceptor sequence");
            self.handle_input_backlog(
                writer,
                result.io_channel_id,
                result.user_channel_id,
                result.message_channel_id,
                result.input_events,
            )
            .await?;
        }

        self.udp_tunnel_tx = None;
        self.multitransport_confirmed = false;
        self.multitransport_request_id = None;
        self.pending_soft_sync = None;
        self.static_channels = result.static_channels;
        if !result.reactivation {
            for (_channel_key, channel, channel_id) in self.static_channels.iter_by_key_mut() {
                debug!(?channel, ?channel_id, "Start");
                let Some(channel_id) = channel_id else {
                    continue;
                };
                let svc_responses = channel.start().map_err_kind("svc start", ServerErrorKind::Pdu)?;
                let response = server_encode_svc_messages(svc_responses, channel_id, result.user_channel_id)
                    .map_err(ServerError::encode)?;
                writer
                    .write_all(&response)
                    .await
                    .map_err(|e| ServerError::io("write svc response", e))?;
            }
        }

        let mut update_codecs = UpdateEncoderCodecs::new();
        let mut surface_flags = CmdFlags::empty();
        let mut pointer_cache_size: u16 = 0;
        // Absence means the client did not send a Large Pointer Capability Set at all,
        // which per MS-RDPBCGR 2.2.7.2.7 leaves the pointer size ceiling at 32x32 (the
        // base Color/New Pointer Update limit with no large-pointer flags set).
        let mut large_pointer_flags = LargePointerSupportFlags::empty();
        for c in result.capabilities {
            match c {
                CapabilitySet::General(c) => {
                    // MS-RDPBCGR 2.2.7.1.1: a client without
                    // FASTPATH_OUTPUT_SUPPORTED receives slow-path output
                    // (2.2.9.1.1) — do not fail the session over it.
                    self.client_fastpath_output = c.extra_flags.contains(GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED);
                    if !self.client_fastpath_output {
                        warn!("client does not support fast-path output; falling back to slow-path updates");
                    }
                }
                CapabilitySet::VirtualChannel(c) => {
                    // MS-RDPBCGR 2.2.7.1.10: VCChunkSize must be in
                    // [16256]. The client→server value is advisory (the pdu
                    // crate deliberately leaves verification to the caller),
                    // and our SVC sender always chunks at the 1600 minimum,
                    // which is legal under any negotiated size — so validate
                    // and warn, never fail the session over it.
                    if let Some(chunk) = c.chunk_size
                        && !(1600..=16256).contains(&chunk)
                    {
                        warn!(chunk_size = chunk, "client VCChunkSize outside 1600..=16256 (2.2.7.1.10); ignoring");
                    }
                }
                CapabilitySet::Bitmap(b) => {
                    if !b.desktop_resize_flag {
                        debug!("Desktop resize is not supported by the client");
                        continue;
                    }

                    let client_size = DesktopSize {
                        width: b.desktop_width,
                        height: b.desktop_height,
                    };
                    let display_size = self.display.lock().await.request_initial_size(client_size).await;

                    // It's problematic when the client didn't resize, as we send bitmap updates that don't fit.
                    // The client will likely drop the connection.
                    if client_size.width < display_size.width || client_size.height < display_size.height {
                        // TODO: we may have different behaviour instead, such as clipping or scaling?
                        warn!(
                            "Client size doesn't fit the server size: {:?} < {:?}",
                            client_size, display_size
                        );
                    }
                }
                CapabilitySet::SurfaceCommands(c) => {
                    surface_flags = c.flags;
                }
                CapabilitySet::BitmapCodecs(BitmapCodecs(codecs)) => {
                    for codec in codecs {
                        match codec.property {
                            // FIXME: The encoder operates in image mode only.
                            //
                            // See [MS-RDPRFX] 3.1.1.1 "State Machine" for
                            // implementation of the video mode. which allows to
                            // skip sending Header for each image.
                            //
                            // We should distinguish parameters for both modes.
                            CodecProperty::RemoteFx(rdp::capability_sets::RemoteFxContainer::ClientContainer(c))
                                if self.opts.has_remote_fx() =>
                            {
                                let offered = c.caps_data.0.0.iter().map(|caps| caps.entropy_bits);
                                let preferred = self.opts.remotefx_entropy_coder;
                                if let Some(entropy_bits) = pick_remotefx_entropy_coder(preferred, offered) {
                                    update_codecs.set_remotefx(Some((entropy_bits, codec.id)));
                                    update_codecs.set_remotefx_quant(self.opts.remotefx_quant.clone());
                                }
                            }
                            CodecProperty::ImageRemoteFx(rdp::capability_sets::RemoteFxContainer::ClientContainer(
                                c,
                            )) if self.opts.has_image_remote_fx() => {
                                let offered = c.caps_data.0.0.iter().map(|caps| caps.entropy_bits);
                                let preferred = self.opts.remotefx_entropy_coder;
                                if let Some(entropy_bits) = pick_remotefx_entropy_coder(preferred, offered) {
                                    update_codecs.set_remotefx(Some((entropy_bits, codec.id)));
                                    update_codecs.set_remotefx_quant(self.opts.remotefx_quant.clone());
                                }
                            }
                            #[cfg(feature = "nscodec")]
                            CodecProperty::NsCodec(client_ns) if self.opts.has_nscodec() => {
                                // MS-RDPNSC 2.2.1: the client's
                                // color_loss_level is the MAXIMUM loss it can
                                // decode (a ceiling, not a target), and each
                                // frame's header carries the level actually
                                // used — the mechanism behind dynamic
                                // fidelity. Encoding every frame at the
                                // client's ceiling (our old behavior) shifts
                                // chroma by 2^CLL and visibly washes out
                                // colors and text edges. Encode at the
                                // minimum loss instead: always within the
                                // client's advertised maximum.
                                debug!(
                                    client_max_cll = client_ns.color_loss_level,
                                    encode_cll = 1,
                                    "NSCodec selected at minimal color loss"
                                );
                                update_codecs.set_nscodec(Some((codec.id, 1)));
                            }
                            CodecProperty::NsCodec(_) => (),
                            #[cfg(feature = "qoi")]
                            CodecProperty::Qoi if self.opts.has_qoi() => {
                                update_codecs.set_qoi(Some(codec.id));
                            }
                            #[cfg(feature = "qoiz")]
                            CodecProperty::QoiZ if self.opts.has_qoiz() => {
                                update_codecs.set_qoiz(Some(codec.id));
                            }
                            _ => (),
                        }
                    }
                }
                CapabilitySet::Pointer(p) => {
                    // MS-RDPBCGR 2.2.7.1.5: pointerCacheSize is the client's advertised cache
                    // size for the New Pointer Update specifically (colorPointerCacheSize is
                    // the separate, always-supported Color Pointer Update cache). A zero or
                    // absent pointerCacheSize means the client did not advertise New Pointer
                    // Update support at all, so `UpdateEncoder` must not emit RGBAPointer, and
                    // must not reference a cache slot via CachedPointer either, since nothing
                    // else in this crate populates that cache via the Color Pointer Update.
                    pointer_cache_size = p.pointer_cache_size;
                    self.negotiated_pointer_cache
                        .store(p.pointer_cache_size, Ordering::Relaxed);
                }
                CapabilitySet::LargePointer(lp) => {
                    // MS-RDPBCGR 2.2.7.2.7: LARGE_POINTER_FLAG_96x96 raises the Color/New
                    // Pointer Update ceiling from 32x32 to 96x96; LARGE_POINTER_FLAG_384x384
                    // additionally unlocks the dedicated Fast-Path Large Pointer Update, up to
                    // 384x384. `UpdateEncoder` uses these flags to decide which pointer
                    // updates it can send at all, and at what size.
                    large_pointer_flags = lp.flags;
                }
                CapabilitySet::FrameAcknowledge(caps) => {
                    // MS-RDPBCGR 2.2.7.2.11 + 2.2.2.3: the client acks each
                    // presented frame (Frame Acknowledge PDU) and tolerates at
                    // most this many unacknowledged ones. That ack stream is
                    // the pacing signal the display loop uses to skip frames
                    // instead of queueing them into growing latency. Zero or a
                    // missing capability set disables pacing — the client will
                    // never ack, and waiting would deadlock the display.
                    self.frame_ack_limit = caps.max_unacknowledged_frame_count;
                    if self.frame_ack_limit > 0 {
                        debug!(limit = self.frame_ack_limit, "frame-acknowledge pacing enabled");
                    }
                }
                _ => {}
            }
        }

        // MS-RDPBCGR 2.2.9.1.1: slow-path output has no surface commands
        // (2.2.9.1.2.1.10) and no Large Pointer Update (2.2.9.1.2.1.11); both
        // exist only as fast-path updates. Each update also has to fit one
        // PDU. So a slow-path client gets Bitmap Updates in small tiles, and
        // pointers of at most 96x96.
        let max_request_size = if self.client_fastpath_output {
            self.opts.max_request_size
        } else {
            surface_flags = CmdFlags::empty();
            large_pointer_flags.remove(LargePointerSupportFlags::UP_TO_384X384_PIXELS);
            self.opts.max_request_size.min(SLOWPATH_TILE_BYTES)
        };

        let desktop_size = self.display.lock().await.size().await;
        let encoder = UpdateEncoder::new(
            desktop_size,
            surface_flags,
            update_codecs,
            max_request_size,
            pointer_cache_size,
            large_pointer_flags,
        )?;

        self.send_next_auto_reconnect_cookie(writer, result.io_channel_id, result.user_channel_id)
            .await?;

        // Ask UDP-capable clients to bootstrap a sideband RDP-UDP transport
        // (MS-RDPEMT). The embedder owns the UDP listener that completes the
        // handshake; here we only send the request carrying the embedder's
        // request_id + security_cookie.
        if let Some(mt) = self.opts.multitransport.clone() {
            if client_can_use_the_tunnel(result.multitransport_flags) {
                // MS-RDPBCGR 2.2.15.1: the Initiate Multitransport Request
                // PDU MUST only be sent over the MCS message channel — so a
                // session without one (client never requested it) cannot
                // bootstrap UDP and stays TCP-only.
                if let Some(message_channel_id) = result.message_channel_id {
                    let pdu = encode_multitransport_request(&mt, message_channel_id, result.user_channel_id)?;
                    writer
                        .write_all(&pdu)
                        .await
                        .map_err(|e| ServerError::io("write multitransport request", e))?;
                    self.multitransport_request_id = Some(mt.request_id);
                    info!(request_id = mt.request_id, "Sent Initiate Multitransport Request (UDP FECR)");
                } else {
                    warn!("No MCS message channel; cannot send Initiate Multitransport Request (staying TCP-only)");
                }
            } else {
                debug!(
                    client_flags = ?result.multitransport_flags,
                    "Client does not announce reliable UDP with Soft-Sync; staying TCP-only"
                );
            }
        }

        // MS-RDPBCGR 3.3.5.7.1: the Set Error Info PDU must only be sent to
        // clients that announced RNS_UD_CS_SUPPORT_ERRINFO_PDU.
        self.client_supports_errinfo = result
            .client_early_capability_flags
            .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU);
        self.client_supports_autodetect = result
            .client_early_capability_flags
            .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_NET_CHAR_AUTODETECT);

        // MS-RDPEGFX 1.5: a client implementing the graphics pipeline MUST
        // advertise RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL here. This is the
        // only signal that exists before the EGFX dynamic channel is created,
        // and it is the one a display backend needs: a client that never
        // advertised it will refuse the channel (NO_LISTENER), and nothing
        // must sit waiting for a readiness that cannot arrive. Reported
        // before `client_loop` opens the display updates stream, so the
        // backend has it in hand before its first frame.
        #[cfg(feature = "egfx")]
        if let Some(gfx_factory) = self.gfx_factory.as_deref() {
            let supported = result
                .client_early_capability_flags
                .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_DYN_VC_GFX_PROTOCOL);
            if !supported {
                debug!("client did not advertise RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL; EGFX will not be awaited");
            }
            gfx_factory.on_client_graphics_support(supported);
        }

        let state = self
            .client_loop(
                reader,
                writer,
                result.io_channel_id,
                result.user_channel_id,
                result.message_channel_id,
                result
                    .client_early_capability_flags
                    .contains(ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_HEART_BEAT_PDU),
                encoder,
            )
            .await?;

        Ok(state)
    }

    async fn handle_input_backlog(
        &mut self,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        frames: Vec<Vec<u8>>,
    ) -> ServerResult<()> {
        for frame in frames {
            match Action::from_fp_output_header(frame[0]) {
                Ok(Action::FastPath) => {
                    let input = decode(&frame).map_err(ServerError::decode)?;
                    self.handle_fastpath(input).await;
                }

                Ok(Action::X224) => {
                    let _ = self
                        .handle_x224(writer, io_channel_id, user_channel_id, message_channel_id, &frame)
                        .await;
                }

                // the frame here is always valid, because otherwise it would
                // have failed during the acceptor loop
                Err(_) => unreachable!(),
            }
        }

        Ok(())
    }

    async fn handle_fastpath(&mut self, input: FastPathInput) {
        for event in input.input_events().iter().copied() {
            let mut handler = self.handler.lock().await;
            match event {
                FastPathInputEvent::KeyboardEvent(flags, key) => {
                    handler.keyboard((key, flags).into());
                }

                FastPathInputEvent::UnicodeKeyboardEvent(flags, key) => {
                    handler.keyboard((key, flags).into());
                }

                FastPathInputEvent::SyncEvent(flags) => {
                    handler.keyboard(flags.into());
                }

                FastPathInputEvent::MouseEvent(mouse) => {
                    handler.mouse(mouse.into());
                }

                FastPathInputEvent::MouseEventEx(mouse) => {
                    handler.mouse(mouse.into());
                }

                FastPathInputEvent::MouseEventRel(mouse) => {
                    handler.mouse(mouse.into());
                }

                FastPathInputEvent::QoeEvent(quality) => {
                    warn!("Received QoE: {}", quality);
                }
            }
        }
    }

    async fn handle_io_channel_data(&mut self, data: SendDataRequest<'_>) -> ServerResult<bool> {
        // Defensive fallback: per MS-RDPBCGR 2.2.15.2 the client's Initiate
        // Multitransport Response arrives on the MCS message channel (handled
        // in `handle_message_channel_data`), but tolerate non-conforming
        // clients that echo it back on the I/O channel. Multitransport PDUs
        // use a BasicSecurityHeader (flagsHi == 0) where every other
        // I/O-channel PDU has a ShareControlHeader (pduType in those bytes,
        // always non-zero), so discriminate first. The response just reports
        // the client-side bootstrap outcome; the tunnel itself is validated
        // over UDP against the security cookie.
        {
            let ud: &[u8] = data.user_data.as_ref();
            if ud.len() >= rdp::headers::BASIC_SECURITY_HEADER_SIZE as usize {
                let flags_raw = u16::from_le_bytes([ud[0], ud[1]]);
                let flags_hi = u16::from_le_bytes([ud[2], ud[3]]);
                if flags_hi == 0 {
                    if let Some(flags) = rdp::headers::BasicSecurityHeaderFlags::from_bits(flags_raw) {
                        if flags.contains(rdp::headers::BasicSecurityHeaderFlags::TRANSPORT_RSP) {
                            match decode::<rdp::multitransport::MultitransportResponsePdu>(ud) {
                                Ok(pdu) => {
                                    info!(
                                        request_id = pdu.request_id,
                                        hr_response = format!("{:#010X}", pdu.hr_response),
                                        "Received Multitransport Response"
                                    );
                                    self.on_multitransport_response(pdu.request_id, pdu.hr_response);
                                    return Ok(false);
                                }
                                Err(e) => {
                                    warn!(error = format!("{e:#}"), "Malformed Multitransport Response; ignoring");
                                    return Ok(false);
                                }
                            }
                        }
                    }
                }
            }
        }

        let control: rdp::headers::ShareControlHeader = decode(data.user_data.as_ref()).map_err(ServerError::decode)?;

        match control.share_control_pdu {
            ShareControlPdu::Data(header) => match header.share_data_pdu {
                rdp::headers::ShareDataPdu::Input(pdu) => {
                    self.handle_input_event(pdu).await;
                }

                rdp::headers::ShareDataPdu::ShutdownRequest => {
                    // MS-RDPBCGR 2.2.2.1/3.3.5.4.1: the client asked the
                    // server to shut down; comply (end the session) and
                    // remember it was client-initiated so the teardown does
                    // not send a redundant Ultimatum back.
                    debug!("client Shutdown Request — ending the session");
                    self.client_initiated_disconnect = true;
                    return Ok(true);
                }

                // Client requests the server stop or resume sending display
                // updates. mstsc sends `desktop_rect: None` on minimize and
                // `desktop_rect: Some(rect)` on refocus. Without honoring
                // this, the server keeps streaming high-bitrate EGFX/H.264
                // frames into a minimized client; on refocus the client
                // must chew through the accumulated backlog before it can
                // present the current frame, locking up its input dispatch
                // for seconds. Flagging the shared `display_suppressed`
                // lets the display backend skip frame emission while it's
                // set.
                rdp::headers::ShareDataPdu::SuppressOutput(pdu) => {
                    let suppress = pdu.desktop_rect.is_none();
                    let was_suppressed = self.display_suppressed.swap(suppress, Ordering::Relaxed);
                    debug!(suppress, "client suppress-output state changed");
                    // MS-RDPBCGR 3.3.5.11.2: output resumes. The client still
                    // shows what it had when output stopped, so the desktop
                    // rectangle it names is drawn again rather than only
                    // what changes from now on.
                    if was_suppressed && let Some(desktop) = pdu.desktop_rect.as_ref() {
                        self.request_refresh(core::slice::from_ref(desktop)).await;
                    }
                }

                // Client asks the server to redraw a rectangle — typical on
                // refocus after a minimize. Clear the suppress flag so the
                // backend resumes emission and treat this as "client wants
                // updates again." (The flag would also be cleared by the
                // `SuppressOutput { Some(rect) }` that usually accompanies
                // this; clearing here is belt-and-braces against clients
                // that send only one of the two.)
                rdp::headers::ShareDataPdu::RefreshRectangle(pdu) => {
                    if self.display_suppressed.swap(false, Ordering::Relaxed) {
                        debug!("client RefreshRectangle cleared suppress-output state");
                    }
                    // MS-RDPBCGR 3.3.5.11.1: "the server MUST send updated
                    // graphics data for the region specified by the PDU".
                    self.request_refresh(&pdu.areas_to_refresh).await;
                }

                // MS-RDPBCGR 2.2.2.3: the client finished presenting the
                // frame with this id. Ids are monotonic, so the ack releases
                // every frame up to and including it — advance the watermark
                // the display loop paces on (never backwards: a delayed ack
                // for an old frame must not un-release newer ones).
                rdp::headers::ShareDataPdu::FrameAcknowledge(pdu) => {
                    let acked_up_to = pdu.frame_id.wrapping_add(1);
                    let prev = self.frame_ack_state.acked.fetch_max(acked_up_to, Ordering::Relaxed);
                    trace!(frame_id = pdu.frame_id, prev_acked = prev, "client acknowledged frame");
                }

                unexpected => {
                    warn!(?unexpected, "Unexpected share data pdu");
                }
            },

            unexpected => {
                warn!(?unexpected, "Unexpected share control");
            }
        }

        Ok(false)
    }

    /// Hand the areas the client wants drawn again to the display handler.
    async fn request_refresh(&self, areas: &[InclusiveRectangle]) {
        if areas.is_empty() {
            return;
        }
        debug!(?areas, "client requested a refresh");
        self.display.lock().await.request_refresh(areas);
    }

    fn handle_message_channel_data(&mut self, data: SendDataRequest<'_>) {
        // The MCS message channel carries PDUs framed by a Basic Security
        // Header rather than a Share Control header. Discriminate on the
        // flag bits: multitransport responses (SEC_TRANSPORT_RSP,
        // MS-RDPBCGR 2.2.15.2) and auto-detect responses
        // (SEC_AUTODETECT_RSP, 2.2.14.4).
        let ud: &[u8] = data.user_data.as_ref();
        if ud.len() >= rdp::headers::BASIC_SECURITY_HEADER_SIZE as usize {
            let flags_raw = u16::from_le_bytes([ud[0], ud[1]]);
            if let Some(flags) = rdp::headers::BasicSecurityHeaderFlags::from_bits(flags_raw) {
                if flags.contains(rdp::headers::BasicSecurityHeaderFlags::TRANSPORT_RSP) {
                    match decode::<rdp::multitransport::MultitransportResponsePdu>(ud) {
                        Ok(pdu) => {
                            info!(
                                request_id = pdu.request_id,
                                hr_response = format!("{:#010X}", pdu.hr_response),
                                "Received Multitransport Response"
                            );
                            self.on_multitransport_response(pdu.request_id, pdu.hr_response);
                        }
                        Err(e) => {
                            warn!(error = format!("{e:#}"), "Malformed Multitransport Response; ignoring");
                        }
                    }
                    return;
                }
            }
        }
        match decode::<rdp::autodetect::AutoDetectRspPdu>(data.user_data.as_ref()) {
            Ok(pdu) => {
                if let Some(ref mut ad) = self.autodetect {
                    match ad.handle_response(&pdu.response, monotonic_now_ms()) {
                        AutoDetectOutcome::Rtt(rtt_ms) => {
                            self.autodetect_rtt.store(rtt_ms, Ordering::Relaxed);
                            // A matched RTT sample always updates the session-lifetime low in the
                            // same call (see `handle_response`'s RttResponse arm), so it is available
                            // unconditionally here, not just on a new low.
                            let baseline_rtt_ms = ad
                                .baseline_rtt_ms()
                                .expect("handle_response just recorded a sample above");
                            self.autodetect_baseline_rtt.store(baseline_rtt_ms, Ordering::Relaxed);
                            debug!(
                                rtt_ms,
                                baseline_rtt_ms,
                                seq = pdu.response.sequence_number(),
                                "RTT measured"
                            );
                        }
                        AutoDetectOutcome::Bandwidth(Some(bandwidth_kbps)) => {
                            self.autodetect_bandwidth.store(bandwidth_kbps, Ordering::Relaxed);
                            debug!(
                                bandwidth_kbps,
                                seq = pdu.response.sequence_number(),
                                "Bandwidth measured"
                            );
                        }
                        AutoDetectOutcome::Bandwidth(None) => {
                            // Unusable results keep the previous figure (see
                            // `handle_response`), so `None` here means no usable
                            // figure was ever measured; mirror that in the handle.
                            self.autodetect_bandwidth.store(u32::MAX, Ordering::Relaxed);
                            trace!(
                                seq = pdu.response.sequence_number(),
                                "Bandwidth measurement completed without a usable figure"
                            );
                        }
                        AutoDetectOutcome::Unmatched => {
                            trace!(seq = pdu.response.sequence_number(), "Unmatched auto-detect response");
                        }
                    }
                }
            }
            Err(error) => {
                warn!(error = format!("{error:#}"), "Unhandled MCS message channel PDU");
            }
        }
    }

    async fn handle_x224(
        &mut self,
        writer: &mut impl FramedWrite,
        io_channel_id: u16,
        user_channel_id: u16,
        message_channel_id: Option<u16>,
        frame: &[u8],
    ) -> ServerResult<bool> {
        let message = decode::<X224<mcs::McsMessage<'_>>>(frame).map_err(ServerError::decode)?;
        match message.0 {
            mcs::McsMessage::SendDataRequest(data) => {
                debug!(
                    initiator_id = data.initiator_id,
                    channel_id = data.channel_id,
                    user_data_len = data.user_data.len(),
                    "McsMessage::SendDataRequest"
                );
                if data.channel_id == io_channel_id {
                    let result = self.handle_io_channel_data(data).await;
                    self.resume_soft_sync(writer, user_channel_id).await?;
                    return result;
                }

                if message_channel_id == Some(data.channel_id) {
                    self.handle_message_channel_data(data);
                    self.resume_soft_sync(writer, user_channel_id).await?;
                    return Ok(false);
                }

                if let Some(svc) = self.static_channels.get_by_channel_id_mut(data.channel_id) {
                    let response_pdus = svc
                        .process(&data.user_data)
                        .map_err_kind("svc process", ServerErrorKind::Pdu)?;
                    let is_drdynvc = self
                        .get_channel_id_by_type::<dvc::DrdynvcServer>()
                        .is_some_and(|id| data.channel_id == id);
                    if is_drdynvc {
                        // After Soft-Sync, DVC responses must follow the
                        // client to the UDP tunnel, not the TCP channel.
                        self.write_dvc_messages(response_pdus, writer, user_channel_id).await?;
                        // A channel the client just confirmed may be the one
                        // a waiting Soft-Sync needs.
                        self.resume_soft_sync(writer, user_channel_id).await?;
                    } else {
                        let response = server_encode_svc_messages(response_pdus, data.channel_id, user_channel_id)
                            .map_err(ServerError::encode)?;
                        writer
                            .write_all(&response)
                            .await
                            .map_err(|e| ServerError::io("write svc response", e))?;
                    }
                } else {
                    warn!(channel_id = data.channel_id, "Unexpected channel received: ID",);
                }
            }

            mcs::McsMessage::DisconnectProviderUltimatum(disconnect) => {
                if disconnect.reason == mcs::DisconnectReason::UserRequested {
                    self.client_initiated_disconnect = true;
                    return Ok(true);
                }
                warn!(reason = ?disconnect.reason, "client Disconnect Provider Ultimatum with a non-user-requested reason");
            }

            _ => {
                warn!(name = ironrdp_core::name(&message), "Unexpected mcs message");
            }
        }

        Ok(false)
    }

    async fn handle_input_event(&mut self, input: InputEventPdu) {
        for event in input.0 {
            let mut handler = self.handler.lock().await;
            match event {
                ironrdp_pdu::input::InputEvent::ScanCode(key) => {
                    handler.keyboard((key.key_code, key.flags).into());
                }

                ironrdp_pdu::input::InputEvent::Unicode(key) => {
                    handler.keyboard((key.unicode_code, key.flags).into());
                }

                ironrdp_pdu::input::InputEvent::Sync(sync) => {
                    handler.keyboard(sync.flags.into());
                }

                ironrdp_pdu::input::InputEvent::Mouse(mouse) => {
                    handler.mouse(mouse.into());
                }

                ironrdp_pdu::input::InputEvent::MouseX(mouse) => {
                    handler.mouse(mouse.into());
                }

                ironrdp_pdu::input::InputEvent::MouseRel(mouse) => {
                    handler.mouse(mouse.into());
                }

                ironrdp_pdu::input::InputEvent::Unused(_) => {}
            }
        }
    }

    async fn accept_finalize<S>(
        &mut self,
        mut framed: TokioFramed<S>,
        mut acceptor: Acceptor,
    ) -> ServerResult<TokioFramed<S>>
    where
        S: AsyncRead + AsyncWrite + Sync + Send + Unpin,
    {
        loop {
            // Bounded: see `FINALIZE_TIMEOUT`. The bound belongs on THIS call
            // and not on `accept_finalize` itself or its callers — the loop
            // below also runs `client_accepted`, which drives the entire live
            // session, so a timeout hoisted any higher would cap session
            // length. Applying it per pass also gives a
            // deactivation-reactivation its own budget rather than sharing one
            // with the initial handshake.
            let finalize = ironrdp_acceptor::accept_finalize(framed, &mut acceptor);
            let (new_framed, result) = match tokio::time::timeout(FINALIZE_TIMEOUT, finalize).await {
                Ok(res) => res.map_err_kind("failed to accept client during finalize", ServerErrorKind::Connector)?,
                Err(_) => {
                    warn!(
                        timeout = ?FINALIZE_TIMEOUT,
                        "Client stopped responding during the finalize handshake, dropping the connection"
                    );
                    return Err(ServerError::io(
                        "timed out waiting for the client during finalize",
                        std::io::Error::from(std::io::ErrorKind::TimedOut),
                    ));
                }
            };

            let (mut reader, mut writer) = split_tokio_framed(new_framed);

            match self.client_accepted(&mut reader, &mut writer, result).await? {
                RunState::Continue => {
                    unreachable!();
                }
                RunState::DeactivationReactivation { desktop_size } => {
                    // No description of such behavior was found in the
                    // specification, but apparently, we must keep the channel
                    // state as they were during reactivation. This fixes
                    // various state issues during client resize.
                    acceptor = Acceptor::new_deactivation_reactivation(
                        acceptor,
                        core::mem::take(&mut self.static_channels),
                        desktop_size,
                    )
                    .map_err_kind("deactivation-reactivation acceptor", ServerErrorKind::Connector)?;
                    framed = unsplit_tokio_framed(reader, writer);
                    continue;
                }
                RunState::Disconnect => {
                    // MS-RDPBCGR 1.3.1.4/3.3.5.6: a server-initiated
                    // teardown ends with an MCS Disconnect Provider
                    // Ultimatum, so the client does not read the drop as a
                    // network failure and auto-reconnect. Best-effort: a
                    // dead socket just fails the write.
                    if !self.client_initiated_disconnect {
                        let ultimatum =
                            mcs::DisconnectProviderUltimatum::from_reason(mcs::DisconnectReason::ProviderInitiated);
                        match ironrdp_core::encode_vec(&X224(mcs::McsMessage::DisconnectProviderUltimatum(ultimatum))) {
                            Ok(bytes) => {
                                if let Err(error) = writer.write_all(&bytes).await {
                                    debug!(%error, "could not send Disconnect Provider Ultimatum; closing anyway");
                                }
                            }
                            Err(error) => {
                                warn!(%error, "could not encode Disconnect Provider Ultimatum; closing anyway");
                            }
                        }
                    }
                    let final_framed = unsplit_tokio_framed(reader, writer);
                    return Ok(final_framed);
                }
            }
        }
    }

    pub fn set_credentials(&mut self, creds: Option<Credentials>) {
        debug!(?creds, "Changing credentials");
        self.creds = creds
    }
}

#[cfg(test)]
mod autodetect_tests {
    use ironrdp_pdu::rdp::autodetect::{AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse};
    use tokio::io::AsyncReadExt as _;

    use super::*;

    /// The Auto-Detect Requests in what the server wrote, in order.
    fn requests(mut written: &[u8]) -> Vec<AutoDetectRequest> {
        let mut requests = Vec::new();
        while !written.is_empty() {
            // TPKT: version, reserved, then the length, big-endian (T.123).
            let length = usize::from(u16::from_be_bytes([written[2], written[3]]));
            let (frame, rest) = written.split_at(length);
            let indication = decode::<X224<SendDataIndication<'_>>>(frame)
                .expect("MCS Send Data Indication")
                .0;
            let pdu = decode::<AutoDetectReqPdu>(&indication.user_data).expect("Auto-Detect Request PDU");
            requests.push(pdu.request);
            written = rest;
        }
        requests
    }

    /// What one probe tick sends.
    async fn probe(server: &mut RdpServer) -> Vec<AutoDetectRequest> {
        let (mut client, server_side) = tokio::io::duplex(64 * 1024);
        let mut writer = TokioFramed::new(server_side);
        let mut events = vec![ServerEvent::AutoDetectRttRequest];
        server
            .dispatch_server_events(&mut events, &mut writer, 1003, 1007, Some(1008))
            .await
            .expect("dispatched");
        drop(writer);

        let mut written = Vec::new();
        client.read_to_end(&mut written).await.expect("read");
        requests(&written)
    }

    fn server_with_autodetect() -> RdpServer {
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();
        server.enable_autodetect();
        server
    }

    /// MS-RDPBCGR 2.2.1.3.2: RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT "indicates
    /// that the client supports network characteristics detection using the
    /// structures and PDUs described in section 2.2.14".
    ///
    /// Regression: every client got the probes.
    #[tokio::test]
    async fn auto_detect_goes_only_to_a_client_that_supports_it() {
        let mut server = server_with_autodetect();
        assert!(probe(&mut server).await.is_empty());

        server.client_supports_autodetect = true;
        assert!(matches!(
            probe(&mut server).await.first(),
            Some(AutoDetectRequest::RttRequest { .. })
        ));
    }

    /// MS-RDPBCGR 1.3.9: over the main connection, Continuous Auto-Detection
    /// sends RTT Measure Requests and Bandwidth Measure Start and Stop. The
    /// Network Characteristics Result is a connect-time message there.
    ///
    /// Regression: one followed the probes as soon as both figures were
    /// known.
    #[tokio::test]
    async fn continuous_auto_detect_sends_no_network_characteristics_result() {
        let mut server = server_with_autodetect();
        server.client_supports_autodetect = true;

        // Measure both figures, which is when a result used to go out.
        let manager = server.autodetect.as_mut().expect("enabled");
        let AutoDetectRequest::RttRequest { sequence_number, .. } = manager.send_rtt_request(0) else {
            panic!("an RTT request");
        };
        manager.handle_response(&AutoDetectResponse::RttResponse { sequence_number }, 20);
        let stop = (0..1000)
            .find_map(|_| match manager.build_bandwidth_measure() {
                Some(AutoDetectRequest::BandwidthMeasureStop { sequence_number, .. }) => Some(sequence_number),
                _ => None,
            })
            .expect("a bandwidth measurement completes");
        manager.handle_response(
            &AutoDetectResponse::BandwidthMeasureResults {
                sequence_number: stop,
                response_type: 0x0003,
                time_delta_ms: 100,
                byte_count: 125_000,
            },
            30,
        );

        let sent = probe(&mut server).await;
        assert!(!sent.is_empty());
        assert!(
            !sent
                .iter()
                .any(|request| matches!(request, AutoDetectRequest::NetworkCharacteristicsResult { .. })),
            "sent {sent:?}"
        );
    }
}

/// Encode a server-initiated Auto-Detect Request PDU for the MCS message channel.
///
/// The request is framed by a Basic Security Header (SEC_AUTODETECT_REQ) per
/// [MS-RDPBCGR] 2.2.14.3 and carried in an MCS Send Data Indication on the
/// negotiated message channel, not as a Share Data PDU on the I/O channel.
fn encode_autodetect_request(
    request: rdp::autodetect::AutoDetectRequest,
    message_channel_id: u16,
    user_channel_id: u16,
) -> ServerResult<Vec<u8>> {
    // Auto-detect rides the MCS message channel framed by a Basic Security
    // Header (SEC_AUTODETECT_REQ), not a Share Control / Share Data header.
    let pdu = rdp::autodetect::AutoDetectReqPdu::new(request);
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: message_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

/// Encode a server-initiated Heartbeat PDU for the MCS message channel.
///
/// Like auto-detect (see [`encode_autodetect_request`]), heartbeats are framed
/// by a Basic Security Header (SEC_HEARTBEAT) and ride the message channel,
/// not a Share Control / Share Data header on the I/O channel
/// (MS-RDPBCGR 2.2.16.1).
fn encode_heartbeat(config: &HeartbeatConfig, message_channel_id: u16, user_channel_id: u16) -> ServerResult<Vec<u8>> {
    let pdu = rdp::heartbeat::HeartbeatPdu {
        security_header: rdp::headers::BasicSecurityHeader {
            flags: rdp::headers::BasicSecurityHeaderFlags::HEARTBEAT,
        },
        period: config.period_secs,
        count1: config.warning_count,
        count2: config.reconnect_count,
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: message_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

/// Encode a Share Data PDU wrapped in a Share Control header and carried in an
/// MCS Send Data Indication on the I/O channel.
///
/// A general `encode_share_data_pdu` helper previously lived here for the
/// auto-detect path; #1348 rerouted auto-detect onto the message channel (see
/// [`encode_autodetect_request`]), leaving the Save Session Info sender as its
/// only user until the eviction notice (`ServerEvent::EvictedByOtherConnection`)
/// became a second one, so the encoder now lives with the former.
///
/// `pdu_source` is a parameter, not hardcoded, because the two callers
/// disagree: MS-RDPBCGR 2.2.1.19 has the server echo the client's own MCS user
/// channel ID here for a normal Share Data PDU (what Save Session Info sends),
/// but 2.2.5.1.1 requires `pduSource` to be zero specifically for
/// TS_SET_ERROR_INFO_PDU (what the eviction notice sends).
/// Token bucket shaping bitmap output to the link bandwidth measured by the
/// auto-detect probes (MS-RDPBCGR 2.2.14).
///
/// Bitmaps share one TCP transport with audio, input and control traffic; an
/// unshaped full-screen video flood queues everything else behind it, which is
/// the root cause of seconds of audio desync. The bucket releases bytes at a
/// fraction of the measured bandwidth, leaving headroom for the other
/// traffic. While a write waits for tokens, the display producer is
/// back-pressured (its pending tiles are replaced by the next frame's diff),
/// so a throttled connection skips frames instead of accumulating stale ones.
struct DisplayBudget {
    bandwidth_kbps: Arc<AtomicU32>,
    tokens: f64,
    last_refill: Instant,
}

/// Fraction of the measured link bandwidth bitmaps may consume. The rest is
/// headroom for audio, input events and protocol overhead.
const BITMAP_BW_SHARE: f64 = 0.7;
/// Never shape below this, even if a measurement glitch reports almost
/// nothing: a floor keeps the session usable instead of freezing solid.
const BITMAP_BW_FLOOR_KBPS: u32 = 1_000;

/// How long the display loop waits for a Frame Acknowledge before emitting
/// the next frame anyway. The ack should arrive within a frame or two of the
/// send; if it never does (client stall, ack-less client misbehaving), this
/// keeps the display crawling instead of freezing solid.
const FRAME_ACK_TIMEOUT: Duration = Duration::from_millis(500);

/// MS-RDPBCGR 2.2.2.3 frame accounting for display pacing.
///
/// Frame ids are monotonic, so "acked frame N" releases every frame ≤ N:
/// `acked` stores `frame id + 1` and `sent` stores the number of frame
/// markers emitted (which is also the id the next frame will carry).
#[derive(Debug, Default)]
struct FrameAckState {
    sent: AtomicU32,
    acked: AtomicU32,
}

impl FrameAckState {
    fn unacked(&self) -> u32 {
        self.sent
            .load(Ordering::Relaxed)
            .saturating_sub(self.acked.load(Ordering::Relaxed))
    }
}

impl DisplayBudget {
    fn new(bandwidth_kbps: Arc<AtomicU32>) -> Self {
        Self {
            bandwidth_kbps,
            tokens: 0.0,
            last_refill: Instant::now(),
        }
    }

    /// Sustainable bitmap rate in bytes per second.
    fn rate(&self) -> f64 {
        let kbps = self.bandwidth_kbps.load(Ordering::Relaxed);
        let kbps = if kbps == u32::MAX { return f64::INFINITY } else { kbps.max(BITMAP_BW_FLOOR_KBPS) };
        f64::from(kbps) * 125.0 * BITMAP_BW_SHARE
    }

    /// Wait until `bytes` fit in the budget, then spend them.
    async fn acquire(&mut self, bytes: usize) {
        loop {
            let now = Instant::now();
            let rate = self.rate();
            if rate.is_finite() {
                // Cap the accumulated burst at one second's worth.
                let cap = rate;
                self.tokens = (self.tokens + now.duration_since(self.last_refill).as_secs_f64() * rate).min(cap);
                if self.tokens >= bytes as f64 {
                    self.tokens -= bytes as f64;
                    self.last_refill = now;
                    return;
                }
                let deficit = bytes as f64 - self.tokens;
                self.last_refill = now;
                tokio::time::sleep(Duration::from_secs_f64(deficit / rate)).await;
            } else {
                // Bandwidth not yet measured: don't shape.
                self.last_refill = now;
                return;
            }
        }
    }
}

/// The slow-path form of an encoded update (MS-RDPBCGR 2.2.9.1.1).
///
/// A Bitmap Update body is already `TS_UPDATE_BITMAP_DATA`, updateType
/// included, which is all a slow-path `TS_UPDATE_BITMAP` carries after its
/// Share Data Header (2.2.9.1.1.3.1). A pointer update becomes a
/// `TS_POINTER_PDU`: messageType, padding, then the same attribute structure
/// the fast-path update carries (2.2.9.1.1.4). `None` for what slow-path
/// output cannot carry: surface commands and the Large Pointer Update are
/// fast-path only, and the server produces no orders, palettes or
/// synchronize updates.
fn slow_path_update(code: ironrdp_pdu::fast_path::UpdateCode, payload: &[u8]) -> Option<rdp::headers::ShareDataPdu> {
    use ironrdp_pdu::fast_path::UpdateCode;

    const TS_PTRMSGTYPE_SYSTEM: u16 = 0x0001;
    const TS_PTRMSGTYPE_POSITION: u16 = 0x0003;
    const TS_PTRMSGTYPE_COLOR: u16 = 0x0006;
    const TS_PTRMSGTYPE_CACHED: u16 = 0x0007;
    const TS_PTRMSGTYPE_POINTER: u16 = 0x0008;
    // TS_SYSTEMPOINTERATTRIBUTE (2.2.9.1.1.4.3).
    const SYSPTR_NULL: u32 = 0x0000_0000;
    const SYSPTR_DEFAULT: u32 = 0x0000_7F00;

    let pointer = |message_type: u16, attribute: &[u8]| {
        let mut body = Vec::with_capacity(4 + attribute.len());
        body.extend_from_slice(&message_type.to_le_bytes());
        body.extend_from_slice(&[0, 0]); // pad2Octets
        body.extend_from_slice(attribute);
        rdp::headers::ShareDataPdu::Pointer(body)
    };

    match code {
        UpdateCode::Bitmap => Some(rdp::headers::ShareDataPdu::Update(payload.to_vec())),
        UpdateCode::HiddenPointer => Some(pointer(TS_PTRMSGTYPE_SYSTEM, &SYSPTR_NULL.to_le_bytes())),
        UpdateCode::DefaultPointer => Some(pointer(TS_PTRMSGTYPE_SYSTEM, &SYSPTR_DEFAULT.to_le_bytes())),
        UpdateCode::PositionPointer => Some(pointer(TS_PTRMSGTYPE_POSITION, payload)),
        UpdateCode::ColorPointer => Some(pointer(TS_PTRMSGTYPE_COLOR, payload)),
        UpdateCode::CachedPointer => Some(pointer(TS_PTRMSGTYPE_CACHED, payload)),
        UpdateCode::NewPointer => Some(pointer(TS_PTRMSGTYPE_POINTER, payload)),
        UpdateCode::SurfaceCommands
        | UpdateCode::LargePointer
        | UpdateCode::Orders
        | UpdateCode::Palette
        | UpdateCode::Synchronize => None,
    }
}

#[cfg(test)]
mod slow_path_tests {
    use core::num::{NonZeroU16, NonZeroUsize};

    use ironrdp_core::ReadCursor;
    use ironrdp_graphics::image_processing::PixelFormat;
    use ironrdp_pdu::fast_path::UpdateCode;
    use ironrdp_pdu::pointer::{CachedPointerAttribute, Point16, PointerUpdateData};
    use ironrdp_pdu::slow_path::{
        GraphicsUpdateType, decode_slow_path_bitmap, decode_slow_path_pointer, read_graphics_update_type,
    };

    use super::*;
    use crate::display::BitmapUpdate;

    /// Every PDU a slow-path client gets for `update`, encoded the way
    /// `client_accepted` sets the encoder up for such a client.
    async fn slow_path_pdus(update: DisplayUpdate) -> Vec<rdp::headers::ShareDataPdu> {
        let mut encoder = UpdateEncoder::new(
            DesktopSize {
                width: 640,
                height: 480,
            },
            CmdFlags::empty(),
            UpdateEncoderCodecs::new(),
            SLOWPATH_TILE_BYTES,
            0,
            LargePointerSupportFlags::empty(),
        )
        .expect("encoder");
        let mut updates = encoder.update(update);
        let mut pdus = Vec::new();
        while let Some(fragmenter) = updates.next().await {
            let fragmenter = fragmenter.expect("encoded");
            assert!(
                fragmenter.payload().len() <= MAX_SLOWPATH_UPDATE_SIZE,
                "{} bytes do not fit one slow-path PDU",
                fragmenter.payload().len()
            );
            pdus.push(slow_path_update(fragmenter.update_code(), fragmenter.payload()).expect("a slow-path form"));
        }
        pdus
    }

    fn pointer(pdu: &rdp::headers::ShareDataPdu) -> PointerUpdateData<'_> {
        let rdp::headers::ShareDataPdu::Pointer(body) = pdu else {
            panic!("expected a Pointer Update PDU, got {}", pdu.as_short_name());
        };
        let mut src = ReadCursor::new(body);
        let pointer = decode_slow_path_pointer(&mut src).expect("TS_POINTER_PDU");
        assert!(src.is_empty(), "nothing may follow the pointer attribute");
        pointer
    }

    /// MS-RDPBCGR 2.2.9.1.1.3.1: after the Share Data Header, a slow-path
    /// Bitmap Update is `TS_UPDATE_BITMAP_DATA`, which starts with its own
    /// updateType.
    ///
    /// Regression: the server put a second updateType in front of it, so a
    /// client read the first as the update type and the second as the
    /// rectangle count. And the whole frame went into one update, far more
    /// than one PDU can carry, so it was dropped.
    #[tokio::test]
    async fn a_frame_goes_out_as_bitmap_updates_that_each_fit_one_pdu() {
        let pixels: Vec<u8> = (0..640 * 480 * 4)
            .map(|i| u8::try_from(i % 251).expect("< 256"))
            .collect();
        let frame = DisplayUpdate::Bitmap(BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(640).expect("width"),
            height: NonZeroU16::new(480).expect("height"),
            format: PixelFormat::BgrX32,
            data: pixels.into(),
            stride: NonZeroUsize::new(640 * 4).expect("stride"),
        });

        let pdus = slow_path_pdus(frame).await;
        assert!(pdus.len() > 1, "a 640x480 frame does not fit one PDU");

        let mut covered = 0u32;
        for pdu in &pdus {
            let rdp::headers::ShareDataPdu::Update(body) = pdu else {
                panic!("expected an Update PDU, got {}", pdu.as_short_name());
            };
            let mut src = ReadCursor::new(body);
            assert_eq!(
                read_graphics_update_type(&mut src).expect("updateType"),
                GraphicsUpdateType::Bitmap
            );
            let bitmap = decode_slow_path_bitmap(&mut src).expect("TS_UPDATE_BITMAP_DATA");
            assert!(src.is_empty(), "nothing may follow the rectangles");
            covered += bitmap
                .rectangles
                .iter()
                .map(|rect| u32::from(rect.width) * u32::from(rect.height))
                .sum::<u32>();
        }
        assert_eq!(covered, 640 * 480, "every pixel is sent once");
    }

    /// MS-RDPBCGR 2.2.9.1.1.4: a slow-path pointer update is a
    /// `TS_POINTER_PDU` — messageType, padding and the pointer attribute.
    /// Hiding and resetting the pointer are System Pointer Updates
    /// (2.2.9.1.1.4.3).
    ///
    /// Regression: pointer updates went out as Update PDUs led by their
    /// fast-path update code.
    #[tokio::test]
    async fn pointer_updates_go_out_as_pointer_pdus() {
        let hidden = slow_path_pdus(DisplayUpdate::HidePointer).await;
        assert!(matches!(pointer(&hidden[0]), PointerUpdateData::SetHidden));

        let default = slow_path_pdus(DisplayUpdate::DefaultPointer).await;
        assert!(matches!(pointer(&default[0]), PointerUpdateData::SetDefault));

        let moved = slow_path_pdus(DisplayUpdate::PointerPosition(Point16 { x: 10, y: 20 })).await;
        assert!(matches!(
            pointer(&moved[0]),
            PointerUpdateData::SetPosition(Point16 { x: 10, y: 20 })
        ));

        // TS_CACHEDPOINTERATTRIBUTE is the same in both paths (2.2.9.1.1.4.6).
        let cached = slow_path_update(UpdateCode::CachedPointer, &5u16.to_le_bytes()).expect("a slow-path form");
        assert!(matches!(
            pointer(&cached),
            PointerUpdateData::Cached(CachedPointerAttribute { cache_index: 5 })
        ));
    }

    /// Surface commands (2.2.9.1.2.1.10) and the Large Pointer Update
    /// (2.2.9.1.2.1.11) exist only in fast-path output.
    #[test]
    fn fast_path_only_updates_have_no_slow_path_form() {
        assert!(slow_path_update(UpdateCode::SurfaceCommands, &[0; 8]).is_none());
        assert!(slow_path_update(UpdateCode::LargePointer, &[0; 8]).is_none());
    }
}

fn encode_share_data_pdu(
    share_data_pdu: rdp::headers::ShareDataPdu,
    pdu_source: u16,
    io_channel_id: u16,
    user_channel_id: u16,
) -> ServerResult<Vec<u8>> {
    let header = rdp::headers::ShareDataHeader {
        share_data_pdu,
        stream_priority: rdp::headers::StreamPriority::Medium,
        compression_flags: rdp::headers::CompressionFlags::empty(),
        compression_type: rdp::client_info::CompressionType::K8,
    };
    let pdu = rdp::headers::ShareControlHeader {
        share_id: 0,
        pdu_source,
        share_control_pdu: ShareControlPdu::Data(header),
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

/// Whether a client can use the tunnel this server offers: reliable UDP
/// (`TRANSPORTTYPE_UDPFECR`) and Soft-Sync (`SOFTSYNC_TCP_TO_UDP`), from its
/// Client Multitransport Channel Data (MS-RDPBCGR 2.2.1.3.8).
///
/// The server opens every dynamic channel on TCP and moves them to the tunnel
/// with a Soft-Sync Request, which MS-RDPEDYC 3.1.5.3 forbids unless both
/// sides announce Soft-Sync. For a client without it, a tunnel would carry
/// nothing.
fn client_can_use_the_tunnel(client: ironrdp_pdu::gcc::MultiTransportFlags) -> bool {
    use ironrdp_pdu::gcc::MultiTransportFlags;

    client.contains(MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR | MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP)
}

/// Encode a Server Initiate Multitransport Request PDU (MS-RDPBCGR 2.2.15.1)
/// for the MCS message channel.
///
/// The PDU rides an MCS Send Data Indication on the negotiated message
/// channel — the spec's MUST — framed by a Basic Security Header
/// (SEC_TRANSPORT_REQ) rather than a Share Control header.
fn encode_multitransport_request(
    mt: &MultiTransportRequest,
    message_channel_id: u16,
    user_channel_id: u16,
) -> ServerResult<Vec<u8>> {
    let pdu = rdp::multitransport::MultitransportRequestPdu {
        security_header: rdp::headers::BasicSecurityHeader {
            flags: rdp::headers::BasicSecurityHeaderFlags::TRANSPORT_REQ,
        },
        request_id: mt.request_id,
        requested_protocol: rdp::multitransport::RequestedProtocol::UdpFecR,
        security_cookie: mt.security_cookie,
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let mcs_pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: message_channel_id,
        user_data,
    };
    encode_vec(&X224(mcs_pdu)).map_err(ServerError::encode)
}

#[cfg(test)]
mod auto_reconnect_tests {
    use core::sync::atomic::AtomicUsize;

    use ironrdp_pdu::rdp::client_info::ClientAutoReconnect;

    use super::*;

    /// Counts its calls and refuses everyone.
    struct Refuse(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl CredentialValidator for Refuse {
        async fn validate(&self, _credentials: &Credentials) -> Result<CredentialDecision, CredentialValidationError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(CredentialDecision::Reject)
        }
    }

    /// MS-RDPBCGR 3.3.5.3.11: "If logon with the cookie fails, the
    /// credentials supplied in the Client Info PDU SHOULD be used".
    ///
    /// Regression: a cookie that did not verify ended the connection with
    /// an access-denied error, however good the credentials were. And the
    /// first connection's refusal was never announced: whether the client
    /// takes a Set Error Info PDU was still unknown at that point.
    #[tokio::test]
    async fn a_cookie_that_does_not_verify_falls_back_to_the_credentials() {
        let validated = Arc::new(AtomicUsize::new(0));
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();
        server.set_credential_validator(Some(Arc::new(Refuse(Arc::clone(&validated)))));

        let result = AcceptorResult {
            static_channels: StaticChannelSet::new(),
            capabilities: Vec::new(),
            input_events: Vec::new(),
            user_channel_id: 1007,
            io_channel_id: 1003,
            message_channel_id: None,
            reactivation: false,
            desktop_size: DesktopSize {
                width: 1024,
                height: 768,
            },
            keyboard_layout: 0,
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
            ime_file_name: String::new(),
            client_cluster: None,
            client_early_capability_flags: ironrdp_pdu::gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU,
            multitransport_flags: ironrdp_pdu::gcc::MultiTransportFlags::empty(),
            credentials: Some(Credentials {
                username: "user".to_owned(),
                password: "password".to_owned(),
                domain: None,
            }),
            auto_reconnect: Some(ClientAutoReconnect {
                logon_id: 1,
                security_verifier: [0x42; 16],
            }),
        };

        let (_client_reader, server_reader) = tokio::io::duplex(1024);
        let (mut client_writer, server_writer) = tokio::io::duplex(64 * 1024);
        let mut reader = TokioFramed::new(server_reader);
        let mut writer = TokioFramed::new(server_writer);
        let outcome = server.client_accepted(&mut reader, &mut writer, result).await;

        assert_eq!(
            validated.load(Ordering::Relaxed),
            1,
            "the credentials decide, not the cookie"
        );
        let error = outcome.expect_err("the validator refuses");
        assert!(format!("{error}").contains("credential validation"), "{error}");
        drop(writer);
        let mut denied = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client_writer, &mut denied)
            .await
            .expect("read");
        assert!(!denied.is_empty(), "the refusal is still announced");
    }
}

async fn deactivate_all(io_channel_id: u16, user_channel_id: u16, writer: &mut impl FramedWrite) -> ServerResult<()> {
    let pdu = ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll);
    let pdu = rdp::headers::ShareControlHeader {
        share_id: 0,
        pdu_source: io_channel_id,
        share_control_pdu: pdu,
    };
    let user_data = encode_vec(&pdu).map_err(ServerError::encode)?.into();
    let pdu = SendDataIndication {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data,
    };
    let msg = encode_vec(&X224(pdu)).map_err(ServerError::encode)?;
    writer
        .write_all(&msg)
        .await
        .map_err(|e| ServerError::io("write deactivate_all", e))?;
    Ok(())
}

/// Send a `ServerSetErrorInfoPdu(ServerDeniedConnection)` to the client, then return.
///
/// Used to deny a connection after credential validation rejects it, mirroring the
/// acceptor's exact-match denial so both paths refuse the same spec-defined way.
/// `client_supports_errinfo` gates the PDU on RNS_UD_CS_SUPPORT_ERRINFO_PDU
/// (MS-RDPBCGR 3.3.5.7.1: MUST NOT send it to clients that did not announce it).
async fn send_access_denied(
    io_channel_id: u16,
    user_channel_id: u16,
    client_supports_errinfo: bool,
    writer: &mut impl FramedWrite,
) -> ServerResult<()> {
    if !client_supports_errinfo {
        debug!("client did not announce SUPPORT_ERRINFO_PDU; denying the connection without a reason PDU");
        return Ok(());
    }
    let msg = encode_access_denied(io_channel_id, user_channel_id)?;
    writer
        .write_all(&msg)
        .await
        .map_err(|e| ServerError::io("write access_denied", e))?;
    Ok(())
}

/// The Set Error Info PDU that refuses a connection with
/// `ERRINFO_SERVER_DENIED_CONNECTION`.
///
/// MS-RDPBCGR 2.2.5.1.1: TS_SET_ERROR_INFO_PDU is a Share Data Header with
/// `pduType2` = PDUTYPE2_SET_ERROR_INFO_PDU followed by the error value, and
/// its `pduSource` MUST be 0. The bare four-byte `errorInfo` this used to send
/// on its own was not a PDU the client could parse, so a refused login read
/// as a protocol error instead of "access denied".
fn encode_access_denied(io_channel_id: u16, user_channel_id: u16) -> ServerResult<Vec<u8>> {
    let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
        ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::ServerDeniedConnection),
    ));
    encode_share_data_pdu(pdu, 0, io_channel_id, user_channel_id)
}

struct SharedWriter<'w, W: FramedWrite> {
    writer: Rc<Mutex<&'w mut W>>,
    /// Count of successful `write_all` calls across all clones. The heartbeat
    /// loop compares it across ticks to honor 2.2.16.1's idle-only SHOULD: a
    /// changed count means ordinary traffic already served as the liveness
    /// signal for that interval.
    writes: Arc<AtomicU64>,
}

impl<W: FramedWrite> Clone for SharedWriter<'_, W> {
    fn clone(&self) -> Self {
        Self {
            writer: Rc::clone(&self.writer),
            writes: Arc::clone(&self.writes),
        }
    }
}

impl<W> FramedWrite for SharedWriter<'_, W>
where
    W: FramedWrite,
{
    type WriteAllFut<'write>
        = core::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + 'write>>
    where
        Self: 'write;

    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteAllFut<'a> {
        Box::pin(async move {
            // D1: time both the lock acquisition and the actual write.
            // Three concurrent tasks (dispatch_pdu, dispatch_display,
            // dispatch_events) share this Rc<Mutex<W>>. When the kernel TCP
            // send buffer fills (slow client), write_all blocks while still
            // holding the mutex — starving the other two tasks. Logging
            // both phases tells us whether a stall is "waiting in line for
            // the writer" (lock-wait) or "TLS write held up by TCP back-
            // pressure" (write-time).
            let len = buf.len();
            let wait_start = Instant::now();
            let mut writer = self.writer.lock().await;
            let wait_ms = u64::try_from(wait_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            let write_start = Instant::now();
            let res = writer.write_all(buf).await;
            let write_ms = u64::try_from(write_start.elapsed().as_millis()).unwrap_or(u64::MAX);

            // Threshold: 50ms total budget for one write_all. Anything above
            // is operationally interesting on a healthy LAN. Logged at WARN
            // when stalled, DEBUG when fast (so wire-time samples are still
            // visible during routine debugging).
            if wait_ms + write_ms >= 50 {
                tracing::warn!(
                    bytes = len,
                    lock_wait_ms = wait_ms,
                    write_ms,
                    "SharedWriter.write_all stalled, possible TCP back-pressure or writer-mutex contention"
                );
            } else {
                tracing::debug!(bytes = len, lock_wait_ms = wait_ms, write_ms, "SharedWriter.write_all");
            }
            if res.is_ok() {
                self.writes.fetch_add(1, Ordering::Relaxed);
            }
            res
        })
    }
}

impl<'a, W: FramedWrite> SharedWriter<'a, W> {
    fn new(writer: &'a mut W) -> Self {
        Self {
            writer: Rc::new(Mutex::new(writer)),
            writes: Arc::new(AtomicU64::new(0)),
        }
    }

    fn write_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.writes)
    }
}

#[cfg(test)]
mod preempt_tests {
    use core::net::Ipv4Addr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    fn ctx_with_no_security() -> NegotiationContext {
        struct NoDisplay;
        #[async_trait::async_trait]
        impl RdpServerDisplay for NoDisplay {
            async fn size(&mut self) -> DesktopSize {
                DesktopSize {
                    width: 1024,
                    height: 768,
                }
            }
            async fn updates(&mut self) -> ServerResult<Box<dyn crate::RdpServerDisplayUpdates>> {
                unreachable!("negotiation never asks for updates")
            }
        }

        NegotiationContext {
            opts: RdpServerOptions {
                addr: (Ipv4Addr::LOCALHOST, 0).into(),
                security: RdpServerSecurity::None,
                codecs: BitmapCodecs(Vec::new()),
                max_request_size: 8 * 1024 * 1024,
                honor_client_desktop_size: None,
                preempt_existing_session: true,
                remotefx_quant: Quant::default(),
                remotefx_entropy_coder: None,
                multitransport: None,
            },
            creds: None,
            credential_resolver: None,
            enable_ainput: false,
            display: Arc::new(Mutex::new(Box::new(NoDisplay))),
        }
    }

    /// The invariant behind this feature: a connection that never completes a
    /// real RDP negotiation must NOT be treated as an eligible candidate, and
    /// so can never evict a live session. This is the case the earlier
    /// two-byte `03 00` peek got wrong — it accepted anything whose first
    /// bytes merely *looked* like a TPKT header.
    #[tokio::test]
    async fn a_candidate_sending_garbage_never_authenticates() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Starts with a plausible TPKT prefix — enough to fool a
            // header peek — but is not a valid X.224 Connection Request.
            stream.write_all(&[0x03, 0x00, 0xff, 0xff, 0x41, 0x41]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (stream, peer) = listener.accept().await.unwrap();
        let ctx = ctx_with_no_security();
        assert!(
            negotiate_candidate(&ctx, stream, peer).await.is_none(),
            "traffic that only looks like RDP must not become an eligible candidate"
        );

        client.await.unwrap();
    }

    /// The other half: a bare connect that sends nothing (a port scan, a
    /// half-open probe) must not qualify either.
    #[tokio::test]
    async fn a_candidate_that_closes_immediately_never_authenticates() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            drop(stream);
        });

        let (stream, peer) = listener.accept().await.unwrap();
        let ctx = ctx_with_no_security();
        assert!(
            negotiate_candidate(&ctx, stream, peer).await.is_none(),
            "a connect-and-close must not become an eligible candidate"
        );

        client.await.unwrap();
    }

    /// The eviction notice must be a properly framed Share Data PDU carrying
    /// `ERRINFO_DISCONNECTED_BY_OTHERCONNECTION` (MS-RDPBCGR 2.2.5.1.1) — that
    /// exact code is what tells a client it was replaced rather than dropped,
    /// and so what stops it auto-reconnecting into a ping-pong. Round-trips
    /// the encoding a real eviction sends.
    #[test]
    fn the_eviction_notice_is_a_share_data_pdu_with_the_takeover_code() {
        let pdu = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
            ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::DisconnectedByOtherconnection),
        ));
        // pdu_source=0 here: unlike the Save Session Info sender (which
        // echoes the client's own user_channel_id), MS-RDPBCGR 2.2.5.1.1
        // requires pduSource to be zero for TS_SET_ERROR_INFO_PDU.
        let bytes = encode_share_data_pdu(pdu, 0, 1003, 1002).expect("encode eviction notice");

        let x224: X224<mcs::McsMessage<'_>> = decode(&bytes).expect("decode X.224/MCS");
        let mcs::McsMessage::SendDataIndication(data) = x224.0 else {
            panic!("eviction notice must ride an MCS Send Data Indication");
        };
        let control: rdp::headers::ShareControlHeader =
            decode(data.user_data.as_ref()).expect("decode Share Control header");
        assert_eq!(
            control.pdu_source, 0,
            "MS-RDPBCGR 2.2.5.1.1 requires pduSource=0 for TS_SET_ERROR_INFO_PDU"
        );
        let ShareControlPdu::Data(header) = control.share_control_pdu else {
            panic!("eviction notice must be a Share Data PDU");
        };
        match header.share_data_pdu {
            rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                ErrorInfo::ProtocolIndependentCode(code),
            )) => {
                assert_eq!(code, ProtocolIndependentCode::DisconnectedByOtherconnection);
            }
            other => panic!("unexpected share data pdu: {other:?}"),
        }
    }

    /// MS-RDPBCGR 2.2.5.1.1: the refusal is a whole TS_SET_ERROR_INFO_PDU —
    /// Share Control and Share Data headers, `pduSource` 0 — carrying
    /// ERRINFO_SERVER_DENIED_CONNECTION, not the bare error value.
    #[test]
    fn a_refused_login_is_a_share_data_pdu_with_the_denied_code() {
        let bytes = encode_access_denied(1003, 1002).expect("encode access denied");

        let x224: X224<mcs::McsMessage<'_>> = decode(&bytes).expect("decode X.224/MCS");
        let mcs::McsMessage::SendDataIndication(data) = x224.0 else {
            panic!("the refusal must ride an MCS Send Data Indication");
        };
        assert_eq!(data.channel_id, 1003, "on the I/O channel");
        let control: rdp::headers::ShareControlHeader =
            decode(data.user_data.as_ref()).expect("decode Share Control header");
        assert_eq!(control.pdu_source, 0, "MS-RDPBCGR 2.2.5.1.1 requires pduSource=0");
        let ShareControlPdu::Data(header) = control.share_control_pdu else {
            panic!("the refusal must be a Share Data PDU");
        };
        match header.share_data_pdu {
            rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                ErrorInfo::ProtocolIndependentCode(code),
            )) => assert_eq!(code, ProtocolIndependentCode::ServerDeniedConnection),
            other => panic!("unexpected share data pdu: {other:?}"),
        }
    }

    /// The anti-storm net: a just-evicted peer may not bounce straight back,
    /// and every refused attempt RE-ARMS the window, so an automatic reconnect
    /// loop cannot immediately outlast it. A peer that goes quiet for the
    /// cooldown (a human closing the client and reconnecting) is let back in.
    #[test]
    fn a_just_evicted_peer_cannot_bounce_back_but_a_quiet_one_can() {
        let cooldown = Duration::from_secs(5);
        let max_lockout = Duration::from_secs(30);
        let evicted: IpAddr = Ipv4Addr::new(192, 168, 4, 46).into();
        let other: IpAddr = Ipv4Addr::new(192, 168, 4, 44).into();

        let t0 = Instant::now();
        let mut state = Some(EvictedPeer {
            ip: evicted,
            evicted_at: t0,
            last_try: t0,
        });

        // An unrelated peer is never affected by someone else's eviction.
        assert!(!refuse_reconnect_from_evicted(
            &mut state,
            other,
            t0 + Duration::from_millis(500),
            cooldown,
            max_lockout,
        ));

        // The evicted peer auto-reconnecting ~1 s later is refused, and each
        // attempt pushes the window out.
        let mut at = t0;
        for _ in 0..5 {
            at += Duration::from_secs(1);
            assert!(
                refuse_reconnect_from_evicted(&mut state, evicted, at, cooldown, max_lockout),
                "an auto-reconnect storm must not immediately win the session back"
            );
        }

        // ...but once it stops hammering for the full cooldown, a deliberate
        // reconnect is allowed through.
        let quiet = at + cooldown + Duration::from_millis(1);
        assert!(
            !refuse_reconnect_from_evicted(&mut state, evicted, quiet, cooldown, max_lockout),
            "a peer that waited out the cooldown must be able to connect again"
        );
    }

    /// The re-arming window MUST NOT lock a peer out forever, or it defeats
    /// the feature's own headline case: a client whose link dropped, whose
    /// stale session is still live, auto-reconnecting to reclaim it. Past
    /// `max_lockout` from the eviction the bar lifts even under a storm that
    /// never pauses.
    #[test]
    fn the_reconnect_bar_lifts_once_the_absolute_cap_passes() {
        let cooldown = Duration::from_secs(5);
        let max_lockout = Duration::from_secs(30);
        let evicted: IpAddr = Ipv4Addr::new(192, 168, 4, 46).into();

        let t0 = Instant::now();
        let mut state = Some(EvictedPeer {
            ip: evicted,
            evicted_at: t0,
            last_try: t0,
        });

        // A relentless 1 s auto-reconnect cadence: refused while inside the
        // cap, even though every attempt re-arms the cooldown...
        let mut at = t0;
        let mut refused_while_capped = 0;
        while at < t0 + max_lockout {
            at += Duration::from_secs(1);
            if at < t0 + max_lockout {
                assert!(
                    refuse_reconnect_from_evicted(&mut state, evicted, at, cooldown, max_lockout),
                    "still inside the cap, so the storm is throttled"
                );
                refused_while_capped += 1;
            }
        }
        assert!(refused_while_capped > 0, "the test must exercise the throttled window");

        // ...and let through the moment the cap passes, WITHOUT the peer ever
        // having paused. Before the cap was added this returned true forever.
        let past_cap = t0 + max_lockout + Duration::from_millis(1);
        assert!(
            !refuse_reconnect_from_evicted(&mut state, evicted, past_cap, cooldown, max_lockout),
            "a peer must not be barred forever just for retrying; that locks out the case the feature exists for"
        );
    }

    /// A silent candidate MUST NOT be able to hang the accept loop.
    ///
    /// `negotiate_candidate` blocks on socket reads from a peer that has not
    /// authenticated. Before `CANDIDATE_NEGOTIATION_TIMEOUT` the probe was
    /// awaited unbounded: a peer that connected and then sent NOTHING parked it
    /// forever, and once the live session ended `run()` blocked on the handoff
    /// await with no `select!` left — no further accepts, no event drain, so
    /// not even `ServerEvent::Quit` could stop the server. An unauthenticated
    /// remote could wedge the listener.
    ///
    /// Drive exactly that: a live session, a silent candidate, then end the
    /// session and require the server to still respond and still shut down.
    #[tokio::test]
    async fn a_silent_candidate_cannot_wedge_the_accept_loop() {
        let local = task::LocalSet::new();
        local
            .run_until(async move {
                let mut server = RdpServer::builder()
                    .with_addr((Ipv4Addr::LOCALHOST, 0))
                    .with_no_security()
                    .with_no_input()
                    .with_no_display()
                    .with_preempt_existing_session(true)
                    .build();

                let event_sender = server.event_sender().clone();
                let run_task = task::spawn_local(async move {
                    let _ = Box::pin(server.run()).await;
                });

                let addr = loop {
                    let (tx, rx) = oneshot::channel();
                    let _ = event_sender.send(ServerEvent::GetLocalAddr(tx));
                    if let Ok(Some(addr)) = rx.await {
                        break addr;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };

                // Client A: the live session (connect, stay silent).
                let client_a = TcpStream::connect(addr).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Client B: the candidate — completes the TCP handshake, then
                // says nothing at all, parking the probe mid-`accept_begin`.
                let _client_b = TcpStream::connect(addr).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;

                // The live session ends. This is the branch that used to do a
                // bare `probe.await` and never come back.
                drop(client_a);

                // The server must still be answering its event channel. With
                // the unbounded await this never resolves.
                let responsive = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let (tx, rx) = oneshot::channel();
                        if event_sender.send(ServerEvent::GetLocalAddr(tx)).is_err() {
                            return;
                        }
                        if rx.await.is_ok() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await;
                assert!(
                    responsive.is_ok(),
                    "the accept loop stopped servicing events while a silent candidate was in flight"
                );

                // ...and must still be stoppable.
                let _ = event_sender.send(ServerEvent::Quit("test over".to_owned()));
                let stopped = tokio::time::timeout(Duration::from_secs(3), run_task).await;
                assert!(
                    stopped.is_ok(),
                    "the server ignored Quit -- the accept loop was wedged by an unauthenticated silent peer"
                );
            })
            .await;
    }

    /// A `ConnectionHandler` that accepts the first connection and rejects
    /// every one after, recording every peer it was consulted about.
    struct RejectAfterFirst {
        seen: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
        accepted_once: bool,
    }

    impl ConnectionHandler for RejectAfterFirst {
        fn on_accept(&mut self, peer: SocketAddr) -> bool {
            self.seen.lock().unwrap().push(peer);
            !core::mem::replace(&mut self.accepted_once, true)
        }
    }

    /// Drives a real `RdpServer::run()` accept loop over TCP with preemption
    /// on. A candidate must be gated through `ConnectionHandler::on_accept`
    /// *before* it is allowed to negotiate — so a rate limiter or IP allowlist
    /// can stop a takeover, rather than only learning about it after the live
    /// session was already evicted.
    #[tokio::test]
    async fn a_candidate_is_gated_through_on_accept_before_it_can_preempt() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_for_handler = Arc::clone(&seen);

        let local = task::LocalSet::new();
        local
            .run_until(async move {
                let mut server = RdpServer::builder()
                    .with_addr((Ipv4Addr::LOCALHOST, 0))
                    .with_no_security()
                    .with_no_input()
                    .with_no_display()
                    .with_connection_handler(Some(Box::new(RejectAfterFirst {
                        seen: seen_for_handler,
                        accepted_once: false,
                    })))
                    .with_preempt_existing_session(true)
                    .build();

                let event_sender = server.event_sender().clone();
                let run_task = task::spawn_local(async move {
                    let _ = Box::pin(server.run()).await;
                });

                // Learn the ephemeral port (retrying while `run()` binds).
                let addr = loop {
                    let (tx, rx) = oneshot::channel();
                    let _ = event_sender.send(ServerEvent::GetLocalAddr(tx));
                    if let Ok(Some(addr)) = rx.await {
                        break addr;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };

                // Client A: connect and go silent. `run_connection` parks
                // reading the first PDU, which is all "a live session" needs
                // to be here.
                let mut client_a = TcpStream::connect(addr).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Client B: the candidate. The handler rejects it, so it must
                // never reach negotiation, let alone evict client A.
                let mut client_b = TcpStream::connect(addr).await.unwrap();
                client_b.write_all(&[0x03, 0x00]).await.unwrap();

                let mut buf = [0u8; 1];
                let client_b_read = tokio::time::timeout(Duration::from_secs(2), client_b.read(&mut buf)).await;
                assert!(
                    matches!(client_b_read, Ok(Ok(0)) | Ok(Err(_))),
                    "the rejected candidate's connection should be closed, got {client_b_read:?}"
                );

                // Client A is untouched: a read TIMES OUT (no EOF, no data)
                // rather than showing the server dropped it for client B.
                let client_a_still_alive =
                    tokio::time::timeout(Duration::from_millis(300), client_a.read(&mut buf)).await;
                assert!(
                    client_a_still_alive.is_err(),
                    "the live session must survive a rejected preemption attempt, got {client_a_still_alive:?}"
                );

                // The handler was actually consulted about the candidate —
                // the gate ran on B, not merely on A.
                let seen = seen.lock().unwrap().clone();
                assert_eq!(
                    seen.len(),
                    2,
                    "on_accept should have been consulted for both peers: {seen:?}"
                );

                run_task.abort();
            })
            .await;
    }

    /// Regression guard for the blocking review finding: invalidating an
    /// evicted peer's ARC cookie must NOT permanently disable auto-reconnect
    /// for the server. `next_auto_reconnect_cookie` treats
    /// `self.auto_reconnect_cookie == None` as "unconfigured" and stops
    /// issuing cookies to EVERY future connection -- a naive
    /// `self.auto_reconnect_cookie = None` on eviction would have silently
    /// killed the feature server-wide the moment the first eviction ever
    /// happened.
    #[test]
    fn invalidating_the_evicted_peers_cookie_does_not_disable_auto_reconnect() {
        let mut server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let seed = RdpServer::generate_auto_reconnect_cookie(4242);
        server.set_auto_reconnect_cookie(Some(seed.clone()));
        // A normal rotation would have run once by the time a real session
        // reaches an eviction; simulate that so `previous_auto_reconnect_
        // cookie` starts populated, which is the slot the fix must ALSO clear.
        server.commit_auto_reconnect_rotation(RdpServer::generate_auto_reconnect_cookie(seed.logon_id));

        server.invalidate_auto_reconnect_cookie_on_eviction();

        let after = server
            .auto_reconnect_cookie
            .as_ref()
            .expect("invalidation must not clear the cookie to None -- that permanently disables auto-reconnect");
        assert_eq!(after.logon_id, seed.logon_id, "the logon_id lineage must be preserved");
        assert_ne!(
            after.random_bits, seed.random_bits,
            "the random bits must actually change, or the evicted peer's OLD cookie would still verify"
        );
        assert!(
            server.previous_auto_reconnect_cookie.is_none(),
            "the outgoing cookie(s) must be discarded, not demoted into previous_ -- demoting would keep an \
             evicted peer's cookie valid for one more attempt, which is exactly the gap this closes"
        );
    }

    /// `discard_stale_session_events` must be an ALLOWLIST of lifecycle
    /// events, not a denylist of `EvictedByOtherConnection` alone -- otherwise
    /// a preemption winner is handed whatever per-session events (audio
    /// waves, clipboard messages, EGFX frames) the session it replaced left
    /// queued but never consumed.
    #[tokio::test]
    async fn stale_session_events_are_dropped_but_lifecycle_events_survive() {
        let mut server = RdpServer::builder()
            .with_addr((Ipv4Addr::LOCALHOST, 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let sender = server.event_sender().clone();
        // A representative per-session event that must NOT survive a
        // takeover -- it belonged to the session just replaced.
        let _ = sender.send(ServerEvent::AutoDetectRttRequest);
        // A lifecycle event that MUST survive.
        let _ = sender.send(ServerEvent::Quit("keep me".to_owned()));

        server.discard_stale_session_events().await;

        let remaining = {
            let mut rx = server.ev_receiver.lock().await;
            let mut events = Vec::new();
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
            events
        };

        assert_eq!(
            remaining.len(),
            1,
            "exactly the lifecycle event should have survived the drain: {remaining:?}"
        );
        assert!(
            matches!(&remaining[0], ServerEvent::Quit(reason) if reason == "keep me"),
            "the surviving event should be the Quit, not the discarded per-session event: {remaining:?}"
        );
    }

    /// Regression guard for the "no happy-path test" review finding, and the
    /// load-bearing claim it's actually worried about: that deferring
    /// `attach_channels` to `serve_negotiated` does NOT silently drop a
    /// preemption winner's channels. That claim rests entirely on
    /// `accept_begin` stopping at `AcceptorState::SecurityUpgrade` -- before
    /// `BasicSettingsWaitInitial` consumes `static_channels` -- for
    /// [`RdpServerSecurity::None`]. If a future `ironrdp-acceptor` change
    /// moved that stop point, a preemption winner would negotiate ZERO static
    /// channels (no clipboard, no sound, no DVC) and every OTHER test in this
    /// module would still pass, since none of them drive a candidate all the
    /// way to `serve_negotiated`.
    ///
    /// Drives a REAL candidate through `negotiate_candidate` (a genuine X.224
    /// Connection Request, matching `RdpServerSecurity::None`'s empty
    /// protocol flags, is enough to reach `BeginResult::Continue` -- no TLS,
    /// no MCS needed) and then `serve_negotiated`, and asserts the sound
    /// factory's backend was actually built. `serve_negotiated` can't finish
    /// without a full MCS/GCC handshake this test doesn't drive, so it's
    /// bounded by a short timeout that is EXPECTED to fire -- the assertion
    /// that matters is the side effect that happens before that point.
    #[tokio::test]
    async fn a_winning_candidate_actually_gets_its_channels_attached() {
        let backend_built = Arc::new(AtomicBool::new(false));

        #[derive(Debug)]
        struct RecordingSoundHandler;
        impl ironrdp_rdpsnd::server::RdpsndServerHandler for RecordingSoundHandler {
            fn get_formats(&self) -> &[ironrdp_rdpsnd::pdu::AudioFormat] {
                &[]
            }
            fn choose_format<'a>(
                &mut self,
                _common: &'a [ironrdp_rdpsnd::server::NegotiatedFormat],
            ) -> Option<&'a ironrdp_rdpsnd::server::NegotiatedFormat> {
                None
            }
            fn start(
                &mut self,
                _format: &ironrdp_rdpsnd::server::NegotiatedFormat,
            ) -> Result<(), Box<dyn ironrdp_rdpsnd::server::RdpsndError>> {
                Ok(())
            }
            fn stop(&mut self) {}
        }

        #[derive(Debug)]
        struct RecordingSoundFactory(Arc<AtomicBool>);
        impl ServerEventSender for RecordingSoundFactory {
            fn set_sender(&mut self, _sender: mpsc::UnboundedSender<ServerEvent>) {}
        }
        impl SoundServerFactory for RecordingSoundFactory {
            fn build_backend(&self) -> Box<dyn ironrdp_rdpsnd::server::RdpsndServerHandler> {
                self.0.store(true, Ordering::SeqCst);
                Box::new(RecordingSoundHandler)
            }
        }

        let local = task::LocalSet::new();
        local
            .run_until(Box::pin(async move {
                let mut server = RdpServer::builder()
                    .with_addr((Ipv4Addr::LOCALHOST, 0))
                    .with_no_security()
                    .with_no_input()
                    .with_no_display()
                    .with_sound_factory(Some(Box::new(RecordingSoundFactory(Arc::clone(&backend_built)))))
                    .build();

                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let addr = listener.local_addr().unwrap();

                let client = tokio::spawn(async move {
                    let mut stream = TcpStream::connect(addr).await.unwrap();
                    let cr = nego::ConnectionRequest {
                        nego_data: None,
                        flags: nego::RequestFlags::empty(),
                        // Matches `RdpServerSecurity::None`'s
                        // `RdpServerSecurity::flag()` exactly -- this is what
                        // makes `accept_begin` reach `BeginResult::Continue`.
                        protocol: nego::SecurityProtocol::empty(),
                        correlation_info: None,
                    };
                    let bytes = encode_vec(&X224(cr)).unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    // Hold the connection open; `serve_negotiated` will try
                    // to read the next (MCS) PDU, which this test never
                    // sends, so the read simply blocks until the test ends.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });

                let (stream, peer) = listener.accept().await.unwrap();
                let (candidate, _peer) = negotiate_candidate(&server.negotiation_context(), stream, peer)
                    .await
                    .expect("a well-formed X.224 Connection Request under RdpServerSecurity::None must authenticate");

                // Bounded: `serve_negotiated` cannot finish without a full
                // MCS/GCC handshake this test doesn't drive, so timing out is
                // the EXPECTED outcome here -- `attach_channels`'s
                // synchronous side effect (below) already happened before
                // `serve_negotiated` reached its first blocking read.
                let _ = tokio::time::timeout(Duration::from_millis(300), server.serve_negotiated(candidate)).await;

                assert!(
                    backend_built.load(Ordering::SeqCst),
                    "the winning candidate's sound backend was never built -- attach_channels was not called, \
                     meaning this preemption winner would have gotten NO static channels at all"
                );

                client.abort();
            }))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicUsize;

    use ironrdp_core::impl_as_any;
    use ironrdp_pdu::gcc::ChannelName;
    use ironrdp_svc::{SvcMessage, SvcServerProcessor};

    use super::*;

    /// A channel backend that owns a resource, released on drop the way
    /// `RdpsndServer` stops its handler.
    #[derive(Debug)]
    struct ResourceChannel(Arc<AtomicBool>);

    impl Drop for ResourceChannel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    impl_as_any!(ResourceChannel);

    impl SvcProcessor for ResourceChannel {
        fn channel_name(&self) -> ChannelName {
            ChannelName::from_static(b"testchan")
        }

        fn process(&mut self, _payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
            Ok(Vec::new())
        }
    }

    impl SvcServerProcessor for ResourceChannel {}

    #[tokio::test]
    async fn run_connection_releases_the_static_channels() {
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let released = Arc::new(AtomicBool::new(false));
        server.static_channels.insert(ResourceChannel(Arc::clone(&released)));

        // A stream that is already at EOF: the connection ends early, which
        // is the path an embedder's accept loop sees when a client vanishes.
        let (client, server_side) = tokio::io::duplex(64);
        drop(client);
        let _ = server.run_connection(server_side).await;

        assert!(
            released.load(Ordering::Relaxed),
            "the channel backends of a finished connection must be released, not held until the next client"
        );
    }

    /// MS-RDPEDYC 3.1.5.3: "Soft-Sync MUST NOT be used unless it is supported
    /// by both the server and client". Dynamic channels reach the tunnel only
    /// through Soft-Sync, so a client that does not announce it gets no
    /// Initiate Multitransport Request.
    ///
    /// Regression: reliable UDP alone was enough, and the Soft-Sync Request
    /// followed anyway.
    #[test]
    fn only_a_client_with_reliable_udp_and_soft_sync_is_offered_the_tunnel() {
        use ironrdp_pdu::gcc::MultiTransportFlags as Flags;

        assert!(client_can_use_the_tunnel(
            Flags::TRANSPORT_TYPE_UDP_FECR | Flags::SOFT_SYNC_TCP_TO_UDP
        ));
        assert!(client_can_use_the_tunnel(
            Flags::TRANSPORT_TYPE_UDP_FECR | Flags::TRANSPORT_TYPE_UDP_FECL | Flags::SOFT_SYNC_TCP_TO_UDP
        ));
        assert!(!client_can_use_the_tunnel(Flags::TRANSPORT_TYPE_UDP_FECR));
        assert!(!client_can_use_the_tunnel(Flags::SOFT_SYNC_TCP_TO_UDP));
        assert!(!client_can_use_the_tunnel(Flags::empty()));
    }

    /// MS-RDPBCGR 2.2.15.2: the response's requestId "MUST contain the ID that
    /// was sent to the client in the requestId field of the associated
    /// Initiate Multitransport Request PDU".
    ///
    /// Regression: any S_OK confirmed the tunnel, whatever it answered.
    #[test]
    fn a_multitransport_response_confirms_only_the_request_that_was_sent() {
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        server.on_multitransport_response(7, 0);
        assert!(!server.multitransport_confirmed, "no request was sent");

        server.multitransport_request_id = Some(7);
        server.on_multitransport_response(8, 0);
        assert!(!server.multitransport_confirmed, "a response to another request");

        server.on_multitransport_response(7, 0);
        assert!(server.multitransport_confirmed);
    }

    /// Counts the teardown an embedder does at the end of a connection.
    #[derive(Debug)]
    struct CountingHandler {
        ended: Arc<AtomicUsize>,
        peer: Arc<std::sync::Mutex<Option<SocketAddr>>>,
    }

    impl ConnectionHandler for CountingHandler {
        fn on_disconnected(
            &mut self,
            peer: SocketAddr,
            _duration: Duration,
            _error: Option<&ServerError>,
        ) -> PostConnectionAction {
            self.ended.fetch_add(1, Ordering::Relaxed);
            *self.peer.lock().unwrap_or_else(|p| p.into_inner()) = Some(peer);
            PostConnectionAction::Continue
        }
    }

    /// An embedder that forks a process per connection calls
    /// `run_connection`, never `run` — and `on_disconnected` used to fire
    /// only from `run`'s accept loop.
    ///
    /// Regression, and not a cosmetic one: everything such an embedder does at
    /// the end of a connection lived in that callback, so none of it happened.
    /// A desktop meant to be locked when its client went away stayed unlocked
    /// for the next connection.
    #[tokio::test]
    async fn run_connection_runs_the_embedders_teardown() {
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let ended = Arc::new(AtomicUsize::new(0));
        let peer = Arc::new(std::sync::Mutex::new(None));
        server.connection_handler = Some(Box::new(CountingHandler {
            ended: Arc::clone(&ended),
            peer: Arc::clone(&peer),
        }));
        let told: SocketAddr = "203.0.113.7:51000".parse().expect("an address");
        server.set_peer_addr(Some(told));

        let (client, server_side) = tokio::io::duplex(64);
        drop(client);
        let _ = server.run_connection(server_side).await;

        assert_eq!(
            ended.load(Ordering::Relaxed),
            1,
            "exactly one teardown per connection — none at all was the bug, twice would be a new one"
        );
        assert_eq!(
            *peer.lock().unwrap_or_else(|p| p.into_inner()),
            Some(told),
            "the address the embedder accepted is the one it must be told about"
        );
    }

    /// MS-RDPEGFX 3.2.5.18: output drained before a mid-session
    /// CapsAdvertise is void once the new CapsConfirm is out, and so is
    /// output for a closed channel.
    ///
    /// Regression: the event loop wrote such batches after the confirm.
    #[cfg(feature = "egfx")]
    #[test]
    fn egfx_output_goes_out_only_in_the_generation_it_was_drained_in() {
        use ironrdp_dvc::DvcProcessor as _;
        use ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, CapabilitySet};
        use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};

        struct Handler;

        impl GraphicsPipelineHandler for Handler {
            fn capabilities_advertise(&mut self, _pdu: &CapabilitiesAdvertisePdu) {}
            fn on_ready(&mut self, _negotiated: &CapabilitySet) {}
        }

        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let pipeline = Arc::new(std::sync::Mutex::new(GraphicsPipelineServer::new(Box::new(Handler))));
        let drained_in = pipeline.lock().expect("pipeline").generation();
        assert!(
            !server.egfx_output_is_current(drained_in),
            "no pipeline on this connection"
        );

        server.gfx_handle = Some(Arc::clone(&pipeline));
        assert!(server.egfx_output_is_current(drained_in));

        pipeline.lock().expect("pipeline").close(0);
        assert!(!server.egfx_output_is_current(drained_in));
    }

    /// Without being told, there is no address to invent.
    #[tokio::test]
    async fn an_unknown_peer_is_reported_as_unspecified() {
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_no_display()
            .build();

        let ended = Arc::new(AtomicUsize::new(0));
        let peer = Arc::new(std::sync::Mutex::new(None));
        server.connection_handler = Some(Box::new(CountingHandler {
            ended: Arc::clone(&ended),
            peer: Arc::clone(&peer),
        }));

        let (client, server_side) = tokio::io::duplex(64);
        drop(client);
        let _ = server.run_connection(server_side).await;

        assert_eq!(ended.load(Ordering::Relaxed), 1);
        assert!(
            peer.lock().unwrap_or_else(|p| p.into_inner()).is_some_and(|p| p.ip().is_unspecified()),
            "an unknown peer is unspecified, not a plausible-looking address"
        );
    }

    /// Records the areas the server asks the display to draw again.
    struct RefreshRecorder(Arc<std::sync::Mutex<Vec<InclusiveRectangle>>>);

    #[async_trait::async_trait]
    impl RdpServerDisplay for RefreshRecorder {
        async fn size(&mut self) -> DesktopSize {
            DesktopSize { width: 64, height: 48 }
        }

        async fn updates(&mut self) -> ServerResult<Box<dyn crate::RdpServerDisplayUpdates>> {
            Err(ServerError::reason("refresh recorder", "no updates"))
        }

        fn request_refresh(&mut self, areas: &[InclusiveRectangle]) {
            self.0.lock().expect("recorder").extend_from_slice(areas);
        }
    }

    /// A client Share Data PDU as it arrives on the I/O channel.
    fn io_channel_pdu(share_data_pdu: rdp::headers::ShareDataPdu) -> Vec<u8> {
        encode_vec(&rdp::headers::ShareControlHeader {
            share_id: 0,
            pdu_source: 1007,
            share_control_pdu: ShareControlPdu::Data(rdp::headers::ShareDataHeader {
                share_data_pdu,
                stream_priority: rdp::headers::StreamPriority::Medium,
                compression_flags: rdp::headers::CompressionFlags::empty(),
                compression_type: rdp::client_info::CompressionType::K8,
            }),
        })
        .expect("encode")
    }

    async fn receive(server: &mut RdpServer, share_data_pdu: rdp::headers::ShareDataPdu) {
        let user_data = io_channel_pdu(share_data_pdu);
        server
            .handle_io_channel_data(SendDataRequest {
                initiator_id: 1007,
                channel_id: 1003,
                user_data: user_data.as_slice().into(),
            })
            .await
            .expect("handled");
    }

    /// MS-RDPBCGR 3.3.5.11.1: after a Refresh Rect PDU "the server MUST send
    /// updated graphics data for the region specified by the PDU", and
    /// 3.3.5.11.2: output stopped by Suppress Output resumes. Both reach the
    /// display handler as areas to draw again.
    ///
    /// Regression: the server advertised Refresh Rect support but only
    /// cleared its suppress-output flag.
    #[tokio::test]
    async fn refresh_requests_reach_the_display() {
        use rdp::refresh_rectangle::RefreshRectanglePdu;
        use rdp::suppress_output::SuppressOutputPdu;

        let requested = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut server = RdpServer::builder()
            .with_addr(([127, 0, 0, 1], 0))
            .with_no_security()
            .with_no_input()
            .with_display_handler(RefreshRecorder(Arc::clone(&requested)))
            .build();
        let area = InclusiveRectangle {
            left: 8,
            top: 4,
            right: 23,
            bottom: 13,
        };
        let desktop = InclusiveRectangle {
            left: 0,
            top: 0,
            right: 63,
            bottom: 47,
        };

        receive(
            &mut server,
            rdp::headers::ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                areas_to_refresh: vec![area.clone()],
            }),
        )
        .await;
        assert_eq!(
            requested.lock().expect("recorder").as_slice(),
            core::slice::from_ref(&area)
        );

        // Output that was never stopped owes the client nothing.
        let allow = || {
            rdp::headers::ShareDataPdu::SuppressOutput(SuppressOutputPdu {
                desktop_rect: Some(desktop.clone()),
            })
        };
        receive(&mut server, allow()).await;
        assert_eq!(requested.lock().expect("recorder").len(), 1);

        receive(
            &mut server,
            rdp::headers::ShareDataPdu::SuppressOutput(SuppressOutputPdu { desktop_rect: None }),
        )
        .await;
        receive(&mut server, allow()).await;
        assert_eq!(*requested.lock().expect("recorder"), [area, desktop.clone()]);
    }
}
