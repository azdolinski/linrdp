use core::any::TypeId;
use core::mem;

use ironrdp_connector::{
    ConnectorError, ConnectorErrorExt as _, ConnectorResult, DesktopSize, MonotonicInstant, Sequence, State, Written,
    encode_x224_packet, general_err, reason_err,
};
use ironrdp_core::{WriteBuf, decode};
use ironrdp_pdu as pdu;
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::x224::X224;
use ironrdp_svc::{MAX_STATIC_CHANNELS, StaticChannelKey, StaticChannelSet, SvcServerProcessor};
use pdu::rdp::capability_sets::CapabilitySet;
use pdu::rdp::client_info::{ClientAutoReconnect, Credentials};
use pdu::rdp::headers::ShareControlPdu;
use pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use pdu::rdp::server_license::{LicensePdu, LicensingErrorMessage};
use pdu::{gcc, mcs, nego, rdp};
use tracing::{debug, warn};

use super::channel_connection::ChannelConnectionSequence;
use super::finalization::FinalizationSequence;
use crate::util::{self, wrap_share_data};

const IO_CHANNEL_ID: u16 = 1003;
const USER_CHANNEL_ID: u16 = 1002;

pub struct Acceptor {
    pub(crate) state: AcceptorState,
    security: SecurityProtocol,
    /// Whether the RDP Negotiation Response announces
    /// DYNVC_GFX_PROTOCOL_SUPPORTED (section 2.2.1.2.1).
    graphics_pipeline_announce: bool,
    io_channel_id: u16,
    user_channel_id: u16,
    message_channel_id: Option<u16>,
    desktop_size: DesktopSize,
    keyboard_layout: u32,
    keyboard_type: gcc::KeyboardType,
    ime_file_name: String,
    client_cluster: Option<gcc::ClientClusterData>,
    multitransport_flags: gcc::MultiTransportFlags,
    early_capability_flags: gcc::ClientEarlyCapabilityFlags,
    server_capabilities: Vec<CapabilitySet>,
    static_channels: StaticChannelSet,
    saved_for_reactivation: AcceptorState,
    pub(crate) creds: Option<Credentials>,
    /// MS-NLMP per-account secret lookup (SAM-style), used by CredSSP/NTLM
    /// to resolve the password for the username the client presented.
    pub(crate) credential_resolver: Option<std::sync::Arc<dyn Fn(&str) -> std::io::Result<Credentials> + Send + Sync>>,
    received_credentials: Option<Credentials>,
    received_auto_reconnect: Option<ClientAutoReconnect>,
    reactivation: bool,
    honor_client_desktop_size: Option<DesktopSize>,
    /// Whether to announce UDP/FECR multitransport and Soft-Sync support in
    /// the server GCC blocks (TS_UD_SC_MULTITRANSPORT, section 2.2.1.4.6).
    /// Per 3.3.5.8 the server only bootstraps a multitransport it announced
    /// here.
    multitransport_announce: bool,
    /// The Initiate Multitransport Request to send in the Optional
    /// Multitransport Bootstrapping phase, if the server offers a tunnel.
    multitransport_request: Option<MultitransportRequest>,
    /// The requestId of the request actually sent on this connection.
    multitransport_request_sent: Option<u32>,
    /// What the client sent on the MCS message channel while the acceptor
    /// waited for something else, in order.
    message_channel_pdus: Vec<Vec<u8>>,
    /// Domain parameters merged from the client's MCS Connect Initial per
    /// 3.3.5.3.3, echoed back in the Connect Response.
    merged_domain_parameters: mcs::DomainParameters,
}

/// The server's offer of a sideband transport: the requestId and
/// securityCookie of its Initiate Multitransport Request PDU (MS-RDPBCGR
/// 2.2.15.1). The client repeats both over the new transport (MS-RDPEMT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultitransportRequest {
    pub request_id: u32,
    pub security_cookie: [u8; 16],
}

/// Minimum and maximum desktop dimension honored from a client.
///
/// A desktop dimension in RDP is a `u16`; [MS-RDPBCGR] caps it at 8192, and
/// 200 is a conservative floor. A client-requested dimension outside this
/// range is not honored: the acceptor keeps the server-provided desktop size
/// rather than treating the request as an error.
const MIN_DESKTOP_DIM: u16 = 200;
const MAX_DESKTOP_DIM: u16 = 8192;

/// Returns the client-requested desktop size if both dimensions are within the
/// protocol-legal range, otherwise `None`.
fn validate_desktop_size(width: u16, height: u16) -> Option<DesktopSize> {
    if (MIN_DESKTOP_DIM..=MAX_DESKTOP_DIM).contains(&width) && (MIN_DESKTOP_DIM..=MAX_DESKTOP_DIM).contains(&height) {
        Some(DesktopSize { width, height })
    } else {
        None
    }
}

/// Writes `size` into every Bitmap capability set in `capabilities`.
///
/// The server advertises its desktop size in the Bitmap capability set of the
/// Demand Active PDU; this keeps that advertisement in sync with `size`.
fn set_bitmap_desktop_size(capabilities: &mut [CapabilitySet], size: DesktopSize) {
    for cap in capabilities.iter_mut() {
        if let CapabilitySet::Bitmap(cap) = cap {
            cap.desktop_width = size.width;
            cap.desktop_height = size.height;
        }
    }
}

#[derive(Debug)]
pub struct AcceptorResult {
    pub static_channels: StaticChannelSet,
    pub capabilities: Vec<CapabilitySet>,
    pub input_events: Vec<Vec<u8>>,
    pub user_channel_id: u16,
    pub io_channel_id: u16,
    /// MCS channel ID of the message channel, present when the client requested
    /// one via Client Message Channel Data (section 2.2.1.3.7).
    ///
    /// Server-initiated PDUs that ride the message channel (network auto-detect
    /// per section 2.2.14, multitransport bootstrap, heartbeat) are sent on this
    /// channel. `None` when the client did not request it.
    pub message_channel_id: Option<u16>,
    pub reactivation: bool,
    /// Desktop size in effect for this connection (MS-RDPBCGR 2.2.1.3.2).
    ///
    /// With `set_honor_client_desktop_size` this is the size the client asked
    /// for, clamped to the configured maximum; otherwise it is the server's
    /// own configured size. A server that materializes a desktop per
    /// connection needs it to create one the client will not have to scale.
    pub desktop_size: DesktopSize,
    /// Keyboard layout identifier (KLID) announced by the client in its GCC
    /// Client Core Data (section 2.2.1.3.2, `keyboardLayout`).
    ///
    /// This is the low word of a Windows locale identifier (e.g. `0x0000_0409`
    /// for US English, `0x0000_040C` for French). `0` when the client did not
    /// announce one. Servers can use it to pick a server-side keyboard layout
    /// matching the client without changing any local input state.
    pub keyboard_layout: u32,
    /// Keyboard type announced by the client in its GCC Client Core Data
    /// (section 2.2.1.3.2, `keyboardType`).
    ///
    /// `KeyboardType(0)` when the client did not announce one (0 is not among the
    /// documented values, so it doubles as "unset" the same way `keyboard_layout`'s
    /// `0` does).
    pub keyboard_type: gcc::KeyboardType,
    /// Input method editor file name announced by the client in its GCC Client Core
    /// Data (section 2.2.1.3.2, `imeFileName`).
    ///
    /// Populated for East Asian IME-based input locales; empty otherwise.
    pub ime_file_name: String,
    /// Client Cluster Data (section 2.2.1.3.5), when the client sent it.
    ///
    /// `REDIRECTED_SESSIONID_FIELD_VALID` with a `RedirectedSessionID` asks
    /// for a particular existing session; clients set it for a console
    /// connection (`mstsc /admin`, FreeRDP `/admin`).
    pub client_cluster: Option<gcc::ClientClusterData>,
    /// Early capability flags announced by the client in its GCC Client Core
    /// Data (section 2.2.1.3.2, `earlyCapabilityFlags`).
    ///
    /// Empty when the client did not send the optional field. Servers use it
    /// to gate optional features the client has to opt into, e.g. Server
    /// Heartbeat PDUs (`RNS_UD_CS_SUPPORT_HEARTBEAT_PDU`, section 2.2.16.1).
    pub client_early_capability_flags: gcc::ClientEarlyCapabilityFlags,
    /// Multitransport (MS-RDPEMT) capability flags announced by the client in
    /// its GCC `MultiTransportChannelData` block (section 2.2.1.3.8).
    ///
    /// Empty when the client did not send a multitransport block. Servers that
    /// implement UDP multitransport can use it to decide whether to send a
    /// Server Initiate Multitransport Request.
    pub multitransport_flags: gcc::MultiTransportFlags,
    /// Credentials received from the client during SecureSettingsExchange.
    ///
    /// Present for TLS-mode connections where the client sends credentials
    /// in the ClientInfoPdu. `None` for CredSSP/Hybrid connections (where
    /// authentication happens during the CredSSP exchange instead).
    ///
    /// Servers that need to validate credentials (e.g., via PAM or LDAP)
    /// can use this field for post-handshake validation.
    pub credentials: Option<Credentials>,
    /// Client Auto-Reconnect Packet received in the Client Info PDU.
    ///
    /// This is present when the client resumes a session using an
    /// `ARC_CS_PRIVATE_PACKET`. The packet has already passed wire-format
    /// validation, but the server must still verify its security verifier
    /// against the reconnect random for the target session.
    pub auto_reconnect: Option<ClientAutoReconnect>,
    /// The requestId of the Initiate Multitransport Request sent during the
    /// connection sequence, if one was (see
    /// [`Acceptor::set_multitransport_request`]).
    pub multitransport_request_id: Option<u32>,
    /// What the client sent on the MCS message channel during the
    /// Capabilities Exchange and the Connection Finalization, in order: the
    /// Multitransport Response (section 2.2.15.2) can arrive then. Each entry
    /// is the user data of one MCS Send Data Request.
    pub message_channel_pdus: Vec<Vec<u8>>,
}

impl Acceptor {
    pub fn new(
        security: SecurityProtocol,
        desktop_size: DesktopSize,
        capabilities: Vec<CapabilitySet>,
        creds: Option<Credentials>,
    ) -> Self {
        Self::new_with_resolver(security, desktop_size, capabilities, creds, None)
    }

    /// Like [`Acceptor::new`], with an MS-NLMP per-account secret resolver
    /// (the SAM-style lookup used by CredSSP/NTLM to verify the password the
    /// client typed, for the username the client presented).
    pub fn new_with_resolver(
        security: SecurityProtocol,
        desktop_size: DesktopSize,
        capabilities: Vec<CapabilitySet>,
        creds: Option<Credentials>,
        credential_resolver: Option<std::sync::Arc<dyn Fn(&str) -> std::io::Result<Credentials> + Send + Sync>>,
    ) -> Self {
        Self {
            security,
            graphics_pipeline_announce: false,
            state: AcceptorState::InitiationWaitRequest,
            user_channel_id: USER_CHANNEL_ID,
            io_channel_id: IO_CHANNEL_ID,
            message_channel_id: None,
            desktop_size,
            keyboard_layout: 0,
            keyboard_type: gcc::KeyboardType(0),
            ime_file_name: String::new(),
            client_cluster: None,
            multitransport_flags: gcc::MultiTransportFlags::empty(),
            early_capability_flags: gcc::ClientEarlyCapabilityFlags::empty(),
            server_capabilities: capabilities,
            static_channels: StaticChannelSet::new(),
            saved_for_reactivation: Default::default(),
            creds,
            credential_resolver,
            received_credentials: None,
            received_auto_reconnect: None,
            reactivation: false,
            honor_client_desktop_size: None,
            multitransport_announce: false,
            multitransport_request: None,
            multitransport_request_sent: None,
            message_channel_pdus: Vec::new(),
            merged_domain_parameters: mcs::DomainParameters::target(),
        }
    }

    /// Announce DYNVC_GFX_PROTOCOL_SUPPORTED in the RDP Negotiation Response:
    /// "The server supports the Graphics Pipeline Extension Protocol described
    /// in [MS-RDPEGFX] sections 1, 2, and 3" ([MS-RDPBCGR] 2.2.1.2.1). The
    /// embedder enables it when it offers the graphics pipeline. Disabled by
    /// default.
    pub fn set_graphics_pipeline_announce(&mut self, announce: bool) {
        self.graphics_pipeline_announce = announce;
    }

    /// Adopt the desktop size requested by the client in its Client Core Data
    /// instead of the size this acceptor was constructed with, clamped to an
    /// operator-configured maximum.
    ///
    /// The client's requested resolution is only carried in the GCC Client
    /// Core Data of the MCS Connect Initial PDU; the desktop size echoed back
    /// later in the client's Confirm Active is, per [MS-RDPBCGR] 2.2.1.13.2,
    /// the value the client copied from the *server's* Demand Active, so it
    /// cannot be used to discover what the client originally asked for. When
    /// this is enabled, the client's request is first clamped per dimension to
    /// the operator maximum and then validated against the protocol-legal range;
    /// if the clamped size is legal the acceptor negotiates it from the start (it
    /// is written into the server's Bitmap capability set before Demand Active is
    /// sent), avoiding a Deactivation-Reactivation resize round trip.
    ///
    /// Pass `Some(max)` to honor the client's request, clamped per dimension to
    /// `max`: the client can ask for a *smaller* desktop than `max`, but never a
    /// larger one. The desktop size is a client-controlled `u16` bounded only by
    /// the protocol ([200, 8192]); without a ceiling, a client could request
    /// e.g. 8192×8192 and drive the server's framebuffer/encoder allocation off
    /// that untrusted number (~256 MiB per frame buffer). `max` is that ceiling
    /// — set it to what the server is actually willing to render (for instance
    /// the host display's native resolution). Pass `None` to disable honoring
    /// entirely and always enforce the server-provided size.
    ///
    /// `None` is the default, preserving the previous behavior of always
    /// enforcing the server-provided size.
    ///
    /// # Precondition
    ///
    /// Enabling this only makes sense together with a display handler
    /// ([`RdpServerDisplay`]) whose `request_initial_size` actually adopts (or
    /// at least intersects) the size it is given. The acceptor negotiates the
    /// client's size, but the server still builds its framebuffer/encoder from
    /// the size the display handler reports; if that handler ignores the
    /// requested size and returns a fixed, smaller framebuffer, the resulting
    /// mismatch can cause the client to be dropped. With a fixed-size display
    /// handler, leave this disabled.
    ///
    /// [`RdpServerDisplay`]: <https://docs.rs/ironrdp-server/latest/ironrdp_server/trait.RdpServerDisplay.html>
    pub fn set_honor_client_desktop_size(&mut self, max: Option<DesktopSize>) {
        self.honor_client_desktop_size = max;
    }

    /// Announce UDP/FECR multitransport and Soft-Sync support in the server
    /// GCC blocks (TS_UD_SC_MULTITRANSPORT, section 2.2.1.4.6).
    ///
    /// [MS-RDPBCGR] 3.3.5.8 ties the later Server Initiate Multitransport
    /// Request to this announcement: a compliant client may reject a
    /// transport the server never advertised, so the embedder must enable
    /// this whenever it intends to bootstrap RDP-UDP. Disabled by default.
    ///
    /// Soft-Sync (`SOFTSYNC_TCP_TO_UDP`) comes with it: the server moves its
    /// dynamic channels to the tunnel with a Soft-Sync Request, which
    /// [MS-RDPEDYC] 3.1.5.3 allows only when both sides announce it, and a
    /// client may answer the Initiate Multitransport Request with S_OK only
    /// to a server that announced it (2.2.15.2).
    pub fn set_multitransport_announce(&mut self, announce: bool) {
        self.multitransport_announce = announce;
    }

    /// Offer the client a sideband transport (MS-RDPEMT) in the Optional
    /// Multitransport Bootstrapping phase ([MS-RDPBCGR] 1.3.1.1): after
    /// Licensing and before the Capabilities Exchange, the acceptor sends an
    /// Initiate Multitransport Request with these values on the MCS message
    /// channel (2.2.15.1).
    ///
    /// It goes only to a client that joined a message channel and announced
    /// reliable UDP with Soft-Sync. Dynamic channels move to a tunnel only by
    /// Soft-Sync ([MS-RDPEDYC] 3.1.5.3), so for any other client the tunnel
    /// would carry nothing. Use with [`Self::set_multitransport_announce`].
    pub fn set_multitransport_request(&mut self, request: Option<MultitransportRequest>) {
        self.multitransport_request = request;
    }

    /// The request to send in the Optional Multitransport Bootstrapping phase
    /// of this connection, with the message channel it goes on.
    fn multitransport_bootstrap(&self) -> Option<(MultitransportRequest, u16)> {
        let request = self.multitransport_request?;
        let message_channel_id = self.message_channel_id?;
        let wanted = gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR | gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP;
        if !self.multitransport_flags.contains(wanted) {
            debug!(client_flags = ?self.multitransport_flags, "Client does not announce reliable UDP with Soft-Sync; staying TCP-only");
            return None;
        }
        Some((request, message_channel_id))
    }

    pub fn new_deactivation_reactivation(
        mut consumed: Acceptor,
        static_channels: StaticChannelSet,
        desktop_size: DesktopSize,
    ) -> ConnectorResult<Self> {
        let AcceptorState::CapabilitiesSendServer {
            early_capability,
            channels,
        } = consumed.saved_for_reactivation
        else {
            return Err(general_err!("invalid acceptor state"));
        };

        set_bitmap_desktop_size(&mut consumed.server_capabilities, desktop_size);
        let state = AcceptorState::CapabilitiesSendServer {
            early_capability,
            channels: channels.clone(),
        };
        let saved_for_reactivation = AcceptorState::CapabilitiesSendServer {
            early_capability,
            channels,
        };
        Ok(Self {
            security: consumed.security,
            graphics_pipeline_announce: consumed.graphics_pipeline_announce,
            state,
            user_channel_id: consumed.user_channel_id,
            io_channel_id: consumed.io_channel_id,
            message_channel_id: consumed.message_channel_id,
            desktop_size,
            keyboard_layout: consumed.keyboard_layout,
            keyboard_type: consumed.keyboard_type,
            ime_file_name: consumed.ime_file_name,
            client_cluster: consumed.client_cluster,
            multitransport_flags: consumed.multitransport_flags,
            early_capability_flags: consumed.early_capability_flags,
            server_capabilities: consumed.server_capabilities,
            static_channels,
            saved_for_reactivation,
            creds: consumed.creds,
            credential_resolver: consumed.credential_resolver,
            received_credentials: consumed.received_credentials,
            received_auto_reconnect: consumed.received_auto_reconnect,
            reactivation: true,
            honor_client_desktop_size: consumed.honor_client_desktop_size,
            multitransport_announce: consumed.multitransport_announce,
            // The request belongs to the connection sequence, not to an
            // activation: a Deactivation-Reactivation Sequence (1.3.1.3) does
            // not repeat it.
            multitransport_request: None,
            multitransport_request_sent: None,
            message_channel_pdus: Vec::new(),
            merged_domain_parameters: mcs::DomainParameters::target(),
        })
    }

    pub fn attach_static_channel<T>(&mut self, channel: T)
    where
        T: SvcServerProcessor + 'static,
    {
        let channel_name = channel.channel_name();
        let channel_key = StaticChannelKey::Typed(TypeId::of::<T>());
        if self.static_channels.get_by_type::<T>().is_none() && self.static_channels.len() >= MAX_STATIC_CHANNELS {
            warn!(max_channels = MAX_STATIC_CHANNELS, "Static channel limit reached");
            return;
        }
        if let Some((existing_key, _)) = self.static_channels.get_by_channel_name_key(&channel_name)
            && existing_key != channel_key
        {
            warn!(?channel_name, "Static channel name is already registered");
            return;
        }
        self.static_channels.insert(channel);
    }

    /// Attaches a runtime-defined static virtual channel.
    ///
    /// This permits multiple instances of the same processor type, each with its own negotiated
    /// channel name. `false` means the static-channel limit was reached or the name is already
    /// registered.
    pub fn attach_dynamic_static_channel<T>(&mut self, channel: T) -> bool
    where
        T: SvcServerProcessor + 'static,
    {
        let channel_name = channel.channel_name();
        if self.static_channels.len() >= MAX_STATIC_CHANNELS
            || self.static_channels.get_by_channel_name_key(&channel_name).is_some()
        {
            return false;
        }

        self.static_channels.insert_dynamic(channel).is_some()
    }

    pub fn reached_security_upgrade(&self) -> Option<SecurityProtocol> {
        match self.state {
            AcceptorState::SecurityUpgrade { .. } => Some(self.security),
            _ => None,
        }
    }

    /// # Panics
    ///
    /// Panics if state is not [AcceptorState::SecurityUpgrade].
    pub fn mark_security_upgrade_as_done(&mut self) {
        assert!(self.reached_security_upgrade().is_some());
        self.step(&[], None, &mut WriteBuf::new())
            .expect("transition to next state");
        debug_assert!(self.reached_security_upgrade().is_none());
    }

    pub fn should_perform_credssp(&self) -> bool {
        matches!(self.state, AcceptorState::Credssp { .. })
    }

    /// # Panics
    ///
    /// Panics if state is not [AcceptorState::Credssp].
    pub fn mark_credssp_as_done(&mut self) {
        assert!(self.should_perform_credssp());
        let res = self
            .step(&[], None, &mut WriteBuf::new())
            .expect("transition to next state");
        debug_assert!(!self.should_perform_credssp());
        assert_eq!(res, Written::Nothing);
    }

    pub fn get_result(&mut self) -> Option<AcceptorResult> {
        match mem::take(&mut self.state) {
            AcceptorState::Accepted {
                channels: _channels, // TODO: what about ChannelDef?
                client_capabilities,
                input_events,
            } => Some(AcceptorResult {
                static_channels: mem::take(&mut self.static_channels),
                capabilities: client_capabilities,
                input_events,
                user_channel_id: self.user_channel_id,
                io_channel_id: self.io_channel_id,
                message_channel_id: self.message_channel_id,
                desktop_size: self.desktop_size,
                keyboard_layout: self.keyboard_layout,
                keyboard_type: self.keyboard_type,
                ime_file_name: self.ime_file_name.clone(),
                client_cluster: self.client_cluster.clone(),
                multitransport_flags: self.multitransport_flags,
                client_early_capability_flags: self.early_capability_flags,
                reactivation: self.reactivation,
                credentials: self.received_credentials.take(),
                auto_reconnect: self.received_auto_reconnect.take(),
                multitransport_request_id: self.multitransport_request_sent,
                message_channel_pdus: mem::take(&mut self.message_channel_pdus),
            }),
            previous_state => {
                self.state = previous_state;
                None
            }
        }
    }
}

#[derive(Default, Debug)]
pub enum AcceptorState {
    #[default]
    Consumed,

    InitiationWaitRequest,
    InitiationSendConfirm {
        requested_protocol: SecurityProtocol,
        /// Whether the client's X.224 Connection Request carried an RDP
        /// Negotiation Request (rdpNegData). MS-RDPBCGR 3.3.5.3.2: when it
        /// did not, the Confirm MUST NOT carry negotiation data either.
        nego_present: bool,
    },
    SecurityUpgrade {
        requested_protocol: SecurityProtocol,
        protocol: SecurityProtocol,
    },
    Credssp {
        requested_protocol: SecurityProtocol,
        protocol: SecurityProtocol,
    },
    BasicSettingsWaitInitial {
        requested_protocol: SecurityProtocol,
        protocol: SecurityProtocol,
    },
    BasicSettingsSendResponse {
        requested_protocol: SecurityProtocol,
        protocol: SecurityProtocol,
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, Option<gcc::ChannelDef>)>,
    },
    ChannelConnection {
        protocol: SecurityProtocol,
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, gcc::ChannelDef)>,
        connection: ChannelConnectionSequence,
    },
    RdpSecurityCommencement {
        protocol: SecurityProtocol,
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    SecureSettingsExchange {
        protocol: SecurityProtocol,
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    LicensingExchange {
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    MultitransportBootstrapping {
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    CapabilitiesSendServer {
        early_capability: Option<gcc::ClientEarlyCapabilityFlags>,
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    MonitorLayoutSend {
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    CapabilitiesWaitConfirm {
        channels: Vec<(u16, gcc::ChannelDef)>,
    },
    ConnectionFinalization {
        finalization: FinalizationSequence,
        channels: Vec<(u16, gcc::ChannelDef)>,
        client_capabilities: Vec<CapabilitySet>,
    },
    Accepted {
        channels: Vec<(u16, gcc::ChannelDef)>,
        client_capabilities: Vec<CapabilitySet>,
        input_events: Vec<Vec<u8>>,
    },
}

impl State for AcceptorState {
    fn name(&self) -> &'static str {
        match self {
            Self::Consumed => "Consumed",
            Self::InitiationWaitRequest => "InitiationWaitRequest",
            Self::InitiationSendConfirm { .. } => "InitiationSendConfirm",
            Self::SecurityUpgrade { .. } => "SecurityUpgrade",
            Self::Credssp { .. } => "Credssp",
            Self::BasicSettingsWaitInitial { .. } => "BasicSettingsWaitInitial",
            Self::BasicSettingsSendResponse { .. } => "BasicSettingsSendResponse",
            Self::ChannelConnection { .. } => "ChannelConnection",
            Self::RdpSecurityCommencement { .. } => "RdpSecurityCommencement",
            Self::SecureSettingsExchange { .. } => "SecureSettingsExchange",
            Self::LicensingExchange { .. } => "LicensingExchange",
            Self::MultitransportBootstrapping { .. } => "MultitransportBootstrapping",
            Self::CapabilitiesSendServer { .. } => "CapabilitiesSendServer",
            Self::MonitorLayoutSend { .. } => "MonitorLayoutSend",
            Self::CapabilitiesWaitConfirm { .. } => "CapabilitiesWaitConfirm",
            Self::ConnectionFinalization { .. } => "ConnectionFinalization",
            Self::Accepted { .. } => "Connected",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Sequence for Acceptor {
    fn next_pdu_hint(&self) -> Option<&dyn pdu::PduHint> {
        match &self.state {
            AcceptorState::Consumed => None,
            AcceptorState::InitiationWaitRequest => Some(&pdu::X224_HINT),
            AcceptorState::InitiationSendConfirm { .. } => None,
            AcceptorState::SecurityUpgrade { .. } => None,
            AcceptorState::Credssp { .. } => None,
            AcceptorState::BasicSettingsWaitInitial { .. } => Some(&pdu::X224_HINT),
            AcceptorState::BasicSettingsSendResponse { .. } => None,
            AcceptorState::ChannelConnection { connection, .. } => connection.next_pdu_hint(),
            AcceptorState::RdpSecurityCommencement { .. } => None,
            AcceptorState::SecureSettingsExchange { .. } => Some(&pdu::X224_HINT),
            AcceptorState::LicensingExchange { .. } => None,
            AcceptorState::MultitransportBootstrapping { .. } => None,
            AcceptorState::CapabilitiesSendServer { .. } => None,
            AcceptorState::MonitorLayoutSend { .. } => None,
            AcceptorState::CapabilitiesWaitConfirm { .. } => Some(&pdu::X224_HINT),
            AcceptorState::ConnectionFinalization { finalization, .. } => finalization.next_pdu_hint(),
            AcceptorState::Accepted { .. } => None,
        }
    }

    fn state(&self) -> &dyn State {
        &self.state
    }

    fn step(
        &mut self,
        input: &[u8],
        received_at: Option<MonotonicInstant>,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let prev_state = mem::take(&mut self.state);

        let (written, next_state) = match prev_state {
            AcceptorState::InitiationWaitRequest => {
                let connection_request = decode::<X224<nego::ConnectionRequest>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;

                debug!(message = ?connection_request, "Received");

                (
                    Written::Nothing,
                    AcceptorState::InitiationSendConfirm {
                        requested_protocol: connection_request.protocol,
                        nego_present: connection_request.nego_data.is_some(),
                    },
                )
            }

            AcceptorState::InitiationSendConfirm {
                requested_protocol,
                nego_present,
            } => {
                let protocols = requested_protocol & self.security;
                let protocol = if protocols.intersects(SecurityProtocol::HYBRID_EX) {
                    SecurityProtocol::HYBRID_EX
                } else if protocols.intersects(SecurityProtocol::HYBRID) {
                    SecurityProtocol::HYBRID
                } else if protocols.intersects(SecurityProtocol::SSL) {
                    SecurityProtocol::SSL
                } else if self.security.is_empty() {
                    SecurityProtocol::empty()
                } else if !nego_present {
                    // The client sent no RDP Negotiation Request at all (a
                    // pre-negotiation client). MS-RDPBCGR 3.3.5.3.2: the
                    // rdpNegData field of the Confirm MUST be left empty for
                    // such clients — no RDP_NEG_FAILURE either. It can only
                    // mean Standard RDP Security, which this server does not
                    // offer, so answer with the empty Confirm and then drop
                    // the connection.
                    let confirm = nego::ConnectionConfirm::NoNegotiation;

                    debug!(message = ?confirm, "Send");

                    ironrdp_core::encode_buf(&X224(confirm), output).map_err(ConnectorError::encode)?;

                    return Err(reason_err!(
                        "security protocol mismatch",
                        "client sent no negotiation data and server requires {:?} (Standard RDP Security is not offered)",
                        self.security,
                    ));
                } else {
                    // No common security protocol. Send RDP_NEG_FAILURE so the client
                    // gets a well-formed response instead of a TCP reset (MS-RDPBCGR 2.2.1.2.2).
                    let failure_code = if self.security.intersects(SecurityProtocol::SSL) {
                        nego::FailureCode::SSL_REQUIRED_BY_SERVER
                    } else if self
                        .security
                        .intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX)
                    {
                        nego::FailureCode::HYBRID_REQUIRED_BY_SERVER
                    } else {
                        nego::FailureCode::SSL_REQUIRED_BY_SERVER
                    };

                    let failure = nego::ConnectionConfirm::Failure { code: failure_code };

                    debug!(message = ?failure, "Send");

                    ironrdp_core::encode_buf(&X224(failure), output).map_err(ConnectorError::encode)?;

                    return Err(reason_err!(
                        "security protocol mismatch",
                        "server requires {:?} but client only offered {:?}",
                        self.security,
                        requested_protocol,
                    ));
                };
                let mut flags = nego::ResponseFlags::EXTENDED_CLIENT_DATA_SUPPORTED;
                flags.set(
                    nego::ResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED,
                    self.graphics_pipeline_announce,
                );
                let connection_confirm = nego::ConnectionConfirm::Response { flags, protocol };

                debug!(message = ?connection_confirm, "Send");

                let written =
                    ironrdp_core::encode_buf(&X224(connection_confirm), output).map_err(ConnectorError::encode)?;

                (
                    Written::from_size(written)?,
                    AcceptorState::SecurityUpgrade {
                        requested_protocol,
                        protocol,
                    },
                )
            }

            AcceptorState::SecurityUpgrade {
                requested_protocol,
                protocol,
            } => {
                debug!(?requested_protocol);
                let next_state = if protocol.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
                    AcceptorState::Credssp {
                        requested_protocol,
                        protocol,
                    }
                } else {
                    AcceptorState::BasicSettingsWaitInitial {
                        requested_protocol,
                        protocol,
                    }
                };
                (Written::Nothing, next_state)
            }

            AcceptorState::Credssp {
                requested_protocol,
                protocol,
            } => (
                Written::Nothing,
                AcceptorState::BasicSettingsWaitInitial {
                    requested_protocol,
                    protocol,
                },
            ),

            AcceptorState::BasicSettingsWaitInitial {
                requested_protocol,
                protocol,
            } => {
                let x224_payload = decode::<X224<pdu::x224::X224Data<'_>>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;
                let settings_initial =
                    decode::<mcs::ConnectInitial>(x224_payload.data.as_ref()).map_err(ConnectorError::decode)?;

                debug!(message = ?settings_initial, "Received");

                // MS-RDPBCGR 3.3.5.3.3: merge the client's domain parameters
                // now (the Connect Response is built in a later state) and
                // drop the connection if the merge fails.
                let merged_domain_parameters = mcs::DomainParameters::merge(
                    &settings_initial.target_parameters,
                    &settings_initial.min_parameters,
                    &settings_initial.max_parameters,
                )
                .ok_or_else(|| {
                    reason_err!(
                        "BasicSettings",
                        "failed to merge the client's MCS domain parameters: {:?}",
                        settings_initial.target_parameters,
                    )
                })?;
                self.merged_domain_parameters = merged_domain_parameters;

                let gcc_blocks = settings_initial.conference_create_request.into_gcc_blocks();
                let early_capability = gcc_blocks.core.optional_data.early_capability_flags;
                self.early_capability_flags = early_capability.unwrap_or(gcc::ClientEarlyCapabilityFlags::empty());
                let client_wants_message_channel = gcc_blocks.message_channel.is_some();
                self.keyboard_layout = gcc_blocks.core.keyboard_layout;
                self.keyboard_type = gcc_blocks.core.keyboard_type;
                self.ime_file_name.clone_from(&gcc_blocks.core.ime_file_name);
                self.client_cluster.clone_from(&gcc_blocks.cluster);
                self.multitransport_flags = gcc_blocks
                    .multi_transport_channel
                    .as_ref()
                    .map(|m| m.flags)
                    .unwrap_or_else(gcc::MultiTransportFlags::empty);

                // Adopt the client's requested desktop size (from its Client
                // Core Data) before Demand Active is sent, so the session is
                // negotiated at that size without a Deactivation-Reactivation
                // resize. The request is clamped to the operator-configured
                // maximum first, so an untrusted client can't drive the
                // framebuffer/encoder allocation past that ceiling. See
                // `set_honor_client_desktop_size`.
                if let Some(max) = self.honor_client_desktop_size {
                    let requested_width = gcc_blocks.core.desktop_width;
                    let requested_height = gcc_blocks.core.desktop_height;
                    let clamped_width = requested_width.min(max.width);
                    let clamped_height = requested_height.min(max.height);
                    if let Some(client_size) = validate_desktop_size(clamped_width, clamped_height) {
                        if client_size != self.desktop_size {
                            debug!(
                                requested = ?DesktopSize { width: requested_width, height: requested_height },
                                max = ?max,
                                adopted = ?client_size,
                                previous = ?self.desktop_size,
                                "Honoring client-requested desktop size (clamped to operator maximum)"
                            );
                            self.desktop_size = client_size;
                            set_bitmap_desktop_size(&mut self.server_capabilities, client_size);
                        }
                    } else {
                        debug!(
                            requested = ?DesktopSize { width: requested_width, height: requested_height },
                            clamped = ?DesktopSize { width: clamped_width, height: clamped_height },
                            max = ?max,
                            "Client-requested desktop size is out of protocol range after clamping to the operator maximum; keeping the server-provided size"
                        );
                    }
                }

                let joined: Vec<_> = gcc_blocks
                    .network
                    .map(|network| {
                        network
                            .channels
                            .into_iter()
                            .map(|c| {
                                self.static_channels
                                    .get_by_channel_name_key(&c.name)
                                    .map(|(key, _)| (key, c))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                #[expect(clippy::arithmetic_side_effects)] // IO channel ID is not big enough for overflowing.
                let channels: Vec<_> = joined
                    .into_iter()
                    .enumerate()
                    .map(|(i, channel)| {
                        let channel_id = u16::try_from(i).expect("always in the range") + self.io_channel_id + 1;
                        if let Some((key, c)) = channel {
                            self.static_channels.attach_channel_id_by_key(key, channel_id);
                            (channel_id, Some(c))
                        } else {
                            (channel_id, None)
                        }
                    })
                    .collect();

                if client_wants_message_channel {
                    // Allocate the message channel ID after the I/O channel and
                    // any static virtual channels. It is advertised in Server
                    // Message Channel Data and joined alongside the others.
                    #[expect(clippy::arithmetic_side_effects)] // IO channel ID is not big enough for overflowing.
                    let channel_id =
                        u16::try_from(channels.len()).expect("always in the range") + self.io_channel_id + 1;
                    self.message_channel_id = Some(channel_id);
                }

                (
                    Written::Nothing,
                    AcceptorState::BasicSettingsSendResponse {
                        requested_protocol,
                        protocol,
                        early_capability,
                        channels,
                    },
                )
            }

            AcceptorState::BasicSettingsSendResponse {
                requested_protocol,
                protocol,
                early_capability,
                channels,
            } => {
                let channel_ids: Vec<u16> = channels.iter().map(|&(i, _)| i).collect();

                let skip_channel_join = early_capability
                    .is_some_and(|client| client.contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_SKIP_CHANNELJOIN));

                let server_blocks = create_gcc_blocks(
                    self.io_channel_id,
                    channel_ids.clone(),
                    requested_protocol,
                    skip_channel_join,
                    self.message_channel_id,
                    self.multitransport_announce,
                );

                let settings_response = mcs::ConnectResponse {
                    conference_create_response: gcc::ConferenceCreateResponse::new(self.user_channel_id, server_blocks)
                        .map_err(ConnectorError::decode)?,
                    called_connect_id: 1,
                    // Merged from the client's Connect Initial per 3.3.5.3.3
                    // (captured in `BasicSettingsWaitInitial`).
                    domain_parameters: self.merged_domain_parameters.clone(),
                };

                debug!(message = ?settings_response, "Send");

                let written = encode_x224_packet(&settings_response, output)?;
                let channels = channels.into_iter().filter_map(|(i, c)| c.map(|c| (i, c))).collect();

                (
                    Written::from_size(written)?,
                    AcceptorState::ChannelConnection {
                        protocol,
                        early_capability,
                        channels,
                        connection: if skip_channel_join {
                            ChannelConnectionSequence::skip_channel_join(self.user_channel_id)
                        } else {
                            let mut join_channel_ids = channel_ids;
                            join_channel_ids.extend(self.message_channel_id);
                            ChannelConnectionSequence::new(self.user_channel_id, self.io_channel_id, join_channel_ids)
                        },
                    },
                )
            }

            AcceptorState::ChannelConnection {
                protocol,
                early_capability,
                channels,
                mut connection,
            } => {
                let written = connection.step(input, received_at, output)?;
                let state = if connection.is_done() {
                    AcceptorState::RdpSecurityCommencement {
                        protocol,
                        early_capability,
                        channels,
                    }
                } else {
                    AcceptorState::ChannelConnection {
                        protocol,
                        early_capability,
                        channels,
                        connection,
                    }
                };

                (written, state)
            }

            AcceptorState::RdpSecurityCommencement {
                protocol,
                early_capability,
                channels,
                ..
            } => (
                Written::Nothing,
                AcceptorState::SecureSettingsExchange {
                    protocol,
                    early_capability,
                    channels,
                },
            ),

            AcceptorState::SecureSettingsExchange {
                protocol,
                early_capability,
                channels,
            } => {
                let data: X224<mcs::SendDataRequest<'_>> = decode(input).map_err(ConnectorError::decode)?;
                let data = data.0;
                let client_info: rdp::ClientInfoPdu =
                    decode(data.user_data.as_ref()).map_err(ConnectorError::decode)?;

                let auto_reconnect = client_info
                    .client_info
                    .extra_info
                    .optional_data
                    .auto_reconnect()
                    .cloned();
                // What the client actually sent, so "logon failed" can be told
                // apart from "the client sent nothing". Never the password:
                // only whether one is present.
                let (info_user, info_domain, info_password_len) = {
                    let c = &client_info.client_info.credentials;
                    (c.username.clone(), c.domain.clone(), c.password.len())
                };
                debug!(
                    has_auto_reconnect = auto_reconnect.is_some(),
                    username = %info_user,
                    domain = ?info_domain,
                    password_present = info_password_len > 0,
                    flags = ?client_info.client_info.flags,
                    "Received Client Info PDU"
                );
                self.received_auto_reconnect = auto_reconnect;

                if !protocol.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
                    let creds = client_info.client_info.credentials;

                    if let Some(expected) = &self.creds {
                        if expected != &creds {
                            // FIXME: How authorization should be denied with standard RDP security?
                            // Since standard RDP security is not a priority, we just send a ServerDeniedConnection ServerSetErrorInfo PDU.
                            // MS-RDPBCGR 3.3.5.7.1: only to clients that set
                            // RNS_UD_CS_SUPPORT_ERRINFO_PDU.
                            if self
                                .early_capability_flags
                                .contains(gcc::ClientEarlyCapabilityFlags::SUPPORT_ERR_INFO_PDU)
                            {
                                let info = rdp::headers::ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                                    ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::ServerDeniedConnection),
                                ));

                                debug!(message = ?info, "Send");

                                // MS-RDPBCGR 2.2.5.1.1: a whole Share Data PDU,
                                // and pduSource MUST be 0.
                                let share_data = wrap_share_data(info, 0);
                                util::encode_send_data_indication(
                                    self.user_channel_id,
                                    self.io_channel_id,
                                    &share_data,
                                    output,
                                )?;
                            }

                            return Err(ConnectorError::general("invalid credentials"));
                        }
                    }

                    // Store credentials for later retrieval via AcceptorResult.
                    self.received_credentials = Some(creds);
                }

                (
                    Written::Nothing,
                    AcceptorState::LicensingExchange {
                        early_capability,
                        channels,
                    },
                )
            }

            AcceptorState::LicensingExchange {
                early_capability,
                channels,
            } => {
                let license: LicensePdu = LicensingErrorMessage::new_valid_client()
                    .map_err(ConnectorError::encode)?
                    .into();

                debug!(message = ?license, "Send");

                let written =
                    util::encode_send_data_indication(self.user_channel_id, self.io_channel_id, &license, output)?;

                // A reactivation starts over at the Capabilities Exchange:
                // licensing and multitransport bootstrapping belong to the
                // connection sequence only (1.3.1.3).
                self.saved_for_reactivation = AcceptorState::CapabilitiesSendServer {
                    early_capability,
                    channels: channels.clone(),
                };

                let next_state = if self.multitransport_bootstrap().is_some() {
                    AcceptorState::MultitransportBootstrapping {
                        early_capability,
                        channels,
                    }
                } else {
                    AcceptorState::CapabilitiesSendServer {
                        early_capability,
                        channels,
                    }
                };

                (Written::from_size(written)?, next_state)
            }

            // 1.3.1.1, Optional Multitransport Bootstrapping: "After the
            // connection has been secured and the Licensing phase has run to
            // completion, the server can choose to initiate multitransport
            // connections." The request MUST go on the message channel
            // (2.2.15.1).
            AcceptorState::MultitransportBootstrapping {
                early_capability,
                channels,
            } => {
                let (request, message_channel_id) = self
                    .multitransport_bootstrap()
                    .ok_or_else(|| ConnectorError::general("no multitransport request to send"))?;
                let pdu = rdp::multitransport::MultitransportRequestPdu {
                    security_header: rdp::headers::BasicSecurityHeader {
                        flags: rdp::headers::BasicSecurityHeaderFlags::TRANSPORT_REQ,
                    },
                    request_id: request.request_id,
                    requested_protocol: rdp::multitransport::RequestedProtocol::UdpFecR,
                    security_cookie: request.security_cookie,
                };

                debug!(
                    request_id = request.request_id,
                    "Send Initiate Multitransport Request (UDP FECR)"
                );

                let written =
                    util::encode_send_data_indication(self.user_channel_id, message_channel_id, &pdu, output)?;
                self.multitransport_request_sent = Some(request.request_id);

                (
                    Written::from_size(written)?,
                    AcceptorState::CapabilitiesSendServer {
                        early_capability,
                        channels,
                    },
                )
            }

            AcceptorState::CapabilitiesSendServer {
                early_capability,
                channels,
            } => {
                let demand_active = rdp::headers::ShareControlHeader {
                    share_id: 0,
                    pdu_source: self.io_channel_id,
                    share_control_pdu: ShareControlPdu::ServerDemandActive(rdp::capability_sets::ServerDemandActive {
                        pdu: rdp::capability_sets::DemandActive {
                            source_descriptor: "".into(),
                            capability_sets: self.server_capabilities.clone(),
                        },
                    }),
                };

                debug!(message = ?demand_active, "Send");

                let written = util::encode_send_data_indication(
                    self.user_channel_id,
                    self.io_channel_id,
                    &demand_active,
                    output,
                )?;

                let layout_flag = gcc::ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU;
                let next_state = if early_capability.is_some_and(|c| c.contains(layout_flag)) {
                    AcceptorState::MonitorLayoutSend { channels }
                } else {
                    AcceptorState::CapabilitiesWaitConfirm { channels }
                };

                (Written::from_size(written)?, next_state)
            }

            AcceptorState::MonitorLayoutSend { channels } => {
                let monitor_layout =
                    rdp::headers::ShareDataPdu::MonitorLayout(rdp::finalization_messages::MonitorLayoutPdu {
                        monitors: vec![gcc::Monitor {
                            left: 0,
                            top: 0,
                            right: i32::from(self.desktop_size.width) - 1,
                            bottom: i32::from(self.desktop_size.height) - 1,
                            flags: gcc::MonitorFlags::PRIMARY,
                        }],
                    });

                debug!(message = ?monitor_layout, "Send");

                let share_data = wrap_share_data(monitor_layout, self.io_channel_id);

                let written =
                    util::encode_send_data_indication(self.user_channel_id, self.io_channel_id, &share_data, output)?;

                (
                    Written::from_size(written)?,
                    AcceptorState::CapabilitiesWaitConfirm { channels },
                )
            }

            AcceptorState::CapabilitiesWaitConfirm { ref channels } => {
                let message = decode::<X224<mcs::McsMessage<'_>>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0);
                let message = match message {
                    Ok(msg) => msg,
                    Err(e) => {
                        if self.reactivation {
                            debug!("Dropping unexpected PDU during reactivation");
                            self.state = prev_state;
                            return Ok(Written::Nothing);
                        } else {
                            return Err(e);
                        }
                    }
                };
                match message {
                    // The Multitransport Response (2.2.15.2), and anything
                    // else the client says on the message channel, can come
                    // before the Confirm Active: kept for the server, not
                    // taken for the Confirm Active.
                    mcs::McsMessage::SendDataRequest(data) if Some(data.channel_id) == self.message_channel_id => {
                        debug!("message channel PDU during the capabilities exchange; kept for the server");
                        self.message_channel_pdus.push(data.user_data.to_vec());

                        (Written::Nothing, prev_state)
                    }

                    mcs::McsMessage::SendDataRequest(data) => {
                        let capabilities_confirm = decode::<rdp::headers::ShareControlHeader>(data.user_data.as_ref())
                            .map_err(ConnectorError::decode);
                        let capabilities_confirm = match capabilities_confirm {
                            Ok(capabilities_confirm) => capabilities_confirm,
                            Err(e) => {
                                if self.reactivation {
                                    debug!("Dropping unexpected PDU during reactivation");
                                    self.state = prev_state;
                                    return Ok(Written::Nothing);
                                } else {
                                    return Err(e);
                                }
                            }
                        };

                        debug!(message = ?capabilities_confirm, "Received");

                        // MS-RDPBCGR 2.2.1.13.2: the Confirm Active PDU's
                        // originatorId MUST be 0x03EA. Log rather than drop:
                        // strict rejection would break otherwise-working
                        // clients over a field they echo from our PDUs.
                        if capabilities_confirm.pdu_source != rdp::capability_sets::SERVER_CHANNEL_ID {
                            tracing::warn!(
                                originator_id = capabilities_confirm.pdu_source,
                                "client Confirm Active has a non-conforming originatorId (MUST be 0x03EA)"
                            );
                        }

                        let ShareControlPdu::ClientConfirmActive(confirm) = capabilities_confirm.share_control_pdu
                        else {
                            return Err(ConnectorError::general("expected client confirm active"));
                        };

                        (
                            Written::Nothing,
                            AcceptorState::ConnectionFinalization {
                                channels: channels.clone(),
                                finalization: FinalizationSequence::new(
                                    self.user_channel_id,
                                    self.io_channel_id,
                                    self.message_channel_id,
                                ),
                                client_capabilities: confirm.pdu.capability_sets,
                            },
                        )
                    }

                    mcs::McsMessage::DisconnectProviderUltimatum(ultimatum) => {
                        return Err(reason_err!("received disconnect ultimatum", "{:?}", ultimatum.reason));
                    }

                    _ => {
                        warn!(?message, "Unexpected MCS message received");

                        (Written::Nothing, prev_state)
                    }
                }
            }

            AcceptorState::ConnectionFinalization {
                mut finalization,
                channels,
                client_capabilities,
            } => {
                let written = finalization.step(input, received_at, output)?;

                let state = if finalization.is_done() {
                    let (input_events, message_channel_pdus) = finalization.into_received();
                    self.message_channel_pdus.extend(message_channel_pdus);
                    AcceptorState::Accepted {
                        channels,
                        client_capabilities,
                        input_events,
                    }
                } else {
                    AcceptorState::ConnectionFinalization {
                        finalization,
                        channels,
                        client_capabilities,
                    }
                };

                (written, state)
            }

            _ => unreachable!(),
        };

        self.state = next_state;
        Ok(written)
    }
}

fn create_gcc_blocks(
    io_channel: u16,
    channel_ids: Vec<u16>,
    requested: SecurityProtocol,
    skip_channel_join: bool,
    message_channel_id: Option<u16>,
    multitransport_announce: bool,
) -> gcc::ServerGccBlocks {
    gcc::ServerGccBlocks {
        core: gcc::ServerCoreData {
            // Announce an RDP 10.7-era server (Server 2022/Win11 class): mstsc
            // gates client-side features on the server version — notably its
            // SYN offered RDP-UDP v1/v2 while this announced V5_PLUS
            // (0x00080004), and version 3 of the UDP protocol (RDP-UDP2) is
            // what this server implements.
            version: gcc::RdpVersion::V10_7,
            optional_data: gcc::ServerCoreOptionalData {
                client_requested_protocols: Some(requested),
                early_capability_flags: skip_channel_join
                    .then_some(gcc::ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED),
            },
        },
        security: gcc::ServerSecurityData::no_security(),
        network: gcc::ServerNetworkData {
            channel_ids,
            io_channel,
        },
        message_channel: message_channel_id.map(|id| gcc::ServerMessageChannelData {
            mcs_message_channel_id: id,
        }),
        // TS_UD_SC_MULTITRANSPORT (2.2.1.4.6): announce the UDP/FECR
        // transport the server is prepared to bootstrap (3.3.5.8), and
        // Soft-Sync, the only way this server moves dynamic channels to it
        // ([MS-RDPEDYC] 3.1.5.3).
        multi_transport_channel: multitransport_announce.then(|| gcc::MultiTransportChannelData {
            flags: gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR | gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_blocks(multitransport_announce: bool) -> gcc::ServerGccBlocks {
        create_gcc_blocks(
            1003,
            vec![1004],
            SecurityProtocol::HYBRID,
            false,
            Some(1005),
            multitransport_announce,
        )
    }

    /// MS-RDPEDYC 3.1.5.3: "Soft-Sync MUST NOT be used unless it is supported
    /// by both the server and client", each saying so with
    /// SOFTSYNC_TCP_TO_UDP in its multitransport block. MS-RDPBCGR 2.2.15.2:
    /// S_OK "MUST only be sent to a server that advertises" it.
    ///
    /// Regression: the server announced UDP/FECR alone, yet waited for S_OK
    /// and then sent a Soft-Sync Request.
    #[test]
    fn a_multitransport_server_announces_soft_sync() {
        let blocks = server_blocks(true);
        let flags = blocks.multi_transport_channel.expect("TS_UD_SC_MULTITRANSPORT").flags;

        assert_eq!(
            flags,
            gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR | gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP
        );
    }

    #[test]
    fn a_server_without_multitransport_announces_nothing() {
        assert!(server_blocks(false).multi_transport_channel.is_none());
    }

    fn acceptor_after_licensing(flags: gcc::MultiTransportFlags, message_channel_id: Option<u16>) -> Acceptor {
        let mut acceptor = Acceptor::new(
            SecurityProtocol::SSL,
            DesktopSize {
                width: 1024,
                height: 768,
            },
            Vec::new(),
            None,
        );
        acceptor.set_multitransport_announce(true);
        acceptor.set_multitransport_request(Some(MultitransportRequest {
            request_id: 7,
            security_cookie: [0x5A; 16],
        }));
        acceptor.multitransport_flags = flags;
        acceptor.message_channel_id = message_channel_id;
        acceptor.state = AcceptorState::LicensingExchange {
            early_capability: None,
            channels: Vec::new(),
        };
        acceptor
    }

    /// One step, and the MCS Send Data Indication it wrote: its channel and
    /// user data.
    fn step_and_read(acceptor: &mut Acceptor) -> (u16, Vec<u8>) {
        let mut output = WriteBuf::new();
        acceptor.step(&[], None, &mut output).expect("step");
        let X224(indication) = decode::<X224<mcs::SendDataIndication<'_>>>(output.filled()).expect("indication");
        (indication.channel_id, indication.user_data.to_vec())
    }

    fn is_demand_active(user_data: &[u8]) -> bool {
        matches!(
            decode::<rdp::headers::ShareControlHeader>(user_data).map(|pdu| pdu.share_control_pdu),
            Ok(ShareControlPdu::ServerDemandActive(_))
        )
    }

    const SOFT_SYNC_UDP: gcc::MultiTransportFlags =
        gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR.union(gcc::MultiTransportFlags::SOFT_SYNC_TCP_TO_UDP);

    /// MS-RDPBCGR 1.3.1.1: Licensing, then Optional Multitransport
    /// Bootstrapping, then the Capabilities Exchange. The request goes on the
    /// MCS message channel (2.2.15.1).
    ///
    /// Regression: the server sent it after the connection finalization.
    #[test]
    fn the_multitransport_request_goes_between_licensing_and_demand_active() {
        let mut acceptor = acceptor_after_licensing(SOFT_SYNC_UDP, Some(1008));

        let (channel, _) = step_and_read(&mut acceptor);
        assert_eq!(channel, acceptor.io_channel_id, "the licensing PDU");

        let (channel, user_data) = step_and_read(&mut acceptor);
        assert_eq!(channel, 1008, "on the message channel");
        let request = decode::<rdp::multitransport::MultitransportRequestPdu>(&user_data).expect("request");
        assert_eq!(request.request_id, 7);
        assert_eq!(request.security_cookie, [0x5A; 16]);

        let (channel, user_data) = step_and_read(&mut acceptor);
        assert_eq!(channel, acceptor.io_channel_id);
        assert!(is_demand_active(&user_data));
        assert_eq!(acceptor.multitransport_request_sent, Some(7));
    }

    /// No Soft-Sync, or no message channel to send it on: no request.
    #[test]
    fn no_multitransport_request_without_soft_sync_or_a_message_channel() {
        for (flags, message_channel_id) in [
            (gcc::MultiTransportFlags::TRANSPORT_TYPE_UDP_FECR, Some(1008)),
            (SOFT_SYNC_UDP, None),
        ] {
            let mut acceptor = acceptor_after_licensing(flags, message_channel_id);
            step_and_read(&mut acceptor);

            let (_, user_data) = step_and_read(&mut acceptor);
            assert!(is_demand_active(&user_data), "{flags:?}, {message_channel_id:?}");
            assert_eq!(acceptor.multitransport_request_sent, None);
        }
    }

    /// MS-RDPBCGR 1.3.1.3: a Deactivation-Reactivation Sequence repeats the
    /// Capabilities Exchange and the Connection Finalization, not the
    /// Optional Multitransport Bootstrapping.
    ///
    /// Regression: the server sent a new request after every activation.
    #[test]
    fn a_reactivation_sends_no_second_multitransport_request() {
        let mut acceptor = acceptor_after_licensing(SOFT_SYNC_UDP, Some(1008));
        step_and_read(&mut acceptor);

        let size = DesktopSize {
            width: 800,
            height: 600,
        };
        let mut reactivation =
            Acceptor::new_deactivation_reactivation(acceptor, StaticChannelSet::new(), size).expect("reactivation");

        let (channel, user_data) = step_and_read(&mut reactivation);
        assert_eq!(channel, reactivation.io_channel_id);
        assert!(is_demand_active(&user_data));
        assert_eq!(reactivation.multitransport_request_sent, None);
    }

    /// MS-RDPBCGR 2.2.15.2: the Multitransport Response can arrive while the
    /// acceptor waits for the Confirm Active. It is kept for the server, not
    /// taken for the Confirm Active.
    #[test]
    fn a_multitransport_response_before_the_confirm_active_is_kept() {
        let mut acceptor = acceptor_after_licensing(SOFT_SYNC_UDP, Some(1008));
        acceptor.state = AcceptorState::CapabilitiesWaitConfirm { channels: Vec::new() };
        let response = ironrdp_core::encode_vec(&rdp::multitransport::MultitransportResponsePdu {
            security_header: rdp::headers::BasicSecurityHeader {
                flags: rdp::headers::BasicSecurityHeaderFlags::TRANSPORT_RSP,
            },
            request_id: 7,
            hr_response: 0,
        })
        .expect("encode");
        let pdu = ironrdp_core::encode_vec(&X224(mcs::SendDataRequest {
            initiator_id: 1007,
            channel_id: 1008,
            user_data: response.as_slice().into(),
        }))
        .expect("encode");

        let mut output = WriteBuf::new();
        acceptor.step(&pdu, None, &mut output).expect("step");

        assert!(matches!(acceptor.state, AcceptorState::CapabilitiesWaitConfirm { .. }));
        assert_eq!(acceptor.message_channel_pdus, [response]);
    }
}
