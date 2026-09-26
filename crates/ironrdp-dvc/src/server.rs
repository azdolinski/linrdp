use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::any::TypeId;
use core::fmt;

use ironrdp_core::{Decode as _, DecodeResult, ReadCursor, impl_as_any, invalid_field_err};
use ironrdp_pdu::{self as pdu, PduError, decode_err, encode_err, pdu_other_err};
use ironrdp_svc::{ChannelFlags, CompressionCondition, SvcMessage, SvcProcessor, SvcServerProcessor};
use pdu::PduResult;
use pdu::gcc::ChannelName;
use tracing::{debug, warn};

use crate::pdu::{
    CapabilitiesRequestPdu, CapsVersion, ClosePdu, CreateRequestPdu, CreationStatus, DrdynvcClientPdu,
    DrdynvcServerPdu, SoftSyncChannelList, SoftSyncRequestPdu, SoftSyncTunnelType,
};
use crate::{CompleteData, DvcProcessor, DynamicChannelMut, DynamicChannelRef, encode_dvc_messages};

pub trait DvcServerProcessor: DvcProcessor {}


#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ChannelState {
    Pending,
    /// `Create Request` has been sent; awaiting `Create Response` from the client.
    Creation,
    Opened,
    CreationFailed(u32),
}

enum SoftSyncState {
    Idle,
    Active {
        requested_tunnels: BTreeSet<SoftSyncTunnelType>,
        response_received: bool,
    },
}

struct DynamicChannel {
    state: ChannelState,
    processor: Box<dyn DvcServerProcessor>,
    complete_data: CompleteData,
    channel_id: u32,
    /// The server asked to close the channel while its Create Request was
    /// still unanswered. The client already knows the ID, so the channel is
    /// closed on the wire as soon as the client confirms it.
    close_when_created: bool,
}

impl Drop for DynamicChannel {
    fn drop(&mut self) {
        if self.state == ChannelState::Opened {
            self.processor.close(self.channel_id);
        }
    }
}

struct DynamicChannelAllocator {
    dynamic_channels: BTreeMap<u32, DynamicChannel>,
    next_channel_id: u32,
}

impl<'a> IntoIterator for &'a DynamicChannelAllocator {
    type Item = (&'a u32, &'a DynamicChannel);

    type IntoIter = alloc::collections::btree_map::Iter<'a, u32, DynamicChannel>;

    fn into_iter(self) -> Self::IntoIter {
        self.dynamic_channels.iter()
    }
}

impl<'a> IntoIterator for &'a mut DynamicChannelAllocator {
    type Item = (&'a u32, &'a mut DynamicChannel);
    type IntoIter = alloc::collections::btree_map::IterMut<'a, u32, DynamicChannel>;
    fn into_iter(self) -> Self::IntoIter {
        self.dynamic_channels.iter_mut()
    }
}

impl DynamicChannelAllocator {
    fn new() -> Self {
        Self {
            dynamic_channels: BTreeMap::new(),
            next_channel_id: 0,
        }
    }

    fn reserve_channel(&mut self) -> u32 {
        let channel_id = self.next_channel_id;
        self.next_channel_id = self
            .next_channel_id
            .checked_add(1)
            .expect("dynamic channels reaches `u32::MAX`");
        channel_id
    }

    fn insert_channel<T>(&mut self, processor: T, state: ChannelState) -> u32
    where
        T: DvcServerProcessor + 'static,
    {
        let channel_id = self.reserve_channel();
        self.insert_channel_with_id(processor, state, channel_id);
        channel_id
    }

    fn insert_channel_with_id<T>(&mut self, processor: T, state: ChannelState, channel_id: u32)
    where
        T: DvcServerProcessor + 'static,
    {
        self.insert_boxed_with_id(Box::new(processor), state, channel_id);
    }

    fn insert_boxed_with_id(&mut self, processor: Box<dyn DvcServerProcessor>, state: ChannelState, channel_id: u32) {
        self.dynamic_channels
            .insert(channel_id, DynamicChannel::new(processor, channel_id, state));
    }

    fn get(&self, channel_id: u32) -> Option<&DynamicChannel> {
        self.dynamic_channels.get(&channel_id)
    }

    fn get_mut(&mut self, channel_id: u32) -> Option<&mut DynamicChannel> {
        self.dynamic_channels.get_mut(&channel_id)
    }

    fn remove(&mut self, channel_id: u32) -> Option<DynamicChannel> {
        self.dynamic_channels.remove(&channel_id)
    }
}

impl DynamicChannel {
    fn new(processor: Box<dyn DvcServerProcessor>, channel_id: u32, state: ChannelState) -> Self {
        Self {
            state,
            processor,
            complete_data: CompleteData::new(),
            channel_id,
            close_when_created: false,
        }
    }

    fn processor_type_id(&self) -> TypeId {
        self.processor.as_any().type_id()
    }
}
/// DRDYNVC Static Virtual Channel (the Remote Desktop Protocol: Dynamic Virtual Channel Extension)
///
/// It adds support for dynamic virtual channels (DVC).
pub struct DrdynvcServer {
    dynamic_channels: DynamicChannelAllocator,
    type_id_to_channel_id: BTreeMap<TypeId, u32>,
    /// Whether the client has answered the Capabilities Request.
    /// MS-RDPEDYC 2.2.1: the server MUST NOT create a channel before that.
    caps_received: bool,
    soft_sync_state: SoftSyncState,
    outgoing_tunnel_channels: BTreeMap<u32, SoftSyncTunnelType>,
    incoming_tunnel_channels: BTreeMap<u32, SoftSyncTunnelType>,
    /// Tunnel frames that arrived before the client's Soft-Sync Response,
    /// oldest first: MS-RDPEDYC 3.3.5.3.2 forbids reading them until then.
    early_tunnel_frames: Vec<Vec<u8>>,
}

/// How many tunnel frames may wait for the Soft-Sync Response. The client
/// sends the response before it writes to the tunnel, so only the ones that
/// overtake it on the way wait here.
const MAX_EARLY_TUNNEL_FRAMES: usize = 1024;

/// The channel a DRDYNVC data PDU (Data First, Data, or their compressed
/// forms) is for, read from its header alone; `None` for any other PDU.
///
/// MS-RDPEDYC 2.2: the header byte is `Cmd << 4 | Sp << 2 | cbId`, and the
/// ChannelId field, 1, 2 or 4 bytes wide by cbId, follows it.
fn data_channel_id(unframed: &[u8]) -> Option<u32> {
    let header = *unframed.first()?;
    // Cmd: 0x02 Data First, 0x03 Data, 0x06 and 0x07 their compressed forms.
    if !matches!(header >> 4, 0x02 | 0x03 | 0x06 | 0x07) {
        return None;
    }
    let id = unframed.get(1..)?;
    match header & 0b11 {
        0 => id.first().map(|&byte| u32::from(byte)),
        1 => id
            .get(..2)
            .map(|bytes| u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
        _ => id
            .get(..4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
    }
}

impl fmt::Debug for DrdynvcServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DrdynvcServer([")?;

        for (i, (id, channel)) in self.dynamic_channels.into_iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}:{} ({:?})", id, channel.processor.channel_name(), channel.state)?;
        }

        write!(f, "])")
    }
}

impl DrdynvcServer {
    pub const NAME: ChannelName = ChannelName::from_static(b"drdynvc\0");

    pub fn new() -> Self {
        Self {
            dynamic_channels: DynamicChannelAllocator::new(),
            type_id_to_channel_id: BTreeMap::new(),
            caps_received: false,
            soft_sync_state: SoftSyncState::Idle,
            outgoing_tunnel_channels: BTreeMap::new(),
            incoming_tunnel_channels: BTreeMap::new(),
            early_tunnel_frames: Vec::new(),
        }
    }

    pub fn get_channel_id_by_type<T>(&self) -> Option<u32>
    where
        T: DvcServerProcessor + 'static,
    {
        self.type_id_to_channel_id.get(&TypeId::of::<T>()).copied()
    }

    /// Returns `true` if the DVC channel with the given ID has completed
    /// its creation handshake and is in the `Opened` state.
    pub fn is_channel_opened(&self, channel_id: u32) -> bool {
        self.dynamic_channels
            .get(channel_id)
            .is_some_and(|c| c.state == ChannelState::Opened)
    }

    /// IDs of every dynamic channel currently in the Opened state — the set a
    /// Soft-Sync request can migrate to a multitransport tunnel.
    pub fn open_channel_ids(&self) -> Vec<u32> {
        (&self.dynamic_channels)
            .into_iter()
            .filter(|(_, c)| c.state == ChannelState::Opened)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Registers a dynamic channel with the server.
    ///
    /// # Panics
    ///
    /// Panics if the number of registered dynamic channels reaches `u32::MAX`.
    #[must_use]
    pub fn with_dynamic_channel<T>(mut self, channel: T) -> Self
    where
        T: DvcServerProcessor + 'static,
    {
        let channel_id = self.dynamic_channels.insert_channel(channel, ChannelState::Pending);
        self.type_id_to_channel_id.insert(TypeId::of::<T>(), channel_id);
        self
    }

    fn channel_by_id(&mut self, id: u32) -> DecodeResult<&mut DynamicChannel> {
        self.dynamic_channels
            .get_mut(id)
            .ok_or_else(|| invalid_field_err!("DRDYNVC", "", "invalid channel id"))
    }

    /// Returns a typed accessor for an active server DVC by channel ID.
    pub fn dvc_by_id<T: DvcServerProcessor>(&self, id: u32) -> Option<DynamicChannelRef<'_, T>> {
        let channel = self.dynamic_channels.get(id)?;
        if channel.state != ChannelState::Opened {
            return None;
        }
        channel
            .processor
            .as_any()
            .downcast_ref()
            .map(|p| DynamicChannelRef::new(id, p))
    }

    /// Returns a mutable typed accessor for an active server DVC by channel ID.
    pub fn dvc_by_id_mut<T: DvcServerProcessor>(&mut self, id: u32) -> Option<DynamicChannelMut<'_, T>> {
        let channel = self.dynamic_channels.get_mut(id)?;
        if channel.state != ChannelState::Opened {
            return None;
        }
        channel
            .processor
            .as_any_mut()
            .downcast_mut()
            .map(|p| DynamicChannelMut::new(id, p))
    }

    /// Creates a new DVC, returning the Create Request PDU to send to the client.
    ///
    /// `None` means nothing is to be sent yet: the capability exchange has not
    /// finished, and MS-RDPEDYC 2.2.1 forbids creating a channel before it has.
    /// The channel is then requested together with the pre-registered ones
    /// when the client's Capabilities Response arrives.
    ///
    /// # Panics
    ///
    /// Panics if the number of registered dynamic channels reaches `u32::MAX`.
    pub fn create_channel<T>(&mut self, channel: T) -> PduResult<Option<SvcMessage>>
    where
        T: DvcServerProcessor + 'static,
    {
        let channel_id = self.dynamic_channels.reserve_channel();
        self.create_channel_with_id(Box::new(channel), channel_id)
    }

    /// Creates a new DVC from a boxed processor — the form an embedder that
    /// opens channels at run time holds them in.
    ///
    /// Returns the ID assigned to the channel, and the Create Request PDU when
    /// one is to be sent now (see [`Self::create_channel`]).
    ///
    /// # Panics
    ///
    /// Panics if the number of registered dynamic channels reaches `u32::MAX`.
    pub fn create_channel_boxed(
        &mut self,
        channel: Box<dyn DvcServerProcessor>,
    ) -> PduResult<(u32, Option<SvcMessage>)> {
        let channel_id = self.dynamic_channels.reserve_channel();
        let message = self.create_channel_with_id(channel, channel_id)?;
        Ok((channel_id, message))
    }

    /// Creates a new DVC using a processor built with its assigned channel ID.
    ///
    /// The next channel ID is reserved and passed to `build`, allowing the
    /// processor or one of its dependencies to use the ID during construction.
    /// The return value is as for [`Self::create_channel`].
    ///
    /// # Panics
    ///
    /// Panics if the number of registered dynamic channels reaches `u32::MAX`.
    pub fn create_channel_with<T, E, F>(&mut self, build: F) -> Result<Option<SvcMessage>, E>
    where
        T: DvcServerProcessor + 'static,
        E: From<PduError>,
        F: FnOnce(u32) -> Result<T, E>,
    {
        let channel_id = self.dynamic_channels.reserve_channel();
        let channel = build(channel_id)?;
        self.create_channel_with_id(Box::new(channel), channel_id)
            .map_err(E::from)
    }

    fn create_channel_with_id(
        &mut self,
        channel: Box<dyn DvcServerProcessor>,
        channel_id: u32,
    ) -> PduResult<Option<SvcMessage>> {
        if !self.caps_received {
            self.dynamic_channels
                .insert_boxed_with_id(channel, ChannelState::Pending, channel_id);
            return Ok(None);
        }
        let channel_name = channel.channel_name().into();
        let req = DrdynvcServerPdu::Create(CreateRequestPdu::new(channel_id, channel_name));
        let svc_msg = as_svc_msg_with_flag(req)?;
        self.dynamic_channels
            .insert_boxed_with_id(channel, ChannelState::Creation, channel_id);
        Ok(Some(svc_msg))
    }

    fn remove_by_channel_id(&mut self, id: u32) -> Option<DynamicChannel> {
        // A later channel may get the same ID, and it was not moved.
        self.outgoing_tunnel_channels.remove(&id);
        self.incoming_tunnel_channels.remove(&id);
        self.dynamic_channels.remove(id).inspect(|dvc| {
            let type_id = dvc.processor_type_id();

            // Only matters for pre-registered channels
            if let alloc::collections::btree_map::Entry::Occupied(entry) = self.type_id_to_channel_id.entry(type_id)
                && entry.get() == &id
            {
                entry.remove();
            }
        })
    }

    /// Closes a dynamic channel the server opened (MS-RDPEDYC 2.2.4, 3.3.5.2).
    ///
    /// Returns the Close PDU to send, or `None` when there is nothing to put
    /// on the wire:
    /// - the channel is unknown;
    /// - its Create Request has not been sent yet (still waiting for the
    ///   capability exchange), so the client never heard of it and it is
    ///   simply forgotten;
    /// - its Create Request is still unanswered: the client already knows the
    ///   ID, so the Close goes out as the reply to its Create Response instead
    ///   of racing it.
    pub fn close_channel(&mut self, channel_id: u32) -> Option<SvcMessage> {
        let channel = self.dynamic_channels.get_mut(channel_id)?;
        match channel.state {
            ChannelState::Creation => {
                channel.close_when_created = true;
                return None;
            }
            ChannelState::Pending | ChannelState::CreationFailed(_) => {
                self.remove_by_channel_id(channel_id);
                return None;
            }
            ChannelState::Opened => {}
        }
        self.remove_by_channel_id(channel_id)?;
        self.outgoing_tunnel_channels.remove(&channel_id);
        self.incoming_tunnel_channels.remove(&channel_id);
        Some(close_pdu(channel_id))
    }

    /// Creates a Soft-Sync request that moves the supplied channels to reliable UDP.
    ///
    /// This API emits exactly one `ReliableUdp` channel list and maps every supplied
    /// channel to that list. A future multi-tunnel request API must establish an
    /// explicit response-routing mapping before it is exposed.
    pub fn request_reliable_udp(&mut self, channel_ids: Vec<u32>) -> PduResult<SvcMessage> {
        if channel_ids.is_empty() {
            return Err(pdu_other_err!("soft-sync requires at least one dynamic channel"));
        }
        if !matches!(self.soft_sync_state, SoftSyncState::Idle) {
            return Err(pdu_other_err!("soft-sync has already been requested"));
        }

        let mut selected_channels = BTreeMap::new();
        for channel_id in &channel_ids {
            if !self.is_channel_opened(*channel_id) {
                return Err(pdu_other_err!(
                    "Soft-Sync requested for a dynamic channel that is not open"
                ));
            }
            if selected_channels
                .insert(*channel_id, SoftSyncTunnelType::RELIABLE_UDP)
                .is_some()
            {
                return Err(pdu_other_err!("soft-sync channel list contains a duplicate channel ID"));
            }
        }

        let request = SoftSyncRequestPdu::new(alloc::vec![SoftSyncChannelList::new(
            SoftSyncTunnelType::RELIABLE_UDP,
            channel_ids,
        )]);
        let message = as_svc_msg_with_flag(DrdynvcServerPdu::SoftSyncRequest(request))?;
        self.outgoing_tunnel_channels = selected_channels;
        self.soft_sync_state = SoftSyncState::Active {
            requested_tunnels: BTreeSet::from([SoftSyncTunnelType::RELIABLE_UDP]),
            response_received: false,
        };
        Ok(message)
    }

    /// Returns whether server-to-client data for `channel_id` must be sent through a tunnel.
    pub fn tunnel_for_outgoing_channel(&self, channel_id: u32) -> Option<SoftSyncTunnelType> {
        self.outgoing_tunnel_channels.get(&channel_id).copied()
    }

    /// Whether a Soft-Sync Request moved any channel to a tunnel.
    pub fn tunnels_channels(&self) -> bool {
        !self.outgoing_tunnel_channels.is_empty()
    }

    /// The tunnel an encoded, unframed DRDYNVC PDU goes through, or `None`
    /// for the DRDYNVC channel on the main connection.
    ///
    /// MS-RDPEDYC 3.3.5.3.1: "Immediately after sending this PDU [the
    /// Soft-Sync Request], for each dynamic virtual channel, the server
    /// manager MUST consistently use either a multitransport tunnel or the
    /// DRDYNVC static virtual channel on the main RDP connection to send
    /// data." Data of a channel the request moved goes through its tunnel,
    /// from the request on. Data of every other channel, and every DRDYNVC PDU
    /// that is not data (Capabilities, Create, Close, Soft-Sync), goes over
    /// the main connection.
    pub fn outgoing_tunnel(&self, unframed: &[u8]) -> Option<SoftSyncTunnelType> {
        if self.outgoing_tunnel_channels.is_empty() {
            return None;
        }
        data_channel_id(unframed).and_then(|channel_id| self.tunnel_for_outgoing_channel(channel_id))
    }

    /// Returns whether the client has acknowledged the Soft-Sync request over TCP.
    pub const fn soft_sync_response_received(&self) -> bool {
        matches!(
            self.soft_sync_state,
            SoftSyncState::Active {
                response_received: true,
                ..
            }
        )
    }

    /// Processes raw DRDYNVC data received through an established multitransport tunnel.
    ///
    /// MS-RDPEDYC 3.3.5.3.2: the server "MUST NOT begin to read dynamic
    /// virtual channel data on any multitransport tunnel until after the
    /// Soft-Sync Response PDU has been received", so what arrives earlier
    /// waits, in order, and is read when the response comes.
    pub fn process_tunnel(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        if !self.soft_sync_response_received() {
            if self.early_tunnel_frames.len() >= MAX_EARLY_TUNNEL_FRAMES {
                return Err(pdu_other_err!("too much tunnel data before the Soft-Sync Response"));
            }
            self.early_tunnel_frames.push(payload.to_vec());
            return Ok(Vec::new());
        }
        self.read_tunnel_frame(payload)
    }

    /// One frame from a tunnel the client has switched to. Data of an open
    /// channel is processed and a Close honored; anything else has no place
    /// on a tunnel and is ignored rather than ending the session.
    fn read_tunnel_frame(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        let pdu = match decode_dvc_message(payload) {
            Ok(pdu) => pdu,
            Err(error) => {
                warn!(%error, "ignoring a tunnel frame that is not a DRDYNVC PDU");
                return Ok(Vec::new());
            }
        };
        match pdu {
            DrdynvcClientPdu::Data(data) => {
                let channel_id = data.channel_id();
                if !self.is_channel_opened(channel_id) {
                    debug!(channel_id, "ignoring tunneled data for a channel that is not open");
                    return Ok(Vec::new());
                }
                if !self.incoming_tunnel_channels.contains_key(&channel_id) {
                    debug!(channel_id, "tunneled data for a channel the Soft-Sync did not move");
                }
                self.process_data(data)
            }
            DrdynvcClientPdu::Close(close) => {
                debug!("Got DVC Close PDU through a tunnel: {close:?}");
                self.remove_by_channel_id(close.channel_id());
                Ok(Vec::new())
            }
            other => {
                warn!(pdu = ?other, "ignoring a DRDYNVC PDU that has no place on a tunnel");
                Ok(Vec::new())
            }
        }
    }

    fn process_data(&mut self, data: crate::pdu::DrdynvcDataPdu) -> PduResult<Vec<SvcMessage>> {
        let channel_id = data.channel_id();
        let c = self.channel_by_id(channel_id).map_err(|e| decode_err!(e))?;
        if c.state != ChannelState::Opened {
            debug!(?channel_id, ?c.state, "Invalid channel state");
            return Err(pdu_other_err!("invalid channel state"));
        }
        let mut resp = Vec::new();
        if let Some(complete) = c.complete_data.process_data(data).map_err(|e| decode_err!(e))? {
            let msg = c.processor.process(channel_id, &complete)?;
            resp.extend(encode_dvc_messages(channel_id, msg, ChannelFlags::SHOW_PROTOCOL).map_err(|e| encode_err!(e))?);
        }
        Ok(resp)
    }

    fn process_soft_sync_response(&mut self, response: crate::pdu::SoftSyncResponsePdu) -> PduResult<Vec<SvcMessage>> {
        let SoftSyncState::Active {
            requested_tunnels,
            response_received,
        } = &mut self.soft_sync_state
        else {
            warn!("ignoring a Soft-Sync Response to no request");
            return Ok(Vec::new());
        };
        if *response_received {
            warn!("ignoring a second Soft-Sync Response");
            return Ok(Vec::new());
        }
        for tunnel_type in response.tunnels_to_switch() {
            if !requested_tunnels.contains(tunnel_type) {
                return Err(pdu_other_err!("soft-sync response selected an unrequested tunnel"));
            }
        }
        self.incoming_tunnel_channels = self
            .outgoing_tunnel_channels
            .iter()
            .filter(|(_, tunnel_type)| response.tunnels_to_switch().contains(tunnel_type))
            .map(|(channel_id, tunnel_type)| (*channel_id, *tunnel_type))
            .collect();
        *response_received = true;

        // The tunnels may be read from now on (3.3.5.3.2), starting with
        // what arrived before the response.
        let mut responses = Vec::new();
        for frame in core::mem::take(&mut self.early_tunnel_frames) {
            responses.extend(self.read_tunnel_frame(&frame)?);
        }
        Ok(responses)
    }
}

impl_as_any!(DrdynvcServer);

impl Default for DrdynvcServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SvcProcessor for DrdynvcServer {
    fn channel_name(&self) -> ChannelName {
        DrdynvcServer::NAME
    }

    fn compression_condition(&self) -> CompressionCondition {
        CompressionCondition::WhenRdpDataIsCompressed
    }

    fn start(&mut self) -> PduResult<Vec<SvcMessage>> {
        let cap = CapabilitiesRequestPdu::new(CapsVersion::V2, None);
        let req = DrdynvcServerPdu::Capabilities(cap);
        let msg = as_svc_msg_with_flag(req)?;
        Ok(alloc::vec![msg])
    }

    fn process(&mut self, payload: &[u8]) -> PduResult<Vec<SvcMessage>> {
        let pdu = decode_dvc_message(payload).map_err(|e| decode_err!(e))?;
        let mut resp = Vec::new();

        match pdu {
            DrdynvcClientPdu::Capabilities(caps_resp) => {
                debug!("Got DVC Capabilities Response PDU: {caps_resp:?}");
                self.caps_received = true;
                for (id, c) in &mut self.dynamic_channels {
                    if c.state != ChannelState::Pending {
                        continue;
                    }
                    let req = DrdynvcServerPdu::Create(CreateRequestPdu::new(*id, c.processor.channel_name().into()));
                    c.state = ChannelState::Creation;
                    resp.push(as_svc_msg_with_flag(req)?);
                }
            }
            DrdynvcClientPdu::Create(create_resp) => {
                debug!("Got DVC Create Response PDU: {create_resp:?}");
                let id = create_resp.channel_id();
                let c = self.channel_by_id(id).map_err(|e| decode_err!(e))?;
                if c.state != ChannelState::Creation {
                    return Err(pdu_other_err!("invalid channel state"));
                }
                if create_resp.creation_status() != CreationStatus::OK {
                    let name = c.processor.channel_name();
                    let status = create_resp.creation_status();
                    warn!(channel_id = ?id, %name, ?status, "DVC channel creation failed");
                    c.state = ChannelState::CreationFailed(status.into());
                    // MS-RDPEDYC 3.3.3.2: a failure here is terminal for this
                    // channel — no retry, no renegotiation, and the ID goes
                    // back into the pool. Tell the processor, or a higher
                    // layer that gates on the channel opening (the EGFX
                    // pipeline does) cannot tell "declined" from "still
                    // negotiating" and waits for a readiness that will never
                    // come.
                    c.processor.close(id);
                    return Ok(resp);
                }
                if c.close_when_created {
                    // Closed by the server while this reply was in flight.
                    // The processor never started, so it is not told again.
                    debug!(channel_id = ?id, "DVC closed before its creation was confirmed");
                    self.remove_by_channel_id(id);
                    resp.push(close_pdu(id));
                    return Ok(resp);
                }
                c.state = ChannelState::Opened;
                let msg = c.processor.start(create_resp.channel_id())?;
                resp.extend(encode_dvc_messages(id, msg, ChannelFlags::SHOW_PROTOCOL).map_err(|e| encode_err!(e))?);
            }
            DrdynvcClientPdu::Close(close) => {
                debug!("Got DVC Close PDU: {close:?}");
                let channel_id = close.channel_id();
                self.remove_by_channel_id(channel_id);
            }
            DrdynvcClientPdu::Data(data) => {
                if self.incoming_tunnel_channels.contains_key(&data.channel_id()) {
                    // The client said it would use the tunnel for this
                    // channel (3.2.5.3.2). Its data still counts.
                    debug!(
                        channel_id = data.channel_id(),
                        "TCP data for a channel moved to a tunnel"
                    );
                }
                resp.extend(self.process_data(data)?);
            }
            DrdynvcClientPdu::SoftSyncResponse(response) => {
                debug!("Got DVC Soft-Sync Response PDU: {response:?}");
                resp.extend(self.process_soft_sync_response(response)?);
            }
        }

        Ok(resp)
    }
}

impl SvcServerProcessor for DrdynvcServer {}

fn decode_dvc_message(user_data: &[u8]) -> DecodeResult<DrdynvcClientPdu> {
    DrdynvcClientPdu::decode(&mut ReadCursor::new(user_data))
}

fn as_svc_msg_with_flag(pdu: DrdynvcServerPdu) -> PduResult<SvcMessage> {
    Ok(SvcMessage::from(pdu).with_flags(ChannelFlags::SHOW_PROTOCOL))
}

fn close_pdu(channel_id: u32) -> SvcMessage {
    SvcMessage::from(DrdynvcServerPdu::Close(ClosePdu::new(channel_id))).with_flags(ChannelFlags::SHOW_PROTOCOL)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDvc;

    impl_as_any!(TestDvc);

    impl DvcProcessor for TestDvc {
        fn channel_name(&self) -> &str {
            "test"
        }

        fn start(&mut self, _channel_id: u32) -> PduResult<Vec<crate::DvcMessage>> {
            Ok(Vec::new())
        }

        fn process(&mut self, _channel_id: u32, _payload: &[u8]) -> PduResult<Vec<crate::DvcMessage>> {
            Ok(Vec::new())
        }
    }

    impl DvcServerProcessor for TestDvc {}

    /// Records whether `close` was called, so a test can assert the failure
    /// path notifies the processor.
    struct ClosableDvc {
        closed: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    }

    impl_as_any!(ClosableDvc);

    impl DvcProcessor for ClosableDvc {
        fn channel_name(&self) -> &str {
            "closable"
        }

        fn start(&mut self, _channel_id: u32) -> PduResult<Vec<crate::DvcMessage>> {
            Ok(Vec::new())
        }

        fn process(&mut self, _channel_id: u32, _payload: &[u8]) -> PduResult<Vec<crate::DvcMessage>> {
            Ok(Vec::new())
        }

        fn close(&mut self, _channel_id: u32) {
            self.closed.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    }

    impl DvcServerProcessor for ClosableDvc {}

    /// MS-RDPEDYC 3.3.3.2: a negative CreationStatus means the channel was not
    /// created — there is no retry and no renegotiation, the ID simply goes
    /// back into the pool. A processor that is never told cannot distinguish
    /// "declined" from "still negotiating", and a higher layer waiting on the
    /// channel (the EGFX display pipeline) waits forever.
    #[test]
    fn a_refused_channel_tells_its_processor_it_will_never_open() {
        let closed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut server = DrdynvcServer::new();
        let channel_id = server.dynamic_channels.insert_channel(
            ClosableDvc {
                closed: alloc::sync::Arc::clone(&closed),
            },
            ChannelState::Creation,
        );

        // 0xC0000001 (NO_LISTENER) — what a client sends for a channel name it
        // has no handler registered for.
        let refusal = ironrdp_core::encode_vec(&DrdynvcClientPdu::Create(crate::pdu::CreateResponsePdu::new(
            channel_id,
            CreationStatus::NO_LISTENER,
        )))
        .unwrap();

        server.process(&refusal).unwrap();

        assert!(
            closed.load(core::sync::atomic::Ordering::Relaxed),
            "the processor must be told the channel was refused"
        );
    }

    fn decode_server_pdus(messages: &[SvcMessage]) -> Vec<DrdynvcServerPdu> {
        messages
            .iter()
            .map(|message| {
                let bytes = message.encode_unframed_pdu().unwrap();
                ironrdp_core::decode::<DrdynvcServerPdu>(&bytes).unwrap()
            })
            .collect()
    }

    fn caps_response() -> Vec<u8> {
        ironrdp_core::encode_vec(&DrdynvcClientPdu::Capabilities(
            crate::pdu::CapabilitiesResponsePdu::new(CapsVersion::V2),
        ))
        .unwrap()
    }

    fn create_response(channel_id: u32) -> Vec<u8> {
        ironrdp_core::encode_vec(&DrdynvcClientPdu::Create(crate::pdu::CreateResponsePdu::new(
            channel_id,
            CreationStatus::OK,
        )))
        .unwrap()
    }

    /// MS-RDPEDYC 2.2.1: "The DVC server manager MUST send a Capabilities
    /// message prior to creating a DVC and wait for a response from the
    /// client." A channel opened at run time before that answer is held back
    /// and requested together with the ones registered up front.
    #[test]
    fn a_channel_opened_before_the_capability_exchange_waits_for_it() {
        let mut server = DrdynvcServer::new();
        let _ = server.start().unwrap();

        let (channel_id, message) = server.create_channel_boxed(Box::new(TestDvc)).unwrap();
        assert!(
            message.is_none(),
            "no Create Request may precede the Capabilities Response"
        );

        let sent = decode_server_pdus(&server.process(&caps_response()).unwrap());
        assert!(
            matches!(sent.as_slice(), [DrdynvcServerPdu::Create(create)] if create.channel_id() == channel_id),
            "the Create Request goes out with the Capabilities Response: {sent:?}"
        );
    }

    #[test]
    fn a_channel_opened_after_the_capability_exchange_is_requested_at_once() {
        let mut server = DrdynvcServer::new();
        let _ = server.process(&caps_response()).unwrap();

        let (channel_id, message) = server.create_channel_boxed(Box::new(TestDvc)).unwrap();
        let sent = decode_server_pdus(&[message.expect("Create Request")]);
        assert!(matches!(sent.as_slice(), [DrdynvcServerPdu::Create(create)] if create.channel_id() == channel_id));
    }

    #[test]
    fn closing_an_open_channel_sends_a_close_and_forgets_it() {
        let closed = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let mut server = DrdynvcServer::new();
        let _ = server.process(&caps_response()).unwrap();
        let (channel_id, _) = server
            .create_channel_boxed(Box::new(ClosableDvc {
                closed: alloc::sync::Arc::clone(&closed),
            }))
            .unwrap();
        let _ = server.process(&create_response(channel_id)).unwrap();
        assert!(server.is_channel_opened(channel_id));

        let sent = decode_server_pdus(&[server.close_channel(channel_id).expect("Close PDU")]);
        assert!(matches!(sent.as_slice(), [DrdynvcServerPdu::Close(close)] if close.channel_id() == channel_id));
        assert!(!server.is_channel_opened(channel_id));
        assert!(
            closed.load(core::sync::atomic::Ordering::Relaxed),
            "the processor is told"
        );
    }

    /// A channel the client never heard of has nothing to close on the wire.
    #[test]
    fn closing_a_channel_not_yet_requested_sends_nothing() {
        let mut server = DrdynvcServer::new();
        let (channel_id, _) = server.create_channel_boxed(Box::new(TestDvc)).unwrap();

        assert!(server.close_channel(channel_id).is_none());
        assert!(
            decode_server_pdus(&server.process(&caps_response()).unwrap()).is_empty(),
            "a forgotten channel is not requested later"
        );
    }

    /// The client knows the ID once it has the Create Request, so a close
    /// while its answer is in flight goes out as the reply to that answer.
    #[test]
    fn closing_a_channel_awaiting_its_create_response_closes_it_once_created() {
        let mut server = DrdynvcServer::new();
        let _ = server.process(&caps_response()).unwrap();
        let (channel_id, _) = server.create_channel_boxed(Box::new(TestDvc)).unwrap();

        assert!(server.close_channel(channel_id).is_none());
        let sent = decode_server_pdus(&server.process(&create_response(channel_id)).unwrap());
        assert!(matches!(sent.as_slice(), [DrdynvcServerPdu::Close(close)] if close.channel_id() == channel_id));
        assert!(!server.is_channel_opened(channel_id));
    }

    /// Answers every message with its own bytes, so a test sees what was
    /// processed and in which order.
    struct EchoDvc;

    impl_as_any!(EchoDvc);

    struct Raw(Vec<u8>);

    impl ironrdp_core::Encode for Raw {
        fn encode(&self, dst: &mut ironrdp_core::WriteCursor<'_>) -> ironrdp_core::EncodeResult<()> {
            ironrdp_core::ensure_size!(in: dst, size: self.0.len());
            dst.write_slice(&self.0);
            Ok(())
        }

        fn name(&self) -> &'static str {
            "Raw"
        }

        fn size(&self) -> usize {
            self.0.len()
        }
    }

    impl crate::DvcEncode for Raw {}

    impl DvcProcessor for EchoDvc {
        fn channel_name(&self) -> &str {
            "echo"
        }

        fn start(&mut self, _channel_id: u32) -> PduResult<Vec<crate::DvcMessage>> {
            Ok(Vec::new())
        }

        fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<crate::DvcMessage>> {
            Ok(alloc::vec![Box::new(Raw(payload.to_vec()))])
        }
    }

    impl DvcServerProcessor for EchoDvc {}

    fn client_data(channel_id: u32, data: &[u8]) -> Vec<u8> {
        ironrdp_core::encode_vec(&DrdynvcClientPdu::Data(crate::pdu::DrdynvcDataPdu::Data(
            crate::pdu::DataPdu::new(channel_id, data.to_vec()),
        )))
        .unwrap()
    }

    fn soft_sync_response() -> Vec<u8> {
        ironrdp_core::encode_vec(&DrdynvcClientPdu::SoftSyncResponse(
            crate::pdu::SoftSyncResponsePdu::new(alloc::vec![SoftSyncTunnelType::RELIABLE_UDP]),
        ))
        .unwrap()
    }

    /// The payloads of the Data PDUs the server answered with.
    fn echoed(messages: &[SvcMessage]) -> Vec<Vec<u8>> {
        decode_server_pdus(messages)
            .into_iter()
            .map(|pdu| match pdu {
                DrdynvcServerPdu::Data(crate::pdu::DrdynvcDataPdu::Data(data)) => data.data().to_vec(),
                other => panic!("expected data, got {other:?}"),
            })
            .collect()
    }

    /// MS-RDPEDYC 3.3.5.3.2: the server "MUST NOT begin to read dynamic
    /// virtual channel data on any multitransport tunnel until after the
    /// Soft-Sync Response PDU has been received".
    ///
    /// Regression: such data ended the session, and a tunnel frame that
    /// overtakes the response on the network is ordinary.
    #[test]
    fn tunnel_data_waits_for_the_soft_sync_response() {
        let mut server = DrdynvcServer::new();
        let channel_id = server.dynamic_channels.insert_channel(EchoDvc, ChannelState::Opened);
        server.request_reliable_udp(alloc::vec![channel_id]).unwrap();

        assert!(
            server
                .process_tunnel(&client_data(channel_id, b"first"))
                .unwrap()
                .is_empty()
        );
        assert!(
            server
                .process_tunnel(&client_data(channel_id, b"second"))
                .unwrap()
                .is_empty()
        );

        let answers = server.process(&soft_sync_response()).unwrap();
        assert_eq!(
            echoed(&answers),
            [b"first".to_vec(), b"second".to_vec()],
            "read in order, once the response is in"
        );

        let answers = server.process_tunnel(&client_data(channel_id, b"third")).unwrap();
        assert_eq!(echoed(&answers), [b"third".to_vec()]);
    }

    /// MS-RDPEDYC 3.3.5.3.1: immediately after the Soft-Sync Request the
    /// server "MUST consistently use either a multitransport tunnel or the
    /// DRDYNVC static virtual channel" per channel. Data of a moved channel
    /// takes the tunnel from the request on; everything else stays on TCP.
    ///
    /// Regression: nothing took the tunnel until the Soft-Sync Response, and
    /// after it everything did, control PDUs and unmoved channels included.
    #[test]
    fn data_of_a_moved_channel_takes_the_tunnel_from_the_request_on() {
        let mut server = DrdynvcServer::new();
        let moved = server.dynamic_channels.insert_channel(EchoDvc, ChannelState::Opened);
        let unmoved = server.dynamic_channels.insert_channel(TestDvc, ChannelState::Opened);
        let data = |channel_id: u32| {
            encode_dvc_messages(
                channel_id,
                alloc::vec![Box::new(Raw(alloc::vec![7; 3000]))],
                ChannelFlags::empty(),
            )
            .unwrap()
            .iter()
            .map(|message| message.encode_unframed_pdu().unwrap())
            .collect::<Vec<_>>()
        };
        let close = ironrdp_core::encode_vec(&DrdynvcServerPdu::Close(ClosePdu::new(moved))).unwrap();

        assert!(
            data(moved).iter().all(|pdu| server.outgoing_tunnel(pdu).is_none()),
            "no request yet"
        );

        server.request_reliable_udp(alloc::vec![moved]).unwrap();
        let moved_data = data(moved);
        assert_eq!(moved_data.len(), 2, "Data First and Data");
        assert!(
            moved_data
                .iter()
                .all(|pdu| server.outgoing_tunnel(pdu) == Some(SoftSyncTunnelType::RELIABLE_UDP))
        );
        assert!(data(unmoved).iter().all(|pdu| server.outgoing_tunnel(pdu).is_none()));
        assert_eq!(server.outgoing_tunnel(&close), None, "control PDUs stay on TCP");
    }

    /// Channel IDs 1, 2 and 4 bytes wide (cbId, MS-RDPEDYC 2.2).
    #[test]
    fn the_channel_of_a_data_pdu_is_read_from_its_header() {
        for channel_id in [5, 0x1234, 0x0012_3456] {
            let pdu = client_data(channel_id, b"x");
            assert_eq!(data_channel_id(&pdu), Some(channel_id));
        }
        assert_eq!(data_channel_id(&caps_response()), None);
        assert_eq!(data_channel_id(&[]), None);
    }

    /// A channel ID the client closed and a later channel reuses was not
    /// moved by the Soft-Sync: its data stays on TCP.
    #[test]
    fn a_reused_channel_id_does_not_inherit_the_tunnel() {
        let mut server = DrdynvcServer::new();
        let _ = server.process(&caps_response()).unwrap();
        let (moved, _) = server.create_channel_boxed(Box::new(EchoDvc)).unwrap();
        let _ = server.process(&create_response(moved)).unwrap();
        server.request_reliable_udp(alloc::vec![moved]).unwrap();

        let close = ironrdp_core::encode_vec(&DrdynvcClientPdu::Close(ClosePdu::new(moved))).unwrap();
        let _ = server.process(&close).unwrap();

        assert_eq!(server.tunnel_for_outgoing_channel(moved), None);
    }

    /// Anything on a tunnel other than data and Close is ignored; it does
    /// not end the session.
    #[test]
    fn an_unexpected_tunnel_pdu_is_ignored() {
        let mut server = DrdynvcServer::new();
        let channel_id = server.dynamic_channels.insert_channel(EchoDvc, ChannelState::Opened);
        server.request_reliable_udp(alloc::vec![channel_id]).unwrap();
        let _ = server.process(&soft_sync_response()).unwrap();

        assert!(server.process_tunnel(&caps_response()).unwrap().is_empty());
        assert!(server.process_tunnel(&[0xFF, 0xFF]).unwrap().is_empty());
        assert!(
            server.process_tunnel(&client_data(999, b"x")).unwrap().is_empty(),
            "no such channel"
        );

        let close = ironrdp_core::encode_vec(&DrdynvcClientPdu::Close(ClosePdu::new(channel_id))).unwrap();
        assert!(server.process_tunnel(&close).unwrap().is_empty());
        assert!(
            !server.is_channel_opened(channel_id),
            "a Close through the tunnel is honored"
        );
    }

    #[test]
    fn soft_sync_accepts_a_response_after_the_selected_channel_closes() {
        let mut server = DrdynvcServer::new();
        let channel_id = server.dynamic_channels.insert_channel(TestDvc, ChannelState::Opened);

        server.request_reliable_udp(alloc::vec![channel_id]).unwrap();
        server.close_channel(channel_id).unwrap();

        server
            .process_soft_sync_response(crate::pdu::SoftSyncResponsePdu::new(alloc::vec![
                SoftSyncTunnelType::RELIABLE_UDP,
            ]))
            .unwrap();

        assert!(server.soft_sync_response_received());
        assert!(server.request_reliable_udp(alloc::vec![channel_id]).is_err());
    }
}
