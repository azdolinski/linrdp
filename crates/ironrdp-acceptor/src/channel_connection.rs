use std::collections::HashSet;

use ironrdp_connector::{
    ConnectorError, ConnectorErrorExt as _, ConnectorResult, MonotonicInstant, Sequence, State, Written,
};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::mcs;
use ironrdp_pdu::x224::X224;
use tracing::debug;

#[derive(Debug)]
pub struct ChannelConnectionSequence {
    state: ChannelConnectionState,
    user_channel_id: u16,
    channel_ids: Option<HashSet<u16>>,
}

#[derive(Default, Debug)]
pub enum ChannelConnectionState {
    #[default]
    Consumed,

    WaitErectDomainRequest,
    WaitAttachUserRequest,
    SendAttachUserConfirm,
    WaitChannelJoinRequest {
        remaining: HashSet<u16>,
        joined: HashSet<u16>,
    },
    SendChannelJoinConfirm {
        remaining: HashSet<u16>,
        channel_id: u16,
        joined: HashSet<u16>,
    },
    AllJoined,
}

/// T.125 Result code for a channel the server never announced: rt-no-such-channel.
const RT_NO_SUCH_CHANNEL: u8 = 3;

impl State for ChannelConnectionState {
    fn name(&self) -> &'static str {
        match self {
            Self::Consumed => "Consumed",
            Self::WaitErectDomainRequest => "WaitErectDomainRequest",
            Self::WaitAttachUserRequest => "WaitAttachUserRequest",
            Self::SendAttachUserConfirm => "SendAttachUserConfirm",
            Self::WaitChannelJoinRequest { .. } => "WaitChannelJoinRequest",
            Self::SendChannelJoinConfirm { .. } => "SendChannelJoinConfirm",
            Self::AllJoined { .. } => "AllJoined",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::AllJoined { .. })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Sequence for ChannelConnectionSequence {
    fn next_pdu_hint(&self) -> Option<&dyn ironrdp_pdu::PduHint> {
        match &self.state {
            ChannelConnectionState::Consumed => None,
            ChannelConnectionState::WaitErectDomainRequest => Some(&ironrdp_pdu::X224_HINT),
            ChannelConnectionState::WaitAttachUserRequest => Some(&ironrdp_pdu::X224_HINT),
            ChannelConnectionState::SendAttachUserConfirm => None,
            ChannelConnectionState::WaitChannelJoinRequest { .. } => Some(&ironrdp_pdu::X224_HINT),
            ChannelConnectionState::SendChannelJoinConfirm { .. } => None,
            ChannelConnectionState::AllJoined => None,
        }
    }

    fn state(&self) -> &dyn State {
        &self.state
    }

    fn step(
        &mut self,
        input: &[u8],
        _received_at: Option<MonotonicInstant>,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let (written, next_state) = match core::mem::take(&mut self.state) {
            ChannelConnectionState::WaitErectDomainRequest => {
                let erect_domain_request = ironrdp_core::decode::<X224<mcs::ErectDomainPdu>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;

                debug!(message = ?erect_domain_request, "Received");

                (Written::Nothing, ChannelConnectionState::WaitAttachUserRequest)
            }

            ChannelConnectionState::WaitAttachUserRequest => {
                let attach_user_request = ironrdp_core::decode::<X224<mcs::AttachUserRequest>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;

                debug!(message = ?attach_user_request, "Received");

                (Written::Nothing, ChannelConnectionState::SendAttachUserConfirm)
            }

            ChannelConnectionState::SendAttachUserConfirm => {
                let attach_user_confirm = mcs::AttachUserConfirm {
                    result: 0,
                    initiator_id: self.user_channel_id,
                };

                debug!(message = ?attach_user_confirm, "Send");

                let written =
                    ironrdp_core::encode_buf(&X224(attach_user_confirm), output).map_err(ConnectorError::encode)?;

                let next_state = match self.channel_ids.take() {
                    Some(channel_ids) => ChannelConnectionState::WaitChannelJoinRequest {
                        remaining: channel_ids,
                        joined: HashSet::new(),
                    },
                    None => ChannelConnectionState::AllJoined,
                };

                (Written::from_size(written)?, next_state)
            }

            ChannelConnectionState::WaitChannelJoinRequest { mut remaining, joined } => {
                let channel_request = ironrdp_core::decode::<X224<mcs::ChannelJoinRequest>>(input)
                    .map_err(ConnectorError::decode)
                    .map(|p| p.0)?;

                debug!(message = ?channel_request, "Received");

                if joined.contains(&channel_request.channel_id) {
                    // MS-RDPBCGR 3.3.5.3.8: a Channel Join Request for a
                    // channel that is already joined SHOULD be ignored — no
                    // confirm is sent.
                    debug!(channel = channel_request.channel_id, "channel already joined; ignoring");
                    self.state = ChannelConnectionState::WaitChannelJoinRequest { remaining, joined };
                    return Ok(Written::Nothing);
                }

                let is_expected = remaining.remove(&channel_request.channel_id);

                if !is_expected {
                    // MS-RDPBCGR 3.3.5.3.8: answer the join with a Channel
                    // Join Confirm carrying a non-zero Result instead of
                    // dropping the whole connection.
                    debug!(channel = channel_request.channel_id, "unexpected channel join; rejecting");
                    let reject = mcs::ChannelJoinConfirm {
                        result: RT_NO_SUCH_CHANNEL,
                        initiator_id: self.user_channel_id,
                        requested_channel_id: channel_request.channel_id,
                        channel_id: channel_request.channel_id,
                    };
                    let written =
                        ironrdp_core::encode_buf(&X224(reject), output).map_err(ConnectorError::encode)?;
                    self.state = ChannelConnectionState::WaitChannelJoinRequest { remaining, joined };
                    return Ok(Written::from_size(written)?);
                }

                (
                    Written::Nothing,
                    ChannelConnectionState::SendChannelJoinConfirm {
                        remaining,
                        channel_id: channel_request.channel_id,
                        joined,
                    },
                )
            }

            ChannelConnectionState::SendChannelJoinConfirm {
                remaining,
                channel_id,
                mut joined,
            } => {
                let channel_confirm = mcs::ChannelJoinConfirm {
                    result: 0,
                    initiator_id: self.user_channel_id,
                    requested_channel_id: channel_id,
                    channel_id,
                };

                debug!(message = ?channel_confirm, "Send");

                let written =
                    ironrdp_core::encode_buf(&X224(channel_confirm), output).map_err(ConnectorError::encode)?;

                joined.insert(channel_id);

                let next_state = if remaining.is_empty() {
                    ChannelConnectionState::AllJoined
                } else {
                    ChannelConnectionState::WaitChannelJoinRequest { remaining, joined }
                };

                (Written::from_size(written)?, next_state)
            }

            _ => unreachable!(),
        };

        self.state = next_state;
        Ok(written)
    }
}

impl ChannelConnectionSequence {
    pub fn new(user_channel_id: u16, io_channel_id: u16, other_channels: Vec<u16>) -> Self {
        Self {
            state: ChannelConnectionState::WaitErectDomainRequest,
            user_channel_id,
            channel_ids: Some(
                vec![user_channel_id, io_channel_id]
                    .into_iter()
                    .chain(other_channels)
                    .collect(),
            ),
        }
    }

    pub fn skip_channel_join(user_channel_id: u16) -> Self {
        Self {
            state: ChannelConnectionState::WaitErectDomainRequest,
            user_channel_id,
            channel_ids: None,
        }
    }

    pub fn is_done(&self) -> bool {
        self.state.is_terminal()
    }
}
