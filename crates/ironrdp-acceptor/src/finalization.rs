use ironrdp_connector::{ConnectorResult, MonotonicInstant, Sequence, State, Written};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::rdp;
use ironrdp_pdu::rdp::finalization_messages::{ControlAction, ControlPdu, FontPdu, SynchronizePdu};
use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu, ShareDataPdu};
use ironrdp_pdu::x224::X224;
use tracing::{debug, warn};

use crate::util::{self, wrap_share_data};

#[derive(Debug)]
pub struct FinalizationSequence {
    state: FinalizationState,
    user_channel_id: u16,
    io_channel_id: u16,
    message_channel_id: Option<u16>,

    input_events: Vec<Vec<u8>>,
    /// What the client sent on the MCS message channel meanwhile, in order.
    message_channel_pdus: Vec<Vec<u8>>,
}

/// A PDU the client sent during the finalization.
enum Received {
    /// Something on the MCS message channel: its user data.
    MessageChannel(Vec<u8>),
    /// A Share Control PDU on the I/O channel.
    ShareControl(ShareControlHeader),
    /// Anything else, such as fast-path input.
    Other,
}

fn receive(input: &[u8], message_channel_id: Option<u16>) -> Received {
    let Ok(X224(request)) = ironrdp_core::decode::<X224<ironrdp_pdu::mcs::SendDataRequest<'_>>>(input) else {
        return Received::Other;
    };
    if Some(request.channel_id) == message_channel_id {
        return Received::MessageChannel(request.user_data.to_vec());
    }
    match ironrdp_core::decode::<ShareControlHeader>(request.user_data.as_ref()) {
        Ok(pdu) => Received::ShareControl(pdu),
        Err(_) => Received::Other,
    }
}

fn share_data(pdu: &ShareControlHeader) -> Option<&ShareDataPdu> {
    match &pdu.share_control_pdu {
        ShareControlPdu::Data(data) => Some(&data.share_data_pdu),
        _ => None,
    }
}

fn is_control(pdu: &ShareControlHeader, action: ControlAction) -> bool {
    matches!(share_data(pdu), Some(ShareDataPdu::Control(control)) if control.action == action)
}

#[derive(Default, Debug)]
pub enum FinalizationState {
    #[default]
    Consumed,

    WaitSynchronize,
    WaitControlCooperate,
    WaitRequestControl,
    WaitFontList,

    SendSynchronizeConfirm,
    SendControlCooperateConfirm,
    SendGrantedControlConfirm,
    SendFontMap,

    Finished,
}

impl State for FinalizationState {
    fn name(&self) -> &'static str {
        match self {
            Self::Consumed => "Consumed",
            Self::WaitSynchronize => "WaitSynchronize",
            Self::WaitControlCooperate => "WaitControlCooperate",
            Self::WaitRequestControl => "WaitRequestControl",
            Self::WaitFontList => "WaitFontList",
            Self::SendSynchronizeConfirm => "SendSynchronizeConfirm",
            Self::SendControlCooperateConfirm => "SendControlCooperateConfirm",
            Self::SendGrantedControlConfirm => "SendGrantedControlConfirm",
            Self::SendFontMap => "SendFontMap",
            Self::Finished => "Finished",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Finished { .. })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Sequence for FinalizationSequence {
    fn next_pdu_hint(&self) -> Option<&dyn ironrdp_pdu::PduHint> {
        match &self.state {
            FinalizationState::Consumed => None,
            FinalizationState::WaitSynchronize => Some(&ironrdp_pdu::RdpHint),
            FinalizationState::WaitControlCooperate => Some(&ironrdp_pdu::RdpHint),
            FinalizationState::WaitRequestControl => Some(&ironrdp_pdu::RdpHint),
            FinalizationState::WaitFontList => Some(&ironrdp_pdu::RdpHint),
            FinalizationState::SendSynchronizeConfirm => None,
            FinalizationState::SendControlCooperateConfirm => None,
            FinalizationState::SendGrantedControlConfirm => None,
            FinalizationState::SendFontMap => None,
            FinalizationState::Finished => None,
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
            // MS-RDPBCGR 1.3.1.1, Connection Finalization: the client sends
            // Synchronize, Control (Cooperate), Control (Request Control),
            // then Font List. Each wait takes only the PDU it waits for; the
            // Multitransport Response or anything else on the message channel
            // is set aside for the server, and other PDUs join the input
            // handed over with the result.
            FinalizationState::WaitSynchronize => match receive(input, self.message_channel_id) {
                Received::ShareControl(pdu) if matches!(share_data(&pdu), Some(ShareDataPdu::Synchronize(_))) => {
                    debug!(message = ?pdu, "Received");

                    (Written::Nothing, FinalizationState::WaitControlCooperate)
                }
                other => (
                    Written::Nothing,
                    self.set_aside(other, input, FinalizationState::WaitSynchronize),
                ),
            },

            FinalizationState::WaitControlCooperate => match receive(input, self.message_channel_id) {
                Received::ShareControl(pdu) if is_control(&pdu, ControlAction::Cooperate) => {
                    debug!(message = ?pdu, "Received");

                    (Written::Nothing, FinalizationState::WaitRequestControl)
                }
                other => (
                    Written::Nothing,
                    self.set_aside(other, input, FinalizationState::WaitControlCooperate),
                ),
            },

            FinalizationState::WaitRequestControl => match receive(input, self.message_channel_id) {
                Received::ShareControl(pdu) if is_control(&pdu, ControlAction::RequestControl) => {
                    debug!(message = ?pdu, "Received");

                    (Written::Nothing, FinalizationState::WaitFontList)
                }
                other => (
                    Written::Nothing,
                    self.set_aside(other, input, FinalizationState::WaitRequestControl),
                ),
            },

            FinalizationState::WaitFontList => match receive(input, self.message_channel_id) {
                Received::ShareControl(pdu) if matches!(share_data(&pdu), Some(ShareDataPdu::FontList(_))) => {
                    debug!(message = ?pdu, "Received");

                    (Written::Nothing, FinalizationState::SendSynchronizeConfirm)
                }
                other => (
                    Written::Nothing,
                    self.set_aside(other, input, FinalizationState::WaitFontList),
                ),
            },

            FinalizationState::SendSynchronizeConfirm => {
                let synchronize_confirm = create_synchronize_confirm();

                debug!(message = ?synchronize_confirm, "Send");

                let share_data = wrap_share_data(synchronize_confirm, self.io_channel_id);
                let written =
                    util::encode_send_data_indication(self.user_channel_id, self.io_channel_id, &share_data, output)?;

                (
                    Written::from_size(written)?,
                    FinalizationState::SendControlCooperateConfirm,
                )
            }

            FinalizationState::SendControlCooperateConfirm => {
                let cooperate_confirm = create_cooperate_confirm();

                debug!(message = ?cooperate_confirm, "Send");

                let share_data = wrap_share_data(cooperate_confirm, self.io_channel_id);
                let written =
                    util::encode_send_data_indication(self.user_channel_id, self.io_channel_id, &share_data, output)?;

                (
                    Written::from_size(written)?,
                    FinalizationState::SendGrantedControlConfirm,
                )
            }

            FinalizationState::SendGrantedControlConfirm => {
                let control_confirm = create_control_confirm(self.user_channel_id);

                debug!(message = ?control_confirm, "Send");

                let share_data = wrap_share_data(control_confirm, self.io_channel_id);
                let written =
                    util::encode_send_data_indication(self.user_channel_id, self.io_channel_id, &share_data, output)?;

                (Written::from_size(written)?, FinalizationState::SendFontMap)
            }

            FinalizationState::SendFontMap => {
                let font_map = create_font_map();

                debug!(message = ?font_map, "Send");

                let share_data = wrap_share_data(font_map, self.io_channel_id);
                let written =
                    util::encode_send_data_indication(self.user_channel_id, self.io_channel_id, &share_data, output)?;

                (Written::from_size(written)?, FinalizationState::Finished)
            }

            _ => unreachable!(),
        };

        self.state = next_state;
        Ok(written)
    }
}

impl FinalizationSequence {
    pub fn new(user_channel_id: u16, io_channel_id: u16, message_channel_id: Option<u16>) -> Self {
        Self {
            state: FinalizationState::WaitSynchronize,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            input_events: Vec::new(),
            message_channel_pdus: Vec::new(),
        }
    }

    pub fn into_input_events(self) -> Vec<Vec<u8>> {
        self.input_events
    }

    /// The PDUs received besides the finalization's own: input, and what
    /// came on the MCS message channel.
    pub fn into_received(self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        (self.input_events, self.message_channel_pdus)
    }

    /// Keep a PDU that is not the one `waiting` waits for, and wait on.
    fn set_aside(&mut self, received: Received, input: &[u8], waiting: FinalizationState) -> FinalizationState {
        match received {
            Received::MessageChannel(user_data) => {
                debug!(
                    ?waiting,
                    "message channel PDU during the finalization; kept for the server"
                );
                self.message_channel_pdus.push(user_data);
            }
            Received::ShareControl(pdu) => {
                if !matches!(waiting, FinalizationState::WaitFontList) {
                    warn!(?waiting, message = ?pdu, "unexpected PDU during the finalization; handed over as input");
                }
                self.input_events.push(input.to_vec());
            }
            Received::Other => self.input_events.push(input.to_vec()),
        }
        waiting
    }

    pub fn is_done(&self) -> bool {
        self.state.is_terminal()
    }
}

fn create_synchronize_confirm() -> ShareDataPdu {
    ShareDataPdu::Synchronize(SynchronizePdu { target_user_id: 0 })
}

fn create_cooperate_confirm() -> ShareDataPdu {
    ShareDataPdu::Control(ControlPdu {
        action: ControlAction::Cooperate,
        grant_id: 0,
        control_id: 0,
    })
}

fn create_control_confirm(user_id: u16) -> ShareDataPdu {
    ShareDataPdu::Control(ControlPdu {
        action: ControlAction::GrantedControl,
        grant_id: user_id,
        control_id: u32::from(rdp::capability_sets::SERVER_CHANNEL_ID),
    })
}

fn create_font_map() -> ShareDataPdu {
    ShareDataPdu::FontMap(FontPdu::default())
}

#[cfg(test)]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::mcs::SendDataRequest;
    use ironrdp_pdu::rdp::client_info::CompressionType;
    use ironrdp_pdu::rdp::headers::{CompressionFlags, ShareDataHeader, StreamPriority};

    use super::*;

    fn on_channel(channel_id: u16, user_data: Vec<u8>) -> Vec<u8> {
        encode_vec(&X224(SendDataRequest {
            initiator_id: 1007,
            channel_id,
            user_data: user_data.into(),
        }))
        .expect("encode")
    }

    /// A Share Data PDU on the I/O channel.
    fn io(pdu: ShareDataPdu) -> Vec<u8> {
        let header = ShareControlHeader {
            share_id: 0,
            pdu_source: 1007,
            share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: pdu,
                stream_priority: StreamPriority::Medium,
                compression_flags: CompressionFlags::empty(),
                compression_type: CompressionType::K8,
            }),
        };
        on_channel(1003, encode_vec(&header).expect("encode"))
    }

    fn control(action: ControlAction) -> Vec<u8> {
        io(ShareDataPdu::Control(ControlPdu {
            action,
            grant_id: 0,
            control_id: 0,
        }))
    }

    fn synchronize() -> Vec<u8> {
        io(ShareDataPdu::Synchronize(SynchronizePdu { target_user_id: 1007 }))
    }

    fn step(finalization: &mut FinalizationSequence, input: &[u8]) {
        finalization.step(input, None, &mut WriteBuf::new()).expect("step");
    }

    /// MS-RDPBCGR 1.3.1.1: the client finalizes with Synchronize, Control
    /// (Cooperate), Control (Request Control) and Font List. A Multitransport
    /// Response on the message channel in between (2.2.15.2) is kept for the
    /// server, not taken for the next of them.
    ///
    /// Regression: any PDU counted as the next one.
    #[test]
    fn a_message_channel_pdu_during_the_finalization_is_set_aside() {
        let mut finalization = FinalizationSequence::new(1007, 1003, Some(1008));
        let response = vec![0x04, 0x00, 0x00, 0x00, 7, 0, 0, 0, 0, 0, 0, 0];

        step(&mut finalization, &synchronize());
        step(&mut finalization, &on_channel(1008, response.clone()));
        step(&mut finalization, &control(ControlAction::Cooperate));
        step(&mut finalization, &control(ControlAction::RequestControl));
        step(&mut finalization, &io(ShareDataPdu::FontList(FontPdu::default())));
        while !finalization.is_done() {
            step(&mut finalization, &[]);
        }

        let (input_events, message_channel_pdus) = finalization.into_received();
        assert!(input_events.is_empty());
        assert_eq!(message_channel_pdus, [response]);
    }

    /// A PDU that is not the one awaited does not move the finalization on;
    /// it is handed over with the input.
    #[test]
    fn an_unexpected_pdu_does_not_advance_the_finalization() {
        let mut finalization = FinalizationSequence::new(1007, 1003, Some(1008));

        step(&mut finalization, &control(ControlAction::Cooperate));
        assert!(matches!(finalization.state, FinalizationState::WaitSynchronize));

        step(&mut finalization, &synchronize());
        assert!(matches!(finalization.state, FinalizationState::WaitControlCooperate));

        let (input_events, _) = finalization.into_received();
        assert_eq!(input_events, [control(ControlAction::Cooperate)]);
    }
}
