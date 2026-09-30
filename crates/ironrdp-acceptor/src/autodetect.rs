//! Optional Connect-Time Auto-Detection ([MS-RDPBCGR] 1.3.1.1, phase 6).
//!
//! Between the Secure Settings Exchange and Licensing the server measures the
//! link and tells the client what it found ([MS-RDPBCGR] 1.3.9). Over the main
//! connection this is the only place for a Network Characteristics Result:
//! during Continuous Auto-Detection that message travels over sideband
//! channels only. A client that never gets one has no network
//! characteristics at all.
//!
//! The exchange, all on the MCS message channel (2.2.14.3, 2.2.14.4):
//!
//! 1. RTT Measure Request (0x1001), answered by an RTT Measure Response.
//! 2. Bandwidth Measure Start (0x1014), Payloads (0x0002) and Stop (0x002B),
//!    answered by Bandwidth Measure Results (0x0003).
//! 3. Network Characteristics Result, which the client does not answer.
//!
//! The client may answer the Start with a Network Characteristics Sync
//! instead (3.2.5.14); the server then MUST stop measuring and use the values
//! it carries (3.3.5.14).

use ironrdp_connector::{ConnectorResult, MonotonicInstant, Written};
use ironrdp_core::{WriteBuf, decode};
use ironrdp_pdu::mcs::SendDataRequest;
use ironrdp_pdu::rdp::autodetect::{
    AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu, BW_RESULTS_CONNECT_TIME,
    NETCHAR_RESULT_RTT,
};
use ironrdp_pdu::x224::X224;
use tracing::debug;

use crate::util;

const RTT_SEQUENCE: u16 = 0;
const BANDWIDTH_START_SEQUENCE: u16 = 1;
/// After the Start, the Payloads and the Stop.
const RESULT_SEQUENCE: u16 = BANDWIDTH_START_SEQUENCE + PAYLOAD_COUNT + 2;

/// Bandwidth Measure Payloads sent between Start and Stop, and the size of
/// each; the Stop carries one more of the same size (2.2.14.1.4: it MUST
/// carry a payload). About 90 KB in all: enough to take a few milliseconds on
/// a gigabit link, a second at under a megabit.
const PAYLOAD_COUNT: u16 = 5;
const PAYLOAD_LEN: usize = 15_000;

/// What Connect-Time Auto-Detection found out about the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkCharacteristics {
    /// Round-trip time in milliseconds, when it could be timed.
    pub rtt_ms: Option<u32>,
    /// Bandwidth in kilobits per second.
    pub bandwidth_kbps: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    SendRttRequest,
    WaitRttResponse,
    SendBandwidthMeasure,
    WaitBandwidthResults,
    SendResult,
    Done,
}

/// The server's side of the Optional Connect-Time Auto-Detection phase.
#[derive(Debug, Clone)]
pub struct ConnectTimeAutoDetection {
    step: Step,
    message_channel_id: u16,
    /// When the RTT Measure Request went out: the arrival of the PDU that
    /// preceded it, since the request follows it without waiting.
    rtt_sent_at: Option<MonotonicInstant>,
    found: NetworkCharacteristics,
}

impl ConnectTimeAutoDetection {
    pub(crate) fn new(message_channel_id: u16, started_at: Option<MonotonicInstant>) -> Self {
        Self {
            step: Step::SendRttRequest,
            message_channel_id,
            rtt_sent_at: started_at,
            found: NetworkCharacteristics::default(),
        }
    }

    pub(crate) fn waits_for_input(&self) -> bool {
        matches!(self.step, Step::WaitRttResponse | Step::WaitBandwidthResults)
    }

    pub(crate) fn is_done(&self) -> bool {
        self.step == Step::Done
    }

    pub(crate) fn found(&self) -> NetworkCharacteristics {
        self.found
    }

    pub(crate) fn step(
        &mut self,
        input: &[u8],
        received_at: Option<MonotonicInstant>,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        match self.step {
            Step::SendRttRequest => {
                let written = self.send(AutoDetectRequest::rtt_connect_time(RTT_SEQUENCE), output)?;
                self.step = Step::WaitRttResponse;
                Written::from_size(written)
            }

            Step::WaitRttResponse => {
                match self.response(input) {
                    Some(AutoDetectResponse::RttResponse { sequence_number }) if sequence_number == RTT_SEQUENCE => {
                        self.found.rtt_ms = match (self.rtt_sent_at, received_at) {
                            (Some(sent), Some(received)) => {
                                Some(u32::try_from(received.duration_since(sent).as_millis()).unwrap_or(u32::MAX))
                            }
                            _ => None,
                        };
                        self.step = Step::SendBandwidthMeasure;
                    }
                    Some(AutoDetectResponse::NetworkCharacteristicsSync {
                        bandwidth_kbps, rtt_ms, ..
                    }) => self.synced(bandwidth_kbps, rtt_ms),
                    other => debug!(?other, "Not the RTT Measure Response; still waiting"),
                }
                Ok(Written::Nothing)
            }

            Step::SendBandwidthMeasure => {
                let mut written = self.send(
                    AutoDetectRequest::bw_start_connect_time(BANDWIDTH_START_SEQUENCE),
                    output,
                )?;
                let mut payload = Payload::new();
                for sequence_number in 1..=PAYLOAD_COUNT {
                    written += self.send(
                        AutoDetectRequest::bw_payload(BANDWIDTH_START_SEQUENCE + sequence_number, payload.next_chunk()),
                        output,
                    )?;
                }
                written += self.send(
                    AutoDetectRequest::bw_stop_connect_time(
                        BANDWIDTH_START_SEQUENCE + PAYLOAD_COUNT + 1,
                        payload.next_chunk(),
                    ),
                    output,
                )?;
                self.step = Step::WaitBandwidthResults;
                Written::from_size(written)
            }

            Step::WaitBandwidthResults => {
                match self.response(input) {
                    Some(
                        response @ AutoDetectResponse::BandwidthMeasureResults {
                            response_type: BW_RESULTS_CONNECT_TIME,
                            time_delta_ms,
                            byte_count,
                            ..
                        },
                    ) => {
                        // A transfer faster than the client's millisecond
                        // timer still took up to one: count it as one rather
                        // than reporting no bandwidth at all.
                        self.found.bandwidth_kbps = response.computed_bandwidth_kbps().or_else(|| {
                            (time_delta_ms == 0).then(|| u32::try_from(u64::from(byte_count) * 8).unwrap_or(u32::MAX))
                        });
                        self.step = Step::SendResult;
                    }
                    Some(AutoDetectResponse::NetworkCharacteristicsSync {
                        bandwidth_kbps, rtt_ms, ..
                    }) => self.synced(bandwidth_kbps, rtt_ms),
                    other => debug!(?other, "Not the Bandwidth Measure Results; still waiting"),
                }
                Ok(Written::Nothing)
            }

            Step::SendResult => {
                self.step = Step::Done;
                let result = match (self.found.rtt_ms, self.found.bandwidth_kbps) {
                    (Some(rtt), Some(bandwidth)) => {
                        AutoDetectRequest::netchar_result(RESULT_SEQUENCE, rtt, bandwidth, rtt)
                    }
                    (Some(rtt), None) => AutoDetectRequest::NetworkCharacteristicsResult {
                        sequence_number: RESULT_SEQUENCE,
                        request_type: NETCHAR_RESULT_RTT,
                        base_rtt_ms: Some(rtt),
                        bandwidth_kbps: None,
                        average_rtt_ms: rtt,
                    },
                    // Every form of the result carries averageRTT, which this
                    // build could not time.
                    (None, _) => return Ok(Written::Nothing),
                };
                debug!(found = ?self.found, "Send Network Characteristics Result");
                Written::from_size(self.send(result, output)?)
            }

            Step::Done => Ok(Written::Nothing),
        }
    }

    /// 3.3.5.14: on a Network Characteristics Sync the server "MUST stop any
    /// RTT or bandwidth measurement operation that is in progress and instead
    /// use the values transmitted". The client has them already, so no result
    /// follows.
    fn synced(&mut self, bandwidth_kbps: u32, rtt_ms: u32) {
        debug!(bandwidth_kbps, rtt_ms, "Client sent Network Characteristics Sync");
        self.found = NetworkCharacteristics {
            rtt_ms: Some(rtt_ms),
            bandwidth_kbps: Some(bandwidth_kbps),
        };
        self.step = Step::Done;
    }

    fn send(&self, request: AutoDetectRequest, output: &mut WriteBuf) -> ConnectorResult<usize> {
        util::encode_send_data_indication(
            ironrdp_pdu::rdp::capability_sets::SERVER_CHANNEL_ID,
            self.message_channel_id,
            &AutoDetectReqPdu::new(request),
            output,
        )
    }

    /// The Auto-Detect Response in `input`, if it is one on the message
    /// channel.
    fn response(&self, input: &[u8]) -> Option<AutoDetectResponse> {
        let X224(request) = decode::<X224<SendDataRequest<'_>>>(input).ok()?;
        if request.channel_id != self.message_channel_id {
            return None;
        }
        decode::<AutoDetectRspPdu>(request.user_data.as_ref())
            .ok()
            .map(|pdu| pdu.response)
    }
}

/// The payload bytes, which 2.2.14.1.3 describes as random data: nothing
/// reads them, they only have to take time to cross the link, so a xorshift
/// sequence serves.
struct Payload(u32);

impl Payload {
    fn new() -> Self {
        Self(0x9E37_79B9)
    }

    fn next_chunk(&mut self) -> Vec<u8> {
        let mut chunk = Vec::with_capacity(PAYLOAD_LEN);
        while chunk.len() < PAYLOAD_LEN {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            chunk.extend_from_slice(&self.0.to_le_bytes());
        }
        chunk.truncate(PAYLOAD_LEN);
        chunk
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::mcs::SendDataIndication;
    use ironrdp_pdu::rdp::autodetect::{
        BW_PAYLOAD, BW_START_CONNECT_TIME, BW_STOP_CONNECT_TIME, NETCHAR_RESULT_ALL, RTT_REQUEST_CONNECT_TIME,
    };

    use super::*;

    const MESSAGE_CHANNEL: u16 = 1008;

    /// The Auto-Detect Requests in `output`, one per MCS PDU, with their
    /// channel.
    fn requests(output: &WriteBuf) -> Vec<(u16, AutoDetectRequest)> {
        let mut frames = output.filled();
        let mut found = Vec::new();
        while !frames.is_empty() {
            let len = usize::from(u16::from_be_bytes([frames[2], frames[3]]));
            let X224(indication) = decode::<X224<SendDataIndication<'_>>>(&frames[..len]).expect("indication");
            let pdu = decode::<AutoDetectReqPdu>(indication.user_data.as_ref()).expect("auto-detect request");
            found.push((indication.channel_id, pdu.request));
            frames = &frames[len..];
        }
        found
    }

    fn response(response: AutoDetectResponse) -> Vec<u8> {
        encode_vec(&X224(SendDataRequest {
            initiator_id: 1007,
            channel_id: MESSAGE_CHANNEL,
            user_data: encode_vec(&AutoDetectRspPdu::new(response)).expect("encode").into(),
        }))
        .expect("encode")
    }

    fn step(detection: &mut ConnectTimeAutoDetection, input: &[u8], at: u64) -> WriteBuf {
        let mut output = WriteBuf::new();
        detection
            .step(input, Some(MonotonicInstant::from_millis(at)), &mut output)
            .expect("step");
        output
    }

    fn request_type(request: &AutoDetectRequest) -> u16 {
        match request {
            AutoDetectRequest::RttRequest { request_type, .. }
            | AutoDetectRequest::BandwidthMeasureStart { request_type, .. }
            | AutoDetectRequest::BandwidthMeasureStop { request_type, .. }
            | AutoDetectRequest::NetworkCharacteristicsResult { request_type, .. } => *request_type,
            AutoDetectRequest::BandwidthMeasurePayload { .. } => BW_PAYLOAD,
        }
    }

    /// MS-RDPBCGR 1.3.9: RTT, then bandwidth, then the Network
    /// Characteristics Result, all on the message channel, with the
    /// connect-time request types (2.2.14.1).
    #[test]
    fn the_link_is_measured_and_the_result_sent() {
        let mut detection = ConnectTimeAutoDetection::new(MESSAGE_CHANNEL, Some(MonotonicInstant::from_millis(1000)));

        let sent = requests(&step(&mut detection, &[], 1000));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, MESSAGE_CHANNEL);
        assert_eq!(request_type(&sent[0].1), RTT_REQUEST_CONNECT_TIME);
        assert!(detection.waits_for_input());

        let rtt = response(AutoDetectResponse::RttResponse {
            sequence_number: sent[0].1.sequence_number(),
        });
        assert!(step(&mut detection, &rtt, 1012).filled().is_empty());

        let sent = requests(&step(&mut detection, &[], 1012));
        let types: Vec<u16> = sent.iter().map(|(_, request)| request_type(request)).collect();
        assert_eq!(
            types,
            [
                BW_START_CONNECT_TIME,
                BW_PAYLOAD,
                BW_PAYLOAD,
                BW_PAYLOAD,
                BW_PAYLOAD,
                BW_PAYLOAD,
                BW_STOP_CONNECT_TIME
            ]
        );
        assert!(matches!(
            &sent[6].1,
            AutoDetectRequest::BandwidthMeasureStop { payload: Some(payload), .. } if !payload.is_empty()
        ));

        let results = response(AutoDetectResponse::BandwidthMeasureResults {
            sequence_number: 7,
            response_type: BW_RESULTS_CONNECT_TIME,
            time_delta_ms: 10,
            byte_count: 90_000,
        });
        step(&mut detection, &results, 1030);

        let sent = requests(&step(&mut detection, &[], 1030));
        assert_eq!(sent.len(), 1);
        assert!(matches!(
            sent[0].1,
            AutoDetectRequest::NetworkCharacteristicsResult {
                request_type: NETCHAR_RESULT_ALL,
                base_rtt_ms: Some(12),
                bandwidth_kbps: Some(72_000),
                average_rtt_ms: 12,
                ..
            }
        ));
        assert!(detection.is_done());
        assert_eq!(
            detection.found(),
            NetworkCharacteristics {
                rtt_ms: Some(12),
                bandwidth_kbps: Some(72_000),
            }
        );
    }

    /// MS-RDPBCGR 3.3.5.14: on a Network Characteristics Sync the server
    /// stops measuring and uses the client's values.
    #[test]
    fn a_sync_ends_the_measurement() {
        let mut detection = ConnectTimeAutoDetection::new(MESSAGE_CHANNEL, Some(MonotonicInstant::from_millis(0)));
        step(&mut detection, &[], 0);

        let sync = response(AutoDetectResponse::NetworkCharacteristicsSync {
            sequence_number: 0,
            bandwidth_kbps: 50_000,
            rtt_ms: 3,
        });
        step(&mut detection, &sync, 5);

        assert!(detection.is_done());
        assert_eq!(
            detection.found(),
            NetworkCharacteristics {
                rtt_ms: Some(3),
                bandwidth_kbps: Some(50_000),
            }
        );
    }

    /// Anything but the awaited response, such as a PDU on another channel,
    /// leaves the exchange waiting.
    #[test]
    fn other_pdus_are_not_taken_for_the_response() {
        let mut detection = ConnectTimeAutoDetection::new(MESSAGE_CHANNEL, None);
        step(&mut detection, &[], 0);

        let elsewhere = encode_vec(&X224(SendDataRequest {
            initiator_id: 1007,
            channel_id: 1003,
            user_data: vec![0; 8].into(),
        }))
        .expect("encode");
        step(&mut detection, &elsewhere, 1);

        assert!(detection.waits_for_input());
        assert!(!detection.is_done());
    }
}
