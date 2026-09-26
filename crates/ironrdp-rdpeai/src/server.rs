//! AUDIO_INPUT dynamic virtual channel server (MS-RDPEAI): the recording side.
//!
//! The server opens the channel when something in the session starts
//! recording (3.1.4.1), then drives the initialization sequence (1.3.1):
//! Version, Sound Formats, Open. Once the client's Open Reply succeeds, the
//! client streams its microphone in Data PDUs, which reach the
//! [`RdpeaiServerHandler`].

use ironrdp_core::{decode, impl_as_any};
use ironrdp_dvc::{DvcMessage, DvcProcessor, DvcServerProcessor};
use ironrdp_pdu::PduResult;
use ironrdp_rdpsnd::pdu::AudioFormat;
use tracing::{debug, info, warn};

use crate::CHANNEL_NAME;
use crate::pdu::{FormatsPdu, OpenPdu, RdpeaiPdu, Version, VersionPdu};

/// How much audio the client puts in one Data PDU (`FramesPerPacket`,
/// MS-RDPEAI 2.2.2.3), in milliseconds.
const PACKET_MS: u32 = 20;

/// The recording side's backend.
pub trait RdpeaiServerHandler: Send {
    /// The formats the server takes, most preferred first. MS-RDPEAI 2.2.2.2:
    /// implementations MUST support `WAVE_FORMAT_PCM`.
    fn formats(&self) -> Vec<AudioFormat>;

    /// The client opened its capture device; its audio arrives in `format`
    /// until the format changes (3.3.5.1.8).
    fn opened(&mut self, _format: &AudioFormat) {}

    /// The client could not open its capture device: `result` is the
    /// HRESULT of its Open Reply PDU (3.3.5.1.8).
    fn open_failed(&mut self, _result: i32) {}

    /// One packet of the client's audio, encoded in `format` (3.3.5.2.2).
    fn data(&mut self, format: &AudioFormat, data: &[u8]);

    /// The channel is gone. `created` is false when the client refused to
    /// create it (MS-RDPEDYC 3.3.3.2), for example because it does not
    /// redirect its microphone.
    fn closed(&mut self, _created: bool) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The channel is not open.
    Idle,
    /// Version sent; waiting for the client's (3.3.5.1.1–2).
    WaitVersion,
    /// Sound Formats sent; waiting for the client's (3.3.5.1.3, 3.3.5.1.5).
    WaitFormats,
    /// Open sent; waiting for the Open Reply (3.3.5.1.6, 3.3.5.1.8).
    WaitOpenReply,
    /// The client records; Data PDUs follow (3.3.5.2).
    Recording,
    /// Nothing more happens on this channel: no format in common, or the
    /// client could not open its capture device.
    Stopped,
}

/// Server processor for the `AUDIO_INPUT` dynamic virtual channel.
pub struct RdpeaiServer {
    handler: Box<dyn RdpeaiServerHandler>,
    state: State,
    /// Whether the client created the channel (`start` ran).
    created: bool,
    client_version: Option<Version>,
    /// The client's Sound Formats list. Open and Format Change indices refer
    /// to it (3.2.5.1.5), so it is kept as the client sent it.
    formats: Vec<AudioFormat>,
    /// Index into `formats` of the format the client encodes in.
    current: Option<usize>,
}

impl RdpeaiServer {
    pub fn new(handler: Box<dyn RdpeaiServerHandler>) -> Self {
        Self {
            handler,
            state: State::Idle,
            created: false,
            client_version: None,
            formats: Vec::new(),
            current: None,
        }
    }

    /// The protocol version the client announced (MS-RDPEAI 3.3.5.1.2), once
    /// it has.
    pub fn client_version(&self) -> Option<Version> {
        self.client_version
    }

    /// MS-RDPEAI 3.3.5.1.5–6: store the client's list, then ask it to record
    /// in the most preferred format it kept.
    fn on_client_formats(&mut self, formats: Vec<AudioFormat>) -> Vec<DvcMessage> {
        self.formats = formats;
        let ours = self.handler.formats();
        let chosen = ours.iter().find_map(|preferred| {
            self.formats
                .iter()
                .position(|offered| offered.matches_for_negotiation(preferred))
        });
        let Some(index) = chosen else {
            warn!(
                client_formats = self.formats.len(),
                "the client kept no audio format this server takes; not recording"
            );
            self.state = State::Stopped;
            return Vec::new();
        };

        let format = self.formats[index].clone();
        // `initialFormat` is a 32-bit index into a list the client sent, so
        // an index that fits in memory fits here.
        let initial_format = u32::try_from(index).unwrap_or(u32::MAX);
        let open = OpenPdu {
            frames_per_packet: (format.n_samples_per_sec / (1000 / PACKET_MS)).max(1),
            initial_format,
            // The same format for capture and encoding: the client records
            // PCM and has nothing to transcode (3.2.5.1.6).
            capture_format: format,
        };
        debug!(initial_format, ?open.capture_format, "AUDIO_INPUT: asking the client to record");
        self.current = Some(index);
        self.state = State::WaitOpenReply;
        vec![Box::new(RdpeaiPdu::Open(open))]
    }

    /// MS-RDPEAI 3.3.5.1.7 and 3.3.5.3.2: the client confirms the format its
    /// audio is encoded in.
    fn on_format_change(&mut self, index: u32) {
        let Some(index) = usize::try_from(index).ok().filter(|index| *index < self.formats.len()) else {
            debug!(index, "ignoring a Format Change PDU outside the negotiated list");
            return;
        };
        self.current = Some(index);
    }
}

impl_as_any!(RdpeaiServer);

impl DvcProcessor for RdpeaiServer {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        debug!(channel_id, "AUDIO_INPUT channel created");
        self.created = true;
        self.client_version = None;
        self.formats.clear();
        self.current = None;
        // MS-RDPEAI 3.3.5.1.1: "The Version PDU MUST be the first PDU sent by
        // the server." Version 2 only matters for AAC (3.3.5.3.1), which this
        // server does not take.
        self.state = State::WaitVersion;
        Ok(vec![Box::new(RdpeaiPdu::Version(VersionPdu::new(Version::V1)))])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        // MS-RDPEAI 3.1.5: "Malformed packets that do not meet the
        // specifications outlined in section 2.2, unrecognized packets, and
        // out-of-sequence packets MUST be ignored by the server and the client."
        let pdu: RdpeaiPdu = match decode(payload) {
            Ok(pdu) => pdu,
            Err(error) => {
                debug!(%error, "ignoring a malformed AUDIO_INPUT PDU");
                return Ok(Vec::new());
            }
        };

        match (self.state, pdu) {
            (State::WaitVersion, RdpeaiPdu::Version(version)) => {
                // 3.3.5.1.2–3: store it, then announce the formats.
                self.client_version = Some(version.version);
                self.state = State::WaitFormats;
                Ok(vec![Box::new(RdpeaiPdu::Formats(FormatsPdu::server(
                    self.handler.formats(),
                )))])
            }
            (State::WaitFormats, RdpeaiPdu::Formats(formats)) => Ok(self.on_client_formats(formats.formats)),
            (State::WaitOpenReply | State::Recording, RdpeaiPdu::FormatChange(change)) => {
                self.on_format_change(change.new_format);
                Ok(Vec::new())
            }
            (State::WaitOpenReply, RdpeaiPdu::OpenReply(reply)) => {
                // An HRESULT is an error when its top bit is set (MS-ERREF 2.1).
                if reply.result >= 0 {
                    if let Some(format) = self.current.and_then(|index| self.formats.get(index)) {
                        info!(?format, "AUDIO_INPUT: the client records its microphone");
                        self.handler.opened(format);
                    }
                    self.state = State::Recording;
                } else {
                    warn!(
                        result = format!("{:#010X}", reply.result),
                        "AUDIO_INPUT: the client could not open its microphone"
                    );
                    self.handler.open_failed(reply.result);
                    self.state = State::Stopped;
                }
                Ok(Vec::new())
            }
            (State::Recording, RdpeaiPdu::Data(data)) => {
                if let Some(format) = self.current.and_then(|index| self.formats.get(index)) {
                    self.handler.data(format, &data.data);
                }
                Ok(Vec::new())
            }
            // 3.3.5.1.4, 3.3.5.2.1: diagnostic only.
            (_, RdpeaiPdu::DataIncoming) => Ok(Vec::new()),
            (state, pdu) => {
                debug!(?state, pdu = ?core::mem::discriminant(&pdu), "ignoring an out-of-sequence AUDIO_INPUT PDU");
                Ok(Vec::new())
            }
        }
    }

    fn close(&mut self, channel_id: u32) {
        debug!(channel_id, created = self.created, "AUDIO_INPUT channel closed");
        self.handler.closed(self.created);
        self.created = false;
        self.state = State::Idle;
        self.formats.clear();
        self.current = None;
    }
}

impl DvcServerProcessor for RdpeaiServer {}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ironrdp_core::encode_vec;

    use super::*;
    use crate::pdu::{DataPdu, FormatChangePdu, OpenReplyPdu, pcm_format};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Opened(AudioFormat),
        OpenFailed(i32),
        Data(AudioFormat, Vec<u8>),
        Closed(bool),
    }

    struct Recorder {
        formats: Vec<AudioFormat>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl RdpeaiServerHandler for Recorder {
        fn formats(&self) -> Vec<AudioFormat> {
            self.formats.clone()
        }

        fn opened(&mut self, format: &AudioFormat) {
            self.events.lock().expect("events").push(Event::Opened(format.clone()));
        }

        fn open_failed(&mut self, result: i32) {
            self.events.lock().expect("events").push(Event::OpenFailed(result));
        }

        fn data(&mut self, format: &AudioFormat, data: &[u8]) {
            self.events
                .lock()
                .expect("events")
                .push(Event::Data(format.clone(), data.to_vec()));
        }

        fn closed(&mut self, created: bool) {
            self.events.lock().expect("events").push(Event::Closed(created));
        }
    }

    fn stereo_48k() -> AudioFormat {
        pcm_format(2, 48_000, 16)
    }

    fn stereo_44k() -> AudioFormat {
        pcm_format(2, 44_100, 16)
    }

    fn server(formats: Vec<AudioFormat>) -> (RdpeaiServer, Arc<Mutex<Vec<Event>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder {
            formats,
            events: Arc::clone(&events),
        };
        (RdpeaiServer::new(Box::new(recorder)), events)
    }

    /// What the server sent, decoded.
    fn sent(messages: PduResult<Vec<DvcMessage>>) -> Vec<RdpeaiPdu> {
        messages
            .expect("processed")
            .iter()
            .map(|message| decode(&encode_vec(message.as_ref()).expect("encode")).expect("decode"))
            .collect()
    }

    fn receive(server: &mut RdpeaiServer, pdu: RdpeaiPdu) -> Vec<RdpeaiPdu> {
        sent(server.process(7, &encode_vec(&pdu).expect("encode")))
    }

    /// Runs the initialization sequence up to the Open PDU.
    fn negotiate(server: &mut RdpeaiServer, client_formats: Vec<AudioFormat>) -> Vec<RdpeaiPdu> {
        sent(server.start(7));
        receive(server, RdpeaiPdu::Version(VersionPdu::new(Version::V2)));
        receive(server, RdpeaiPdu::DataIncoming);
        receive(server, RdpeaiPdu::Formats(FormatsPdu::client(client_formats)))
    }

    /// MS-RDPEAI 3.3.5.1.1: "The Version PDU MUST be the first PDU sent by the
    /// server."
    ///
    /// Regression: linrdp ran the client role on this channel, which sends
    /// nothing first, so the microphone never started.
    #[test]
    fn the_server_speaks_first_with_its_version() {
        let (mut server, _) = server(vec![stereo_48k()]);

        assert_eq!(
            sent(server.start(7)),
            [RdpeaiPdu::Version(VersionPdu::new(Version::V1))]
        );
    }

    /// MS-RDPEAI 1.3.1: Version, Sound Formats, Open, then the client's
    /// Format Change and Open Reply, then Data.
    #[test]
    fn the_initialization_sequence_leads_to_the_clients_audio() {
        let (mut server, events) = server(vec![stereo_48k(), stereo_44k()]);

        assert_eq!(
            sent(server.start(7)),
            [RdpeaiPdu::Version(VersionPdu::new(Version::V1))]
        );
        assert_eq!(
            receive(&mut server, RdpeaiPdu::Version(VersionPdu::new(Version::V2))),
            [RdpeaiPdu::Formats(FormatsPdu::server(vec![stereo_48k(), stereo_44k()]))]
        );
        assert!(receive(&mut server, RdpeaiPdu::DataIncoming).is_empty());
        assert_eq!(
            receive(&mut server, RdpeaiPdu::Formats(FormatsPdu::client(vec![stereo_48k()]))),
            [RdpeaiPdu::Open(OpenPdu {
                frames_per_packet: 960,
                initial_format: 0,
                capture_format: stereo_48k(),
            })]
        );
        assert!(receive(&mut server, RdpeaiPdu::FormatChange(FormatChangePdu::new(0))).is_empty());
        assert!(receive(&mut server, RdpeaiPdu::OpenReply(OpenReplyPdu::ok())).is_empty());
        receive(&mut server, RdpeaiPdu::DataIncoming);
        receive(&mut server, RdpeaiPdu::Data(DataPdu::new(vec![1, 2, 3, 4])));

        assert_eq!(
            *events.lock().expect("events"),
            [Event::Opened(stereo_48k()), Event::Data(stereo_48k(), vec![1, 2, 3, 4])]
        );
    }

    /// `initialFormat` indexes the client's list (3.2.5.1.5), and the server
    /// picks its own most preferred format from it.
    #[test]
    fn the_initial_format_is_the_preferred_one_indexed_in_the_clients_list() {
        let (mut server, _) = server(vec![stereo_48k(), stereo_44k()]);

        let open = negotiate(&mut server, vec![stereo_44k(), stereo_48k()]);
        assert!(matches!(
            open.as_slice(),
            [RdpeaiPdu::Open(OpenPdu {
                initial_format: 1,
                frames_per_packet: 960,
                ..
            })]
        ));
    }

    #[test]
    fn without_a_common_format_nothing_is_opened() {
        let (mut server, events) = server(vec![stereo_48k()]);

        assert!(negotiate(&mut server, vec![pcm_format(1, 8_000, 8)]).is_empty());
        receive(&mut server, RdpeaiPdu::OpenReply(OpenReplyPdu::ok()));
        receive(&mut server, RdpeaiPdu::Data(DataPdu::new(vec![1, 2])));
        assert!(events.lock().expect("events").is_empty());
    }

    /// MS-RDPEAI 3.1.5: malformed, unrecognized and out-of-sequence packets
    /// MUST be ignored, not end the channel.
    #[test]
    fn malformed_and_out_of_sequence_pdus_are_ignored() {
        let (mut server, events) = server(vec![stereo_48k()]);
        sent(server.start(7));

        assert!(sent(server.process(7, &[0xFF, 0x00])).is_empty(), "unknown message id");
        assert!(sent(server.process(7, &[])).is_empty(), "empty");
        assert!(
            receive(&mut server, RdpeaiPdu::Formats(FormatsPdu::client(vec![stereo_48k()]))).is_empty(),
            "Sound Formats before Version"
        );
        assert!(
            receive(&mut server, RdpeaiPdu::Data(DataPdu::new(vec![9]))).is_empty(),
            "Data before Open"
        );

        // The sequence still works afterwards.
        assert!(matches!(
            receive(&mut server, RdpeaiPdu::Version(VersionPdu::new(Version::V1))).as_slice(),
            [RdpeaiPdu::Formats(_)]
        ));
        assert!(events.lock().expect("events").is_empty());
    }

    /// MS-RDPEAI 3.3.5.1.8: after an error the client "MUST not send audio
    /// data".
    #[test]
    fn a_failed_open_reply_ends_recording() {
        let (mut server, events) = server(vec![stereo_48k()]);
        negotiate(&mut server, vec![stereo_48k()]);

        receive(&mut server, RdpeaiPdu::OpenReply(OpenReplyPdu::fail()));
        receive(&mut server, RdpeaiPdu::Data(DataPdu::new(vec![1, 2])));

        assert_eq!(
            *events.lock().expect("events"),
            [Event::OpenFailed(OpenReplyPdu::E_FAIL)]
        );
    }

    /// MS-RDPEAI 3.3.5.3.2: after the client's Format Change the server
    /// "MUST decode all audio packets that arrive after this PDU according to
    /// the new audio format".
    #[test]
    fn a_format_change_switches_the_decoding_format() {
        let (mut server, events) = server(vec![stereo_48k(), stereo_44k()]);
        negotiate(&mut server, vec![stereo_48k(), stereo_44k()]);
        receive(&mut server, RdpeaiPdu::OpenReply(OpenReplyPdu::ok()));

        receive(&mut server, RdpeaiPdu::FormatChange(FormatChangePdu::new(1)));
        receive(&mut server, RdpeaiPdu::Data(DataPdu::new(vec![5, 6])));
        receive(&mut server, RdpeaiPdu::FormatChange(FormatChangePdu::new(9)));
        receive(&mut server, RdpeaiPdu::Data(DataPdu::new(vec![7, 8])));

        assert_eq!(
            events.lock().expect("events")[1..],
            [
                Event::Data(stereo_44k(), vec![5, 6]),
                Event::Data(stereo_44k(), vec![7, 8])
            ]
        );
    }

    /// A channel closed before it was ever created was refused by the client.
    #[test]
    fn the_handler_learns_whether_the_channel_was_ever_created() {
        let (mut refused, events) = server(vec![stereo_48k()]);
        refused.close(7);
        assert_eq!(*events.lock().expect("events"), [Event::Closed(false)]);

        let (mut used, events) = server(vec![stereo_48k()]);
        sent(used.start(7));
        used.close(7);
        assert_eq!(*events.lock().expect("events"), [Event::Closed(true)]);
    }
}
