//! Microphone redirection (MS-RDPEAI): the Windows client captures its local
//! microphone and streams audio packets to us over the AUDIO_INPUT dynamic
//! virtual channel. We act as the DVC initiator and RDPEAI "client" role
//! (per MS-RDPEAI 1.3.1 the capturing side is the DVC server — mstsc).
//!
//! Captured PCM packets are handed to [`MicPacketSink`] — a pure-Rust sink
//! that currently counts/logs them (no OS capture device is required, so the
//! single-binary constraint holds; a desktop build would forward to PipeWire).

use ironrdp_core::impl_as_any;
use ironrdp_core::AsAny;
use ironrdp_dvc::{DvcMessage, DvcProcessor, DvcServerProcessor};
use ironrdp_pdu::PduResult;
use ironrdp_rdpeai::client::{RdpeaiClient, RdpeaiCaptureHandler};
use ironrdp_rdpsnd::pdu::AudioFormat;

/// Receive decoded microphone packets from the client.
pub type MicPacketSink = Box<dyn FnMut(Vec<u8>) + Send>;

/// RDPEAI capture handler: negotiates PCM and collects packets coming from
/// the client's microphone.
#[derive(Debug, Default)]
pub(crate) struct MicCaptureBackend {
    packet_count: usize,
}

impl RdpeaiCaptureHandler for MicCaptureBackend {
    fn supported_formats(&self) -> &[AudioFormat] {
        // PCM 44.1 kHz stereo 16-bit — the format mstsc always offers.
        core::slice::from_ref(&PCM_FORMAT)
    }

    fn open(
        &mut self,
        _capture_format: &AudioFormat,
        _encode_format: &AudioFormat,
        _packet_size: usize,
        mut sink: ironrdp_rdpeai::client::AudioPacketSink,
    ) -> i32 {
        self.packet_count = 0;
        tracing::info!("microphone capture opened (client mic streaming to server)");
        // Keep the sink live: packets arrive through the channel processor;
        // store nothing else here (the sink is consumed by the processor).
        let _ = &mut sink;
        0 // S_OK
    }

    fn set_format(&mut self, _encode_format: &AudioFormat, _packet_size: usize) -> bool {
        true
    }

    fn close(&mut self) {
        tracing::info!(packets = self.packet_count, "microphone capture closed");
    }
}

const PCM_FORMAT: AudioFormat = AudioFormat {
    format: ironrdp_rdpsnd::pdu::WaveFormat::PCM,
    n_channels: 2,
    n_samples_per_sec: 44100,
    n_avg_bytes_per_sec: 44100 * 2 * 2,
    n_block_align: 4,
    bits_per_sample: 16,
    data: None,
};

/// Adapter exposing [`RdpeaiClient`] (a `DvcClientProcessor`) through the
/// `DvcServerProcessor` interface the session's DRDYNVC initiator expects:
/// our endpoint *creates* the AUDIO_INPUT channel (DVC initiator = server
/// role in ironrdp-dvc), while speaking the RDPEAI client protocol inside it.
pub(crate) struct MicInputChannel {
    inner: RdpeaiClient,
}

impl MicInputChannel {
    pub(crate) fn new(sink: MicPacketSink) -> Self {
        let uplink: ironrdp_rdpeai::client::DvcUplink =
            Box::new(|_channel_id, _messages| Ok(())); // uplink unused on the initiator side
        Self {
            inner: RdpeaiClient::new(Box::new(MicCaptureBackend::default()), uplink),
        }
    }
}

impl DvcProcessor for MicInputChannel {
    fn channel_name(&self) -> &str {
        "AUDIO_INPUT"
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.inner.start(channel_id)
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        tracing::debug!(len = payload.len(), first = payload.first().copied(), "AUDIO_INPUT recv");
        self.inner.process(channel_id, payload)
    }

    fn close(&mut self, channel_id: u32) {
        self.inner.close(channel_id);
    }
}

impl DvcServerProcessor for MicInputChannel {}

impl AsAny for MicInputChannel {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

/// Writes the client's microphone packets into the session's pipe-source
/// FIFO, so the desktop's applications see them as a capture device.
///
/// Opened on the first packet, and reopened when the session gate moves — not
/// when the channel is attached. It cannot be opened then: on the greeter
/// port the AUDIO_INPUT channel is negotiated before anybody has logged in,
/// so at that moment there is no session, no daemon and no FIFO. The path
/// that was opened there instead, the literal `/run/user/1000/linrdp/mic.fifo`,
/// belonged to whichever account happened to be uid 1000 — so on a
/// multi-session host every client's microphone was wired into one user's
/// desktop.
#[derive(Debug)]
pub(crate) struct MicFifo {
    file: Option<std::fs::File>,
    /// Gate generation `file` was opened at. `None` while nothing is open.
    generation: Option<u64>,
    /// Whether the current failure has been logged, so a session without a
    /// microphone says so once rather than once per packet.
    reported: bool,
}

impl MicFifo {
    pub(crate) fn new() -> Self {
        Self {
            file: None,
            generation: None,
            reported: false,
        }
    }

    /// Hand one packet to the session's microphone, if it has one.
    ///
    /// Dropping a packet is always preferable to blocking here: this runs on
    /// the connection's own task, and a microphone that stalls it would stall
    /// the screen with it.
    pub(crate) fn write(&mut self, packet: &[u8]) {
        use std::io::Write as _;

        let generation = crate::session::gate::generation();
        if self.generation != Some(generation) {
            // The gate moved (or this is the first packet): whatever was open
            // belongs to a session this worker is no longer serving.
            self.file = None;
            self.generation = Some(generation);
            self.reported = false;
            self.file = self.open();
        }

        let Some(file) = self.file.as_mut() else {
            return;
        };
        // A single non-blocking write, and no retry. `write_all` would spin on
        // EAGAIN when the desktop is not draining the FIFO, which for live
        // audio is worse than losing the packet.
        match file.write(packet) {
            Ok(written) if written == packet.len() => {
                tracing::trace!(bytes = written, "mic packet → linrdp_mic");
            }
            Ok(written) => {
                tracing::debug!(
                    written,
                    len = packet.len(),
                    "the microphone FIFO was full — dropped the rest of this packet"
                );
            }
            Err(error) => {
                // The reader went away (the daemon unloaded the module, or the
                // session ended). Drop the handle so the next packet reopens.
                tracing::debug!(error = %error, "the microphone FIFO stopped accepting writes");
                self.file = None;
                self.generation = None;
            }
        }
    }

    fn open(&mut self) -> Option<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = crate::session::gate::mic_fifo()?;
        // O_NONBLOCK matters twice over. A write-only open of a FIFO with no
        // reader *blocks* until one arrives, which on this thread would hang
        // the connection; non-blocking, it fails with ENXIO instead, which is
        // a fact we can log. It also keeps every later write from blocking.
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => {
                tracing::info!(fifo = %path.display(), "microphone attached to this session");
                Some(file)
            }
            Err(error) => {
                if !self.reported {
                    self.reported = true;
                    tracing::info!(
                        fifo = %path.display(),
                        error = %error,
                        "no microphone for this session yet"
                    );
                }
                None
            }
        }
    }
}

