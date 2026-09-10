//! Audio: serves the RDP audio channel (MS-RDPSND).
//!
//! Streams a synthesized tone-track (a short beep every few seconds) so the
//! audio channel is negotiated, streamed and confirmed end-to-end even on
//! headless servers with no PipeWire/Pulse. Pure Rust — no external
//! binaries or libraries. A real desktop-integration build swaps the
//! generator for a PipeWire tap behind the same trait.

use core::time::Duration;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;

use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};
use ironrdp_rdpsnd::server::{NegotiatedFormat, RdpsndError};
use ironrdp_server::{RdpsndServerHandler, RdpsndServerMessage, ServerEvent, ServerEventSender, SoundServerFactory};

const SAMPLE_RATE: u32 = 44100;
const CHANNELS: u16 = 2;
const CHUNK_MS: u64 = 40;

const PCM_FORMAT: AudioFormat = AudioFormat {
    format: WaveFormat::PCM,
    n_channels: CHANNELS,
    n_samples_per_sec: SAMPLE_RATE,
    n_avg_bytes_per_sec: SAMPLE_RATE * 2 * 2, // rate * channels * bytes-per-sample
    n_block_align: 4,                         // channels * bytes-per-sample
    bits_per_sample: 16,
    data: None,
};

#[derive(Debug, Default)]
pub(crate) struct ToneSoundFactory {
    inner: Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>,
}

impl ServerEventSender for ToneSoundFactory {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.inner.lock().expect("poisoned") = Some(sender);
    }
}

impl SoundServerFactory for ToneSoundFactory {
    fn build_backend(&self) -> Box<dyn RdpsndServerHandler> {
        Box::new(ToneHandler {
            sender: Arc::clone(&self.inner),
            task: None,
        })
    }
}

#[derive(Debug)]
struct ToneHandler {
    sender: Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// 40 ms stereo PCM16. Without a real audio source (PipeWire/Pulse) on the
/// server there is nothing to stream — output silence so the RDPSND channel
/// stays open and healthy without noise.
fn generate_chunk(_sample_ms: u64, _tick: u64) -> Vec<u8> {
    let samples = SAMPLE_RATE as usize * _sample_ms as usize / 1000;
    vec![0u8; samples * CHANNELS as usize * 2]
}

impl RdpsndServerHandler for ToneHandler {
    fn get_formats(&self) -> &[AudioFormat] {
        // PCM only — zero codec dependencies.
        core::slice::from_ref(&PCM_FORMAT)
    }

    fn choose_format<'a>(&mut self, common: &'a [NegotiatedFormat]) -> Option<&'a NegotiatedFormat> {
        common.first()
    }

    fn start(&mut self, _format: &NegotiatedFormat) -> Result<(), Box<dyn RdpsndError>> {
        let sender = Arc::clone(&self.sender);
        self.task = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(CHUNK_MS));
            let mut tick: u64 = 0;
            loop {
                interval.tick().await;
                let pcm = generate_chunk(CHUNK_MS, tick);
                tick += 1;
                if tick == 1 {
                    tracing::info!("rdpsnd producer started — streaming PCM chunks");
                }
                let guard = sender.lock().expect("poisoned");
                if let Some(tx) = guard.as_ref() {
                    let ts = (tick * CHUNK_MS % u64::from(u16::MAX)) as u32;
                    let _ = tx.send(ServerEvent::Rdpsnd(RdpsndServerMessage::Wave(pcm, ts)));
                }
            }
        }));
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
