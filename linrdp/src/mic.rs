//! Microphone redirection (MS-RDPEAI).
//!
//! The session's applications record from [`MIC_SOURCE`], a PulseAudio pipe
//! source, and the client's microphone is what feeds it. MS-RDPEAI 3.1.4.1
//! starts the protocol when the server starts recording, so that is when it
//! starts here: [`spawn_watcher`] watches the session's daemon and, when an
//! application starts recording from the microphone, opens the AUDIO_INPUT
//! dynamic channel. [`RdpeaiServer`] then runs the server side of the
//! protocol, the client captures its microphone, and [`MicSink`] converts the
//! audio to the pipe source's format and writes it into its FIFO
//! ([`MicFifo`]). When recording stops, the channel is closed, and the
//! client's microphone with it.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use ironrdp_rdpeai::server::{RdpeaiServer, RdpeaiServerHandler};
use ironrdp_rdpsnd::pdu::{AudioFormat, WaveFormat};
use ironrdp_server::ServerEvent;
use libpulse_binding as pulse;
use tokio::sync::{mpsc, oneshot};

use crate::sound_real::{self, Attach, MIC_SOURCE};

/// The rate and channel count of the pipe source (`sound_real`'s
/// `pipe_source_args`): what the client's audio is converted to.
const PIPE_RATE: u32 = 48_000;

/// Formats the microphone channel takes, most preferred first: what the
/// pipe source reads, then what needs converting. All 16-bit PCM, which
/// MS-RDPEAI 2.2.2.2 requires every implementation to support.
const MIC_FORMATS: [(u16, u32); 4] = [(2, 48_000), (2, 44_100), (1, 48_000), (1, 44_100)];

/// How long the channel stays open after the last recording stream stopped,
/// so an application that pauses and resumes does not reopen it each time.
const CLOSE_DELAY: Duration = Duration::from_secs(2);

/// How often the watcher looks at the daemon when no event arrives.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long one turn of the watcher loop sleeps.
const TICK: Duration = Duration::from_millis(50);

fn mic_formats() -> Vec<AudioFormat> {
    MIC_FORMATS
        .iter()
        .map(|&(channels, rate)| ironrdp_rdpeai::pdu::pcm_format(channels, rate, 16))
        .collect()
}

/// Whether an application records from the source at `mic`: a stream on it
/// that is not paused.
fn recording(mic: u32, outputs: &[sound_real::SourceOutput]) -> bool {
    outputs.iter().any(|output| output.source == mic && !output.corked)
}

/// What the connection did with one microphone channel, reported by its
/// [`MicSink`] to the watcher.
#[derive(Debug, Default)]
struct ChannelFate {
    /// The client refused to create the channel (MS-RDPEDYC 3.3.3.2).
    refused: AtomicBool,
    /// The channel was created and is gone again.
    closed: AtomicBool,
}

/// The handler of one AUDIO_INPUT channel: the client's audio goes into the
/// session's microphone.
struct MicSink {
    fifo: MicFifo,
    converter: Option<Converter>,
    fate: Arc<ChannelFate>,
}

impl MicSink {
    fn new(fate: Arc<ChannelFate>) -> Self {
        Self {
            fifo: MicFifo::new(),
            converter: None,
            fate,
        }
    }
}

impl RdpeaiServerHandler for MicSink {
    fn formats(&self) -> Vec<AudioFormat> {
        mic_formats()
    }

    fn opened(&mut self, format: &AudioFormat) {
        tracing::info!(?format, "the client's microphone feeds {MIC_SOURCE}");
        self.converter = Converter::new(format);
    }

    fn data(&mut self, format: &AudioFormat, data: &[u8]) {
        if self
            .converter
            .as_ref()
            .is_none_or(|converter| converter.format != *format)
        {
            self.converter = Converter::new(format);
        }
        let Some(converter) = self.converter.as_mut() else {
            return;
        };
        self.fifo.write(&converter.convert(data));
    }

    fn closed(&mut self, created: bool) {
        let flag = if created { &self.fate.closed } else { &self.fate.refused };
        flag.store(true, Ordering::Relaxed);
    }
}

/// Turns the client's 16-bit PCM into what the pipe source reads: s16le,
/// 48 kHz, stereo.
struct Converter {
    format: AudioFormat,
    channels: usize,
    resampler: Resampler,
}

impl Converter {
    fn new(format: &AudioFormat) -> Option<Self> {
        if format.format != WaveFormat::PCM || format.bits_per_sample != 16 || format.n_channels == 0 {
            tracing::warn!(?format, "cannot feed this format to the microphone");
            return None;
        }
        Some(Self {
            format: format.clone(),
            channels: usize::from(format.n_channels),
            resampler: Resampler::new(format.n_samples_per_sec, PIPE_RATE),
        })
    }

    fn convert(&mut self, data: &[u8]) -> Vec<u8> {
        // Mono is heard on both sides; more channels than two keep their
        // first two.
        let frames: Vec<[i16; 2]> = data
            .chunks_exact(self.channels * 2)
            .map(|frame| {
                let left = i16::from_le_bytes([frame[0], frame[1]]);
                let right = if self.channels > 1 {
                    i16::from_le_bytes([frame[2], frame[3]])
                } else {
                    left
                };
                [left, right]
            })
            .collect();
        self.resampler
            .process(&frames)
            .iter()
            .flat_map(|[left, right]| [left.to_le_bytes(), right.to_le_bytes()])
            .flatten()
            .collect()
    }
}

/// Linear-interpolation resampler for stereo frames that keeps its phase
/// from one packet to the next, so packet boundaries are inaudible.
///
/// Positions are counted in ticks: one input frame is `to` ticks, one output
/// frame `from` ticks, so no fraction is ever rounded.
struct Resampler {
    from: u32,
    to: u32,
    /// Position of the next output frame, in ticks from the start of the
    /// input the next call sees: `last` first, then the new frames.
    position: u64,
    /// The last input frame of the previous call.
    last: Option<[i16; 2]>,
}

impl Resampler {
    fn new(from: u32, to: u32) -> Self {
        Self {
            from: from.max(1),
            to: to.max(1),
            position: 0,
            last: None,
        }
    }

    fn process(&mut self, frames: &[[i16; 2]]) -> Vec<[i16; 2]> {
        if self.from == self.to {
            return frames.to_vec();
        }
        let input: Vec<[i16; 2]> = self.last.into_iter().chain(frames.iter().copied()).collect();
        let Some(&newest) = input.last() else {
            return Vec::new();
        };
        let (from, to) = (u64::from(self.from), u64::from(self.to));
        // Interpolating needs the frame after the position, so the output
        // stops before the newest frame; that one leads the next call.
        let end = u64::try_from(input.len() - 1).unwrap_or(u64::MAX).saturating_mul(to);
        let mut output = Vec::new();
        while self.position < end {
            let index = usize::try_from(self.position / to).unwrap_or(usize::MAX);
            let fraction = self.position % to;
            let (a, b) = (input[index], input[index + 1]);
            output.push([
                interpolate(a[0], b[0], fraction, to),
                interpolate(a[1], b[1], fraction, to),
            ]);
            self.position += from;
        }
        self.position -= end;
        self.last = Some(newest);
        output
    }
}

/// `a` moved towards `b` by `fraction / whole`.
fn interpolate(a: i16, b: i16, fraction: u64, whole: u64) -> i16 {
    let (a, b) = (i64::from(a), i64::from(b));
    let fraction = i64::try_from(fraction).unwrap_or(0);
    let whole = i64::try_from(whole).unwrap_or(1).max(1);
    i16::try_from(a + (b - a) * fraction / whole).unwrap_or(if b > a { i16::MAX } else { i16::MIN })
}

/// The channel the watcher asked the connection for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    None,
    /// Asked for; the connection has not said which ID it got.
    Requested,
    /// Open, or being created, under this ID.
    Open(u32),
}

/// What the watcher does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Stay,
    Open,
    Close(u32),
}

/// When the microphone channel opens and closes: MS-RDPEAI 3.1.4.1 starts
/// the protocol when the server starts recording, and nothing is recorded
/// while no application listens.
#[derive(Debug)]
struct Control {
    channel: Channel,
    /// The client refused the channel, or the connection has none to give:
    /// it is not asked again.
    unavailable: bool,
    /// The client closed the channel while recording went on: it is not
    /// reopened until recording stops and starts again.
    wait_for_stop: bool,
    /// When recording stopped with the channel open.
    idle_since: Option<Instant>,
}

impl Control {
    fn new() -> Self {
        Self {
            channel: Channel::None,
            unavailable: false,
            wait_for_stop: false,
            idle_since: None,
        }
    }

    fn next(&mut self, recording: bool, now: Instant) -> Step {
        if !recording {
            self.wait_for_stop = false;
        }
        match self.channel {
            Channel::None if recording && !self.unavailable && !self.wait_for_stop => {
                self.channel = Channel::Requested;
                Step::Open
            }
            Channel::None | Channel::Requested => Step::Stay,
            Channel::Open(_) if recording => {
                self.idle_since = None;
                Step::Stay
            }
            Channel::Open(id) => {
                let since = *self.idle_since.get_or_insert(now);
                if now.duration_since(since) < CLOSE_DELAY {
                    return Step::Stay;
                }
                self.channel = Channel::None;
                self.idle_since = None;
                Step::Close(id)
            }
        }
    }

    /// The connection gave the requested channel this ID, or had no dynamic
    /// channels to open it on (`None`).
    fn assigned(&mut self, id: Option<u32>) {
        match id {
            Some(id) => self.channel = Channel::Open(id),
            None => {
                self.channel = Channel::None;
                self.unavailable = true;
            }
        }
    }

    /// The client refused to create the channel.
    fn refused(&mut self) {
        self.channel = Channel::None;
        self.unavailable = true;
    }

    /// The client closed the channel.
    fn closed_by_client(&mut self) {
        self.channel = Channel::None;
        self.idle_since = None;
        self.wait_for_stop = true;
    }
}

/// The channel the watcher is responsible for, if any.
struct Current {
    fate: Arc<ChannelFate>,
    reply: Option<oneshot::Receiver<Option<u32>>>,
}

/// Watches the session's daemon and opens the microphone channel while an
/// application records.
struct Watcher {
    events: mpsc::UnboundedSender<ServerEvent>,
    control: Control,
    current: Option<Current>,
}

/// Start watching for applications that record from the session's
/// microphone, for the life of this worker (which serves one connection).
pub(crate) fn spawn_watcher(events: mpsc::UnboundedSender<ServerEvent>) {
    let watcher = Watcher {
        events,
        control: Control::new(),
        current: None,
    };
    if let Err(error) = std::thread::Builder::new()
        .name("linrdp-mic".into())
        .spawn(move || watcher.run())
    {
        tracing::warn!(%error, "cannot watch for microphone use; the microphone stays off");
    }
}

impl Watcher {
    fn run(mut self) {
        let mut reported: Option<String> = None;
        loop {
            let generation = crate::session::gate::generation();
            let target = match sound_real::attach_point() {
                Attach::Nothing => {
                    if !self.tick(false) {
                        return;
                    }
                    std::thread::sleep(sound_real::ATTACH_RETRY);
                    continue;
                }
                Attach::Ambient => None,
                Attach::Session(target) => Some(target),
            };
            match self.watch(target.as_ref(), generation) {
                Ok(true) => reported = None,
                Ok(false) => return,
                Err(error) => {
                    let text = format!("{error:#}");
                    if reported.as_deref() != Some(text.as_str()) {
                        tracing::info!(error = %text, "[microphone] cannot watch the session's daemon yet; retrying");
                        reported = Some(text);
                    }
                    if !self.tick(false) {
                        return;
                    }
                    std::thread::sleep(sound_real::ATTACH_RETRY);
                }
            }
        }
    }

    /// Watch one daemon until the gate moves (`Ok(true)`) or the server is
    /// gone (`Ok(false)`).
    fn watch(&mut self, target: Option<&crate::session::gate::AudioTarget>, generation: u64) -> anyhow::Result<bool> {
        let moved = || crate::session::gate::generation() != generation;
        let Some((mut mainloop, mut context)) = sound_real::connect(target, "linrdp-microphone", &moved)? else {
            return Ok(true);
        };
        let fifo = target
            .map(|t| t.mic_fifo())
            .or_else(crate::session::gate::mic_fifo)
            .ok_or_else(|| anyhow::anyhow!("this session has nowhere to put a microphone"))?;
        // The microphone exists, and is the default source, whether or not
        // the client plays sound.
        sound_real::ensure_microphone(&mut mainloop, &mut context, &fifo)?;

        // Recording starts and stops show up as source-output events.
        let changed = std::rc::Rc::new(core::cell::Cell::new(true));
        let flag = std::rc::Rc::clone(&changed);
        context.set_subscribe_callback(Some(Box::new(move |_, _, _| flag.set(true))));
        let _subscription = context.subscribe(
            pulse::context::subscribe::InterestMaskSet::SOURCE
                | pulse::context::subscribe::InterestMaskSet::SOURCE_OUTPUT,
            |_| {},
        );

        let mut is_recording = false;
        let mut last_look = Instant::now();
        loop {
            if moved() {
                return Ok(true);
            }
            mainloop.iterate(false);
            if changed.replace(false) || last_look.elapsed() >= POLL_INTERVAL {
                last_look = Instant::now();
                let mic = match sound_real::source_index(&mut mainloop, &context, MIC_SOURCE)? {
                    Some(index) => index,
                    None => {
                        sound_real::ensure_microphone(&mut mainloop, &mut context, &fifo)?;
                        sound_real::source_index(&mut mainloop, &context, MIC_SOURCE)?
                            .ok_or_else(|| anyhow::anyhow!("{MIC_SOURCE} is missing after it was made"))?
                    }
                };
                is_recording = recording(mic, &sound_real::source_outputs(&mut mainloop, &context)?);
            }
            if !self.tick(is_recording) {
                return Ok(false);
            }
            std::thread::sleep(TICK);
        }
    }

    /// Act on the latest recording state. `false` when the server is gone.
    fn tick(&mut self, recording: bool) -> bool {
        if let Some(current) = self.current.as_mut()
            && let Some(reply) = current.reply.as_mut()
        {
            match reply.try_recv() {
                Ok(id) => {
                    current.reply = None;
                    self.control.assigned(id);
                    if id.is_none() {
                        tracing::info!("[microphone] this connection has no dynamic channels, so no microphone");
                        self.current = None;
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.control.assigned(None);
                    self.current = None;
                }
            }
        }
        if let Some(current) = self.current.as_ref() {
            if current.fate.refused.load(Ordering::Relaxed) {
                tracing::info!("[microphone] the client does not redirect its microphone");
                self.control.refused();
                self.current = None;
            } else if current.fate.closed.load(Ordering::Relaxed) {
                tracing::info!("[microphone] the client closed the microphone channel");
                self.control.closed_by_client();
                self.current = None;
            }
        }

        let event = match self.control.next(recording, Instant::now()) {
            Step::Stay => return true,
            Step::Open => {
                tracing::info!(
                    "[microphone] an application records from {MIC_SOURCE}: asking the client for its microphone"
                );
                let fate = Arc::new(ChannelFate::default());
                let (reply, receiver) = oneshot::channel();
                self.current = Some(Current {
                    fate: Arc::clone(&fate),
                    reply: Some(receiver),
                });
                ServerEvent::OpenDynamicChannel {
                    processor: Box::new(RdpeaiServer::new(Box::new(MicSink::new(fate)))),
                    reply: Some(reply),
                }
            }
            Step::Close(channel_id) => {
                tracing::info!("[microphone] nothing records any more: closing the microphone channel");
                self.current = None;
                ServerEvent::CloseDynamicChannel { channel_id }
            }
        };
        self.events.send(event).is_ok()
    }
}

/// Writes the client's microphone packets into the session's pipe-source
/// FIFO, so the desktop's applications see them as a capture device.
///
/// Opened on the first packet, and reopened when the session gate moves, so
/// the path always belongs to the session this worker serves. A fixed path
/// such as `/run/user/1000/linrdp/mic.fifo` belonged to whichever account
/// happened to be uid 1000 — so on a multi-session host every client's
/// microphone was wired into one user's desktop.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sound_real::SourceOutput;

    /// Recording means a stream on the microphone that is not paused.
    #[test]
    fn only_an_unpaused_stream_on_the_microphone_is_recording() {
        let on_mic = SourceOutput {
            source: 3,
            corked: false,
        };
        let elsewhere = SourceOutput {
            source: 1,
            corked: false,
        };
        let paused = SourceOutput {
            source: 3,
            corked: true,
        };

        assert!(recording(3, &[elsewhere, on_mic]));
        assert!(!recording(3, &[elsewhere, paused]));
        assert!(!recording(3, &[]));
    }

    /// MS-RDPEAI 3.1.4.1: the protocol starts when the server starts
    /// recording, and the channel goes once nothing records.
    ///
    /// Regression: the channel was opened with every connection and the
    /// client's microphone stayed on for the whole session.
    #[test]
    fn the_channel_opens_while_recording_and_closes_after_it() {
        let start = Instant::now();
        let mut control = Control::new();

        assert_eq!(control.next(false, start), Step::Stay);
        assert_eq!(control.next(true, start), Step::Open);
        assert_eq!(control.next(true, start), Step::Stay, "one request at a time");
        control.assigned(Some(4));
        assert_eq!(control.next(true, start), Step::Stay);

        // A short pause keeps the channel.
        assert_eq!(control.next(false, start), Step::Stay);
        assert_eq!(control.next(true, start + Duration::from_secs(1)), Step::Stay);
        // A longer one closes it.
        let stop = start + Duration::from_secs(5);
        assert_eq!(control.next(false, stop), Step::Stay);
        assert_eq!(control.next(false, stop + CLOSE_DELAY), Step::Close(4));
        assert_eq!(
            control.next(true, stop + CLOSE_DELAY),
            Step::Open,
            "and recording again reopens it"
        );
    }

    /// A client that refuses the channel (MS-RDPEDYC 3.3.3.2) does not
    /// redirect its microphone: it is not asked again.
    #[test]
    fn a_refused_channel_is_not_asked_for_again() {
        let now = Instant::now();
        let mut control = Control::new();
        assert_eq!(control.next(true, now), Step::Open);
        control.assigned(Some(4));
        control.refused();

        assert_eq!(control.next(true, now), Step::Stay);
        assert_eq!(control.next(false, now), Step::Stay);
        assert_eq!(control.next(true, now), Step::Stay);
    }

    #[test]
    fn a_connection_without_dynamic_channels_is_not_asked_again() {
        let now = Instant::now();
        let mut control = Control::new();
        assert_eq!(control.next(true, now), Step::Open);
        control.assigned(None);

        assert_eq!(control.next(true, now), Step::Stay);
    }

    /// A client that closes the channel is not overruled while the same
    /// recording goes on, but the next one asks again.
    #[test]
    fn a_channel_the_client_closed_waits_for_the_next_recording() {
        let now = Instant::now();
        let mut control = Control::new();
        assert_eq!(control.next(true, now), Step::Open);
        control.assigned(Some(4));
        control.closed_by_client();

        assert_eq!(control.next(true, now), Step::Stay);
        assert_eq!(control.next(false, now), Step::Stay);
        assert_eq!(control.next(true, now), Step::Open);
    }

    fn pcm(frames: &[[i16; 2]]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|[left, right]| [left.to_le_bytes(), right.to_le_bytes()])
            .flatten()
            .collect()
    }

    fn format(channels: u16, rate: u32) -> AudioFormat {
        ironrdp_rdpeai::pdu::pcm_format(channels, rate, 16)
    }

    /// The pipe source reads s16le, 48 kHz, stereo: that passes unchanged.
    #[test]
    fn the_pipe_sources_own_format_passes_unchanged() {
        let mut converter = Converter::new(&format(2, 48_000)).expect("PCM");
        let data = pcm(&[[1, -1], [300, -300], [i16::MAX, i16::MIN]]);

        assert_eq!(converter.convert(&data), data);
    }

    #[test]
    fn mono_is_heard_on_both_sides() {
        let mut converter = Converter::new(&format(1, 48_000)).expect("PCM");
        let data: Vec<u8> = [5i16, -7].iter().flat_map(|sample| sample.to_le_bytes()).collect();

        assert_eq!(converter.convert(&data), pcm(&[[5, 5], [-7, -7]]));
    }

    /// 44.1 kHz becomes 48 kHz: 441 frames in, 480 out over whole packets,
    /// and a steady signal stays steady.
    #[test]
    fn a_44_1_khz_microphone_is_resampled_to_48_khz() {
        let mut converter = Converter::new(&format(2, 44_100)).expect("PCM");
        let packet = pcm(&[[1000, -1000]; 441]);

        let mut output = Vec::new();
        for _ in 0..10 {
            output.extend(converter.convert(&packet));
        }
        let frames = output.len() / 4;
        assert!((4799..=4800).contains(&frames), "{frames} frames");
        assert!(output.chunks_exact(4).all(|frame| frame == pcm(&[[1000, -1000]])));
    }

    /// Splitting the input into packets does not change what comes out.
    #[test]
    fn packet_boundaries_are_inaudible() {
        let ramp: Vec<[i16; 2]> = (0..882).map(|i| [i, -i]).collect();

        let mut whole = Resampler::new(44_100, 48_000);
        let expected = whole.process(&ramp);
        let mut split = Resampler::new(44_100, 48_000);
        let mut actual = split.process(&ramp[..300]);
        actual.extend(split.process(&ramp[300..301]));
        actual.extend(split.process(&ramp[301..]));

        assert_eq!(actual, expected);
    }

    #[test]
    fn a_format_the_pipe_cannot_take_is_refused() {
        assert!(Converter::new(&format(2, 48_000)).is_some());
        assert!(Converter::new(&ironrdp_rdpeai::pdu::pcm_format(2, 48_000, 8)).is_none());
    }

    /// The watcher learns whether the client refused the channel or closed it.
    #[test]
    fn a_sink_reports_what_became_of_its_channel() {
        let refused = Arc::new(ChannelFate::default());
        MicSink::new(Arc::clone(&refused)).closed(false);
        assert!(refused.refused.load(Ordering::Relaxed));
        assert!(!refused.closed.load(Ordering::Relaxed));

        let closed = Arc::new(ChannelFate::default());
        MicSink::new(Arc::clone(&closed)).closed(true);
        assert!(closed.closed.load(Ordering::Relaxed));
        assert!(!closed.refused.load(Ordering::Relaxed));
    }
}
