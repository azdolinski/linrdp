//! Probe: verifies the PulseAudio monitor capture path (same API usage as
//! sound_real.rs). Run with `cargo run --release --example pa_capture_test`
//! while something plays into `linrdp_sink` — expects NON-ZERO audio.
use libpulse_binding as pulse;
use pulse::context::FlagSet as ContextFlags;
use pulse::context::Context;
use pulse::mainloop::standard::Mainloop;
use pulse::sample::Spec;
use pulse::stream::{self, Direction, FlagSet as StreamFlags};

fn main() -> anyhow::Result<()> {
    let mut mainloop = Mainloop::new().ok_or_else(|| anyhow::anyhow!("mainloop"))?;
    let mut ctx = Context::new(&mainloop, "pa-test").ok_or_else(|| anyhow::anyhow!("context"))?;
    ctx.connect(None, ContextFlags::NOFLAGS, None)
        .map_err(|e| anyhow::anyhow!("ctx connect: {e}"))?;
    ctx.set_state_callback(Some(Box::new(|| {})));
    loop {
        match ctx.get_state() {
            pulse::context::State::Ready => break,
            pulse::context::State::Failed | pulse::context::State::Terminated => anyhow::bail!("ctx failed"),
            _ => { mainloop.iterate(false); }
        }
    }
    let mut map = pulse::channelmap::Map::default();
    map.init_stereo();
    let spec = Spec {
        format: pulse::sample::Format::S16le,
        channels: 2,
        rate: 44100,
    };
    let mut stream = pulse::stream::Stream::new(&mut ctx, "pa-test", &spec, Some(&map))
        .ok_or_else(|| anyhow::anyhow!("stream"))?;
    stream
        .connect_record(
            Some("linrdp_sink.monitor"),
            None,
            StreamFlags::START_UNMUTED | StreamFlags::ADJUST_LATENCY,
        )
        .map_err(|e| anyhow::anyhow!("connect_record: {e}"))?;
    stream.set_read_callback(Some(Box::new(|_n: usize| {})));
    stream.set_state_callback(Some(Box::new(|| {})));
    loop {
        match stream.get_state() {
            pulse::stream::State::Ready => break,
            pulse::stream::State::Failed | pulse::stream::State::Terminated => anyhow::bail!("stream failed"),
            _ => { mainloop.iterate(false); }
        }
    }
    println!("capturing from linrdp_sink.monitor for 6s — play something!");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    let mut got_nonzero = false;
    let mut total = 0usize;
    while std::time::Instant::now() < deadline {
        mainloop.iterate(false);
        if let Ok(peek) = stream.peek() {
            match peek {
                pulse::stream::PeekResult::Data(data) => {
                    total += data.len();
                    if !got_nonzero && data.iter().any(|&b| b != 0) {
                        got_nonzero = true;
                        println!("NON-ZERO audio captured!");
                    }
                    stream.discard().ok();
                }
                _ => {}
            }
        }
    }
    println!("total={total} nonzero={got_nonzero}");
    Ok(())
}
