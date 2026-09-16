//! x264-based H.264 encoder (Annex-B, I420 input) — the selkies-grade
//! software path.
//!
//! x264 replaces OpenH264 as the motion encoder: native multithreading,
//! substantially better compression at the same bitrate, and a quality
//! floor OpenH264 cannot reach. The output is Annex-B with in-band
//! SPS/PPS at every IDR, exactly what the EGFX AVC420/AVC444v2 wire
//! format expects.

use anyhow::Context as _;
use x264::{Colorspace, Encoder, Image, Plane, Preset, Setup, Tune};

pub struct X264Encoder {
    enc: Encoder,
    pts: i64,
    params: (u32, f32, u16, u16),
    needs_recreate: bool,
}

// SAFETY: the raw x264 handle is used from one thread at a time — the
// encoder is moved in and out of the blocking encode task and every access
// is sequential; nothing else touches the handle concurrently.
unsafe impl Send for X264Encoder {}

impl X264Encoder {
    /// Create the encoder: ABR rate control at `bitrate_bps`, preset
    /// superfast + zero-latency (no B-frames, no lookahead — interactive
    /// latency), IDR every ~250 frames. Recreate to force a keyframe.
    pub fn new(bitrate_bps: u32, fps: f32, width: u16, height: u16) -> anyhow::Result<Self> {
        let kbps = i32::try_from((bitrate_bps / 1000).clamp(1, 50_000)).unwrap_or(19_000);
        // Precision guard: clamped to 1..=60 fps, so the f32→u32 cast is
        // lossless for the integer part.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "clamped to 1..=60"
        )]
        let fps_u = fps.round().clamp(1.0, 60.0) as u32;
        let enc = Setup::preset(Preset::Superfast, Tune::None, false, true)
            .fps(fps_u, 1)
            // ABR at the adaptive bitrate target; VBV bounds bursts.
            .bitrate(kbps)
            .vbv(kbps * 2, kbps * 4)
            // Normal GOP: IDR every ~10 s of video, P-frames in between.
            // All-intra (keyint=1) made EVERY frame a full SPS+PPS+IDR
            // stream restart — mstsc's decoder processed 27 of those per
            // second on a busy desktop and gave up within seconds (the
            // terminal mid-session CapsAdvertise). Windows servers do the
            // same: rare IDRs, skip-coded P-frames of static content are
            // near-zero bits, so unchanged regions stay flicker-free.
            .max_keyframe_interval(250)
            .min_keyframe_interval(250)
            .annexb(true)
            .build(Colorspace::I420, i32::from(width), i32::from(height))
            .map_err(|e| anyhow::anyhow!("x264 setup: {e:?}"))
            .context("x264 encoder init")?;
        Ok(Self {
            enc,
            pts: 0,
            params: (bitrate_bps, fps, width, height),
            needs_recreate: false,
        })
    }

    /// Encode one I420 frame (planes tightly packed: Y stride `w`,
    /// U/V stride `w/2`). Returns the Annex-B bitstream, possibly empty.
    pub fn encode_planes(&mut self, y: &[u8], u: &[u8], v: &[u8]) -> Vec<u8> {
        if self.needs_recreate {
            // x264 has no runtime force-IDR; recreating the encoder is the
            // cheapest reliable keyframe trigger (rare: resizes, drift).
            if let Ok(fresh) = Self::new(self.params.0, self.params.1, self.params.2, self.params.3) {
                self.enc = fresh.enc;
                self.needs_recreate = false;
            } else {
                return Vec::new();
            }
        }

        let (w, h) = (self.params.2, self.params.3);
        let image = Image::new(
            Colorspace::I420,
            i32::from(w),
            i32::from(h),
            &[
                Plane {
                    stride: i32::from(w),
                    data: y,
                },
                Plane {
                    stride: i32::from(w / 2),
                    data: u,
                },
                Plane {
                    stride: i32::from(w / 2),
                    data: v,
                },
            ],
        );

        match self.enc.encode(self.pts, image) {
            Ok((data, _)) => {
                self.pts += 1;
                data.entirety().to_vec()
            }
            Err(_) => Vec::new(),
        }
    }

    /// Request a keyframe on the next encode (encoder recreation).
    pub fn force_intra(&mut self) {
        self.needs_recreate = true;
    }
}
