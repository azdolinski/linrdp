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
            // Normal GOP: IDR every ~250 frames, P-frames in between.
            // With the per-substream encoders each stream restarts cleanly
            // from its own IDR, and P-frames keep the busy-desktop bitrate
            // inside mstsc's software decode budget (all-intra pushed
            // 27 full SPS+PPS+IDR stream restarts per second at ~36 Mbps).
            // Static content P-frames are skip-coded — near-zero bits, no
            // pump on unchanged regions.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Annex-B NAL unit types in stream order (start-code prefixed).
    fn nal_types(stream: &[u8]) -> Vec<u8> {
        let mut types = Vec::new();
        let mut i = 0;
        while i + 3 <= stream.len() {
            let sc = if stream[i..].starts_with(&[0, 0, 0, 1]) {
                4
            } else if stream[i..].starts_with(&[0, 0, 1]) {
                3
            } else {
                i += 1;
                continue;
            };
            i += sc;
            if i < stream.len() {
                types.push(stream[i] & 0x1F);
            }
        }
        types
    }

    fn pseudo_frame(seed: u32, w: usize, h: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut s = seed | 1;
        let mut next = move || {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (s >> 16) as u8
        };
        let y: Vec<u8> = (0..w * h).map(|_| next()).collect();
        let u: Vec<u8> = (0..w * h / 4).map(|_| next()).collect();
        let v: Vec<u8> = (0..w * h / 4).map(|_| next()).collect();
        (y, u, v)
    }

    /// [MS-RDPEGFX 2.2.4.5/2.2.4.6]: the two AVC444 subframes "MUST be
    /// encoded using the same MPEG-4 AVC/H.264 encoder and decoded by a
    /// single MPEG-4 AVC/H.264 decoder as one stream".
    ///
    /// So the concatenation of everything we send must be ONE well-formed
    /// stream: exactly one SPS/PPS+IDR at the start, then nothing but
    /// P-frames. The regression this guards is the opposite design — a
    /// second encoder for the chroma view, whose own IDR flushed the single
    /// decoder's DPB and left the next luma P-frame referencing a picture
    /// that no longer existed. mstsc answered that with a pipeline reset and
    /// an RST 70 ms later.
    #[test]
    fn both_avc444_views_form_one_stream_from_one_encoder() {
        const W: usize = 320;
        const H: usize = 320;
        let mut enc = crate::gfx_display::make_h264_encoder(6_000_000, 30.0, W as u16, H as u16).unwrap();

        // 20 v2 frames: each is the luma view followed by the chroma view,
        // both through this one encoder.
        let mut stream_types = Vec::new();
        for i in 0..20u32 {
            let (ly, lu, lv) = pseudo_frame(2 * i + 1, W, H);
            let (cy, cu, cv) = pseudo_frame(2 * i + 2, W, H);

            let luma_bs = enc.encode_planes(&ly, &lu, &lv);
            assert!(!luma_bs.is_empty(), "luma view of frame {i} produced nothing");
            stream_types.extend(nal_types(&luma_bs));

            let chroma_bs = enc.encode_planes(&cy, &cu, &cv);
            assert!(!chroma_bs.is_empty(), "chroma view of frame {i} produced nothing");
            stream_types.extend(nal_types(&chroma_bs));
        }

        // NAL 7 = SPS, 8 = PPS, 5 = IDR slice, 1 = non-IDR (P) slice. x264
        // splits each picture into several slices here (sliced threads), so
        // count parameter sets and slice ORDER, not slice counts.
        assert_eq!(
            stream_types.iter().filter(|&&t| t == 7).count(),
            1,
            "a second SPS is a second stream restarting the client's decoder, got {stream_types:?}"
        );
        assert_eq!(
            stream_types.iter().filter(|&&t| t == 8).count(),
            1,
            "a second PPS means the same, got {stream_types:?}"
        );

        let sps_at = stream_types.iter().position(|&t| t == 7).expect("SPS present");
        let first_idr = stream_types.iter().position(|&t| t == 5).expect("IDR present");
        let last_idr = stream_types.iter().rposition(|&t| t == 5).expect("IDR present");
        let first_p = stream_types.iter().position(|&t| t == 1).expect("P slices present");

        assert!(sps_at < first_idr, "SPS/PPS must precede the IDR");
        assert!(
            last_idr < first_p,
            "every IDR slice belongs to the first picture; an IDR after P slices would \
             flush the single decoder's DPB mid-session, got {stream_types:?}"
        );
    }
}
