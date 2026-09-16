use crate::{Encoder, Encoding, Error, Result};
use core::ffi::c_char;
use core::mem::MaybeUninit;
use x264::*;

mod preset;
mod tune;

pub use self::preset::*;
pub use self::tune::*;

/// Builds a new encoder.
pub struct Setup {
    raw: x264_param_t,
}

impl Setup {
    /// Creates a new builder with the specified preset and tune.
    pub fn preset(preset: Preset, tune: Tune, fast_decode: bool, zero_latency: bool) -> Self {
        let mut raw = MaybeUninit::uninit();

        // Name validity verified at compile-time.
        assert_eq!(0, unsafe {
            x264_param_default_preset(
                raw.as_mut_ptr(),
                preset.to_cstr(),
                tune.to_cstr(fast_decode, zero_latency),
            )
        });

        Self {
            raw: unsafe { raw.assume_init() },
        }
    }

    /// Makes the first pass faster.
    pub fn fastfirstpass(mut self) -> Self {
        unsafe {
            x264_param_apply_fastfirstpass(&mut self.raw);
        }
        self
    }

    /// The video's framerate, represented as a rational number.
    ///
    /// The value is in frames per second.
    pub fn fps(mut self, num: u32, den: u32) -> Self {
        self.raw.i_fps_num = num;
        self.raw.i_fps_den = den;
        self
    }

    /// The encoder's timebase, used in rate control with timestamps.
    ///
    /// The value is in seconds per tick.
    pub fn timebase(mut self, num: u32, den: u32) -> Self {
        self.raw.i_timebase_num = num;
        self.raw.i_timebase_den = den;
        self
    }

    /// Enable/disable Annex B start codes. Defaults to `true`.
    ///
    /// Annex B start codes are not used by containers based on the ISO BMFF
    /// (Base Media File Format), such as MP4 and MOV.
    pub fn annexb(mut self, annexb: bool) -> Self {
        self.raw.b_annexb = annexb as i32;
        self
    }

    /// Approximately restricts the bitrate.
    ///
    /// The value is in metric kilobits per second.
    /// Constant-quality rate control (CRF): stable QP across frames —
    /// identical input encodes to identical output, no rate-control feedback
    /// pumping on static content. Pair with `vbv` to bound the rate.
    pub fn crf(mut self, crf: i32) -> Self {
        self.raw.rc.i_rc_method = x264_sys::x264::X264_RC_CRF as i32;
        self.raw.rc.f_rf_constant = crf as f32;
        self
    }

    /// VBV peak rate and buffer size (both kbps/kbit) — caps the
    /// instantaneous bitrate under CRF.
    pub fn vbv(mut self, maxrate: i32, bufsize: i32) -> Self {
        self.raw.rc.i_vbv_max_bitrate = maxrate;
        self.raw.rc.i_vbv_buffer_size = bufsize;
        self
    }

    pub fn bitrate(mut self, bitrate: i32) -> Self {
        self.raw.rc.i_bitrate = bitrate;
        self
    }

    /// The lowest profile, with guaranteed compatibility with all decoders.
    pub fn baseline(mut self) -> Self {
        unsafe {
            x264_param_apply_profile(&mut self.raw, b"baseline\0" as *const u8 as *const c_char);
        }
        self
    }

    /// A useless middleground between the baseline and high profiles.
    pub fn main(mut self) -> Self {
        unsafe {
            x264_param_apply_profile(&mut self.raw, b"main\0" as *const u8 as *const c_char);
        }
        self
    }

    /// The highest profile, which almost all encoders support.
    pub fn high(mut self) -> Self {
        unsafe {
            x264_param_apply_profile(&mut self.raw, b"high\0" as *const u8 as *const c_char);
        }
        self
    }

    /// Set the maximum number of frames between keyframes.
    pub fn max_keyframe_interval(mut self, interval: i32) -> Self {
        self.raw.i_keyint_max = interval;
        self
    }

    /// Set the minimum number of frames between keyframes.
    pub fn min_keyframe_interval(mut self, interval: i32) -> Self {
        self.raw.i_keyint_min = interval;
        self
    }

    /// Set the scenecut threshold. Set this to zero to guarantee a keyframe
    /// every `max_keyframe_interval`.
    pub fn scenecut_threshold(mut self, threshold: i32) -> Self {
        self.raw.i_scenecut_threshold = threshold;
        self
    }

    /// Number of reference frames the encoder may keep (`i_frame_reference`).
    ///
    /// The fast presets pin this to 1, so a frame can only be predicted from
    /// its immediate predecessor. That is wrong for any stream whose
    /// consecutive frames alternate between two different images — such as
    /// the AVC444v2 luma/chroma views, which MS-RDPEGFX 2.2.4.6 requires to
    /// share one encoder. With 2 or more, the encoder can predict from the
    /// previous frame of the SAME view instead.
    pub fn frame_reference(mut self, frames: i32) -> Self {
        self.raw.i_frame_reference = frames;
        self
    }

    /// Build the encoder.
    pub fn build<C>(mut self, csp: C, width: i32, height: i32) -> Result<Encoder>
    where
        C: Into<Encoding>,
    {
        self.raw.i_csp = csp.into().into_raw();
        self.raw.i_width = width;
        self.raw.i_height = height;

        let raw = unsafe { x264_encoder_open(&mut self.raw) };

        if raw.is_null() {
            Err(Error)
        } else {
            Ok(unsafe { Encoder::from_raw(raw) })
        }
    }
}

impl Default for Setup {
    fn default() -> Self {
        let raw = unsafe {
            let mut raw = MaybeUninit::uninit();
            x264_param_default(raw.as_mut_ptr());
            raw.assume_init()
        };

        Self { raw }
    }
}
