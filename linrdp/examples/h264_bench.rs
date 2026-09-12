//! Micro-benchmark for the EGFX H.264 encoder configurations.
//!
//! Encodes synthetic "video-like" frames at the deployed desktop resolution
//! with the configurations we are choosing between (single-slice vs
//! size-limited-slice multi-threading, RC frame-rate assumptions) and prints
//! per-frame encode time and output size. Run with:
//!
//! ```text
//! cargo run --release -p linrdp --example h264_bench -- [width] [height] [frames]
//! ```
//!
//! The frames blend scrolling noise with a static grid, which approximates
//! YouTube-in-a-browser worse than real content but is good enough to compare
//! encoder configurations and thread scaling on the same machine that serves
//! the sessions.

#![allow(clippy::print_stdout)]

use std::time::Instant;

use openh264::encoder::{BitRate, Encoder as OpenH264, EncoderConfig, FrameRate, RateControlMode, UsageType, VuiConfig};
use openh264::formats::YUVBuffer;

fn make_encoder(bitrate_bps: u32, fps: f32, max_slice_len: Option<u32>, threads: u16, usage: UsageType) -> OpenH264 {
    let api = openh264::OpenH264API::from_source();
    let mut config = EncoderConfig::new()
        .bitrate(BitRate::from_bps(bitrate_bps))
        .max_frame_rate(FrameRate::from_hz(fps))
        .usage_type(usage)
        .rate_control_mode(RateControlMode::Bitrate)
        .skip_frames(false)
        .vui(VuiConfig::bt709().full_range(true));
    if threads > 1 {
        config = config.num_threads(threads);
    }
    if let Some(len) = max_slice_len {
        config = config.max_slice_len(len);
    }
    OpenH264::with_api_config(api, config).expect("encoder init")
}

/// Synthetic frame: scrolling noise band (video region) over a static grid
/// (desktop UI), as BGRX.
fn make_frame(w: usize, h: usize, tick: usize, prev: Option<&mut Vec<u8>>) -> Vec<u8> {
    let mut data = vec![0u8; w * h * 4];
    let scroll = tick % h;
    for y in 0..h {
        for x in 0..w {
            let off = (y * w + x) * 4;
            // Static "desktop" areas: slow-changing grid.
            let grid = if (x / 97 + y / 61) % 2 == 0 { 210 } else { 60 };
            // Scrolling "video" band in the middle third: fast noise.
            let video = (y + scroll) % h >= h / 3 && (y + scroll) % h < 2 * h / 3;
            let (r, g, b) = if video {
                (
                    ((x * 13 + (y + scroll) * 7 + tick * 31) % 251) as u8,
                    ((x * 7 + (y + scroll) * 11 + tick * 17) % 241) as u8,
                    ((x * 5 + (y + scroll) * 3 + tick * 47) % 247) as u8,
                )
            } else {
                (grid, grid, grid)
            };
            data[off] = b;
            data[off + 1] = g;
            data[off + 2] = r;
            data[off + 3] = 0xFF;
        }
    }
    // Warm up slightly: keep half of the previous frame so inter prediction
    // has something to chew on, like a real desktop.
    if let Some(prev) = prev {
        for (dst, src) in data.chunks_exact_mut(4).zip(prev.chunks_exact(4)) {
            if (dst.as_ptr() as usize / 4) % 2 == 0 {
                dst.copy_from_slice(src);
            }
        }
    }
    data
}

fn bgrx_to_yuv420(src: &[u8], w: usize, h: usize) -> YUVBuffer {
    let (pw, ph) = (w.div_ceil(16) * 16, h.div_ceil(16) * 16);
    let mut yuv = vec![0u8; 3 * (pw * ph) / 2];
    let (y_len, u_len) = (pw * ph, pw * ph / 4);
    let (y_plane, rest) = yuv.split_at_mut(y_len);
    let (u_plane, v_plane) = rest.split_at_mut(u_len);
    for j in 0..ph / 2 {
        for i in 0..pw / 2 {
            for (dy, dx) in [(0usize, 0usize), (0, 1), (1, 0), (1, 1)] {
                let (x, y) = (i * 2 + dx, j * 2 + dy);
                if x < w && y < h {
                    let off = y * w * 4 + x * 4;
                    let (b, g, r) = (i32::from(src[off]), i32::from(src[off + 1]), i32::from(src[off + 2]));
                    y_plane[y * pw + x] = ((54 * r + 183 * g + 18 * b) >> 8).clamp(0, 255) as u8;
                }
            }
            let px = |x: usize, y: usize| -> (i32, i32, i32) {
                if x < w && y < h {
                    let off = y * w * 4 + x * 4;
                    (i32::from(src[off + 2]), i32::from(src[off + 1]), i32::from(src[off]))
                } else {
                    (0, 0, 0)
                }
            };
            let (p00, p01, p10, p11) = (px(i * 2, j * 2), px(i * 2, j * 2 + 1), px(i * 2 + 1, j * 2), px(i * 2 + 1, j * 2 + 1));
            let r = (p00.0 + p01.0 + p10.0 + p11.0) / 4;
            let g = (p00.1 + p01.1 + p10.1 + p11.1) / 4;
            let b = (p00.2 + p01.2 + p10.2 + p11.2) / 4;
            u_plane[j * (pw / 2) + i] = (((-29 * r - 99 * g + 128 * b) >> 8) + 128).clamp(0, 255) as u8;
            v_plane[j * (pw / 2) + i] = (((128 * r - 116 * g - 12 * b) >> 8) + 128).clamp(0, 255) as u8;
        }
    }
    YUVBuffer::from_vec(yuv, pw, ph)
}

fn bench(name: &str, w: usize, h: usize, frames: usize, bitrate: u32, rc_fps: f32, max_slice_len: Option<u32>, threads: u16, usage: UsageType) {
    let mut enc = make_encoder(bitrate, rc_fps, max_slice_len, threads, usage);
    let mut prev: Option<Vec<u8>> = None;
    let mut total_bytes = 0usize;
    // Warm-up (first frame is an IDR with different cost).
    let mut times = Vec::with_capacity(frames);
    for tick in 0..frames + 3 {
        let data = make_frame(w, h, tick, prev.as_mut());
        let yuv = bgrx_to_yuv420(&data, w, h);
        let start = Instant::now();
        let bs = enc.encode(&yuv).expect("encode").to_vec();
        let elapsed = start.elapsed();
        if tick >= 3 {
            times.push(elapsed);
            total_bytes += bs.len();
        }
        prev = Some(data);
    }
    let avg_ms = times.iter().map(|t| t.as_secs_f64() * 1000.0).sum::<f64>() / times.len() as f64;
    let max_ms = times.iter().map(|t| t.as_secs_f64() * 1000.0).fold(0.0, f64::max);
    let fps = 1000.0 / avg_ms;
    println!(
        "{name:<58} avg {avg_ms:7.1} ms  max {max_ms:7.1} ms  -> {fps:5.1} fps  avg frame {:7.0} B",
        total_bytes as f64 / times.len() as f64
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let w: usize = args.get(1).map(|a| a.parse().expect("width")).unwrap_or(2880);
    let h: usize = args.get(2).map(|a| a.parse().expect("height")).unwrap_or(1800);
    let frames: usize = args.get(3).map(|a| a.parse().expect("frames")).unwrap_or(30);
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

    println!("resolution {w}x{h}, {frames} frames, {cores} cores");
    let bitrate = 6_000_000;

    bench("single slice (deployed config)", w, h, frames, bitrate, 30.0, None, 0, UsageType::ScreenContentRealTime);
    bench("size-limited 16 KB, auto threads", w, h, frames, bitrate, 30.0, Some(16 * 1024), 0, UsageType::ScreenContentRealTime);
    bench("size-limited 32 KB, threads=2", w, h, frames, bitrate, 30.0, Some(32 * 1024), 2, UsageType::ScreenContentRealTime);
    bench("size-limited 32 KB, threads=4", w, h, frames, bitrate, 30.0, Some(32 * 1024), 4, UsageType::ScreenContentRealTime);
    bench("size-limited 32 KB, threads=8", w, h, frames, bitrate, 30.0, Some(32 * 1024), 8, UsageType::ScreenContentRealTime);
    bench("camera mode, size-limited 32 KB, auto", w, h, frames, bitrate, 30.0, Some(32 * 1024), 0, UsageType::CameraVideoRealTime);
    bench("camera mode, single slice", w, h, frames, bitrate, 30.0, None, 0, UsageType::CameraVideoRealTime);
}
