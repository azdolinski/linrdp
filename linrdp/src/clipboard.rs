//! Real clipboard synchronization: X11 ↔ RDP (MS-RDPECLIP), server side.
//!
//! Linux → Windows (we advertise, client pulls):
//! - Text: X11 clipboard text (read on an explicit X connection) ↔ CF_UNICODETEXT.
//! - Files: X11 `file://` URI list ↔ FileGroupDescriptorW + FileContents,
//!   served from local paths (MS-RDPECLIP 2.2.5 / 2.2.6).
//!
//! Windows → Linux (client advertises, we pull eagerly on every FormatList):
//! - Text: CF_UNICODETEXT (UTF-16LE on the wire) decoded and served on the
//!   X11 CLIPBOARD selection.
//! - Images: `PNG` / CF_DIB / CF_DIBV5 fetched from the client and served as
//!   `image/png` / `image/bmp`.
//! - Files: FileGroupDescriptorW metadata, then the contents streamed to disk
//!   with FileContents RANGE requests; the downloaded files are offered as a
//!   `text/uri-list` so Linux file managers can paste them.
//!
//! All X11 publishing goes through [`crate::x11_selection`], which keeps
//! owning the CLIPBOARD selection until the next copy anywhere — unlike
//! `arboard`, whose clipboard data disappears when its handle is dropped
//! unless an X11 clipboard manager happens to be running.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use std::sync::{Arc, Mutex};

use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackend};
use ironrdp_cliprdr::pdu::ClipboardFileAttributes;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsFlags,
    FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataRequest, FormatDataResponse,
    LockDataId, OwnedFormatDataResponse,
};
use ironrdp_pdu::utf16::read_utf16_string;
use ironrdp_pdu::IntoOwned;
use tokio::sync::mpsc::UnboundedSender;

use crate::x11_selection;
use ironrdp_server::{ServerEvent, ServerEventSender};

/// Windows standard clipboard formats we support.
const CF_UNICODETEXT: ClipboardFormatId = ClipboardFormatId(13);
const CF_DIB: ClipboardFormatId = ClipboardFormatId(8);
const CF_DIBV5: ClipboardFormatId = ClipboardFormatId(17);

/// Bytes requested per FileContents RANGE round-trip (MS-RDPECLIP 2.2.5.3).
const FILE_CHUNK_SIZE: u32 = 512 * 1024;
/// Refuse single files larger than this (descriptor sizes are remote input).
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Refuse whole file lists larger than this.
const MAX_TOTAL_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// The largest RANGE response this server will ever build (MS-RDPECLIP
/// 2.2.5.3).
///
/// `requested_size` is a `u32` straight off the wire, and it used to size the
/// buffer directly: a client that asked for `u32::MAX` got a four-gigabyte
/// allocation attempt for one chunk. `MAX_FILE_SIZE` and `MAX_TOTAL_SIZE` do
/// not help — they bound what we *download from* a client, not what we serve
/// to one, and a genuinely large file made the request legitimate-looking.
///
/// Same size as [`FILE_CHUNK_SIZE`], which is what our own requests ask for;
/// a client wanting more simply asks again from the next offset, which is how
/// the protocol is meant to be driven anyway.
const MAX_RANGE_RESPONSE: u32 = FILE_CHUNK_SIZE;

/// What we asked the client for with our last `initiate_paste`, so
/// `on_format_data_response` knows how to interpret the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncomingKind {
    Text,
    Png,
    Dib,
}

/// State of an image fetch (Windows → Linux): targets already fetched, plus
/// an optional DIB fetch to perform afterwards. Serving both `image/png` and
/// `image/bmp` matters because GTK/Qt apps happily paste PNG while Wine apps
/// and older tools only ever ask for BMP.
#[derive(Debug)]
struct ImageFetch {
    targets: Vec<x11_selection::SelectionTarget>,
    dib_followup: Option<ClipboardFormatId>,
}

#[derive(Debug, Clone)]
pub(crate) struct OfferedFile {
    pub size: u64,
    /// Absolute path on the LOCAL Linux filesystem to read content from.
    pub linux_path: PathBuf,
}

/// Read text on an explicit X connection; never change process environment.
pub(crate) fn x11_get_text(display: &str, xauthority: &str) -> Option<String> {
    let bytes = x11_selection::read_selection_target_with_auth(display, xauthority, "UTF8_STRING")?;
    String::from_utf8(bytes).ok().filter(|text| !text.is_empty())
}

/// Parse an `x-special/gnome-copied-files` / text/uri-list payload into
/// local Linux file paths (strip `file://` prefix, URL-decode %XX).
pub(crate) fn parse_uri_list(text: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("file://") {
            let decoded = line
                .trim_start_matches("file://")
                .replace("%20", " ")
                .replace("%C3", "\u{c3}"); // minimal percent-decode for common cases
            paths.push(PathBuf::from(decoded));
        } else if !line.is_empty() && !line.starts_with("copy") && !line.starts_with("cut") {
            // Plain path (some file managers put bare paths).
            paths.push(PathBuf::from(line));
        }
    }
    paths
}

/// Serve `text` on the X11 CLIPBOARD under all common text targets.
fn set_x11_text_selection(display: &str, text: &str) {
    let data = text.as_bytes().to_vec();
    let targets = ["UTF8_STRING", "text/plain;charset=utf-8", "text/plain", "STRING", "TEXT"]
        .into_iter()
        .map(|name| (name.to_owned(), data.clone()))
        .collect();
    x11_selection::take_ownership(display.to_owned(), targets);
}

/// One file of an in-flight Windows → Linux download.
#[derive(Debug)]
struct DownloadTarget {
    /// Index of the descriptor inside the remote FILEGROUPDESCRIPTORW
    /// (FileContentsRequest addresses files by this index).
    index: i32,
    /// Where the file goes, **relative to the paste directory**. The absolute
    /// path is never resolved here: the file helper resolves it once, under
    /// its own directory descriptor, with no symlink followed. What comes back
    /// is the descriptor, and a descriptor cannot be redirected afterwards.
    relative: PathBuf,
    /// The absolute path the same file will have, for the `file://` URI the
    /// desktop is offered afterwards. Used to name the file, never to open it.
    path: PathBuf,
    size: Option<u64>,
}

#[derive(Debug)]
enum CurrentDownload {
    /// The descriptor carried no size; a SIZE request is outstanding.
    SizeQuery {
        index: i32,
        relative: PathBuf,
        path: PathBuf,
    },
    /// RANGE requests are streaming into `file`.
    Ranges {
        file: std::fs::File,
        index: i32,
        relative: PathBuf,
        path: PathBuf,
        remaining: u64,
        offset: u64,
    },
}

#[derive(Debug)]
struct Download {
    clip_data_id: Option<u32>,
    stream_id: u32,
    next_stream_id: u32,
    dest_dir: PathBuf,
    /// The helper that creates every file below `dest_dir`, as the session
    /// user. The download cannot start without one.
    files: Arc<Mutex<Option<SessionFiles>>>,
    /// Files not yet started.
    pending: VecDeque<DownloadTarget>,
    current: Option<CurrentDownload>,
    done: Vec<PathBuf>,
    expected: Vec<PathBuf>,
    /// Bytes still allowed for the rest of the list.
    total_budget: u64,
}

impl Download {
    fn alloc_stream_id(&mut self) -> u32 {
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        self.next_stream_id
    }

    /// Create one pasted file, as the session user.
    fn create(&self, relative: &Path) -> anyhow::Result<std::fs::File> {
        X11CliprdrBackend::with_files(&self.files, |agent| agent.create_file(relative))
    }

    /// Drop the file being downloaded (if any), removing the partial result.
    fn skip_current(&mut self) {
        if let Some(CurrentDownload::Ranges { relative, .. }) = self.current.take() {
            let _ = X11CliprdrBackend::with_files(&self.files, |agent| agent.remove(&relative));
        }
    }

    /// Move on to the next file, creating directories and empty files as a
    /// side effect. Returns the request to send for the new current file, or
    /// `None` when the whole download is finished.
    fn advance(&mut self) -> Option<FileContentsRequest> {
        while self.current.is_none() {
            let next = self.pending.pop_front()?;
            match next.size {
                None => {
                    self.stream_id = self.alloc_stream_id();
                    self.current = Some(CurrentDownload::SizeQuery {
                        index: next.index,
                        relative: next.relative,
                        path: next.path,
                    });
                }
                Some(0) => {
                    if let Err(e) = self.create(&next.relative) {
                        tracing::warn!(path = %next.path.display(), error = format!("{e:#}"), "clipboard: cannot create pasted file");
                        continue;
                    }
                    self.done.push(next.path);
                }
                Some(size) if size > MAX_FILE_SIZE || size > self.total_budget => {
                    tracing::warn!(size, path = %next.path.display(), "clipboard: skipping oversized file");
                    continue;
                }
                Some(size) => match self.create(&next.relative) {
                    Ok(file) => {
                        self.total_budget -= size;
                        self.stream_id = self.alloc_stream_id();
                        self.current = Some(CurrentDownload::Ranges {
                            file,
                            index: next.index,
                            relative: next.relative,
                            path: next.path,
                            remaining: size,
                            offset: 0,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(path = %next.path.display(), error = format!("{e:#}"), "clipboard: cannot create pasted file");
                        continue;
                    }
                },
            }
        }
        self.request_for_current()
    }

    fn request_for_current(&self) -> Option<FileContentsRequest> {
        match self.current.as_ref()? {
            CurrentDownload::SizeQuery { index, .. } => Some(FileContentsRequest {
                stream_id: self.stream_id,
                index: *index,
                flags: FileContentsFlags::SIZE,
                position: 0,
                requested_size: 8,
                data_id: self.clip_data_id,
            }),
            CurrentDownload::Ranges {
                index, offset, remaining, ..
            } => Some(FileContentsRequest {
                stream_id: self.stream_id,
                index: *index,
                flags: FileContentsFlags::RANGE,
                position: *offset,
                requested_size: u32::try_from(u64::from(FILE_CHUNK_SIZE).min(*remaining))
                    .unwrap_or(FILE_CHUNK_SIZE),
                data_id: self.clip_data_id,
            }),
        }
    }
}

/// Which index the client will use for the file being added to `advertised`.
///
/// The position in the list actually sent, never the position in the selection
/// it was filtered from — see the call site for what the difference cost.
fn advertised_index(already_advertised: usize) -> i32 {
    i32::try_from(already_advertised).unwrap_or(i32::MAX)
}

/// Turn a remote descriptor's directory and name into a path **relative to**
/// the paste directory.
///
/// Relative on purpose. This used to build the absolute path the worker then
/// opened as root, which meant a textual containment check was standing in for
/// a guarantee only the kernel can give: a symlink anywhere along the way is
/// invisible here and is followed at `open`. What comes out now is handed to
/// the file helper, which walks it one component at a time under its own
/// directory descriptor with `O_NOFOLLOW`. This remains as the first filter —
/// a name with a separator in it is a malformed descriptor worth refusing
/// outright — not as the protection.
fn safe_relative(relative_dir: Option<&str>, name: &str) -> Option<PathBuf> {
    let name = name.trim();
    if name.is_empty() || name.contains(['/', '\\']) {
        return None;
    }
    let mut path = PathBuf::new();
    if let Some(rel) = relative_dir {
        for component in rel.split(['\\', '/']) {
            let component = component.trim();
            if component.is_empty() || component == "." || component == ".." {
                continue;
            }
            path.push(component);
        }
    }
    path.push(name);
    Some(path)
}

/// `file://` URI for a local path, percent-encoded per RFC 8089.
fn path_to_uri(path: &Path) -> String {
    let mut uri = String::from("file://");
    for &byte in path.as_os_str().as_encoded_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                uri.push(byte as char);
            }
            _ => uri.push_str(&format!("%{byte:02X}")),
        }
    }
    uri
}

/// Wrap a CF_DIB / CF_DIBV5 payload (BITMAPINFO…, no file header) into a
/// standalone BMP file by prepending the 14-byte BITMAPFILEHEADER.
fn dib_to_bmp(dib: &[u8]) -> Option<Vec<u8>> {
    let read_u32 = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(dib.get(offset..offset + 4)?.try_into().ok()?))
    };
    let read_u16 = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(dib.get(offset..offset + 2)?.try_into().ok()?))
    };

    if dib.len() < 40 {
        return None;
    }
    let header_size = read_u32(0)? as usize;
    if !(40..=dib.len()).contains(&header_size) {
        return None;
    }
    let bpp = read_u16(14)? as usize;
    let compression = read_u32(16)?;
    let clr_used = read_u32(32)? as usize;
    let palette_entries = if clr_used > 0 {
        clr_used
    } else if bpp <= 8 {
        1usize << bpp
    } else {
        0
    };
    // BI_BITFIELDS with a 40-byte header carries its 3 color-mask DWORDs
    // after the header (MS-RDPECLIP / GDI convention).
    let masks = if compression == 3 && header_size == 40 { 12 } else { 0 };

    let offset = 14usize
        .checked_add(header_size)?
        .checked_add(palette_entries.checked_mul(4)?)?
        .checked_add(masks)?;
    if offset > dib.len() {
        return None;
    }
    let file_len = dib.len().checked_add(14)?;

    let mut bmp = Vec::with_capacity(file_len);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(file_len as u32).to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&(offset as u32).to_le_bytes());
    bmp.extend_from_slice(dib);
    Some(bmp)
}

/// Decode a CF_DIB / CF_DIBV5 payload into 8-bit RGB pixels (row-major,
/// top-down). Alpha is forced opaque: Windows clipboard bitmaps usually carry
/// zeroed/undefined alpha, and honoring it would paste a transparent image.
fn decode_dib(dib: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    const MAX_DIM: i32 = 16384;

    if dib.len() < 40 {
        return None;
    }
    let read_u32 = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(dib.get(offset..offset + 4)?.try_into().ok()?))
    };
    let read_u16 = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(dib.get(offset..offset + 2)?.try_into().ok()?))
    };

    let header_size = read_u32(0)? as usize;
    if !(40..=124).contains(&header_size) || dib.len() < header_size {
        return None;
    }
    let width = read_u32(4)? as i32;
    let height_raw = read_u32(8)? as i32;
    let top_down = height_raw < 0;
    let height = height_raw.unsigned_abs() as i32;
    if !(1..=MAX_DIM).contains(&width) || !(1..=MAX_DIM).contains(&height) {
        return None;
    }
    let bpp = u32::from(read_u16(14)?);
    let compression = read_u32(16)?;
    if !matches!((compression, bpp), (0, 24) | (0, 32) | (3, 32)) {
        return None;
    }

    let clr_used = read_u32(32)? as usize;
    let palette = if clr_used > 0 { clr_used } else if bpp <= 8 { 1usize << bpp } else { 0 };
    let masks_len = if compression == 3 && header_size == 40 { 12 } else { 0 };
    let pixels_off = header_size.checked_add(palette.checked_mul(4)?)?.checked_add(masks_len)?;

    // Color masks: BI_RGB has the fixed BGRX layout; BI_BITFIELDS carries the
    // masks either right after a 40-byte header or inside V4/V5 headers at
    // offset 40 — the same offset in both cases.
    let (r_mask, g_mask, b_mask) = if compression == 3 {
        (read_u32(40)?, read_u32(44)?, read_u32(48)?)
    } else {
        (0x00FF_0000, 0x0000_FF00, 0x0000_00FF)
    };
    if r_mask == 0 || g_mask == 0 || b_mask == 0 {
        return None;
    }

    let bytes_per_px = (bpp / 8) as usize;
    let row_bytes = (bpp as usize * width as usize).div_ceil(32) * 4;
    let needed = pixels_off.checked_add(row_bytes.checked_mul(height as usize)?)?;
    if dib.len() < needed {
        return None;
    }

    let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
    for row in 0..height as usize {
        let src_row = if top_down {
            row
        } else {
            height as usize - 1 - row
        };
        let row_start = pixels_off + src_row * row_bytes;
        for x in 0..width as usize {
            let px = &dib[row_start + x * bytes_per_px..][..bytes_per_px];
            let raw = match bpp {
                24 => u32::from(px[0]) | u32::from(px[1]) << 8 | u32::from(px[2]) << 16,
                _ => u32::from_le_bytes([px[0], px[1], px[2], px[3]]),
            };
            rgb.push(scale_channel(raw, r_mask));
            rgb.push(scale_channel(raw, g_mask));
            rgb.push(scale_channel(raw, b_mask));
        }
    }
    Some((width as u32, height as u32, rgb))
}

/// Extract an 8-bit channel value from a pixel word through its mask.
fn scale_channel(raw: u32, mask: u32) -> u8 {
    let shift = mask.trailing_zeros();
    let bits = mask.count_ones().min(32);
    if bits == 0 {
        return 0;
    }
    let value = (raw & mask) >> shift;
    let max = (1u64 << bits) - 1;
    if bits >= 8 {
        u8::try_from((u64::from(value) * 255 / max).min(255)).unwrap_or(255)
    } else {
        u8::try_from((u64::from(value) * 255 + max / 2) / max).unwrap_or(255)
    }
}

/// Encode RGB8 pixels as a PNG file.
fn rgb_to_png(width: u32, height: u32, rgb: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, width, height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(rgb).ok()?;
    writer.finish().ok()?;
    Some(out)
}
fn decode_utf16_lossy(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Poller generation: each `on_ready` (channel re-initialization) spawns a
/// fresh poller; older ones see the counter move and exit instead of leaking
/// (and advertising in parallel) for the rest of the process lifetime.
static POLLER_GENERATION: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub(crate) struct X11CliprdrBackend {
    #[cfg(test)]
    poller_thread: Option<std::thread::JoinHandle<()>>,
    proxy: Arc<Mutex<Option<Box<dyn ClipboardMessageProxy>>>>,
    display: String,
    xauthority: String,

    /// Kind of the format data we requested from the client most recently,
    /// together with the copy generation it belongs to. Responses arriving
    /// after a newer FormatList are dropped instead of being misinterpreted.
    incoming: Option<IncomingKind>,
    incoming_gen: u32,
    copy_generation: u32,

    /// In-flight image fetch (Windows → Linux), if any.
    image_fetch: Option<ImageFetch>,

    /// Files offered to the client (Linux → Windows), keyed by the
    /// descriptor index the client addresses them with.
    outgoing_files: Arc<Mutex<HashMap<i32, OfferedFile>>>,
    files_advertised: Arc<Mutex<bool>>,

    /// Text we wrote to X11 from client data; the poller consumes it once to
    /// avoid re-advertising the client's own clipboard back to it.
    echo_guard: Arc<Mutex<Option<String>>>,

    /// In-flight Windows → Linux file download, if any.
    download: Option<Download>,

    /// Image format-list announcements arriving before this instant are the
    /// client re-advertising its EXISTING clipboard right at session start —
    /// fetching them eagerly transfers multi-megabyte screenshots through
    /// the young session's control channel exactly while the client is
    /// trying to finish connecting, which mstsc manifests as a black screen.
    /// Hold those fetches a few seconds; the data syncs once the session is
    /// up (a genuine new copy mid-session is fetched immediately).
    hold_image_fetch_until: Option<std::time::Instant>,

    /// The helper that touches files for this session, running as the session
    /// user.
    ///
    /// Every file this module opens or creates goes through it. The worker is
    /// root, and both directions of file transfer are named by somebody who
    /// is not: the session names what to read, the remote client names what
    /// to write. `None` means no session is bound (the logon screen) or the
    /// helper could not start — either way file transfer is off, which is the
    /// safe direction. Text and images are unaffected.
    files: Arc<Mutex<Option<SessionFiles>>>,
}

impl X11CliprdrBackend {
    pub(crate) fn new(display: String, xauthority: String) -> Self {
        Self {
            #[cfg(test)]
            poller_thread: None,
            proxy: Arc::new(Mutex::new(None)),
            display,
            xauthority,
            files: Arc::new(Mutex::new(None)),
            incoming: None,
            incoming_gen: 0,
            copy_generation: 0,
            image_fetch: None,
            outgoing_files: Arc::new(Mutex::new(HashMap::new())),
            files_advertised: Arc::new(Mutex::new(false)),
            echo_guard: Arc::new(Mutex::new(None)),
            download: None,
            hold_image_fetch_until: None,
        }
    }

    /// Which X server this connection's clipboard belongs to *now*.
    ///
    /// Read from the gate at every use, not captured when the backend was
    /// built. With `auth: greeter` the CLIPRDR channel is negotiated while the
    /// logon form is on screen, so what was captured then was the logon
    /// screen's own X server — and after the handover the clipboard went on
    /// talking to it while the user looked at their desktop. The gate is the
    /// thing that knows which display this worker is pointed at, and it is
    /// updated by the handover.
    ///
    /// Falls back to what was captured at construction, which is what an
    /// unarmed worker (single session, or console mode) has and is correct
    /// there.
    fn target(&self) -> (String, String) {
        crate::session::gate::clipboard_target().unwrap_or_else(|_| (self.display.clone(), self.xauthority.clone()))
    }

    /// Read the current X11 clipboard text (best-effort).
    fn read_x11_text(&self) -> Option<String> {
        let (display, xauthority) = self.target();
        x11_get_text(&display, &xauthority)
    }

    fn send_msg(&self, msg: ClipboardMessage) {
        let guard = self.proxy.lock().expect("poisoned");
        if let Some(proxy) = guard.as_ref() {
            proxy.send_clipboard_message(msg);
        }
    }

    /// Publish the fetched image targets — or, when a DIB follow-up is
    /// pending, fetch that first so both `image/png` and `image/bmp` end up
    /// on the X11 clipboard.
    fn finish_image_fetch(&mut self) {
        let Some(fetch) = self.image_fetch.take() else {
            return;
        };
        if let Some(dib_format) = fetch.dib_followup {
            tracing::debug!("clipboard: fetching DIB alongside PNG for BMP-only paste targets");
            self.incoming = Some(IncomingKind::Dib);
            self.incoming_gen = self.copy_generation;
            self.image_fetch = Some(ImageFetch {
                targets: fetch.targets,
                dib_followup: None,
            });
            self.send_msg(ClipboardMessage::SendInitiatePaste(dib_format));
            return;
        }
        if fetch.targets.is_empty() {
            tracing::warn!("clipboard: no usable image data from client");
            return;
        }
        let bytes = fetch.targets.iter().map(|(_, data)| data.len()).sum::<usize>();
        let names: Vec<&str> = fetch.targets.iter().map(|(name, _)| name.as_str()).collect();
        tracing::info!(formats = ?names, bytes, "clipboard: client image → X11");
        x11_selection::take_ownership(self.target().0, fetch.targets);
    }

    /// Finish a Windows → Linux download: publish the files as a uri-list.
    fn download_finished(&mut self) {
        let Some(download) = self.download.take() else {
            return;
        };
        tracing::info!(
            dir = %download.dest_dir.display(),
            count = download.done.len(),
            "clipboard: files pasted from client"
        );
        let roots = publication_roots(&download.dest_dir, &download.expected, &download.done);
        if roots.is_empty() {
            return;
        }
        let uris: Vec<String> = roots.iter().map(|path| path_to_uri(path)).collect();
        let uri_list = uris.join("\r\n").into_bytes();
        let gnome_copied = format!("copy\n{}", uris.join("\n"));
        // Prime the echo guard with the exact payload we are about to serve,
        // so the poller does not advertise the client's own files back to it.
        *self.echo_guard.lock().expect("poisoned") = Some(gnome_copied.clone());
        x11_selection::take_ownership(
            self.target().0,
            vec![
                ("x-special/gnome-copied-files".to_owned(), gnome_copied.into_bytes()),
                ("text/uri-list".to_owned(), uri_list),
            ],
        );
    }

    /// Run `f` against this session's file helper, starting one if the
    /// session now has an owner and does not yet have a helper.
    ///
    /// Started here rather than once at channel-ready, because at channel-ready
    /// there is often nobody to start it as. With `auth: greeter` the CLIPRDR
    /// channel is negotiated while the logon form is still on screen: the gate
    /// has no owner, so the helper could not be started, and nothing tried
    /// again after the user logged in — the poller watches its own CLIPRDR
    /// generation, not a change of session owner. File transfer stayed off for
    /// the rest of the connection, with the channel perfectly healthy.
    ///
    /// A helper started for one owner is also thrown away when the owner
    /// changes, which is exactly the greeter's handover: the logon screen is
    /// nobody's session, and its helper — if there somehow were one — has no
    /// business opening the user's files.
    ///
    /// Never falls back to doing the work in this process. A worker is root;
    /// that fallback is the bug this whole arrangement replaces.
    fn with_files<T>(
        files: &Arc<Mutex<Option<SessionFiles>>>,
        f: impl FnOnce(&mut crate::session::fileagent::FileAgent) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let owner = crate::session::gate::session_user()
            .context("no session is bound, so there is nobody to open files as")?;

        let mut guard = files.lock().expect("poisoned");
        if guard.as_ref().is_some_and(|held| held.owner != owner) {
            tracing::info!(from = %guard.as_ref().expect("checked").owner, to = %owner, "clipboard: session owner changed — replacing the file helper");
            *guard = None;
        }
        if guard.is_none() {
            let agent = crate::session::fileagent::FileAgent::start(&owner)
                .with_context(|| format!("start a file helper running as {owner}"))?;
            *guard = Some(SessionFiles {
                owner: owner.clone(),
                agent,
            });
        }
        f(&mut guard.as_mut().expect("just started").agent)
    }
}

/// A file helper together with the account it is running as.
///
/// The account is not decoration: a connection can change owner exactly once,
/// when the logon screen hands over to a desktop, and a helper acting as the
/// wrong account is the whole class of bug this module exists to prevent.
#[derive(Debug)]
pub(crate) struct SessionFiles {
    owner: String,
    agent: crate::session::fileagent::FileAgent,
}

ironrdp_core::impl_as_any!(X11CliprdrBackend);

impl CliprdrBackend for X11CliprdrBackend {
    fn temporary_directory(&self) -> &str {
        "/tmp"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
            | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
    }

    fn on_ready(&mut self) {
        tracing::info!("clipboard: channel ready (X11 ↔ RDP sync: text + files + images)");
        // The helper is started on first use, not here: with `auth: greeter`
        // this runs while the logon form is still up, when the session has no
        // owner to run one as.
        self.hold_image_fetch_until = Some(std::time::Instant::now() + Duration::from_secs(4));

        // Poll the current session for local copies (Linux → Windows). The
        // echo guard keeps remote-sourced data from being advertised back.
        let proxy = Arc::clone(&self.proxy);
        let files = Arc::clone(&self.files);
        let outgoing_files = Arc::clone(&self.outgoing_files);
        let files_advertised = Arc::clone(&self.files_advertised);
        let echo_guard = Arc::clone(&self.echo_guard);
        let generation = POLLER_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;

        let spawned = std::thread::Builder::new()
            .name("linrdp-cliprdr-poll".into())
            .spawn(move || {
                // No construction-time display snapshot: the router may already
                // have bound another screen before the channel becomes ready.
                let mut bound_at = None;
                let mut last_text: Option<String> = None;
                let mut last_files: Option<String> = None;
                loop {
                    std::thread::sleep(Duration::from_millis(700));
                    if POLLER_GENERATION.load(Ordering::Relaxed) != generation {
                        tracing::debug!("clipboard: stale poller exiting");
                        break;
                    }

                    // Follow the worker to whatever display it is pointed at
                    // now. With `auth: greeter` this thread starts while the
                    // logon form is up, so the screen it was given belongs to
                    // the form; the handover to the user's desktop moves the
                    // gate, and a poller that kept its original value went on
                    // watching a clipboard the user could no longer see.
                    let now = crate::session::gate::generation();
                    let Ok((display, xauthority)) = crate::session::gate::clipboard_target() else {
                        continue; // An armed, unbound worker has no clipboard.
                    };
                    if bound_at != Some(now) {
                        bound_at = Some(now);
                        // The gate owns DISPLAY/XAUTHORITY. Never restore stale
                        // backend values over its environment after a bind.
                        // The previous screen's clipboard says nothing about
                        // this one: start clean rather than treating the first
                        // read as unchanged.
                        last_text = None;
                        last_files = None;
                        // A binding with another name: tracing's `%` shorthand
                        // pulls `display` into scope as a function and would
                        // shadow the variable.
                        let now_on = display.clone();
                        tracing::info!(target_display = %now_on, "clipboard: following the session handover");
                    }

                    // File managers put copied files under dedicated targets;
                    // query those before ordinary text.
                    let uri_text = x11_selection::read_selection_target_with_auth(&display, &xauthority, "x-special/gnome-copied-files")
                        .or_else(|| x11_selection::read_selection_target_with_auth(&display, &xauthority, "text/uri-list"))
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());

                    let board_text = x11_get_text(&display, &xauthority);

                    let guard = echo_guard.lock().expect("poisoned").take();
                    if let Some(text) = uri_text.as_ref() {
                        if guard.as_deref() == Some(text.as_str()) {
                            // File list we ourselves published from client data.
                            last_files = Some(text.clone());
                            continue;
                        }
                    }
                    if let Some(text) = board_text.as_ref() {
                        if guard.as_deref() == Some(text.as_str()) {
                            // Text we ourselves published from client data.
                            last_text = Some(text.clone());
                            continue;
                        }
                    }

                    let file_source = uri_text
                        .filter(|text| text.contains("file://"))
                        .or_else(|| board_text.clone().filter(|text| text.contains("file://")));

                    if let Some(files_text) = file_source {
                        if last_files.as_deref() == Some(files_text.as_str()) {
                            continue;
                        }
                        last_files = Some(files_text.clone());
                        last_text = Some(files_text.clone());

                        let paths = parse_uri_list(&files_text);
                        let mut descriptors = Vec::new();
                        let mut offered: HashMap<i32, OfferedFile> = HashMap::new();
                        for (i, path) in paths.iter().enumerate() {
                            // Through the helper, as the session user. Doing
                            // this as root is how a program on the desktop
                            // could put `file:///etc/shadow` on the clipboard
                            // and have it served to the RDP client: naming
                            // the file was enough, because the account that
                            // named it never needed to be able to read it.
                            let facts = match Self::with_files(&files, |agent| agent.stat(path)) {
                                Ok(facts) => facts,
                                Err(error) => {
                                    tracing::debug!(
                                        path = %path.display(),
                                        error = format!("{error:#}"),
                                        "clipboard: not offering a file this session cannot read"
                                    );
                                    continue;
                                }
                            };
                            if !facts.is_file {
                                continue;
                            }
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| format!("file{i}"));
                            // The client addresses files by their position in
                            // the list it was SENT, which is this one — not by
                            // their position in the selection we started from.
                            // Keying the map on the latter meant that as soon
                            // as anything was skipped (a directory in a mixed
                            // selection, a file removed mid-copy, a file this
                            // session cannot read) every index after it was off
                            // by one: the first request was refused and the
                            // next returned the wrong file's contents under the
                            // right file's name.
                            let index = advertised_index(descriptors.len());
                            descriptors.push(
                                FileDescriptor::new(name.clone())
                                    .with_file_size(facts.size)
                                    .with_attributes(ClipboardFileAttributes::ARCHIVE),
                            );
                            offered.insert(
                                index,
                                OfferedFile {
                                    size: facts.size,
                                    linux_path: path.clone(),
                                },
                            );
                        }
                        if descriptors.is_empty() {
                            continue;
                        }
                        *outgoing_files.lock().expect("poisoned") = offered;
                        *files_advertised.lock().expect("poisoned") = true;
                        tracing::info!(count = descriptors.len(), "clipboard: X11 files → advertise to client");
                        if let Some(p) = proxy.lock().expect("poisoned").as_ref() {
                            p.send_clipboard_message(ClipboardMessage::SendInitiateFileCopy(descriptors));
                        }
                    } else if let Some(text) = board_text {
                        if last_text.as_deref() == Some(text.as_str()) {
                            continue;
                        }
                        last_text = Some(text.clone());
                        last_files = None;
                        *files_advertised.lock().expect("poisoned") = false;
                        tracing::info!(bytes = text.len(), "clipboard: X11 text → advertise to client");
                        if let Some(p) = proxy.lock().expect("poisoned").as_ref() {
                            p.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
                                ClipboardFormat::new(CF_UNICODETEXT),
                            ]));
                        }
                    }
                }
            });
        match spawned {
            Ok(handle) => {
                #[cfg(test)]
                { self.poller_thread = Some(handle); }
                #[cfg(not(test))]
                { drop(handle); }
            }
            Err(error) => tracing::warn!(%error, "clipboard: cannot start poller"),
        }
    }

    fn on_request_format_list(&mut self) {
        // Channel initialization: advertise text only if the X11 clipboard
        // actually holds some — the poller re-advertises on every change.
        if self.read_x11_text().is_some() {
            self.send_msg(ClipboardMessage::SendInitiateCopy(vec![ClipboardFormat::new(
                CF_UNICODETEXT,
            )]));
        }
    }

    fn on_format_list_response(&mut self, ok: bool) {
        if !ok {
            tracing::debug!("clipboard: client rejected our format list");
        }
    }

    fn on_process_negotiated_capabilities(&mut self, _caps: ClipboardGeneralCapabilityFlags) {}

    /// The client copied something: fetch it eagerly so it lands in the X11
    /// clipboard (text/images) or on disk (files).
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        let named = |want: &str| {
            formats
                .iter()
                .find(|f| f.name.as_ref().map(|n| n.value() == want).unwrap_or(false))
        };

        // Log every format list verbatim: this is the primary diagnostic for
        // "copy on Windows does nothing on the server".
        let summary: Vec<String> = formats
            .iter()
            .map(|f| match &f.name {
                Some(name) => format!("{}#{}", name.value(), f.id.0),
                None => format!("#{}", f.id.0),
            })
            .collect();
        tracing::info!(formats = ?summary, "clipboard: client format list");

        self.copy_generation = self.copy_generation.wrapping_add(1);
        self.image_fetch = None;

        if let Some(file_list) = named("FileGroupDescriptorW") {
            tracing::info!("clipboard: client copied files — fetching file list");
            self.incoming = None; // routed to on_remote_file_list by the core
            self.send_msg(ClipboardMessage::SendInitiatePaste(file_list.id));
            return;
        }

        // Eager fetch unless the session just came up: a startup format list
        // re-announces whatever (possibly huge) image already sits in the
        // client clipboard, and hauling it mid-connect is the black-screen
        // trigger — defer to when the session has settled.
        let eager_fetch = !matches!(self.hold_image_fetch_until, Some(until) if std::time::Instant::now() < until);
        let initiate_image_fetch = |backend: &Self, kind: IncomingKind, format: ClipboardFormatId| {
            if eager_fetch {
                backend.send_msg(ClipboardMessage::SendInitiatePaste(format));
                return;
            }
            tracing::info!("clipboard: deferring image fetch until the session settles");
            let proxy = Arc::clone(&backend.proxy);
            std::thread::Builder::new()
                .name("linrdp-cliprdr-defer".into())
                .spawn(move || {
                    std::thread::sleep(Duration::from_secs(4));
                    let guard = proxy.lock().expect("poisoned");
                    if let Some(proxy) = guard.as_ref() {
                        proxy.send_clipboard_message(ClipboardMessage::SendInitiatePaste(format));
                    }
                    let _ = kind; // bookkeeping already recorded by the caller
                })
                .ok();
        };

        let png = named("PNG");
        let dib = [CF_DIB, CF_DIBV5].into_iter().find(|id| formats.iter().any(|f| f.id == *id));
        match (png, dib) {
            (Some(png), dib) => {
                tracing::info!("clipboard: client copied image (PNG) — fetching");
                self.image_fetch = Some(ImageFetch {
                    targets: Vec::new(),
                    dib_followup: dib,
                });
                self.incoming = Some(IncomingKind::Png);
                self.incoming_gen = self.copy_generation;
                initiate_image_fetch(self, IncomingKind::Png, png.id);
            }
            (None, Some(dib)) => {
                tracing::info!(format = ?dib, "clipboard: client copied image (DIB) — fetching");
                self.image_fetch = Some(ImageFetch {
                    targets: Vec::new(),
                    dib_followup: None,
                });
                self.incoming = Some(IncomingKind::Dib);
                self.incoming_gen = self.copy_generation;
                initiate_image_fetch(self, IncomingKind::Dib, dib);
            }
            (None, None) => {
                self.incoming = None;
                if formats.iter().any(|f| f.id == CF_UNICODETEXT) {
                    tracing::info!("clipboard: client copied text — fetching");
                    self.incoming = Some(IncomingKind::Text);
                    self.incoming_gen = self.copy_generation;
                    self.send_msg(ClipboardMessage::SendInitiatePaste(CF_UNICODETEXT));
                } else {
                    tracing::debug!("clipboard: no supported format in client format list");
                }
            }
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        tracing::debug!(format = ?request.format, "clipboard: client requests format data");
        let response: OwnedFormatDataResponse = if request.format == CF_UNICODETEXT {
            // CF_UNICODETEXT is UTF-16LE with CRLF line endings, NUL-terminated.
            // Sending UTF-8 bytes here makes Windows decode them as UTF-16LE,
            // which renders every two ASCII characters as one CJK glyph.
            match self.read_x11_text() {
                Some(text) => FormatDataResponse::new_data(text_to_utf16_crlf(&text)).into_owned(),
                None => FormatDataResponse::new_error(),
            }
        } else {
            FormatDataResponse::new_error()
        };
        self.send_msg(ClipboardMessage::SendFormatData(response));
    }

    /// Payload fetched from the client (text or image); file lists arrive in
    /// `on_remote_file_list` instead.
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let Some(kind) = self.incoming.take() else {
            tracing::trace!("clipboard: ignoring unsolicited format data response");
            return;
        };
        if self.incoming_gen != self.copy_generation {
            tracing::trace!("clipboard: dropping stale format data response");
            return;
        }
        let data = if response.is_error() {
            tracing::warn!("clipboard: client failed to serve requested format data");
            None
        } else {
            Some(response.data())
        };
        match kind {
            IncomingKind::Text => {
                let Some(data) = data else { return };
                // CF_UNICODETEXT is UTF-16LE with CRLF line endings.
                let text = read_utf16_string(data, None).unwrap_or_else(|_| decode_utf16_lossy(data));
                let text = text.replace("\r\n", "\n");
                if text.is_empty() {
                    return;
                }
                tracing::info!(bytes = text.len(), "clipboard: client text → X11");
                *self.echo_guard.lock().expect("poisoned") = Some(text.clone());
                set_x11_text_selection(&self.target().0, &text);
            }
            IncomingKind::Png => {
                if let Some(data) = data {
                    if data.starts_with(&[0x89, b'P', b'N', b'G']) {
                        if let Some(fetch) = self.image_fetch.as_mut() {
                            fetch.targets.push(("image/png".to_owned(), data.to_vec()));
                        }
                    } else {
                        tracing::warn!("clipboard: client sent malformed PNG data");
                    }
                }
                self.finish_image_fetch();
            }
            IncomingKind::Dib => {
                if let Some(data) = data {
                    if let Some(fetch) = self.image_fetch.as_mut() {
                        // PNG is what most Linux apps request on paste; mstsc
                        // often offers only CF_DIB (no "PNG" format), so
                        // transcode the DIB ourselves.
                        if let Some((width, height, rgb)) = decode_dib(data) {
                            if let Some(png) = rgb_to_png(width, height, &rgb) {
                                tracing::debug!(width, height, "clipboard: DIB transcoded to PNG");
                                fetch.targets.push(("image/png".to_owned(), png));
                            }
                        }
                        match dib_to_bmp(data) {
                            Some(bmp) => {
                                fetch.targets.push(("image/bmp".to_owned(), bmp.clone()));
                                fetch.targets.push(("image/x-bmp".to_owned(), bmp));
                            }
                            None => tracing::warn!("clipboard: client sent malformed CF_DIB data"),
                        }
                    }
                }
                self.finish_image_fetch();
            }
        }
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        tracing::debug!(stream_id = request.stream_id, index = request.index, "clipboard: file contents request from client");
        let response = match self.outgoing_files.lock().expect("poisoned").get(&request.index) {
            Some(file) if request.flags.contains(FileContentsFlags::SIZE) => {
                FileContentsResponse::new_data_response(request.stream_id, file.size.to_le_bytes().to_vec())
            }
            Some(file) => {
                // Opened by the helper, as the session user. The descriptor
                // that comes back is the answer to "which file is this" —
                // there is no second path resolution for anything to be
                // substituted into.
                match Self::with_files(&self.files, |agent| agent.open_read(&file.linux_path)) {
                    Ok(handle) => read_file_range(file, handle, &request),
                    Err(error) => {
                        tracing::warn!(
                            path = %file.linux_path.display(),
                            error = format!("{error:#}"),
                            "clipboard: cannot serve a file this session cannot open"
                        );
                        FileContentsResponse::new_error(request.stream_id)
                    }
                }
            }
            None => FileContentsResponse::new_error(request.stream_id),
        };
        self.send_msg(ClipboardMessage::SendFileContentsResponse(response));
    }

    /// One chunk of the in-flight Windows → Linux download.
    fn on_file_contents_response(&mut self, response: FileContentsResponse<'_>) {
        let Some(download) = self.download.as_mut() else {
            return;
        };
        if response.stream_id() != download.stream_id {
            tracing::trace!(stream_id = response.stream_id(), "clipboard: dropping stale file contents response");
            return;
        }
        if response.is_error() {
            tracing::warn!("clipboard: file contents transfer failed — skipping file");
            download.skip_current();
        } else {
            match download.current.as_mut() {
                Some(CurrentDownload::SizeQuery { index, relative, path }) => {
                    let (index, relative, path) = (*index, relative.clone(), path.clone());
                    match response.data_as_size().ok() {
                        Some(0) => {
                            if download.create(&relative).is_ok() {
                                download.done.push(path);
                            }
                            download.current = None;
                        }
                        Some(size) if size <= MAX_FILE_SIZE && size <= download.total_budget => {
                            match download.create(&relative) {
                                Ok(file) => {
                                    download.total_budget -= size;
                                    download.current = Some(CurrentDownload::Ranges {
                                        file,
                                        index,
                                        relative,
                                        path,
                                        remaining: size,
                                        offset: 0,
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(path = %path.display(), error = format!("{e:#}"), "clipboard: cannot create pasted file");
                                    download.current = None;
                                }
                            }
                        }
                        Some(size) => {
                            tracing::warn!(size, path = %path.display(), "clipboard: skipping oversized file");
                            download.current = None;
                        }
                        None => {
                            tracing::warn!("clipboard: malformed SIZE response — skipping file");
                            download.current = None;
                        }
                    }
                }
                Some(CurrentDownload::Ranges {
                    file,
                    path,
                    remaining,
                    offset,
                    ..
                }) => {
                    let data = response.data();
                    let take = data.len().min(usize::try_from(*remaining).unwrap_or(0));
                    if take == 0 {
                        tracing::warn!("clipboard: empty file contents chunk — skipping file");
                        download.skip_current();
                    } else if let Err(e) = file.write_all(&data[..take]) {
                        tracing::warn!(path = %path.display(), %e, "clipboard: write failed — skipping file");
                        download.skip_current();
                    } else {
                        *remaining -= take as u64;
                        *offset += take as u64;
                        if *remaining == 0 {
                            let _ = file.sync_all();
                            tracing::debug!(path = %path.display(), "clipboard: file downloaded");
                            download.done.push(path.clone());
                            download.current = None;
                        }
                    }
                }
                None => return,
            }
        }

        let request = download.advance();
        match request {
            Some(request) => self.send_msg(ClipboardMessage::SendFileContentsRequest(request)),
            None => self.download_finished(),
        }
    }

    /// File list metadata from the client: start streaming the files to disk.
    fn on_remote_file_list(&mut self, files: &[FileDescriptor], clip_data_id: Option<u32>) {
        // The directory belongs to the session user and is made by the helper:
        // a random name, `mkdir` exclusive, mode 0700. Every worker used to
        // number its own from zero, so two sessions shared `linrdp-paste-0`
        // and the same file name in both meant one truncating the other's
        // download — while `umask 022` left the lot readable by every account
        // on the machine.
        let transfer = match Self::with_files(&self.files, crate::session::fileagent::FileAgent::new_transfer) {
            Ok(dir) => dir,
            Err(error) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "clipboard: refusing a file paste — there is no helper to write it as the \
                     session user, and the worker is root"
                );
                return;
            }
        };

        let mut pending = VecDeque::new();
        let mut expected = Vec::new();
        let mut done = Vec::new();
        for (i, file) in files.iter().enumerate() {
            let is_dir = file
                .attributes
                .is_some_and(|attributes| attributes.contains(ClipboardFileAttributes::DIRECTORY));
            // Under this transfer's own directory, so a second copy of the
            // same file name in the same connection cannot replace the first
            // under a URI the desktop already holds.
            let Some(relative) = safe_relative(file.relative_path.as_deref(), &file.name)
                .map(|rel| transfer.name.join(rel))
            else {
                tracing::warn!(name = %file.name, "clipboard: skipping file with unsafe name");
                continue;
            };
            let path = transfer.path.join(relative.strip_prefix(&transfer.name).unwrap_or(&relative));
            expected.push(path.clone());
            if is_dir {
                match Self::with_files(&self.files, |agent| agent.make_dir(&relative)) {
                    Ok(()) => done.push(path),
                    Err(error) => tracing::warn!(dir = %relative.display(), error = format!("{error:#}"), "clipboard: cannot create pasted directory"),
                }
                continue;
            }
            pending.push_back(DownloadTarget {
                index: i as i32,
                path,
                relative,
                size: file.file_size,
            });
        }
        tracing::info!(dir = %transfer.path.display(), count = pending.len(), "clipboard: downloading pasted files");

        let mut download = Download {
            clip_data_id,
            stream_id: 0,
            next_stream_id: 1,
            dest_dir: transfer.path,
            files: Arc::clone(&self.files),
            pending,
            current: None,
            done,
            expected,
            total_budget: MAX_TOTAL_SIZE,
        };
        let request = download.advance();
        self.download = Some(download);
        match request {
            Some(request) => self.send_msg(ClipboardMessage::SendFileContentsRequest(request)),
            None => self.download_finished(),
        }
    }

    fn on_lock(&mut self, _id: LockDataId) {}

    fn on_unlock(&mut self, _id: LockDataId) {}
}

/// Publish complete top-level selections, never their flattened leaves.
/// A failed entry suppresses its entire root; unrelated selections survive.
fn publication_roots(base: &Path, expected: &[PathBuf], done: &[PathBuf]) -> Vec<PathBuf> {
    let complete: std::collections::HashSet<_> = done.iter().collect();
    let mut roots = Vec::new();
    let mut status = HashMap::new();
    for path in expected {
        let Some(first) = path.strip_prefix(base).ok().and_then(|p| p.components().next()) else { continue };
        let root = base.join(first.as_os_str());
        let ready = status.entry(root.clone()).or_insert_with(|| { roots.push(root); true });
        *ready &= complete.contains(path);
    }
    roots.into_iter().filter(|root| status[root]).collect()
}

/// How many bytes a RANGE request may actually be answered with.
///
/// Three bounds, all applied before a single byte is allocated: the chunk
/// ceiling, what is left of the file past `position`, and — for a position
/// beyond the file — nothing at all.
fn range_response_len(offered_size: u64, position: u64, requested: u32) -> usize {
    let remaining = offered_size.saturating_sub(position);
    let capped = u64::from(requested.min(MAX_RANGE_RESPONSE)).min(remaining);
    usize::try_from(capped).unwrap_or(0)
}

/// Serve a RANGE FileContentsRequest from an already-open file.
///
/// `handle` arrives open on purpose: it was opened by the session's file
/// helper with the session user's credentials, and this function is not given
/// a path it could open itself.
fn read_file_range(
    file: &OfferedFile,
    mut f: std::fs::File,
    request: &FileContentsRequest,
) -> FileContentsResponse<'static> {
    use std::io::{Read, Seek};
    let want = range_response_len(file.size, request.position, request.requested_size);
    if want == 0 {
        // Either the client asked past the end of what we offered, or for
        // nothing. Both are answered, never allocated for.
        return FileContentsResponse::new_data_response(request.stream_id, Vec::new());
    }
    if f.seek(std::io::SeekFrom::Start(request.position)).is_err() {
        return FileContentsResponse::new_error(request.stream_id);
    }
    let mut buf = vec![0u8; want];
    let mut total = 0usize;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => return FileContentsResponse::new_error(request.stream_id),
        }
    }
    buf.truncate(total);
    FileContentsResponse::new_data_response(request.stream_id, buf)
}

pub(crate) fn text_to_crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' {
            // Bare LF: emit CRLF; the next line's newline is its own.
            out.push_str("\r\n");
        } else if c == '\r' {
            // CRLF pair already: emit once, skip the LF half.
            out.push_str("\r\n");
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// CF_UNICODETEXT wire format: UTF-16LE, CRLF line endings, NUL-terminated.
pub(crate) fn text_to_utf16_crlf(text: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = text_to_crlf(text)
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

/// Forwards clipboard messages from the backend into the session event loop,
/// where they are turned into CLIPRDR PDUs (server.rs `ServerEvent::Clipboard`).
#[derive(Debug)]
struct ServerEventClipboardProxy {
    sender: Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>,
}

impl ClipboardMessageProxy for ServerEventClipboardProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        let guard = self.sender.lock().expect("poisoned");
        if let Some(sender) = guard.as_ref() {
            if sender.send(ServerEvent::Clipboard(message)).is_err() {
                tracing::debug!("clipboard: session event channel closed, dropping message");
            }
        } else {
            tracing::debug!("clipboard: no session event channel yet, dropping message");
        }
    }
}

/// Factory for the X11 ↔ RDP clipboard backend.
#[derive(Debug, Default)]
pub(crate) struct X11CliprdrServerFactory {
    sender: Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>,
}

impl ServerEventSender for X11CliprdrServerFactory {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.sender.lock().expect("poisoned") = Some(sender);
    }
}

impl ironrdp_cliprdr::backend::CliprdrBackendFactory for X11CliprdrServerFactory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        let backend = X11CliprdrBackend::new(
            std::env::var("DISPLAY").unwrap_or_default(),
            std::env::var("XAUTHORITY").unwrap_or_default(),
        );
        *backend.proxy.lock().expect("poisoned") = Some(Box::new(ServerEventClipboardProxy {
            sender: Arc::clone(&self.sender),
        }));
        Box::new(backend)
    }
}

impl ironrdp_server::CliprdrServerFactory for X11CliprdrServerFactory {}

#[cfg(test)]
mod tests {
    #[test]
    fn poller_does_not_restore_the_screen_captured_before_binding() {
        const CHILD: &str = "LINRDP_TEST_POLLER_BINDING";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "clipboard::tests::poller_does_not_restore_the_screen_captured_before_binding", "--nocapture"])
                .env(CHILD, "1")
                .output().unwrap();
            assert!(result.status.success(), "{} {}",
                String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
            return;
        }
        use std::io::{BufRead as _, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        fn server() -> (Server, u16) {
            let mut child = Command::new("Xvfb").args(["-displayfd", "1", "-screen", "0", "800x600x24", "-nolisten", "tcp", "-ac"])
                .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("Xvfb is required for this regression");
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
            (Server(child), line.trim().parse().unwrap())
        }
        let (_first, first) = server();
        let (_second, second) = server();
        let runtime = std::env::temp_dir().join(format!("linrdp-poller-test-{}", std::process::id()));
        std::fs::create_dir(&runtime).unwrap();
        let owner = crate::session::privilege::lookup_user(&current_account()).unwrap();
        let cookie1 = crate::session::xauth::write_cookie(runtime.to_str().unwrap(), first, &owner).unwrap();
        let cookie2 = crate::session::xauth::write_cookie(runtime.to_str().unwrap(), second, &owner).unwrap();
        let (mut backend, proxy) = backend_with_proxy();
        backend.display = format!(":{second}"); // stale construction snapshot
        crate::session::gate::arm();
        crate::session::gate::bind_greeter(first, cookie1.to_str().unwrap(), runtime.to_str().unwrap(), (800, 600)).unwrap();
        set_x11_text_selection(&format!(":{first}"), "first-screen");
        std::thread::sleep(Duration::from_millis(100));
        backend.on_ready();
        proxy.0.lock().unwrap().clear();
        let wait_copy = || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                if proxy.0.lock().unwrap().iter().any(|(kind, _)| *kind == "copy") { break; }
                assert!(std::time::Instant::now() < deadline, "poller did not advertise the current screen");
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        wait_copy();
        assert_eq!(backend.read_x11_text().as_deref(), Some("first-screen"));
        proxy.0.lock().unwrap().clear();
        crate::session::gate::bind(&current_account(), second, cookie2.to_str().unwrap(), runtime.to_str().unwrap(), (800, 600)).unwrap();
        set_x11_text_selection(&format!(":{second}"), "second-screen");
        wait_copy();
        assert_eq!(backend.read_x11_text().as_deref(), Some("second-screen"));
        // A request paused before handover must not restore its old environment.
        assert_eq!(x11_get_text(&format!(":{first}"), cookie1.to_str().unwrap()).as_deref(), Some("first-screen"));
        assert_eq!(std::env::var("DISPLAY").unwrap(), format!(":{second}"));
        assert_eq!(std::env::var("XAUTHORITY").unwrap(), cookie2.to_str().unwrap());
        // arboard's owner uses INCR for large selections; preserve that support
        // when reading through our explicit X connection instead of arboard.
        let mut board = arboard::Clipboard::new().unwrap();
        let large = "long-text-".repeat(100_000);
        board.set_text(large.clone()).unwrap();
        assert_eq!(x11_get_text(&format!(":{second}"), cookie2.to_str().unwrap()).as_deref(), Some(large.as_str()));
        POLLER_GENERATION.fetch_add(1, Ordering::Relaxed);
        backend.poller_thread.take().unwrap().join().expect("poller must not panic");
        std::fs::remove_dir_all(runtime).unwrap();
    }

    #[test]
    fn pasted_directories_keep_their_structure_and_empty_roots() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (mut backend, _proxy) = backend_with_proxy();
        let owner = current_account();
        crate::session::gate::set_console_user(&owner);
        *backend.files.lock().unwrap() = Some(SessionFiles {
            owner,
            agent: crate::session::fileagent::FileAgent::in_process_for_test().unwrap(),
        });
        let directory = |name: &str| FileDescriptor::new(name).with_attributes(ClipboardFileAttributes::DIRECTORY);
        backend.on_remote_file_list(&[
            directory("empty"), directory("A"), directory("sub").with_relative_path("A"),
            FileDescriptor::new("same.txt").with_relative_path("A/sub").with_file_size(0),
            directory("B"), FileDescriptor::new("same.txt").with_relative_path("B").with_file_size(0),
            FileDescriptor::new("single.txt").with_file_size(0),
        ], None);
        let published = backend.echo_guard.lock().unwrap().clone().expect("published roots");
        let roots = parse_uri_list(&published);
        assert_eq!(roots.iter().map(|p| p.file_name().unwrap().to_str().unwrap()).collect::<Vec<_>>(),
            ["empty", "A", "B", "single.txt"]);
        assert!(roots[0].is_dir());
        assert!(roots[1].join("sub/same.txt").is_file());
        assert!(roots[2].join("same.txt").is_file());
        let session_root = roots[0].parent().unwrap().parent().unwrap().to_path_buf();
        backend.on_remote_file_list(&[
            directory("failed"),
            FileDescriptor::new("missing.txt").with_relative_path("failed").with_file_size(4),
            FileDescriptor::new("independent.txt").with_file_size(0),
        ], None);
        let stream = backend.download.as_ref().unwrap().stream_id;
        backend.on_file_contents_response(FileContentsResponse::new_error(stream));
        let published = backend.echo_guard.lock().unwrap().clone().unwrap();
        let survivors = parse_uri_list(&published);
        assert_eq!(survivors.len(), 1, "failed folder must not be advertised as complete");
        assert_eq!(survivors[0].file_name().unwrap(), "independent.txt");
        std::fs::remove_dir_all(session_root).unwrap();
        crate::session::gate::clear_console_user_for_test();
    }

    /// The client addresses offered files by their position in the list it was
    /// sent. Keying the map on the position in the *selection* meant that one
    /// skipped entry desynchronised everything after it.
    ///
    /// Regression: for a selection of `[directory, a.txt, b.txt]` the client
    /// saw 0 = a and 1 = b while the backend held 1 = a and 2 = b. Request 0
    /// was refused, and request 1 returned a's contents as b.
    #[test]
    fn offered_files_are_keyed_by_the_index_the_client_will_ask_for() {
        // Walking a selection where the first entry is skipped, then one in
        // the middle: what the map must end up holding is 0, 1, 2 with no gaps.
        let mut offered: Vec<i32> = Vec::new();
        let selection = ["dir", "a.txt", "gone", "b.txt", "c.txt"];
        let mut advertised = 0usize;
        for entry in selection {
            if entry == "dir" || entry == "gone" {
                continue; // stat said not a file, or it vanished mid-copy
            }
            offered.push(advertised_index(advertised));
            advertised += 1;
        }
        assert_eq!(
            offered,
            vec![0, 1, 2],
            "three files were advertised, so the client asks for 0, 1 and 2"
        );
        assert_eq!(advertised, 3);
    }

    /// A RANGE request is remote input, and it used to size an allocation on
    /// its own word.
    ///
    /// Regression: `vec![0u8; request.requested_size as usize]` with no
    /// ceiling. A client that offered a large file and then asked for one
    /// `u32::MAX` chunk made the worker try to allocate four gigabytes for a
    /// single response — enough to take the session, and the host's memory,
    /// down. MAX_FILE_SIZE and MAX_TOTAL_SIZE never applied here: they bound
    /// what we download from a client, not what we serve to one.
    #[test]
    fn a_range_request_cannot_ask_for_more_than_one_chunk() {
        let huge = 8 * 1024 * 1024 * 1024u64;
        assert_eq!(
            range_response_len(huge, 0, u32::MAX),
            MAX_RANGE_RESPONSE as usize,
            "the chunk ceiling is what bounds the allocation, not the client"
        );
        assert_eq!(
            range_response_len(huge, 0, 4096),
            4096,
            "a modest request is still served in full"
        );
    }

    /// Past the end of what was offered there is nothing to send, and nothing
    /// to allocate.
    #[test]
    fn a_range_past_the_end_of_the_file_yields_nothing() {
        assert_eq!(range_response_len(1000, 1000, u32::MAX), 0);
        assert_eq!(range_response_len(1000, 5000, 4096), 0, "an offset beyond the file");
        assert_eq!(
            range_response_len(1000, 900, u32::MAX),
            100,
            "only what is actually left of the file"
        );
    }

    use super::*;
    use ironrdp_cliprdr::pdu::ClipboardFormatName;

    /// Records the ClipboardMessages the backend emits (discriminant + id),
    /// plus the payload of the last SendFormatData (text serving).
    #[derive(Debug)]
    struct CapturingProxy(Mutex<Vec<(&'static str, u32)>>, Mutex<Option<Vec<u8>>>);

    impl ClipboardMessageProxy for CapturingProxy {
        fn send_clipboard_message(&self, message: ClipboardMessage) {
            let entry = match &message {
                ClipboardMessage::SendInitiatePaste(id) => ("paste", id.0),
                ClipboardMessage::SendInitiateCopy(_) => ("copy", 0),
                ClipboardMessage::SendFormatData(data) => {
                    *self.1.lock().expect("poisoned") = Some(data.data().to_vec());
                    ("data", 0)
                }
                ClipboardMessage::SendFileContentsRequest(request) => ("freq", request.stream_id),
                ClipboardMessage::SendFileContentsResponse(_) => ("fresp", 0),
                ClipboardMessage::SendInitiateFileCopy(_) => ("fcopy", 0),
                ClipboardMessage::Error(_) => ("error", 0),
            };
            self.0.lock().expect("poisoned").push(entry);
        }
    }

    #[derive(Debug)]
    struct CapturingProxyHandle(Arc<CapturingProxy>);

    impl ClipboardMessageProxy for CapturingProxyHandle {
        fn send_clipboard_message(&self, message: ClipboardMessage) {
            self.0.send_clipboard_message(message);
        }
    }

    fn backend_with_proxy() -> (X11CliprdrBackend, Arc<CapturingProxy>) {
        let proxy = Arc::new(CapturingProxy(
            Mutex::new(Vec::new()),
            Mutex::new(None),
        ));
        let backend = X11CliprdrBackend::new(String::new(), String::new());
        *backend.proxy.lock().expect("poisoned") =
            Some(Box::new(CapturingProxyHandle(Arc::clone(&proxy))));
        (backend, proxy)
    }

    #[test]
    fn image_copy_fetches_png_then_dib_and_publishes() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (mut backend, proxy) = backend_with_proxy();
        let png_id = ClipboardFormatId(0xC00B);
        let formats = vec![
            ClipboardFormat::new(CF_UNICODETEXT),
            ClipboardFormat::new(CF_DIB),
            ClipboardFormat::new(png_id).with_name(ClipboardFormatName::new_static("PNG")),
        ];
        backend.on_remote_copy(&formats);
        assert_eq!(*proxy.0.lock().expect("poisoned"), vec![("paste", 0xC00B)]);

        let png = [0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A].to_vec();
        backend.on_format_data_response(FormatDataResponse::new_data(png));
        // PNG alone is not published yet: the DIB follow-up comes first.
        assert_eq!(
            *proxy.0.lock().expect("poisoned"),
            vec![("paste", 0xC00B), ("paste", CF_DIB.0)]
        );

        // Minimal valid DIB: 1×1 px, 24 bpp BI_RGB (row padded to 4 bytes).
        let mut dib = vec![0u8; 40 + 4];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&1i32.to_le_bytes());
        dib[8..12].copy_from_slice(&1i32.to_le_bytes());
        dib[12..14].copy_from_slice(&1u16.to_le_bytes());
        dib[14..16].copy_from_slice(&24u16.to_le_bytes());
        backend.on_format_data_response(FormatDataResponse::new_data(dib));

        assert!(backend.image_fetch.is_none(), "image fetch must complete");
        assert_eq!(proxy.0.lock().expect("poisoned").len(), 2, "no further messages");

        // The published selection owner runs on $DISPLAY in the background;
        // let it take over before the lock releases and the next X11 test
        // claims the same selection.
        std::thread::sleep(Duration::from_millis(500));
    }

    #[test]
    fn malformed_png_still_serves_bmp() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (mut backend, proxy) = backend_with_proxy();
        let formats = vec![
            ClipboardFormat::new(CF_DIB),
            ClipboardFormat::new(ClipboardFormatId(0xC00B)).with_name(ClipboardFormatName::new_static("PNG")),
        ];
        backend.on_remote_copy(&formats);
        // PNG request first…
        backend.on_format_data_response(FormatDataResponse::new_data(vec![0, 1, 2, 3]));
        // …but the payload is not a PNG → only the DIB follow-up is requested.
        assert_eq!(*proxy.0.lock().expect("poisoned"), vec![("paste", 0xC00B), ("paste", CF_DIB.0)]);
    }

    #[test]
    fn text_copy_decodes_utf16_and_sets_echo_guard() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (mut backend, proxy) = backend_with_proxy();
        backend.on_remote_copy(&[ClipboardFormat::new(CF_UNICODETEXT)]);
        assert_eq!(*proxy.0.lock().expect("poisoned"), vec![("paste", CF_UNICODETEXT.0)]);

        let mut data: Vec<u8> = "cześć".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        data.extend_from_slice(&[0, 0]); // CF_UNICODETEXT is NUL-terminated
        backend.on_format_data_response(FormatDataResponse::new_data(data));

        assert_eq!(
            backend.echo_guard.lock().expect("poisoned").as_deref(),
            Some("cześć"),
            "UTF-16LE must be decoded and the echo guard primed"
        );

        // Same as above: the spawned owner must settle inside the lock.
        std::thread::sleep(Duration::from_millis(500));
    }

    #[test]
    fn stale_generation_response_is_dropped() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (mut backend, proxy) = backend_with_proxy();
        backend.on_remote_copy(&[ClipboardFormat::new(CF_UNICODETEXT)]);
        // A new copy arrives before the response to the first request.
        backend.on_remote_copy(&[ClipboardFormat::new(CF_DIB)]);
        let mut data: Vec<u8> = "stale".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        data.extend_from_slice(&[0, 0]);
        backend.on_format_data_response(FormatDataResponse::new_data(data));
        assert_ne!(
            backend.echo_guard.lock().expect("poisoned").as_deref(),
            Some("stale"),
            "response from an older copy generation must not be published"
        );
        assert_eq!(proxy.0.lock().expect("poisoned").len(), 2);
    }

    #[test]
    fn file_download_streams_to_disk() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (mut backend, proxy) = backend_with_proxy();
        // Every pasted file is created by the session's own file helper now,
        // so a backend without one has nowhere to put them — which is the
        // point: the worker is root and must not create them itself.
        let owner = current_account();
        crate::session::gate::set_console_user(&owner);
        *backend.files.lock().expect("poisoned") = Some(SessionFiles {
            owner,
            agent: crate::session::fileagent::FileAgent::in_process_for_test().expect("helper"),
        });
        // The directory the transfer below will land in is the one the
        // backend's own helper hands out next.

        let files = vec![
            FileDescriptor::new("small.bin").with_file_size(10),
            FileDescriptor::new("sized-by-query.bin"),
        ];
        backend.on_remote_file_list(&files, None);

        // 1st request: RANGE for the first file (size known from descriptor).
        let first = *proxy.0.lock().expect("poisoned").first().expect("range request");
        assert_eq!(first.0, "freq");
        backend.on_file_contents_response(FileContentsResponse::new_data_response(first.1, vec![7u8; 10]));

        // 2nd request: SIZE query for the second file.
        let second = *proxy.0.lock().expect("poisoned").get(1).expect("size query");
        assert_eq!(second.0, "freq");
        backend.on_file_contents_response(FileContentsResponse::new_data_response(
            second.1,
            1234u64.to_le_bytes().to_vec(),
        ));

        // 3rd request: RANGE for the now-sized second file.
        let third = *proxy.0.lock().expect("poisoned").get(2).expect("range request");
        assert_eq!(third.0, "freq");
        backend.on_file_contents_response(FileContentsResponse::new_data_response(third.1, vec![9u8; 1234]));

        assert!(backend.download.is_none(), "download must finish");
        assert!(
            backend.echo_guard.lock().expect("poisoned").is_some(),
            "uri-list must be published (echo guard primed)"
        );
        // Where the files actually went, taken from the URIs the desktop was
        // offered rather than guessed at from the temp directory.
        let finished = Arc::new(Mutex::new(
            backend
                .echo_guard
                .lock()
                .expect("poisoned")
                .as_deref()
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.strip_prefix("file://"))
                .map(|uri| PathBuf::from(uri.replace("%20", " ")))
                .collect::<Vec<_>>(),
        ));

        // Both files must exist with the served contents, inside this
        // transfer's own directory and nowhere else.
        let done = finished.lock().expect("poisoned").clone();
        assert_eq!(done.len(), 2, "both files finished");
        let transfer_dir = done[0].parent().expect("a transfer directory").to_path_buf();
        assert_eq!(
            std::fs::read(transfer_dir.join("small.bin")).expect("small.bin"),
            vec![7u8; 10]
        );
        assert_eq!(
            std::fs::read(transfer_dir.join("sized-by-query.bin"))
                .expect("sized-by-query.bin")
                .len(),
            1234
        );
        let session_root = transfer_dir.parent().expect("session root");
        let _ = std::fs::remove_dir_all(session_root);
        crate::session::gate::clear_console_user_for_test();
    }

    /// Without a file helper there is nobody to write as, and the worker is
    /// root — so a paste is refused rather than performed with root's
    /// credentials in a directory every session shared.
    #[test]
    fn a_paste_without_a_file_helper_is_refused() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::session::gate::clear_console_user_for_test();
        let (mut backend, proxy) = backend_with_proxy();
        backend.on_remote_file_list(&[FileDescriptor::new("loot.bin").with_file_size(10)], None);
        assert!(backend.download.is_none(), "nothing may be downloaded");
        assert!(
            proxy.0.lock().expect("poisoned").is_empty(),
            "not a single file contents request may be sent"
        );
    }

    /// The account these tests run as — the only one they can act for.
    fn current_account() -> String {
        // SAFETY: getpwuid's result is read into an owned value immediately.
        unsafe {
            let pw = libc::getpwuid(libc::getuid());
            assert!(!pw.is_null(), "this uid has an account");
            std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
        }
    }



    #[test]
    fn served_text_is_utf16le_with_crlf() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let display = std::env::var("DISPLAY").unwrap_or_default();
        if !display.contains(':') {
            eprintln!("skipping: no X11 display");
            return;
        }
        set_x11_text_selection(&display, "cześć\nlinie");
        std::thread::sleep(Duration::from_millis(400));

        let (mut backend, proxy) = backend_with_proxy();
        backend.on_format_data_request(FormatDataRequest { format: CF_UNICODETEXT });

        let sent = proxy.1.lock().expect("poisoned").clone().expect("format data sent");
        // Round-trip: Windows decodes these bytes as UTF-16LE, CRLF, NUL-terminated.
        let decoded = read_utf16_string(&sent, None).expect("valid UTF-16LE");
        assert_eq!(decoded, "cześć\r\nlinie");
        assert!(sent.ends_with(&[0, 0]), "must be NUL-terminated");
    }

    #[test]
    fn text_to_utf16_crlf_encodes_ascii_pairs() {
        assert_eq!(text_to_utf16_crlf("hi"), vec![0x68, 0x00, 0x69, 0x00, 0x00, 0x00]);
        assert_eq!(
            text_to_utf16_crlf("a\nb"),
            vec![0x61, 0x00, 0x0D, 0x00, 0x0A, 0x00, 0x62, 0x00, 0x00, 0x00]
        );
        // Blank lines must survive, and an existing CRLF must not double.
        assert_eq!(text_to_crlf("a\n\nb"), "a\r\n\r\nb");
        assert_eq!(text_to_crlf("a\r\nb"), "a\r\nb");
    }

    #[test]
    fn text_selection_is_readable_on_an_explicit_connection() {
        let _guard = crate::x11_selection::X11_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let display = std::env::var("DISPLAY").unwrap_or_default();
        if !display.contains(':') {
            eprintln!("skipping: no X11 display");
            return;
        }
        set_x11_text_selection(&display, "hello from linrdp test");
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(x11_get_text(&display, "").as_deref(), Some("hello from linrdp test"));
    }


    #[test]
    fn dib_to_bmp_prepends_file_header() {
        // 2×2 px, 24 bpp BI_RGB: 40-byte header + rows padded to 4 bytes
        // (2 px × 3 B = 6 → 8 B/row).
        let mut dib = vec![0u8; 40 + 2 * 8];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&2i32.to_le_bytes());
        dib[8..12].copy_from_slice(&2i32.to_le_bytes());
        dib[12..14].copy_from_slice(&1u16.to_le_bytes()); // planes
        dib[14..16].copy_from_slice(&24u16.to_le_bytes()); // bpp
        dib[16..20].copy_from_slice(&0u32.to_le_bytes()); // BI_RGB

        let bmp = dib_to_bmp(&dib).expect("valid DIB");
        assert_eq!(&bmp[0..2], b"BM");
        let file_len = u32::from_le_bytes(bmp[2..6].try_into().unwrap()) as usize;
        assert_eq!(file_len, bmp.len());
        assert_eq!(file_len, dib.len() + 14);
        let offset = u32::from_le_bytes(bmp[10..14].try_into().unwrap()) as usize;
        assert_eq!(offset, 14 + 40); // header + no palette/masks
        assert_eq!(&bmp[14..], &dib[..]);
    }

    #[test]
    fn dib_to_bmp_counts_bitfield_masks_and_palette() {
        // 32 bpp BI_BITFIELDS with a 40-byte header: 3 mask DWORDs follow it,
        // then 2×2 px × 4 B of pixels.
        let mut dib = vec![0u8; 40 + 12 + 16];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[14..16].copy_from_slice(&32u16.to_le_bytes());
        dib[16..20].copy_from_slice(&3u32.to_le_bytes()); // BI_BITFIELDS

        let bmp = dib_to_bmp(&dib).expect("valid DIB");
        let offset = u32::from_le_bytes(bmp[10..14].try_into().unwrap()) as usize;
        assert_eq!(offset, 14 + 40 + 12);
    }

    #[test]
    fn dib_to_bmp_rejects_garbage() {
        assert!(dib_to_bmp(&[]).is_none());
        assert!(dib_to_bmp(&[0u8; 8]).is_none());
        let mut truncated = vec![0u8; 40];
        truncated[0..4].copy_from_slice(&200u32.to_le_bytes()); // header > payload
        assert!(dib_to_bmp(&truncated).is_none());
    }

    /// 2×2 px 24 bpp BI_RGB DIB with four distinct, known colors.
    fn dib_2x2_bgr() -> Vec<u8> {
        let mut dib = vec![0u8; 40 + 2 * 8]; // rows padded to 8 bytes
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&2i32.to_le_bytes());
        dib[8..12].copy_from_slice(&2i32.to_le_bytes()); // positive height = bottom-up
        dib[12..14].copy_from_slice(&1u16.to_le_bytes());
        dib[14..16].copy_from_slice(&24u16.to_le_bytes());
        dib[16..20].copy_from_slice(&0u32.to_le_bytes());
        // Bottom-up: first stored row is the BOTTOM (red,green), second is the
        // TOP (blue,white). BGR byte order, rows padded from 6 to 8 bytes.
        dib[40..46].copy_from_slice(&[0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00]); // red, green
        dib[48..54].copy_from_slice(&[0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF]); // blue, white
        dib
    }

    #[test]
    fn decode_dib_flips_rows_and_orders_rgb() {
        let (width, height, rgb) = decode_dib(&dib_2x2_bgr()).expect("decodable DIB");
        assert_eq!((width, height), (2, 2));
        // Top-down RGB order: blue, white, red, green.
        assert_eq!(
            rgb,
            vec![
                0x00, 0x00, 0xFF, // blue
                0xFF, 0xFF, 0xFF, // white
                0xFF, 0x00, 0x00, // red
                0x00, 0xFF, 0x00, // green
            ]
        );
    }

    #[test]
    fn decode_dib_handles_topdown_bitfields() {
        // 1×2 px, 32 bpp BI_BITFIELDS, negative height (top-down),
        // non-standard masks (BGRW-ish shifted by 4 bits).
        let mut dib = vec![0u8; 40 + 12 + 8];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&1i32.to_le_bytes());
        dib[8..12].copy_from_slice(&(-2i32).to_le_bytes());
        dib[12..14].copy_from_slice(&1u16.to_le_bytes());
        dib[14..16].copy_from_slice(&32u16.to_le_bytes());
        dib[16..20].copy_from_slice(&3u32.to_le_bytes()); // BI_BITFIELDS
        dib[40..44].copy_from_slice(&0x00FF_0000u32.to_le_bytes());
        dib[44..48].copy_from_slice(&0x0000_FF00u32.to_le_bytes());
        dib[48..52].copy_from_slice(&0x0000_00FFu32.to_le_bytes());
        // First pixel full-range, second mid-range (mask value 0x7F → ~127).
        dib[52..56].copy_from_slice(&0x00FF_FF7Fu32.to_le_bytes());
        dib[56..60].copy_from_slice(&0x0000_7F00u32.to_le_bytes());

        let (width, height, rgb) = decode_dib(&dib).expect("decodable DIB");
        assert_eq!((width, height), (1, 2));
        assert_eq!(rgb, vec![0xFF, 0xFF, 0x7F, 0x00, 0x7F, 0x00]);
    }

    #[test]
    fn dib_to_png_round_trips() {
        let (width, height, rgb) = decode_dib(&dib_2x2_bgr()).expect("decodable DIB");
        let png_bytes = rgb_to_png(width, height, &rgb).expect("encodable PNG");
        assert!(png_bytes.starts_with(&[0x89, b'P', b'N', b'G']));

        let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
        let mut reader = decoder.read_info().expect("PNG info");
        assert_eq!((reader.info().width, reader.info().height), (2, 2));
        let mut buf = vec![0u8; reader.output_buffer_size().expect("PNG size known")];
        let info = reader.next_frame(&mut buf).expect("PNG pixels");
        assert_eq!(info.color_type, png::ColorType::Rgb);
        assert_eq!(&buf[..rgb.len()], &rgb[..]);
    }

    #[test]
    fn path_to_uri_encodes_unsafe_bytes() {
        assert_eq!(path_to_uri(Path::new("/tmp/a b.txt")), "file:///tmp/a%20b.txt");
        assert_eq!(path_to_uri(Path::new("/tmp/linrdp-paste-1/żółć.png")), "file:///tmp/linrdp-paste-1/%C5%BC%C3%B3%C5%82%C4%87.png");
    }

    /// A descriptor from the client names where a pasted file goes, and what
    /// comes out of this must stay a *relative* path — the absolute one is the
    /// file helper's to resolve, under its own directory descriptor.
    #[test]
    fn a_remote_descriptor_yields_a_relative_path_with_no_way_out() {
        assert_eq!(
            safe_relative(Some("sub\\dir"), "file.txt"),
            Some(PathBuf::from("sub/dir/file.txt"))
        );
        assert_eq!(
            safe_relative(Some("..\\..\\etc"), "passwd"),
            Some(PathBuf::from("etc/passwd")),
            "`..` components are dropped, never followed"
        );
        assert_eq!(safe_relative(None, ""), None);
        assert_eq!(safe_relative(None, "a/b"), None, "a separator in the name is malformed");

        let relative = safe_relative(Some("a\\b"), "c.txt").expect("a name");
        assert!(relative.is_relative(), "an absolute path would be resolved by the wrong process");
        assert!(
            relative.components().all(|c| matches!(c, std::path::Component::Normal(_))),
            "only plain names survive: {}",
            relative.display()
        );
    }

    #[test]
    fn utf16_decoding_stops_at_nul() {
        let mut data = "hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
        data.extend_from_slice(&[0, 0, 0x41, 0]);
        assert_eq!(decode_utf16_lossy(&data), "hi");
    }
}
