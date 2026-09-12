//! Real clipboard synchronization: X11 ↔ RDP (MS-RDPECLIP), server side.
//!
//! Linux → Windows (we advertise, client pulls):
//! - Text: X11 clipboard text (read via `arboard`) ↔ CF_UNICODETEXT.
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

/// Read the X11 clipboard text (arboard needs DISPLAY set and is not Sync).
pub(crate) fn x11_get_text(display: &str, xauthority: &str) -> Option<String> {
    // SAFETY: arboard reads these only during its constructor/getters, and
    // every other access in this module writes the same captured values.
    if !display.is_empty() {
        unsafe { std::env::set_var("DISPLAY", display) };
    }
    if !xauthority.is_empty() {
        unsafe { std::env::set_var("XAUTHORITY", xauthority) };
    }
    let mut board = arboard::Clipboard::new().ok()?;
    board.get_text().ok().filter(|t| !t.is_empty())
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
    path: PathBuf,
    size: Option<u64>,
}

#[derive(Debug)]
enum CurrentDownload {
    /// The descriptor carried no size; a SIZE request is outstanding.
    SizeQuery { index: i32, path: PathBuf },
    /// RANGE requests are streaming into `file`.
    Ranges {
        file: std::fs::File,
        index: i32,
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
    /// Files not yet started.
    pending: VecDeque<DownloadTarget>,
    current: Option<CurrentDownload>,
    done: Vec<PathBuf>,
    /// Bytes still allowed for the rest of the list.
    total_budget: u64,
}

impl Download {
    fn alloc_stream_id(&mut self) -> u32 {
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        self.next_stream_id
    }

    /// Drop the file being downloaded (if any), removing the partial result.
    fn skip_current(&mut self) {
        if let Some(CurrentDownload::Ranges { path, .. }) = self.current.take() {
            let _ = std::fs::remove_file(path);
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
                        path: next.path,
                    });
                }
                Some(0) => {
                    if let Err(e) = std::fs::File::create(&next.path) {
                        tracing::warn!(path = %next.path.display(), %e, "clipboard: cannot create pasted file");
                        continue;
                    }
                    self.done.push(next.path);
                }
                Some(size) if size > MAX_FILE_SIZE || size > self.total_budget => {
                    tracing::warn!(size, path = %next.path.display(), "clipboard: skipping oversized file");
                    continue;
                }
                Some(size) => match std::fs::File::create(&next.path) {
                    Ok(file) => {
                        self.total_budget -= size;
                        self.stream_id = self.alloc_stream_id();
                        self.current = Some(CurrentDownload::Ranges {
                            file,
                            index: next.index,
                            path: next.path,
                            remaining: size,
                            offset: 0,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(path = %next.path.display(), %e, "clipboard: cannot create pasted file");
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

/// Build `dest_dir/relative_dir/name`, keeping the result inside `dest_dir`.
/// (The cliprdr core sanitizes descriptors too; this is belt and braces.)
fn safe_join(dest_dir: &Path, relative_dir: Option<&str>, name: &str) -> Option<PathBuf> {
    let name = name.trim();
    if name.is_empty() || name.contains(['/', '\\']) {
        return None;
    }
    let mut path = dest_dir.to_path_buf();
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
    // BI_BITFIELDS with a 40-byte header carries its color masks after the
    // header (3 DWORDs; 32-bpp images often carry a 4th alpha mask).
    let masks = if compression == 3 && header_size == 40 {
        if bpp == 32 { 16 } else { 12 }
    } else {
        0
    };

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

/// Decode CF_UNICODETEXT payload with lone surrogates replaced instead of
/// failing the whole paste.
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
}

impl X11CliprdrBackend {
    pub(crate) fn new(display: String, xauthority: String) -> Self {
        Self {
            proxy: Arc::new(Mutex::new(None)),
            display,
            xauthority,
            incoming: None,
            incoming_gen: 0,
            copy_generation: 0,
            image_fetch: None,
            outgoing_files: Arc::new(Mutex::new(HashMap::new())),
            files_advertised: Arc::new(Mutex::new(false)),
            echo_guard: Arc::new(Mutex::new(None)),
            download: None,
        }
    }

    /// Read the current X11 clipboard text (best-effort).
    fn read_x11_text(&self) -> Option<String> {
        x11_get_text(&self.display, &self.xauthority)
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
        x11_selection::take_ownership(self.display.clone(), fetch.targets);
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
        if download.done.is_empty() {
            return;
        }
        let uris: Vec<String> = download.done.iter().map(|path| path_to_uri(path)).collect();
        let uri_list = uris.join("\r\n").into_bytes();
        let gnome_copied = format!("copy\n{}", uris.join("\n")).into_bytes();
        x11_selection::take_ownership(
            self.display.clone(),
            vec![
                ("x-special/gnome-copied-files".to_owned(), gnome_copied),
                ("text/uri-list".to_owned(), uri_list),
            ],
        );
    }

    /// Delete paste leftovers older than a day (best-effort).
    fn clean_stale_paste_dirs(&self) {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(24 * 60 * 60);
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.starts_with("linrdp-paste-") {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .map(|modified| modified < cutoff)
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
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
        self.clean_stale_paste_dirs();

        // Poll the X11 clipboard for local copies (Linux → Windows). A poller
        // is used instead of X11 selection events because arboard owns no
        // window here; the echo guard keeps remote-sourced data from being
        // advertised straight back.
        let proxy = Arc::clone(&self.proxy);
        let outgoing_files = Arc::clone(&self.outgoing_files);
        let files_advertised = Arc::clone(&self.files_advertised);
        let echo_guard = Arc::clone(&self.echo_guard);
        let display = self.display.clone();
        let xauthority = self.xauthority.clone();
        let generation = POLLER_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;

        let spawned = std::thread::Builder::new()
            .name("linrdp-cliprdr-poll".into())
            .spawn(move || {
                // SAFETY: same constants every time; other threads using
                // arboard set identical values before any access.
                if !display.is_empty() {
                    unsafe { std::env::set_var("DISPLAY", &display) };
                }
                if !xauthority.is_empty() {
                    unsafe { std::env::set_var("XAUTHORITY", &xauthority) };
                }
                let mut last_text: Option<String> = None;
                let mut last_files: Option<String> = None;
                loop {
                    std::thread::sleep(Duration::from_millis(700));
                    if POLLER_GENERATION.load(Ordering::Relaxed) != generation {
                        tracing::debug!("clipboard: stale poller exiting");
                        break;
                    }
                    let Ok(mut board) = arboard::Clipboard::new() else { continue };
                    let Ok(text) = board.get_text() else { continue };

                    let guard = echo_guard.lock().expect("poisoned").take();
                    if guard.as_deref() == Some(text.as_str()) {
                        // Text we ourselves published from client data.
                        last_text = Some(text);
                        continue;
                    }

                    if text.contains("file://") {
                        if last_files.as_deref() == Some(text.as_str()) {
                            continue;
                        }
                        last_files = Some(text.clone());
                        last_text = Some(text.clone());

                        let paths = parse_uri_list(&text);
                        let mut descriptors = Vec::new();
                        let mut offered: HashMap<i32, OfferedFile> = HashMap::new();
                        for (i, path) in paths.iter().enumerate() {
                            let Ok(meta) = std::fs::metadata(path) else { continue };
                            if !meta.is_file() {
                                continue;
                            }
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| format!("file{i}"));
                            descriptors.push(
                                FileDescriptor::new(name.clone())
                                    .with_file_size(meta.len())
                                    .with_attributes(ClipboardFileAttributes::ARCHIVE),
                            );
                            offered.insert(
                                i as i32,
                                OfferedFile {
                                    size: meta.len(),
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
                    } else if !text.is_empty() && last_text.as_deref() != Some(text.as_str()) {
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
        if spawned.is_err() {
            tracing::warn!("clipboard: failed to spawn X11 poller thread");
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
                self.send_msg(ClipboardMessage::SendInitiatePaste(png.id));
            }
            (None, Some(dib)) => {
                tracing::info!(format = ?dib, "clipboard: client copied image (DIB) — fetching");
                self.image_fetch = Some(ImageFetch {
                    targets: Vec::new(),
                    dib_followup: None,
                });
                self.incoming = Some(IncomingKind::Dib);
                self.incoming_gen = self.copy_generation;
                self.send_msg(ClipboardMessage::SendInitiatePaste(dib));
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
            match self.read_x11_text() {
                Some(text) => FormatDataResponse::new_data(text_to_crlf(&text).into_bytes()).into_owned(),
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
                set_x11_text_selection(&self.display, &text);
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
                    match dib_to_bmp(data) {
                        Some(bmp) => {
                            if let Some(fetch) = self.image_fetch.as_mut() {
                                fetch.targets.push(("image/bmp".to_owned(), bmp));
                            }
                        }
                        None => tracing::warn!("clipboard: client sent malformed CF_DIB data"),
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
            Some(file) => read_file_range(file, &request),
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
                Some(CurrentDownload::SizeQuery { index, path }) => {
                    let path = path.clone();
                    match response.data_as_size().ok() {
                        Some(0) => {
                            if std::fs::File::create(&path).is_ok() {
                                download.done.push(path);
                            }
                            download.current = None;
                        }
                        Some(size) if size <= MAX_FILE_SIZE && size <= download.total_budget => {
                            match std::fs::File::create(&path) {
                                Ok(file) => {
                                    download.total_budget -= size;
                                    download.current = Some(CurrentDownload::Ranges {
                                        file,
                                        index: *index,
                                        path,
                                        remaining: size,
                                        offset: 0,
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(path = %path.display(), %e, "clipboard: cannot create pasted file");
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
        static PASTE_SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = PASTE_SEQ.fetch_add(1, Ordering::Relaxed);
        let dest_dir = std::env::temp_dir().join(format!("linrdp-paste-{seq}"));
        if let Err(e) = std::fs::create_dir_all(&dest_dir) {
            tracing::warn!(dir = %dest_dir.display(), %e, "clipboard: cannot create paste directory");
            return;
        }

        let mut pending = VecDeque::new();
        for (i, file) in files.iter().enumerate() {
            let is_dir = file
                .attributes
                .is_some_and(|attributes| attributes.contains(ClipboardFileAttributes::DIRECTORY));
            let Some(path) = safe_join(&dest_dir, file.relative_path.as_deref(), &file.name) else {
                tracing::warn!(name = %file.name, "clipboard: skipping file with unsafe name");
                continue;
            };
            if is_dir {
                let _ = std::fs::create_dir_all(&path);
                continue;
            }
            pending.push_back(DownloadTarget {
                index: i as i32,
                path,
                size: file.file_size,
            });
        }
        tracing::info!(dir = %dest_dir.display(), count = pending.len(), "clipboard: downloading pasted files");

        let mut download = Download {
            clip_data_id,
            stream_id: 0,
            next_stream_id: 1,
            dest_dir,
            pending,
            current: None,
            done: Vec::new(),
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

/// Serve a RANGE FileContentsRequest from a local file.
fn read_file_range(file: &OfferedFile, request: &FileContentsRequest) -> FileContentsResponse<'static> {
    use std::io::{Read, Seek};
    let Ok(mut f) = std::fs::File::open(&file.linux_path) else {
        return FileContentsResponse::new_error(request.stream_id);
    };
    if f.seek(std::io::SeekFrom::Start(request.position)).is_err() {
        return FileContentsResponse::new_error(request.stream_id);
    }
    let mut buf = vec![0u8; request.requested_size as usize];
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
            out.push_str("\r\n");
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
        } else if c == '\r' {
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
    use super::*;
    use ironrdp_cliprdr::pdu::ClipboardFormatName;

    /// Records the ClipboardMessages the backend emits (discriminant + id).
    #[derive(Debug)]
    struct CapturingProxy(Mutex<Vec<(&'static str, u32)>>);

    impl ClipboardMessageProxy for CapturingProxy {
        fn send_clipboard_message(&self, message: ClipboardMessage) {
            let entry = match &message {
                ClipboardMessage::SendInitiatePaste(id) => ("paste", id.0),
                ClipboardMessage::SendInitiateCopy(_) => ("copy", 0),
                ClipboardMessage::SendFormatData(_) => ("data", 0),
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
        let proxy = Arc::new(CapturingProxy(Mutex::new(Vec::new())));
        let mut backend = X11CliprdrBackend::new(String::new(), String::new());
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
    fn text_selection_is_readable_by_arboard() {
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
        // 32 bpp BI_BITFIELDS with a 40-byte header: 4 mask DWORDs follow it,
        // then 2×2 px × 4 B of pixels.
        let mut dib = vec![0u8; 40 + 16 + 16];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[14..16].copy_from_slice(&32u16.to_le_bytes());
        dib[16..20].copy_from_slice(&3u32.to_le_bytes()); // BI_BITFIELDS

        let bmp = dib_to_bmp(&dib).expect("valid DIB");
        let offset = u32::from_le_bytes(bmp[10..14].try_into().unwrap()) as usize;
        assert_eq!(offset, 14 + 40 + 16);
    }

    #[test]
    fn dib_to_bmp_rejects_garbage() {
        assert!(dib_to_bmp(&[]).is_none());
        assert!(dib_to_bmp(&[0u8; 8]).is_none());
        let mut truncated = vec![0u8; 40];
        truncated[0..4].copy_from_slice(&200u32.to_le_bytes()); // header > payload
        assert!(dib_to_bmp(&truncated).is_none());
    }

    #[test]
    fn path_to_uri_encodes_unsafe_bytes() {
        assert_eq!(path_to_uri(Path::new("/tmp/a b.txt")), "file:///tmp/a%20b.txt");
        assert_eq!(path_to_uri(Path::new("/tmp/linrdp-paste-1/żółć.png")), "file:///tmp/linrdp-paste-1/%C5%BC%C3%B3%C5%82%C4%87.png");
    }

    #[test]
    fn safe_join_stays_inside_dest_dir() {
        let dir = Path::new("/tmp/linrdp-paste-0");
        assert_eq!(
            safe_join(dir, Some("sub\\dir"), "file.txt"),
            Some(dir.join("sub/dir/file.txt"))
        );
        assert_eq!(safe_join(dir, Some("..\\..\\etc"), "passwd"), Some(dir.join("etc/passwd")));
        assert_eq!(safe_join(dir, None, ""), None);
        assert_eq!(safe_join(dir, None, "a/b"), None);
    }

    #[test]
    fn utf16_decoding_stops_at_nul() {
        let mut data = "hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
        data.extend_from_slice(&[0, 0, 0x41, 0]);
        assert_eq!(decode_utf16_lossy(&data), "hi");
    }
}
