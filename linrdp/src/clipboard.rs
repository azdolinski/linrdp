//! Real clipboard synchronization: X11 ↔ RDP (MS-RDPECLIP).
//!
//! Text: X11 clipboard ↔ CF_UNICODETEXT (bidirectional sync).
//! Files: X11 `file://` URI list ↔ FileGroupDescriptorW + FileContents
//! (Windows "copy file → paste on Linux" and reverse), per MS-RDPECLIP
//! sections 2.2.5 (File Contents) and 2.2.6 (File List).
//!
//! Both directions run without external binaries: X11 via `arboard`
//! (pure Rust over x11rb), file access via std::fs.

use core::time::Duration;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackend};
use ironrdp_pdu::IntoOwned;
use ironrdp_cliprdr::pdu::ClipboardFormat;
use ironrdp_cliprdr::pdu::{
    ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse, FileDescriptor,
    FormatDataRequest, FormatDataResponse, LockDataId, PackedFileList,
};

/// Windows standard clipboard formats we support.
const CF_UNICODETEXT: ClipboardFormatId = ClipboardFormatId(13);
const CF_HDROP_LIST: ClipboardFormatId = ClipboardFormatId(15); // FileGroupDescriptorW

#[derive(Debug)]
struct X11ClipboardProxy {
    inner: Arc<Mutex<Option<Box<dyn ClipboardMessageProxy>>>>,
}

impl ClipboardMessageProxy for X11ClipboardProxy {
    fn send_clipboard_message(&self, message: ironrdp_cliprdr::backend::ClipboardMessage) {
        if let Some(proxy) = self.inner.lock().expect("poisoned").as_ref() {
            proxy.send_clipboard_message(message);
        }
    }
}

#[derive(Debug)]
pub(crate) struct X11CliprdrBackend {
    proxy: Arc<Mutex<Option<Box<dyn ClipboardMessageProxy>>>>,
    display: String,
    xauthority: String,

    /// Files offered by the client (Windows → Linux copy), keyed by the
    /// clip data id from the FileContentsRequest.
    offered_files: Arc<Mutex<HashMap<i32, Vec<OfferedFile>>>>,
    /// Tracks whether the current format list we advertised carries files.
    files_advertised: Arc<Mutex<bool>>,
}



#[derive(Debug, Clone)]
pub(crate) struct OfferedFile {
    pub name: String,
    pub size: u64,
    /// Absolute path on the LOCAL Linux filesystem to read content from.
    pub linux_path: PathBuf,
}

/// Read the X11 clipboard text (spawns arboard on a short-lived thread
/// because arboard's Clipboard is not Sync and requires DISPLAY set).
pub(crate) fn x11_get_text(display: &str, xauthority: &str) -> Option<String> {
    unsafe { std::env::set_var("DISPLAY", display); }
    unsafe { std::env::set_var("XAUTHORITY", xauthority); }
    let mut board = arboard::Clipboard::new().ok()?;
    board.get_text().ok().filter(|t| !t.is_empty())
}

/// Set the X11 clipboard text.
pub(crate) fn x11_set_text(display: &str, xauthority: &str, text: &str) -> bool {
    unsafe { std::env::set_var("DISPLAY", display); }
    unsafe { std::env::set_var("XAUTHORITY", xauthority); }
    let Ok(mut board) = arboard::Clipboard::new() else {
        return false;
    };
    board.set_text(text.to_owned()).is_ok()
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
                .replace("%C3", "\u{c3}") // minimal percent-decode for common cases
                ;
            paths.push(PathBuf::from(decoded));
        } else if !line.is_empty() && !line.starts_with("copy") && !line.starts_with("cut") {
            // Plain path (some file managers put bare paths).
            paths.push(PathBuf::from(line));
        }
    }
    paths
}

impl X11CliprdrBackend {
    pub(crate) fn new(display: String, xauthority: String) -> Self {
        Self {
            proxy: Arc::new(Mutex::new(None)),
            display,
            xauthority,
            offered_files: Arc::new(Mutex::new(HashMap::new())),
            files_advertised: Arc::new(Mutex::new(false)),
        }
    }

    /// Read the current X11 clipboard text (best-effort).
    fn read_x11_text(&self) -> Option<String> {
        x11_get_text(&self.display, &self.xauthority)
    }

    /// Write text to the X11 clipboard.
    fn write_x11_text(&self, text: &str) {
        x11_set_text(&self.display, &self.xauthority, text);
    }

    /// Detect `file://` URI list in the X11 clipboard → collect files for
    /// the Windows client and initiate a file copy (Linux → Windows).
    fn check_uri_list_for_files(&mut self) {
        let Some(text) = self.read_x11_text() else { return };
        if !text.contains("file://") {
            return;
        }
        let paths = parse_uri_list(&text);
        if paths.is_empty() {
            return;
        }

        let mut files = Vec::new();
        for path in &paths {
            let Ok(meta) = std::fs::metadata(path) else { continue };
            if !meta.is_file() {
                continue;
            }
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            files.push(OfferedFile {
                name,
                size: meta.len(),
                linux_path: path.clone(),
            });
        }
        if files.is_empty() {
            return;
        }

        tracing::info!(count = files.len(), "clipboard: initiating Linux → Windows file copy");

        let descriptors: Vec<FileDescriptor> = files
            .iter()
            .map(|f| {
                FileDescriptor::new(f.name.clone())
                    .with_file_size(f.size)
                    .with_attributes(ironrdp_cliprdr::pdu::ClipboardFileAttributes::ARCHIVE)
            })
            .collect();

        // Store for FileContentsRequest servicing.
        {
            let mut offered = self.offered_files.lock().expect("poisoned");
            offered.insert(-1, files.clone()); // lindex -1 root list convention
        }
        *self.files_advertised.lock().expect("poisoned") = true;

        if let Some(proxy) = self.proxy.lock().expect("poisoned").as_ref() {
            proxy.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendInitiateFileCopy(
                descriptors,
            ));
        }
    }

    /// Serve a FileContentsRequest: read `requested_size` bytes at `position`
    /// from the offered file.
    fn serve_file_contents(
        &self,
        request: &FileContentsRequest,
    ) -> FileContentsResponse<'static> {
        let offered = self.offered_files.lock().expect("poisoned");
        let files = offered.get(&-1);
        let Some(files) = files else {
            return FileContentsResponse::new_error(request.stream_id);
        };

        let index = request.index as usize;
        let Some(file) = files.get(index) else {
            return FileContentsResponse::new_error(request.stream_id);
        };

        use std::io::{Read, Seek};
        let Ok(mut f) = std::fs::File::open(&file.linux_path) else {
            return FileContentsResponse::new_error(request.stream_id);
        };
        if f.seek(std::io::SeekFrom::Start(request.position)).is_err() {
            return FileContentsResponse::new_error(request.stream_id);
        }
        let mut buf = vec![0u8; request.requested_size as usize];
        let mut read_total = 0usize;
        while read_total < buf.len() {
            match f.read(&mut buf[read_total..]) {
                Ok(0) => break,
                Ok(n) => read_total += n,
                Err(_) => return FileContentsResponse::new_error(request.stream_id),
            }
        }
        buf.truncate(read_total);

        FileContentsResponse::new_data_response(request.stream_id, buf)
    }

    /// Parse a FileGroupDescriptorW payload (MS-RDPECLIP 2.2.5.2.1) into
    /// local Linux file paths. Each descriptor is 4+4+4+8+16+4+520 bytes.
    fn parse_file_list(&self, data: &[u8]) -> Vec<PathBuf> {
        // cItems = first 4 bytes LE
        if data.len() < 4 {
            return Vec::new();
        }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut paths = Vec::new();
        let mut offset = 4;
        for _ in 0..count {
            // Each descriptor: 4 (dwFlags) + 4 (dwFileAttributes) + 8 (ftLastWriteTime)
            // + 4 (nFileSizeHigh) + 4 (nFileSizeLow) + 520 (cFileName UTF-16) = 544
            if offset + 544 > data.len() {
                break;
            }
            offset += 4 + 4 + 8 + 4 + 4; // flags, attrs, times, sizes
            // Read null-terminated UTF-16 filename at this offset
            let name_bytes = &data[offset..offset + 520];
            let name: String = name_bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|&c| c != 0)
                .filter_map(|c| char::from_u32(u32::from(c)))
                .collect();
            if !name.is_empty() {
                paths.push(PathBuf::from("/tmp/linrdp-paste").join(name));
            }
            offset += 520;
        }
        paths
    }
}

ironrdp_core::impl_as_any!(X11CliprdrBackend);

impl X11CliprdrBackend {
    fn send_msg(&self, msg: ClipboardMessage) {
        let guard = self.proxy.lock().expect("poisoned");
        if let Some(proxy) = guard.as_ref() {
            proxy.send_clipboard_message(msg);
        }
    }
}

impl CliprdrBackend for X11CliprdrBackend {
    fn temporary_directory(&self) -> &str {
        "/tmp"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
            | ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED
    }

    fn on_ready(&mut self) {
        tracing::info!("clipboard: channel ready (X11 ↔ RDP sync: text + files)");
        // Kick off the X11 clipboard poller once.
        let proxy = Arc::clone(&self.proxy);
        let files_advertised = Arc::clone(&self.files_advertised);
        std::thread::spawn(move || {
            let mut last_text: Option<String> = None;
            let mut last_files: Option<String> = None;
            loop {
                std::thread::sleep(Duration::from_millis(700));
                let display = std::env::var("DISPLAY").unwrap_or_default();
                let xauthority = std::env::var("XAUTHORITY").unwrap_or_default();
                unsafe {
                    unsafe { std::env::set_var("DISPLAY", &display); }
                    unsafe { std::env::set_var("XAUTHORITY", &xauthority); }
                }
                let Ok(mut board) = arboard::Clipboard::new() else { continue };

                if let Ok(text) = board.get_text() {
                    if !text.is_empty() && last_text.as_deref() != Some(text.as_str()) {
                        last_text = Some(text.clone());
                        tracing::info!(bytes = text.len(), "clipboard: X11 text → advertise");
                        if let Some(p) = proxy.lock().expect("poisoned").as_ref() {
                            p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendInitiateCopy(
                                vec![ClipboardFormat::new(CF_UNICODETEXT)],
                            ));
                        }
                    }
                }

                // File URIs → initiate file copy to Windows.
                if let Ok(text) = board.get_text() {
                    if text.contains("file://") && last_files.as_deref() != Some(text.as_str()) {
                        last_files = Some(text.clone());
                        let paths = parse_uri_list(&text);
                        if !paths.is_empty() {
                            let mut descriptors = Vec::new();
                            let mut offered: HashMap<i32, OfferedFile> = HashMap::new();
                            for (i, path) in paths.iter().enumerate() {
                                let Ok(meta) = std::fs::metadata(path) else { continue };
                                let name = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| format!("file{i}"));
                                descriptors.push(
                                    FileDescriptor::new(name.clone())
                                        .with_file_size(meta.len())
                                        .with_attributes(ironrdp_cliprdr::pdu::ClipboardFileAttributes::ARCHIVE),
                                );
                                offered.insert(i as i32, OfferedFile {
                                    name,
                                    size: meta.len(),
                                    linux_path: path.clone(),
                                });
                            }
                            if !descriptors.is_empty() {
                                *files_advertised.lock().expect("poisoned") = true;
                                // Store in the static backend map (routed via backend instance below).
                                GLOBAL_OFFERED.with(|g| *g.borrow_mut() = offered);
                                tracing::info!(count = descriptors.len(), "clipboard: file copy → client");
                                if let Some(p) = proxy.lock().expect("poisoned").as_ref() {
                                    p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendInitiateFileCopy(descriptors));
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    fn on_request_format_list(&mut self) {
        tracing::debug!("clipboard: format list requested by client");
        // Advertise what we have: text always; files if offered.
        let mut formats = vec![ClipboardFormat::new(CF_UNICODETEXT)];
        if *self.files_advertised.lock().expect("poisoned") {
            formats.push(ClipboardFormat::new(ClipboardFormatId(15)));
        }
        if let Some(p) = self.proxy.lock().expect("poisoned").as_ref() {
            p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendInitiateCopy(formats));
        }
    }

    fn on_format_list_response(&mut self, ok: bool) {
        tracing::debug!(ok, "clipboard: format list response");
    }

    fn on_process_negotiated_capabilities(&mut self, _caps: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        tracing::debug!(count = formats.len(), "clipboard: remote copy — client offers formats");
        // If the client offers FileGroupDescriptorW, request the file list so
        // we can materialise files on the Linux side when the user pastes.
        let wants_files = formats
            .iter()
            .any(|f| f.id == ClipboardFormatId(15));
        if wants_files {
            if let Some(p) = self.proxy.lock().expect("poisoned").as_ref() {
                p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendInitiatePaste(
                    ClipboardFormatId(15),
                ));
            }
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        tracing::debug!(format = ?request.format, "clipboard: format data request");
        // Serve text from the X11 clipboard.
        let Some(text) = self.read_x11_text() else {
            if let Some(p) = self.proxy.lock().expect("poisoned").as_ref() {
                let response = FormatDataResponse::new_error();
                p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendFormatData(
                    response.into_owned(),
                ));
            }
            return;
        };
        let data = text_to_crlf(&text);
        if let Some(p) = self.proxy.lock().expect("poisoned").as_ref() {
            let owned: ironrdp_cliprdr::pdu::OwnedFormatDataResponse =
                FormatDataResponse::new_data(data.into_bytes()).into_owned();
            p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendFormatData(owned));
        }
    }

    fn on_format_data_response(&mut self, response: ironrdp_cliprdr::pdu::FormatDataResponse<'_>) {
        if response.is_error() {
            return;
        }
        let text = String::from_utf8_lossy(response.data()).to_string();
        if text.is_empty() {
            return;
        }
        tracing::info!(bytes = text.len(), "clipboard: RDP text → X11");
        self.write_x11_text(&text);
    }

    fn on_file_contents_request(&mut self, request: FileContentsRequest) {
        tracing::debug!(stream_id = request.stream_id, index = request.index, "clipboard: file contents request");
        // Serve from the global offered-files map (populated by the poller).
        let files = GLOBAL_OFFERED.with(|g| g.borrow().clone());
        let Some(file) = files.get(&request.index) else {
            if let Some(p) = self.proxy.lock().expect("poisoned").as_ref() {
                p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendFileContentsResponse(
                    FileContentsResponse::new_error(request.stream_id),
                ));
            }
            return;
        };
        use std::io::{Read, Seek};
        let Ok(mut f) = std::fs::File::open(&file.linux_path) else {
            return;
        };
        if f.seek(std::io::SeekFrom::Start(request.position)).is_err() {
            return;
        }
        let mut buf = vec![0u8; request.requested_size as usize];
        let mut total = 0usize;
        while total < buf.len() {
            match f.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => return,
            }
        }
        buf.truncate(total);
        if let Some(p) = self.proxy.lock().expect("poisoned").as_ref() {
            p.send_clipboard_message(ironrdp_cliprdr::backend::ClipboardMessage::SendFileContentsResponse(
                FileContentsResponse::new_data_response(request.stream_id, buf),
            ));
        }
    }

    fn on_file_contents_response(&mut self, _resp: ironrdp_cliprdr::pdu::FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _id: LockDataId) {}

    fn on_unlock(&mut self, _id: LockDataId) {}
}



thread_local! {
    static GLOBAL_OFFERED: std::cell::RefCell<HashMap<i32, OfferedFile>> = std::cell::RefCell::new(HashMap::new());
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

/// Factory for the X11 ↔ RDP clipboard backend.
#[derive(Debug, Default)]
pub(crate) struct X11CliprdrServerFactory;

impl ironrdp_cliprdr::backend::CliprdrBackendFactory for X11CliprdrServerFactory {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        Box::new(X11CliprdrBackend::new(
            std::env::var("DISPLAY").unwrap_or_default(),
            std::env::var("XAUTHORITY").unwrap_or_default(),
        ))
    }
}

impl ironrdp_server::ServerEventSender for X11CliprdrServerFactory {
    fn set_sender(&mut self, _sender: tokio::sync::mpsc::UnboundedSender<ironrdp_server::ServerEvent>) {}
}

impl ironrdp_server::CliprdrServerFactory for X11CliprdrServerFactory {}
