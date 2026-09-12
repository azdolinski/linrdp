//! PipeWire screencast consumer over `dlopen("libpipewire-0.3.so.0")` — the
//! capture half of KRdp's Wayland path, feeding this server's shared
//! damage/EGFX display machinery.
//!
//! Build-time independence notes:
//! - only `pw_*` functions are dlsym'ed. The SPA helpers (`spa_pod_builder`,
//!   `spa_format_video_raw_parse`, ...) are `static inline` in the SPA
//!   headers and not exported from any library, so the POD writer/parser
//!   below re-implements the wire format (verified against
//!   spa-0.2/pod/pod.h: props are `key,flags,pod` rounded up to 8 bytes);
//! - buffers are consumed as raw BGRx frames (the portal stream is asked for
//!   exactly that); no DMA-BUF yet — mmap'ed memfd only.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ironrdp_connector::DesktopSize;

use crate::capture::{compute_tile_damage, Grab};
use crate::gfx_display::{DisplaySourceFactory, FrameSource};

// ---- constants (SPA/pipewire ABI, verified against spa-0.2 headers) --------

const SPA_TYPE_ID: u32 = 2;
const SPA_TYPE_INT: u32 = 3;
const SPA_TYPE_RECTANGLE: u32 = 10;
const SPA_TYPE_OBJECT: u32 = 15;

const SPA_TYPE_OBJECT_FORMAT: u32 = 0x40003;
const SPA_TYPE_OBJECT_PARAM_BUFFERS: u32 = 0x40004;

const SPA_MEDIA_TYPE_VIDEO: u32 = 2;
const SPA_MEDIA_SUBTYPE_RAW: u32 = 1;

const SPA_VIDEO_FORMAT_BGRX: u32 = 8;

const SPA_FORMAT_MEDIA_TYPE: u32 = 1;
const SPA_FORMAT_MEDIA_SUBTYPE: u32 = 2;
const SPA_FORMAT_VIDEO_FORMAT: u32 = 16;
const SPA_FORMAT_VIDEO_SIZE: u32 = 18;

const SPA_PARAM_ENUM_FORMAT: u32 = 3;
const SPA_PARAM_FORMAT: u32 = 4;
const SPA_PARAM_BUFFERS: u32 = 5;

const SPA_PARAM_BUFFERS_BUFFERS: u32 = 1;
const SPA_PARAM_BUFFERS_BLOCKS: u32 = 2;
const SPA_PARAM_BUFFERS_SIZE: u32 = 3;
const SPA_PARAM_BUFFERS_STRIDE: u32 = 4;
const SPA_PARAM_BUFFERS_ALIGN: u32 = 5;

const PW_DIRECTION_INPUT: i32 = 0;
const PW_ID_ANY: u32 = 0xffff_ffff;

const PW_STREAM_FLAG_AUTOCONNECT: u32 = 1 << 0;
const PW_STREAM_FLAG_MAP_BUFFERS: u32 = 1 << 2;
const PW_STREAM_FLAG_DONT_RECONNECT: u32 = 1 << 7;

// ---- repr(C) mirrors (verified against spa-0.2 / pipewire headers) ---------

#[repr(C)]
struct SpaPod {
    size: u32,
    pod_type: u32,
}

#[repr(C)]
struct SpaRectangle {
    width: u32,
    height: u32,
}

#[repr(C)]
struct SpaCallbacks {
    funcs: *const c_void,
    data: *mut c_void,
}

#[repr(C)]
struct SpaList {
    next: *mut SpaList,
    prev: *mut SpaList,
}

/// `struct spa_hook` — 5 pointers.
#[repr(C)]
struct SpaHook {
    link: SpaList,
    cb: SpaCallbacks,
    removed: Option<unsafe extern "C" fn(hook: *mut SpaHook)>,
}

/// `struct pw_stream_events` — version field + 11 callbacks, padded like C.
#[repr(C)]
struct PwStreamEvents {
    version: u32,
    destroy: Option<unsafe extern "C" fn(data: *mut c_void)>,
    state_changed: Option<
        unsafe extern "C" fn(data: *mut c_void, old: i32, state: i32, error: *const c_char),
    >,
    control_info: Option<unsafe extern "C" fn(data: *mut c_void, id: u32, control: *const c_void)>,
    io_changed: Option<unsafe extern "C" fn(data: *mut c_void, id: u32, area: *mut c_void, size: u32)>,
    param_changed: Option<unsafe extern "C" fn(data: *mut c_void, id: u32, param: *const SpaPod)>,
    add_buffer: Option<unsafe extern "C" fn(data: *mut c_void, buffer: *mut PwBuffer)>,
    remove_buffer: Option<unsafe extern "C" fn(data: *mut c_void, buffer: *mut PwBuffer)>,
    process: Option<unsafe extern "C" fn(data: *mut c_void)>,
    drained: Option<unsafe extern "C" fn(data: *mut c_void)>,
    command: Option<unsafe extern "C" fn(data: *mut c_void, command: *const c_void)>,
    trigger_done: Option<unsafe extern "C" fn(data: *mut c_void)>,
}

#[repr(C)]
struct SpaChunk {
    offset: u32,
    size: u32,
    flags: u32,
}

#[repr(C)]
struct SpaData {
    data_type: u32,
    flags: u32,
    fd: i64,
    mapoffset: u32,
    maxsize: u32,
    data: *mut c_void,
    chunk: *mut SpaChunk,
}

#[repr(C)]
struct SpaBuffer {
    n_metas: u32,
    n_datas: u32,
    metas: *mut c_void, // struct spa_meta*
    datas: *mut SpaData,
}

#[repr(C)]
struct PwBuffer {
    buffer: *mut SpaBuffer,
    user_data: *mut c_void,
    size: u64,
}

/// Opaque pipewire types.
#[repr(C)]
struct PwThreadLoop {
    _private: [u8; 0],
}
#[repr(C)]
struct PwLoop {
    _private: [u8; 0],
}
#[repr(C)]
struct PwProperties {
    _private: [u8; 0],
}
#[repr(C)]
struct PwContext {
    _private: [u8; 0],
}
#[repr(C)]
struct PwCore {
    _private: [u8; 0],
}
#[repr(C)]
struct PwStream {
    _private: [u8; 0],
}

// ---- dlopen API -------------------------------------------------------------

struct PwApi {
    _lib: *mut c_void,
    pw_thread_loop_new: unsafe extern "C" fn(name: *const c_char, props: *const c_void) -> *mut PwThreadLoop,
    pw_thread_loop_start: unsafe extern "C" fn(loop_: *mut PwThreadLoop) -> c_int,
    pw_thread_loop_lock: unsafe extern "C" fn(loop_: *mut PwThreadLoop),
    pw_thread_loop_unlock: unsafe extern "C" fn(loop_: *mut PwThreadLoop),
    pw_thread_loop_get_loop: unsafe extern "C" fn(loop_: *mut PwThreadLoop) -> *mut PwLoop,
    pw_thread_loop_destroy: unsafe extern "C" fn(loop_: *mut PwThreadLoop),
    pw_properties_new_string: unsafe extern "C" fn(args: *const c_char) -> *mut PwProperties,
    pw_context_new:
        unsafe extern "C" fn(loop_: *mut PwLoop, props: *mut PwProperties, user_data_size: usize) -> *mut PwContext,
    pw_context_connect_fd:
        unsafe extern "C" fn(context: *mut PwContext, fd: c_int, props: *mut PwProperties, user_data_size: usize) -> *mut PwCore,
    pw_stream_new:
        unsafe extern "C" fn(core: *mut PwCore, name: *const c_char, props: *mut PwProperties) -> *mut PwStream,
    pw_stream_add_listener: unsafe extern "C" fn(
        stream: *mut PwStream,
        listener: *mut SpaHook,
        events: *const PwStreamEvents,
        data: *mut c_void,
    ),
    pw_stream_connect: unsafe extern "C" fn(
        stream: *mut PwStream,
        direction: c_int,
        target_id: u32,
        flags: u32,
        params: *const *const SpaPod,
        n_params: u32,
    ) -> c_int,
    pw_stream_update_params:
        unsafe extern "C" fn(stream: *mut PwStream, params: *const *const SpaPod, n_params: u32) -> c_int,
    pw_stream_dequeue_buffer: unsafe extern "C" fn(stream: *mut PwStream) -> *mut PwBuffer,
    pw_stream_queue_buffer:
        unsafe extern "C" fn(stream: *mut PwStream, buffer: *mut PwBuffer) -> c_int,
    pw_stream_destroy: unsafe extern "C" fn(stream: *mut PwStream),
    pw_context_destroy: unsafe extern "C" fn(context: *mut PwContext),
}

unsafe impl Send for PwApi {}
unsafe impl Sync for PwApi {}

static PW: OnceLock<Result<PwApi, &'static str>> = OnceLock::new();

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
const RTLD_NOW: c_int = 0x2;
const RTLD_GLOBAL: c_int = 0x100;

fn load_pw() -> Result<PwApi, &'static str> {
    // SAFETY: as with PAM/libei — refcounted loader, signatures per headers.
    unsafe {
        let lib = ["libpipewire-0.3.so.0", "libpipewire-0.3.so"]
            .iter()
            .find_map(|name| {
                let cname = CString::new(*name).ok()?;
                let handle = dlopen(cname.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
                (!handle.is_null()).then_some(handle)
            })
            .ok_or("libpipewire-0.3.so.0 not loadable (install pipewire for Wayland capture)")?;

        macro_rules! sym {
            ($name:expr) => {{
                let cname = CString::new($name).map_err(|_| "bad symbol name")?;
                let ptr = dlsym(lib, cname.as_ptr());
                if ptr.is_null() {
                    return Err(concat!("pipewire missing symbol ", $name));
                }
                std::mem::transmute::<*mut c_void, _>(ptr)
            }};
        }

        Ok(PwApi {
            _lib: lib,
            pw_thread_loop_new: sym!("pw_thread_loop_new"),
            pw_thread_loop_start: sym!("pw_thread_loop_start"),
            pw_thread_loop_lock: sym!("pw_thread_loop_lock"),
            pw_thread_loop_unlock: sym!("pw_thread_loop_unlock"),
            pw_thread_loop_get_loop: sym!("pw_thread_loop_get_loop"),
            pw_thread_loop_destroy: sym!("pw_thread_loop_destroy"),
            pw_properties_new_string: sym!("pw_properties_new_string"),
            pw_context_new: sym!("pw_context_new"),
            pw_context_connect_fd: sym!("pw_context_connect_fd"),
            pw_stream_new: sym!("pw_stream_new"),
            pw_stream_add_listener: sym!("pw_stream_add_listener"),
            pw_stream_connect: sym!("pw_stream_connect"),
            pw_stream_update_params: sym!("pw_stream_update_params"),
            pw_stream_dequeue_buffer: sym!("pw_stream_dequeue_buffer"),
            pw_stream_queue_buffer: sym!("pw_stream_queue_buffer"),
            pw_stream_destroy: sym!("pw_stream_destroy"),
            pw_context_destroy: sym!("pw_context_destroy"),
        })
    }
}

// ---- POD writer/parser (SPA wire format, 8-byte prop alignment) -------------

/// Append a property: `key, flags, pod{size,type} value` padded to 8 bytes.
fn push_prop(buf: &mut Vec<u8>, key: u32, pod_type: u32, value: &[u8]) {
    buf.extend_from_slice(&key.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // flags
    buf.extend_from_slice(&(value.len() as u32).to_ne_bytes()); // pod.size
    buf.extend_from_slice(&pod_type.to_ne_bytes());
    buf.extend_from_slice(value);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
}

/// Build an object POD (header + body type/id + props). Returns the byte
/// buffer; pass `buf.as_ptr()` as the param pointer.
fn build_object_pod(object_type: u32, id: u32, props: &mut dyn FnMut(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&object_type.to_ne_bytes());
    body.extend_from_slice(&id.to_ne_bytes());
    props(&mut body);
    let mut pod = Vec::with_capacity(8 + body.len());
    pod.extend_from_slice(&(body.len() as u32).to_ne_bytes());
    pod.extend_from_slice(&SPA_TYPE_OBJECT.to_ne_bytes());
    pod.extend_from_slice(&body);
    while pod.len() % 8 != 0 {
        pod.push(0);
    }
    pod
}

fn enum_format_pod() -> Vec<u8> {
    build_object_pod(SPA_TYPE_OBJECT_FORMAT, SPA_PARAM_ENUM_FORMAT, &mut |body| {
        push_prop(body, SPA_FORMAT_MEDIA_TYPE, SPA_TYPE_ID, &SPA_MEDIA_TYPE_VIDEO.to_ne_bytes());
        push_prop(
            body,
            SPA_FORMAT_MEDIA_SUBTYPE,
            SPA_TYPE_ID,
            &SPA_MEDIA_SUBTYPE_RAW.to_ne_bytes(),
        );
        push_prop(body, SPA_FORMAT_VIDEO_FORMAT, SPA_TYPE_ID, &SPA_VIDEO_FORMAT_BGRX.to_ne_bytes());
    })
}

fn buffers_pod(size: u32, stride: u32) -> Vec<u8> {
    build_object_pod(
        SPA_TYPE_OBJECT_PARAM_BUFFERS,
        SPA_PARAM_BUFFERS,
        &mut |body| {
            push_prop(body, SPA_PARAM_BUFFERS_BUFFERS, SPA_TYPE_INT, &8i32.to_ne_bytes());
            push_prop(body, SPA_PARAM_BUFFERS_BLOCKS, SPA_TYPE_INT, &1i32.to_ne_bytes());
            push_prop(body, SPA_PARAM_BUFFERS_SIZE, SPA_TYPE_INT, &(size as i32).to_ne_bytes());
            push_prop(body, SPA_PARAM_BUFFERS_STRIDE, SPA_TYPE_INT, &(stride as i32).to_ne_bytes());
            push_prop(body, SPA_PARAM_BUFFERS_ALIGN, SPA_TYPE_INT, &16i32.to_ne_bytes());
        },
    )
}

/// Parsed `SPA_PARAM_Format` video fields.
struct RawVideoFormat {
    format: u32,
    width: u32,
    height: u32,
}

/// Walk an object POD's props, extracting the raw-video fields we care
/// about (mediaType/mediaSubtype are validated implicitly by the stream).
fn parse_raw_format(pod: *const SpaPod) -> Option<RawVideoFormat> {
    // SAFETY: pod comes from the param_changed callback and is valid for
    // the call; we only read within `pod.size` bytes of the body.
    unsafe {
        if pod.is_null() || (*pod).pod_type != SPA_TYPE_OBJECT {
            return None;
        }
        let body = pod.add(1) as *const u8; // after the 8-byte header
        let body_size = (*pod).size as usize;
        if body_size < 8 {
            return None;
        }
        let mut out = RawVideoFormat {
            format: 0,
            width: 0,
            height: 0,
        };
        let mut offset = 8usize; // skip object body type/id
        while offset + 16 <= body_size {
            let key = u32::from_ne_bytes(read4(body, offset)?);
            let value_size = u32::from_ne_bytes(read4(body, offset + 8)?) as usize;
            let value_type = u32::from_ne_bytes(read4(body, offset + 12)?);
            let value_at = offset + 16;
            if value_at + value_size > body_size {
                break;
            }
            match (key, value_type) {
                (SPA_FORMAT_VIDEO_FORMAT, SPA_TYPE_ID) if value_size >= 4 => {
                    out.format = u32::from_ne_bytes(read4(body, value_at)?);
                }
                // size arrives as a Rectangle (or a Choice of rectangles —
                // fixated by the time it reaches Format).
                (SPA_FORMAT_VIDEO_SIZE, SPA_TYPE_RECTANGLE) if value_size >= 8 => {
                    out.width = u32::from_ne_bytes(read4(body, value_at)?);
                    out.height = u32::from_ne_bytes(read4(body, value_at + 4)?);
                }
                _ => {}
            }
            // struct spa_pod_prop total size, rounded up to 8.
            let prop_size = 16 + value_size;
            offset += prop_size.div_ceil(8) * 8;
        }
        (out.format != 0 && out.width != 0).then_some(out)
    }
}

/// # Safety
/// `base` must have at least `off + 4` readable bytes.
unsafe fn read4(base: *const u8, off: usize) -> Option<[u8; 4]> {
    unsafe {
        let mut out = [0u8; 4];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = *base.add(off + i);
        }
        Some(out)
    }
}

// ---- shared state -----------------------------------------------------------

/// Latest decoded frame (or nothing yet).
struct FrameSlot {
    data: Vec<u8>,
    width: u32,
    height: u32,
    seq: u64,
    /// Set when the stream size changed — the source reports it as the
    /// post-change settle window.
    geometry_changed_at: Option<Instant>,
}

struct PwInner {
    api: &'static PwApi,
    thread_loop: *mut PwThreadLoop,
    context: *mut PwContext,
    stream: *mut PwStream,
    /// Hook + events must outlive the stream.
    _hook: Box<SpaHook>,
    _events: Box<PwStreamEvents>,
    /// The `data` pointer handed to events — a leaked Arc re-lived below.
    _events_data: *mut c_void,
}

unsafe impl Send for PwInner {}

/// State shared between the pw thread (events), the display loop (frame
/// pulls) and the factory.
pub(crate) struct PwShared {
    inner: Mutex<Option<PwInner>>,
    frame: Mutex<FrameSlot>,
    stream_ready: AtomicBool,
    failed: AtomicBool,
    frame_seq: AtomicU64,
    node_serial: Option<u64>,
}

/// The process-wide capture: start once, then hand `Arc<PwShared>` to the
/// display factory and any number of per-session frame sources.
pub(crate) struct PwCapture {
    shared: Arc<PwShared>,
}

impl PwCapture {
    /// Connect the capture stream to the portal's PipeWire remote. Blocking
    /// (thread-loop handshake); call before the server starts.
    pub(crate) fn start(
        fd: std::os::fd::OwnedFd,
        node_id: u32,
        node_serial: Option<u64>,
    ) -> anyhow::Result<Self> {
        let api = match PW.get_or_init(load_pw) {
            Ok(api) => api,
            Err(reason) => anyhow::bail!("pipewire unavailable: {reason}"),
        };

        let shared = Arc::new(PwShared {
            inner: Mutex::new(None),
            frame: Mutex::new(FrameSlot {
                data: Vec::new(),
                width: 0,
                height: 0,
                seq: 0,
                geometry_changed_at: None,
            }),
            stream_ready: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            frame_seq: AtomicU64::new(0),
            node_serial,
        });

        // Events `data` — a leaked Arc clone; teardown stops the loop before
        // anything is freed, so callbacks never race Drop.
        let events_data: *mut c_void = Arc::into_raw(Arc::clone(&shared)) as *mut c_void;

        // SAFETY: the whole setup sequence below follows pipewire's
        // thread-loop usage; all pointers are stored in PwInner.
        unsafe {
            let name = c"linrdp-pw";
            let thread_loop = (api.pw_thread_loop_new)(name.as_ptr(), std::ptr::null());
            if thread_loop.is_null() {
                anyhow::bail!("pw_thread_loop_new failed");
            }
            (api.pw_thread_loop_lock)(thread_loop);
            let loop_ok = (api.pw_thread_loop_start)(thread_loop);
            let context = if loop_ok == 0 {
                (api.pw_context_new)(
                    (api.pw_thread_loop_get_loop)(thread_loop),
                    std::ptr::null_mut(),
                    0,
                )
            } else {
                std::ptr::null_mut()
            };
            if context.is_null() {
                (api.pw_thread_loop_unlock)(thread_loop);
                (api.pw_thread_loop_destroy)(thread_loop);
                anyhow::bail!("pipewire context setup failed");
            }
            let core = (api.pw_context_connect_fd)(context, std::os::fd::IntoRawFd::into_raw_fd(fd), std::ptr::null_mut(), 0);
            if core.is_null() {
                (api.pw_context_destroy)(context);
                (api.pw_thread_loop_unlock)(thread_loop);
                (api.pw_thread_loop_destroy)(thread_loop);
                anyhow::bail!("pw_context_connect_fd failed (portal fd closed?)");
            }

            let mut props = String::from("media.type=Video media.category=Capture stream.capture.sink=true");
            if let Some(serial) = node_serial {
                props.push_str(&format!(" target.object={serial}"));
            }
            let props_c = CString::new(props).expect("no NUL in props");
            let stream_props = (api.pw_properties_new_string)(props_c.as_ptr());
            let stream = (api.pw_stream_new)(
                core,
                name.as_ptr(),
                stream_props,
            );
            if stream.is_null() {
                (api.pw_context_destroy)(context);
                (api.pw_thread_loop_unlock)(thread_loop);
                (api.pw_thread_loop_destroy)(thread_loop);
                anyhow::bail!("pw_stream_new failed");
            }

            let mut events = Box::new(PwStreamEvents {
                version: 2,
                destroy: None,
                state_changed: Some(on_state_changed),
                control_info: None,
                io_changed: None,
                param_changed: Some(on_param_changed),
                add_buffer: None,
                remove_buffer: None,
                process: Some(on_process),
                drained: None,
                command: None,
                trigger_done: None,
            });
            let mut hook = Box::new(SpaHook {
                link: SpaList {
                    next: std::ptr::null_mut(),
                    prev: std::ptr::null_mut(),
                },
                cb: SpaCallbacks {
                    funcs: std::ptr::null(),
                    data: std::ptr::null_mut(),
                },
                removed: None,
            });
            (api.pw_stream_add_listener)(stream, &mut *hook, &*events, events_data);

            let enum_pod = enum_format_pod();
            let params = [enum_pod.as_ptr() as *const SpaPod];
            let rc = (api.pw_stream_connect)(
                stream,
                PW_DIRECTION_INPUT,
                if node_serial.is_some() { PW_ID_ANY } else { node_id },
                PW_STREAM_FLAG_AUTOCONNECT
                    | PW_STREAM_FLAG_MAP_BUFFERS
                    | PW_STREAM_FLAG_DONT_RECONNECT,
                params.as_ptr(),
                1,
            );
            (api.pw_thread_loop_unlock)(thread_loop);
            if rc != 0 {
                (api.pw_stream_destroy)(stream);
                (api.pw_context_destroy)(context);
                (api.pw_thread_loop_destroy)(thread_loop);
                anyhow::bail!("pw_stream_connect failed: {rc}");
            }

            *shared.inner.lock().expect("inner lock") = Some(PwInner {
                api,
                thread_loop,
                context,
                stream,
                _hook: hook,
                _events: events,
                _events_data: events_data,
            });
        }

        tracing::info!(node_id, "PipeWire capture stream connecting");
        Ok(Self { shared })
    }

    pub(crate) fn shared(&self) -> Arc<PwShared> {
        Arc::clone(&self.shared)
    }
}

impl Drop for PwCapture {
    fn drop(&mut self) {
        let Some(inner) = self.shared.inner.lock().ok().and_then(|mut g| g.take()) else {
            return;
        };
        // SAFETY: teardown stops the thread loop (joins the pw thread) before
        // the stream/context are destroyed, so no callback can run after.
        unsafe {
            (inner.api.pw_thread_loop_lock)(inner.thread_loop);
            (inner.api.pw_stream_destroy)(inner.stream);
            (inner.api.pw_thread_loop_unlock)(inner.thread_loop);
            (inner.api.pw_context_destroy)(inner.context);
            (inner.api.pw_thread_loop_destroy)(inner.thread_loop);
        }
    }
}

// ---- stream events ----------------------------------------------------------

unsafe extern "C" fn on_state_changed(data: *mut c_void, _old: i32, state: i32, error: *const c_char) {
    // SAFETY: data is the leaked Arc<PwShared>.
    let shared = unsafe { &*(data as *const PwShared) };
    // PW_STREAM_STATE_ERROR == 4 (pipewire stream.h enum order).
    if state == 4 {
        let message = if error.is_null() {
            "unknown".to_owned()
        } else {
            unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()
        };
        tracing::error!(%message, "PipeWire stream error");
        shared.failed.store(true, Ordering::Relaxed);
    }
}

unsafe extern "C" fn on_param_changed(data: *mut c_void, id: u32, param: *const SpaPod) {
    // SAFETY: data is the leaked Arc<PwShared>; param is valid for the call.
    let shared = unsafe { &*(data as *const PwShared) };
    if id == SPA_PARAM_FORMAT {
        if let Some(format) = parse_raw_format(param) {
            let stride = format.width.saturating_mul(4);
            let size = stride.saturating_mul(format.height);
            // Answer the format with our buffer layout (video-src dance).
            let shared_mut = shared as *const PwShared as *mut PwShared;
            unsafe {
                if let Some(inner) = (*shared_mut).inner.lock().ok().and_then(|mut g| g.take()) {
                    let pod = buffers_pod(size, stride);
                    let params = [pod.as_ptr() as *const SpaPod];
                    (inner.api.pw_stream_update_params)(inner.stream, params.as_ptr(), 1);
                    *(*shared_mut).inner.lock().expect("inner lock") = Some(inner);
                }
            }
            let mut slot = shared.frame.lock().expect("frame lock");
            if slot.width != format.width || slot.height != format.height {
                slot.geometry_changed_at = Some(Instant::now());
            }
            slot.width = format.width;
            slot.height = format.height;
            drop(slot);
            shared.stream_ready.store(true, Ordering::Relaxed);
            tracing::info!(
                width = format.width,
                height = format.height,
                format = format.format,
                "PipeWire video format negotiated"
            );
        }
        return;
    }
    if id == SPA_PARAM_BUFFERS {
        // Negotiation finished — frames may flow.
    }
}

unsafe extern "C" fn on_process(data: *mut c_void) {
    // SAFETY: data is the leaked Arc<PwShared>; stream calls run under the
    // thread-loop lock as pw-cat does.
    let shared = unsafe { &*(data as *const PwShared) };
    let shared_mut = shared as *const PwShared as *mut PwShared;
    unsafe {
        let Some(inner) = (*shared_mut).inner.lock().ok().and_then(|mut g| g.take()) else {
            return;
        };
        (inner.api.pw_thread_loop_lock)(inner.thread_loop);
        let buffer = (inner.api.pw_stream_dequeue_buffer)(inner.stream);
        if !buffer.is_null() {
            copy_frame(&*shared, &*buffer);
            (inner.api.pw_stream_queue_buffer)(inner.stream, buffer);
        }
        (inner.api.pw_thread_loop_unlock)(inner.thread_loop);
        *(*shared_mut).inner.lock().expect("inner lock") = Some(inner);
    }
}

/// Copy one BGRx frame out of the pw buffer into the shared slot (tightly
/// packed `width * 4` stride).
///
/// # Safety
/// `buffer` is a dequeued, mapped pw buffer.
unsafe fn copy_frame(shared: &PwShared, buffer: &PwBuffer) {
    unsafe {
        let spa = buffer.buffer;
        if spa.is_null() || (*spa).n_datas == 0 || (*spa).datas.is_null() {
            return;
        }
        let slot_lock = shared.frame.lock().expect("frame lock");
        let (width, height) = (slot_lock.width, slot_lock.height);
        drop(slot_lock);
        if width == 0 || height == 0 {
            return;
        }
        let data = &*(*spa).datas;
        let chunk = &*data.chunk;
        let valid = chunk.size.min(data.maxsize.saturating_sub(chunk.offset)) as usize;
        if data.data.is_null() || valid == 0 {
            return;
        }
        let src = (data.data as *const u8).add(chunk.offset as usize);
        let tight = width as usize * 4;
        let expected = tight * height as usize;
        if valid < expected {
            return; // torn frame — wait for the next
        }
        // Chunk size is stride * height; the portal always negotiates our
        // tightly-packed stride, but honor a larger one just in case.
        let stride = valid / height as usize;

        let seq = shared.frame_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut slot = shared.frame.lock().expect("frame lock");
        slot.data.clear();
        if stride == tight {
            slot.data.extend_from_slice(std::slice::from_raw_parts(src, expected));
        } else {
            for row in 0..height as usize {
                let start = row * stride;
                slot.data
                    .extend_from_slice(std::slice::from_raw_parts(src.add(start), tight));
            }
        }
        slot.seq = seq;
    }
}

// ---- source traits ----------------------------------------------------------

/// Per-session frame source pulling from the shared slot.
struct PwFrameSource {
    shared: Arc<PwShared>,
    prev_frame: Option<Vec<u8>>,
    last_seq: u64,
}

impl FrameSource for PwFrameSource {
    fn poll_and_cursor(
        &mut self,
        _cursor_due: bool,
    ) -> Option<(Grab, Option<crate::capture::CursorImage>)> {
        if !self.shared.stream_ready.load(Ordering::Relaxed) || self.shared.failed.load(Ordering::Relaxed) {
            return None;
        }
        let slot = self.shared.frame.lock().ok()?;
        if slot.seq == self.last_seq || slot.width == 0 || slot.height == 0 {
            return None; // no new frame this tick
        }
        let (Ok(width), Ok(height)) = (u16::try_from(slot.width), u16::try_from(slot.height)) else {
            return None; // screen larger than 65535px — treat as no frame
        };
        // The cursor is composited into the frames (portal cursor_mode=2),
        // so no separate cursor channel is needed.
        let data = slot.data.clone();
        self.last_seq = slot.seq;
        drop(slot);

        let (damage, changed_tiles, total_tiles) =
            compute_tile_damage(self.prev_frame.as_deref(), &data, width, height);
        if damage.is_some() {
            self.prev_frame = Some(data.clone());
        }
        Some((
            Grab {
                data,
                width,
                height,
                damage,
                changed_tiles,
                total_tiles,
            },
            None,
        ))
    }

    fn is_attached(&self) -> bool {
        !self.shared.failed.load(Ordering::Relaxed)
    }

    fn name(&self) -> &str {
        "pipewire"
    }

    fn settle_until(&self) -> Instant {
        self.shared
            .frame
            .lock()
            .ok()
            .and_then(|slot| slot.geometry_changed_at)
            .map(|at| at + SETTLE_AFTER_FORMAT_CHANGE)
            .unwrap_or_else(Instant::now)
    }
}

/// How long to hold frames after a format (screen size) change so the
/// compositor settles — mirrors the X11 post-resize window.
const SETTLE_AFTER_FORMAT_CHANGE: Duration = Duration::from_millis(1500);

/// Display factory handed to the EGFX backend under `--wayland`.
pub(crate) struct PwDisplayFactory {
    shared: Arc<PwShared>,
}

impl PwDisplayFactory {
    pub(crate) fn new(shared: Arc<PwShared>) -> Self {
        Self { shared }
    }
}

impl DisplaySourceFactory for PwDisplayFactory {
    fn size(&self) -> DesktopSize {
        let slot = self.shared.frame.lock().expect("frame lock");
        DesktopSize {
            width: u16::try_from(slot.width.max(1)).unwrap_or(1920),
            height: u16::try_from(slot.height.max(1)).unwrap_or(1080),
        }
    }

    fn request_initial_size(&self, client_size: DesktopSize) -> DesktopSize {
        // The Wayland screen is what it is — the client scales, exactly like
        // a Windows session to a differently-sized monitor.
        let size = self.size();
        tracing::debug!(?client_size, ?size, "wayland: fixed screen size, client scales");
        size
    }

    fn request_layout(&self, layout: ironrdp_displaycontrol::pdu::DisplayControlMonitorLayout) {
        // No RandR equivalent here: monitor layout changes would go through
        // the portal's virtual-monitor support (future work).
        tracing::debug!(?layout, "wayland: client layout change ignored (no display control)");
    }

    fn updates_source(&self) -> Box<dyn FrameSource> {
        Box::new(PwFrameSource {
            shared: Arc::clone(&self.shared),
            prev_frame: None,
            last_seq: 0,
        })
    }
}
