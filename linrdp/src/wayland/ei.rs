//! libei input injection over the portal's EIS fd — the Rust port of KRdp's
//! `EiConnection`, loaded at runtime with `dlopen("libei.so.1")`.
//!
//! ABI notes (verified against the libei 1.3 and 1.6 public headers):
//! - event enum values 1..8 used here are identical in both;
//! - `EI_DEVICE_CAP_TEXT`, `ei_device_text_keysym` and
//!   `ei_seat_request_device_with_capabilities` exist only from ~1.4 — they
//!   are dlsym-probed and the text path degrades to a warning when absent.
//!
//! A dedicated OS thread pumps the ei fd (poll → dispatch → drain events);
//! the RDP input handler serializes against it through the state mutex.
//! Device pointers are `ei_device_ref`-ed when adopted and unref'd on
//! removal / teardown, all under that mutex.

use std::collections::HashSet;
use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler};

// ---- libei ABI (subset) -----------------------------------------------------

mod abi {
    #![allow(non_snake_case)]

    use std::ffi::{c_char, c_int, c_void};

    // enum ei_event_type (libei >= 1.0; unchanged through 1.6). The full
    // prefix is kept for ABI readability even where a value is not matched.
    #[allow(dead_code, reason = "ABI completeness")]
    pub const EI_EVENT_CONNECT: u32 = 1;
    pub const EI_EVENT_DISCONNECT: u32 = 2;
    pub const EI_EVENT_SEAT_ADDED: u32 = 3;
    pub const EI_EVENT_SEAT_REMOVED: u32 = 4;
    pub const EI_EVENT_DEVICE_ADDED: u32 = 5;
    pub const EI_EVENT_DEVICE_REMOVED: u32 = 6;
    pub const EI_EVENT_DEVICE_PAUSED: u32 = 7;
    pub const EI_EVENT_DEVICE_RESUMED: u32 = 8;

    // enum ei_device_capability
    pub const EI_DEVICE_CAP_POINTER_ABSOLUTE: c_int = 1 << 1;
    pub const EI_DEVICE_CAP_KEYBOARD: c_int = 1 << 2;
    pub const EI_DEVICE_CAP_SCROLL: c_int = 1 << 4;
    pub const EI_DEVICE_CAP_BUTTON: c_int = 1 << 5;
    /// libei >= ~1.4 only; bound only when the matching function exists.
    pub const EI_DEVICE_CAP_TEXT: c_int = 1 << 6;

    // linux/input-event-codes.h
    pub const BTN_LEFT: u32 = 0x110;
    pub const BTN_RIGHT: u32 = 0x111;
    pub const BTN_MIDDLE: u32 = 0x112;

    /// Opaque libei types.
    #[repr(C)]
    pub struct Ei {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct EiEvent {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct EiSeat {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct EiDevice {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct EiRegion {
        _private: [u8; 0],
    }

    pub type EiNewSender = unsafe extern "C" fn(user_data: *mut c_void) -> *mut Ei;
    pub type EiUnref = unsafe extern "C" fn(ei: *mut Ei) -> *mut Ei;
    pub type EiConfigureName = unsafe extern "C" fn(ei: *mut Ei, name: *const c_char);
    pub type EiSetupBackendFd = unsafe extern "C" fn(ei: *mut Ei, fd: c_int) -> c_int;
    pub type EiGetFd = unsafe extern "C" fn(ei: *mut Ei) -> c_int;
    pub type EiDispatch = unsafe extern "C" fn(ei: *mut Ei);
    pub type EiGetEvent = unsafe extern "C" fn(ei: *mut Ei) -> *mut EiEvent;
    pub type EiEventUnref = unsafe extern "C" fn(event: *mut EiEvent) -> *mut EiEvent;
    pub type EiEventGetType = unsafe extern "C" fn(event: *const EiEvent) -> u32;
    pub type EiEventGetSeat = unsafe extern "C" fn(event: *const EiEvent) -> *mut EiSeat;
    pub type EiEventGetDevice = unsafe extern "C" fn(event: *const EiEvent) -> *mut EiDevice;
    pub type EiSeatBindCapabilities = unsafe extern "C" fn(seat: *mut EiSeat, ...);
    pub type EiSeatRequestDevice = unsafe extern "C" fn(seat: *mut EiSeat, ...);
    pub type EiDeviceRef = unsafe extern "C" fn(device: *mut EiDevice) -> *mut EiDevice;
    pub type EiDeviceUnref = unsafe extern "C" fn(device: *mut EiDevice) -> *mut EiDevice;
    pub type EiDeviceHasCapability =
        unsafe extern "C" fn(device: *const EiDevice, cap: c_int) -> bool;
    pub type EiDeviceGetRegion =
        unsafe extern "C" fn(device: *const EiDevice, index: usize) -> *mut EiRegion;
    pub type EiRegionGetX = unsafe extern "C" fn(region: *const EiRegion) -> u32;
    pub type EiRegionGetY = unsafe extern "C" fn(region: *const EiRegion) -> u32;
    pub type EiRegionGetWidth = unsafe extern "C" fn(region: *const EiRegion) -> u32;
    pub type EiRegionGetHeight = unsafe extern "C" fn(region: *const EiRegion) -> u32;
    pub type EiDeviceStartEmulating = unsafe extern "C" fn(device: *mut EiDevice, sequence: u32);
    pub type EiDeviceFrame = unsafe extern "C" fn(device: *mut EiDevice, time_us: u64);
    pub type EiNow = unsafe extern "C" fn(ei: *mut Ei) -> u64;
    pub type EiDevicePointerMotionAbsolute =
        unsafe extern "C" fn(device: *mut EiDevice, x: f64, y: f64);
    pub type EiDeviceButtonButton =
        unsafe extern "C" fn(device: *mut EiDevice, button: u32, is_press: bool);
    pub type EiDeviceScrollDiscrete =
        unsafe extern "C" fn(device: *mut EiDevice, x: i32, y: i32);
    pub type EiDeviceKeyboardKey =
        unsafe extern "C" fn(device: *mut EiDevice, keycode: u32, is_press: bool);
    pub type EiDeviceTextKeysym =
        unsafe extern "C" fn(device: *mut EiDevice, keysym: u32, is_press: bool);
}

use abi::*;

struct EiApi {
    _lib: *mut c_void,
    ei_new_sender: EiNewSender,
    ei_unref: EiUnref,
    ei_configure_name: EiConfigureName,
    ei_setup_backend_fd: EiSetupBackendFd,
    ei_get_fd: EiGetFd,
    ei_dispatch: EiDispatch,
    ei_get_event: EiGetEvent,
    ei_event_unref: EiEventUnref,
    ei_event_get_type: abi::EiEventGetType,
    ei_event_get_seat: EiEventGetSeat,
    ei_event_get_device: EiEventGetDevice,
    ei_seat_bind_capabilities: EiSeatBindCapabilities,
    ei_device_ref: EiDeviceRef,
    ei_device_unref: EiDeviceUnref,
    ei_device_has_capability: EiDeviceHasCapability,
    ei_device_get_region: EiDeviceGetRegion,
    ei_region_get_x: EiRegionGetX,
    ei_region_get_y: EiRegionGetY,
    ei_region_get_width: EiRegionGetWidth,
    ei_region_get_height: EiRegionGetHeight,
    ei_device_start_emulating: EiDeviceStartEmulating,
    ei_device_frame: EiDeviceFrame,
    ei_now: EiNow,
    ei_device_pointer_motion_absolute: EiDevicePointerMotionAbsolute,
    ei_device_button_button: EiDeviceButtonButton,
    ei_device_scroll_discrete: EiDeviceScrollDiscrete,
    ei_device_keyboard_key: EiDeviceKeyboardKey,
    /// None on libei < ~1.4 (text device unavailable).
    ei_device_text_keysym: Option<EiDeviceTextKeysym>,
    /// None on libei < ~1.4 (plain `ei_seat_bind_capabilities` still works).
    ei_seat_request_device_with_capabilities: Option<EiSeatRequestDevice>,
}

unsafe impl Send for EiApi {}
unsafe impl Sync for EiApi {}

static EI: OnceLock<Result<EiApi, &'static str>> = OnceLock::new();

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
const RTLD_NOW: c_int = 0x2;
const RTLD_GLOBAL: c_int = 0x100;

fn load_ei() -> Result<EiApi, &'static str> {
    // SAFETY: dlopen/dlsym are thread-safe; signatures follow the public
    // libei headers (verified against 1.3 and 1.6).
    unsafe {
        let lib = ["libei.so.1", "libei.so"]
            .iter()
            .find_map(|name| {
                let cname = CString::new(*name).ok()?;
                let handle = dlopen(cname.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
                (!handle.is_null()).then_some(handle)
            })
            .ok_or("libei.so.1 not loadable (install libei for Wayland input)")?;

        macro_rules! sym {
            ($name:expr) => {{
                let cname = CString::new($name).map_err(|_| "bad symbol name")?;
                let ptr = dlsym(lib, cname.as_ptr());
                if ptr.is_null() {
                    return Err(concat!("libei missing symbol ", $name));
                }
                std::mem::transmute::<*mut c_void, _>(ptr)
            }};
        }
        macro_rules! sym_opt {
            ($name:expr) => {{
                let Ok(cname) = CString::new($name) else { unreachable!("literal") };
                let ptr = dlsym(lib, cname.as_ptr());
                (!ptr.is_null()).then(|| std::mem::transmute::<*mut c_void, _>(ptr))
            }};
        }

        Ok(EiApi {
            _lib: lib,
            ei_new_sender: sym!("ei_new_sender"),
            ei_unref: sym!("ei_unref"),
            ei_configure_name: sym!("ei_configure_name"),
            ei_setup_backend_fd: sym!("ei_setup_backend_fd"),
            ei_get_fd: sym!("ei_get_fd"),
            ei_dispatch: sym!("ei_dispatch"),
            ei_get_event: sym!("ei_get_event"),
            ei_event_unref: sym!("ei_event_unref"),
            ei_event_get_type: sym!("ei_event_get_type"),
            ei_event_get_seat: sym!("ei_event_get_seat"),
            ei_event_get_device: sym!("ei_event_get_device"),
            ei_seat_bind_capabilities: sym!("ei_seat_bind_capabilities"),
            ei_device_ref: sym!("ei_device_ref"),
            ei_device_unref: sym!("ei_device_unref"),
            ei_device_has_capability: sym!("ei_device_has_capability"),
            ei_device_get_region: sym!("ei_device_get_region"),
            ei_region_get_x: sym!("ei_region_get_x"),
            ei_region_get_y: sym!("ei_region_get_y"),
            ei_region_get_width: sym!("ei_region_get_width"),
            ei_region_get_height: sym!("ei_region_get_height"),
            ei_device_start_emulating: sym!("ei_device_start_emulating"),
            ei_device_frame: sym!("ei_device_frame"),
            ei_now: sym!("ei_now"),
            ei_device_pointer_motion_absolute: sym!("ei_device_pointer_motion_absolute"),
            ei_device_button_button: sym!("ei_device_button_button"),
            ei_device_scroll_discrete: sym!("ei_device_scroll_discrete"),
            ei_device_keyboard_key: sym!("ei_device_keyboard_key"),
            ei_device_text_keysym: sym_opt!("ei_device_text_keysym"),
            ei_seat_request_device_with_capabilities: sym_opt!(
                "ei_seat_request_device_with_capabilities"
            ),
        })
    }
}

/// One pointer device region (the screen area it addresses).
#[derive(Clone, Copy, Debug)]
struct Region {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

/// Live EIS connection state. Device pointers are refcounted on adoption;
/// everything is touched only under the owning mutex (the pump thread and
/// the RDP input handler serialize through it).
struct EiState {
    api: &'static EiApi,
    ei: *mut Ei,
    /// First device with POINTER_ABSOLUTE, plus its region for coordinate
    /// mapping (KRdp's mapping_id logic).
    pointer: Option<(*mut EiDevice, Option<Region>)>,
    keyboard: Option<*mut EiDevice>,
    text: Option<*mut EiDevice>,
    disconnected: bool,
}

unsafe impl Send for EiState {}

/// The input handler the RDP server drives.
pub(crate) struct EiInputHandler {
    state: Arc<Mutex<Option<EiState>>>,
    /// Screencast size — absolute motion is scaled from it into the device
    /// region.
    stream_size: (u32, u32),
    /// Keys the client holds; released wholesale on SynchronizeEvent (the
    /// same stuck-key protection the X11 path has).
    pressed_keys: Mutex<HashSet<u32>>,
    running: Arc<AtomicBool>,
}

impl EiInputHandler {
    /// Connect a sender context to the portal's EIS fd and start the event
    /// pump thread. Fails when libei is absent or the backend rejects the fd.
    pub(crate) fn new(
        eis_fd: std::os::fd::OwnedFd,
        stream_size: (u32, u32),
    ) -> anyhow::Result<Self> {
        let api = match EI.get_or_init(load_ei) {
            Ok(api) => api,
            Err(reason) => anyhow::bail!("libei unavailable: {reason}"),
        };

        // SAFETY: the ei context lives until Drop; it and its devices are
        // only used under the state mutex.
        unsafe {
            let ei = (api.ei_new_sender)(std::ptr::null_mut());
            if ei.is_null() {
                anyhow::bail!("ei_new_sender failed");
            }
            (api.ei_configure_name)(ei, c"linrdp".as_ptr());
            let fd = eis_fd
                .try_clone()
                .map_err(|e| anyhow::anyhow!("dup eis fd: {e}"))?;
            let rc = (api.ei_setup_backend_fd)(ei, std::os::fd::IntoRawFd::into_raw_fd(fd));
            if rc != 0 {
                (api.ei_unref)(ei);
                anyhow::bail!("ei_setup_backend_fd failed: {rc}");
            }

            let state = Arc::new(Mutex::new(Some(EiState {
                api,
                ei,
                pointer: None,
                keyboard: None,
                text: None,
                disconnected: false,
            })));
            let running = Arc::new(AtomicBool::new(true));
            let pump_state = Arc::clone(&state);
            let pump_running = Arc::clone(&running);
            let ei_fd = (api.ei_get_fd)(ei);
            std::thread::Builder::new()
                .name("linrdp-ei".into())
                .spawn(move || pump_events(pump_state, pump_running, ei_fd))
                .map_err(|e| anyhow::anyhow!("spawn ei thread: {e}"))?;

            Ok(Self {
                state,
                stream_size,
                pressed_keys: Mutex::new(HashSet::new()),
                running,
            })
        }
    }
}

impl Drop for EiInputHandler {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        // The pump exits within one poll timeout (250 ms) or on the next
        // event; take the state under the lock and tear it down.
        if let Ok(mut guard) = self.state.lock() {
            if let Some(mut state) = guard.take() {
                // SAFETY: last owner — the pump re-checks the lock after
                // every poll iteration and exits on None.
                unsafe {
                    if let Some((device, _)) = state.pointer.take() {
                        (state.api.ei_device_unref)(device);
                    }
                    if let Some(device) = state.keyboard.take() {
                        (state.api.ei_device_unref)(device);
                    }
                    if let Some(device) = state.text.take() {
                        (state.api.ei_device_unref)(device);
                    }
                    (state.api.ei_unref)(state.ei);
                }
            }
        }
    }
}

/// Event pump: poll the ei fd, then dispatch and drain under the state lock.
fn pump_events(state: Arc<Mutex<Option<EiState>>>, running: Arc<AtomicBool>, fd: i32) {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    unsafe extern "C" {
        fn poll(fds: *mut PollFd, nfds: u64, timeout: c_int) -> c_int;
    }
    const POLLIN: i16 = 0x001;

    while running.load(Ordering::Relaxed) {
        let mut pfd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: local pfd, valid for the call; 250 ms keeps the exit flag
        // responsive when no events arrive.
        let ready = unsafe { poll(&mut pfd, 1, 250) };
        if ready < 0 {
            continue; // EINTR et al.
        }

        let Ok(mut guard) = state.lock() else { break };
        let Some(live) = guard.as_mut() else { break };
        // SAFETY: everything below runs under the state mutex.
        unsafe {
            if ready == 1 && (pfd.revents & POLLIN) != 0 {
                (live.api.ei_dispatch)(live.ei);
            }
            drain_events(live);
        }
        if live.disconnected {
            tracing::warn!("EIS connection disconnected — Wayland input unavailable");
            break;
        }
    }
}

/// Drain all pending libei events, adopting/removing devices.
///
/// # Safety
/// Caller holds the state mutex.
unsafe fn drain_events(state: &mut EiState) {
    unsafe {
        loop {
            let event = (state.api.ei_get_event)(state.ei);
            if event.is_null() {
                return;
            }
            let kind = (state.api.ei_event_get_type)(event);
            match kind {
                EI_EVENT_DISCONNECT => state.disconnected = true,
                EI_EVENT_SEAT_ADDED => {
                    let seat = (state.api.ei_event_get_seat)(event);
                    if !seat.is_null() {
                        let wants_text = state.api.ei_device_text_keysym.is_some();
                        let text_cap = if wants_text { EI_DEVICE_CAP_TEXT } else { 0 };
                        // Variadic, sentinel-terminated capability list.
                        (state.api.ei_seat_bind_capabilities)(
                            seat,
                            EI_DEVICE_CAP_POINTER_ABSOLUTE,
                            EI_DEVICE_CAP_BUTTON,
                            EI_DEVICE_CAP_SCROLL,
                            EI_DEVICE_CAP_KEYBOARD,
                            text_cap,
                            std::ptr::null::<c_void>(),
                        );
                        if wants_text {
                            if let Some(request) =
                                state.api.ei_seat_request_device_with_capabilities
                            {
                                request(
                                    seat,
                                    EI_DEVICE_CAP_POINTER_ABSOLUTE,
                                    EI_DEVICE_CAP_BUTTON,
                                    EI_DEVICE_CAP_SCROLL,
                                    EI_DEVICE_CAP_KEYBOARD,
                                    EI_DEVICE_CAP_TEXT,
                                    std::ptr::null::<c_void>(),
                                );
                            }
                        }
                    }
                }
                EI_EVENT_DEVICE_ADDED => {
                    let device = (state.api.ei_event_get_device)(event);
                    if !device.is_null() {
                        adopt_device(state, device);
                        (state.api.ei_device_start_emulating)(device, 1);
                        tracing::debug!("EIS device added");
                    }
                }
                EI_EVENT_DEVICE_REMOVED => {
                    let device = (state.api.ei_event_get_device)(event);
                    if !device.is_null() {
                        drop_device(state, device);
                    }
                }
                EI_EVENT_DEVICE_RESUMED => {
                    let device = (state.api.ei_event_get_device)(event);
                    if !device.is_null() {
                        (state.api.ei_device_start_emulating)(device, 1);
                    }
                }
                _ => {}
            }
            (state.api.ei_event_unref)(event);
        }
    }
}

/// # Safety
/// Caller holds the state mutex; `device` came from an ADDED event.
unsafe fn adopt_device(state: &mut EiState, device: *mut EiDevice) {
    unsafe {
        if (state.api.ei_device_has_capability)(device, EI_DEVICE_CAP_POINTER_ABSOLUTE) {
            let region = device_region(state, device);
            if let Some((old, _)) = state.pointer.replace(((state.api.ei_device_ref)(device), region))
            {
                (state.api.ei_device_unref)(old);
            }
        }
        if state.keyboard.is_none()
            && (state.api.ei_device_has_capability)(device, EI_DEVICE_CAP_KEYBOARD)
        {
            state.keyboard = Some((state.api.ei_device_ref)(device));
        }
        if state.text.is_none()
            && state.api.ei_device_text_keysym.is_some()
            && (state.api.ei_device_has_capability)(device, EI_DEVICE_CAP_TEXT)
        {
            state.text = Some((state.api.ei_device_ref)(device));
        }
    }
}

/// # Safety
/// Caller holds the state mutex; `device` came from a REMOVED event and is
/// still owned by the event (only unref our references).
unsafe fn drop_device(state: &mut EiState, device: *mut EiDevice) {
    unsafe {
        if state.pointer.is_some_and(|(d, _)| d == device) {
            if let Some((old, _)) = state.pointer.take() {
                (state.api.ei_device_unref)(old);
            }
        }
        if state.keyboard == Some(device) {
            if let Some(old) = state.keyboard.take() {
                (state.api.ei_device_unref)(old);
            }
        }
        if state.text == Some(device) {
            if let Some(old) = state.text.take() {
                (state.api.ei_device_unref)(old);
            }
        }
    }
}

/// # Safety
/// Caller holds the state mutex.
unsafe fn device_region(state: &EiState, device: *mut EiDevice) -> Option<Region> {
    unsafe {
        let region = (state.api.ei_device_get_region)(device, 0);
        if region.is_null() {
            return None;
        }
        Some(Region {
            x: (state.api.ei_region_get_x)(region),
            y: (state.api.ei_region_get_y)(region),
            width: (state.api.ei_region_get_width)(region),
            height: (state.api.ei_region_get_height)(region),
        })
    }
}

impl RdpServerInputHandler for EiInputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        let Ok(mut guard) = self.state.lock() else { return };
        let Some(state) = guard.as_mut() else { return };
        // SAFETY: handler calls are serialized per session; the pump thread
        // shares the same mutex.
        unsafe {
            match event {
                KeyboardEvent::Pressed { code, extended } => {
                    if let Some(device) = state.keyboard {
                        if let Some(keycode) = evdev_keycode(code, extended) {
                            if let Ok(mut keys) = self.pressed_keys.lock() {
                                keys.insert(keycode);
                            }
                            (state.api.ei_device_keyboard_key)(device, keycode, true);
                            (state.api.ei_device_frame)(device, (state.api.ei_now)(state.ei));
                        }
                    }
                }
                KeyboardEvent::Released { code, extended } => {
                    if let Some(device) = state.keyboard {
                        if let Some(keycode) = evdev_keycode(code, extended) {
                            if let Ok(mut keys) = self.pressed_keys.lock() {
                                keys.remove(&keycode);
                            }
                            (state.api.ei_device_keyboard_key)(device, keycode, false);
                            (state.api.ei_device_frame)(device, (state.api.ei_now)(state.ei));
                        }
                    }
                }
                KeyboardEvent::UnicodePressed(code) => {
                    let Some(device) = state.text else {
                        tracing::debug!(
                            "unicode input dropped: no EIS text device (libei too old?)"
                        );
                        return;
                    };
                    let Some(text_keysym) = state.api.ei_device_text_keysym else {
                        return;
                    };
                    let keysym = unicode_to_keysym(u32::from(code));
                    if keysym != 0 {
                        text_keysym(device, keysym, true);
                        text_keysym(device, keysym, false);
                        (state.api.ei_device_frame)(device, (state.api.ei_now)(state.ei));
                    }
                }
                KeyboardEvent::UnicodeReleased(_) => {
                    // Press+release pair emitted on UnicodePressed.
                }
                KeyboardEvent::Synchronize(_) => {
                    // Release every held key — a lost key-release must not
                    // leave a key stuck (same protection as the X11 path).
                    let stuck: Vec<u32> = self
                        .pressed_keys
                        .lock()
                        .map(|mut keys| keys.drain().collect())
                        .unwrap_or_default();
                    if let Some(device) = state.keyboard {
                        for keycode in stuck {
                            (state.api.ei_device_keyboard_key)(device, keycode, false);
                        }
                        (state.api.ei_device_frame)(device, (state.api.ei_now)(state.ei));
                    }
                }
            }
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        let Ok(mut guard) = self.state.lock() else { return };
        let Some(state) = guard.as_mut() else { return };
        // SAFETY: as above.
        unsafe {
            let Some((pointer, region)) = state.pointer else { return };
            let now = (state.api.ei_now)(state.ei);
            match event {
                MouseEvent::Move { x, y } => {
                    let (dx, dy) = map_to_region(f64::from(x), f64::from(y), self.stream_size, region);
                    (state.api.ei_device_pointer_motion_absolute)(pointer, dx, dy);
                    (state.api.ei_device_frame)(pointer, now);
                }
                MouseEvent::Button { x, y, button, pressed } => {
                    let (dx, dy) = map_to_region(f64::from(x), f64::from(y), self.stream_size, region);
                    (state.api.ei_device_pointer_motion_absolute)(pointer, dx, dy);
                    let b = match button {
                        MouseButton::Left => BTN_LEFT,
                        MouseButton::Middle => BTN_MIDDLE,
                        MouseButton::Right => BTN_RIGHT,
                        _ => 0,
                    };
                    if b != 0 {
                        (state.api.ei_device_button_button)(pointer, b, pressed);
                        (state.api.ei_device_frame)(pointer, (state.api.ei_now)(state.ei));
                    }
                }
                // RDP wheel units are 120 per notch — exactly the discrete
                // step libei's receivers expect (KRdp passes them through
                // the same way).
                MouseEvent::VerticalScroll { value } => {
                    (state.api.ei_device_scroll_discrete)(pointer, 0, i32::from(value));
                    (state.api.ei_device_frame)(pointer, now);
                }
                MouseEvent::HorizontalScroll { value } => {
                    (state.api.ei_device_scroll_discrete)(pointer, -i32::from(value), 0);
                    (state.api.ei_device_frame)(pointer, now);
                }
                _ => {}
            }
        }
    }
}

/// RDP scancode → evdev keycode via the shared X keycode table (X keycode =
/// evdev + 8).
fn evdev_keycode(code: u8, extended: bool) -> Option<u32> {
    crate::input::keycode_for(code, extended).map(|x_keycode| u32::from(x_keycode) - 8)
}

/// Scale stream coordinates into the device region (KRdp's mapping).
fn map_to_region(x: f64, y: f64, stream: (u32, u32), region: Option<Region>) -> (f64, f64) {
    let Some(region) = region.filter(|r| r.width > 0 && r.height > 0) else {
        return (x, y);
    };
    let (sw, sh) = (f64::from(stream.0.max(1)), f64::from(stream.1.max(1)));
    (
        f64::from(region.x) + x / sw * f64::from(region.width),
        f64::from(region.y) + y / sh * f64::from(region.height),
    )
}

/// X keysym encoding: Latin-1 identity, else the Unicode plane base — the
/// same mapping the X11 TS_UNICODE path uses.
fn unicode_to_keysym(cp: u32) -> u32 {
    match cp {
        0x20..=0x7e => cp,
        _ => 0x0100_0000 | cp,
    }
}
