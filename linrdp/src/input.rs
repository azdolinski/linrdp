//! Input injection: keyboard and mouse events from the RDP client are fed
//! into the X11 server via XTEST (x11rb, pure Rust — no external binaries),
//! so the remote desktop reacts exactly like a local console session.

use std::sync::Arc;

use anyhow::Context as _;
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;

use ironrdp_pdu::input::fast_path::SynchronizeFlags;
use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler};

// XTEST FakeInput event types (X.Org xtest protocol).
const FAKE_KEY_PRESS: u8 = 2;
const FAKE_KEY_RELEASE: u8 = 3;
const FAKE_BUTTON_PRESS: u8 = 4;
const FAKE_BUTTON_RELEASE: u8 = 5;
const FAKE_MOTION: u8 = 6;
// XTEST uses a special device id for synthesized input.
const XTEST_DEVICE_ID: u8 = 0;

// Lock-key keycodes on the evdev/Xvfb layout (XT scancode + 8): CapsLock
// 0x3A->66, NumLock 0x45->77, ScrollLock 0x46->78.
const KEYCODE_CAPS_LOCK: u8 = 66;
const KEYCODE_NUM_LOCK: u8 = 77;
const KEYCODE_SCROLL_LOCK: u8 = 78;

#[derive(Debug, Clone)]
pub(crate) struct X11InputHandler {
    conn: Arc<x11rb::rust_connection::RustConnection>,
    root: u32,
    /// Keycode remapped on the fly for TS_UNICODE injection (MS-RDPBCGR
    /// 2.2.8.1.1.3.1.1.4): discovered lazily as a keycode with no keysyms
    /// bound, then pointed at the needed Unicode keysym before each
    /// press/release pair.
    unicode_keycode: Option<u8>,
    /// Our belief of the X server lock states, tracked so a client
    /// TS_SYNC_FLAGS event (2.2.8.1.1.3.1.1.5) can toggle the locks toward
    /// the requested state. Starts all-off, matching a fresh Xvfb.
    locks: SynchronizeFlags,
}

impl X11InputHandler {
    pub(crate) fn connect() -> anyhow::Result<Self> {
        let display_name = std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_owned());
        let (conn, screen_num) = x11rb::rust_connection::RustConnection::connect(Some(display_name.as_str()))
            .with_context(|| format!("connect to X display {display_name}"))?;
        let root = conn.setup().roots.get(screen_num).context("no X screen")?.root;
        Ok(Self {
            conn: Arc::new(conn),
            root,
            unicode_keycode: None,
            locks: SynchronizeFlags::empty(),
        })
    }

    /// Find a keycode with no keysyms bound anywhere (NoSymbol in every
    /// group) — safe to remap for Unicode injection.
    fn find_free_keycode(&self) -> Option<u8> {
        let setup = self.conn.setup();
        let min = setup.min_keycode;
        let max = setup.max_keycode;
        let count = max - min + 1;
        let reply = self
            .conn
            .get_keyboard_mapping(min, count)
            .ok()?
            .reply()
            .ok()?;
        let per_keycode = usize::from(reply.keysyms_per_keycode.max(1));
        for (i, chunk) in reply.keysyms.chunks(per_keycode).enumerate() {
            if chunk.iter().all(|&sym| sym == 0) {
                return Some(min + i as u8);
            }
        }
        None
    }

    /// TS_UNICODE (MS-RDPBCGR 2.2.8.1.1.3.1.1.4): remap the scratch keycode
    /// to the character's keysym and press it. Latin-1 code points use their
    /// identity keysym; the rest use the Unicode keysym range (0x0100_0000 |
    /// cp, X11 protocol § "Keysym Encoding").
    fn send_unicode(&mut self, code: u16) {
        let Some(ch) = char::from_u32(u32::from(code)) else {
            return;
        };
        let cp = u32::from(ch);
        let keysym = if (0x20..=0x7e).contains(&cp) { cp } else { 0x0100_0000 | cp };

        if self.unicode_keycode.is_none() {
            self.unicode_keycode = self.find_free_keycode();
            if let Some(kc) = self.unicode_keycode {
                tracing::debug!(keycode = kc, "using keycode for TS_UNICODE injection");
            } else {
                tracing::warn!("no free keycode for TS_UNICODE injection; unicode input dropped");
            }
        }
        let Some(keycode) = self.unicode_keycode else { return };

        if let Err(e) = self
            .conn
            .change_keyboard_mapping(1, keycode, 1, &[keysym])
        {
            tracing::warn!(error = %e, "ChangeKeyboardMapping failed for unicode input");
            return;
        }
        // Wait for the mapping change to land before synthesizing the key.
        let _ = x11rb::wrapper::ConnectionExt::sync(self.conn.as_ref());
        self.fake_key(keycode, true);
        self.fake_key(keycode, false);
    }

    /// TS_SYNC_FLAGS (2.2.8.1.1.3.1.1.5): bring the X server lock states in
    /// line with the client's by toggling the corresponding lock keys.
    fn synchronize(&mut self, want: SynchronizeFlags) {
        let toggles = [
            (want.contains(SynchronizeFlags::CAPS_LOCK), self.locks.contains(SynchronizeFlags::CAPS_LOCK), KEYCODE_CAPS_LOCK, SynchronizeFlags::CAPS_LOCK),
            (want.contains(SynchronizeFlags::NUM_LOCK), self.locks.contains(SynchronizeFlags::NUM_LOCK), KEYCODE_NUM_LOCK, SynchronizeFlags::NUM_LOCK),
            (want.contains(SynchronizeFlags::SCROLL_LOCK), self.locks.contains(SynchronizeFlags::SCROLL_LOCK), KEYCODE_SCROLL_LOCK, SynchronizeFlags::SCROLL_LOCK),
        ];
        for (desired, current, keycode, flag) in toggles {
            if desired != current {
                self.fake_key(keycode, true);
                self.fake_key(keycode, false);
                self.locks.toggle(flag);
            }
        }
    }

    fn fake_key(&self, keycode: u8, pressed: bool) {
        let ty = if pressed { FAKE_KEY_PRESS } else { FAKE_KEY_RELEASE };
        if let Err(e) = self.conn.xtest_fake_input(ty, keycode, 0, self.root, 0, 0, XTEST_DEVICE_ID) {
            tracing::warn!(error = %e, keycode, "XTEST key event failed");
        }
    }

    fn fake_button(&self, button: u8, pressed: bool) {
        let ty = if pressed { FAKE_BUTTON_PRESS } else { FAKE_BUTTON_RELEASE };
        if let Err(e) = self.conn.xtest_fake_input(ty, button, 0, self.root, 0, 0, XTEST_DEVICE_ID) {
            tracing::warn!(error = %e, button, "XTEST button event failed");
        }
    }

    fn fake_motion(&self, x: u16, y: u16) {
        if let Err(e) = self.conn.xtest_fake_input(
            FAKE_MOTION,
            0,
            0,
            self.root,
            i16::try_from(x).unwrap_or(i16::MAX),
            i16::try_from(y).unwrap_or(i16::MAX),
            XTEST_DEVICE_ID,
        ) {
            tracing::warn!(error = %e, "XTEST motion failed");
        }
    }
}

impl RdpServerInputHandler for X11InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        tracing::debug!(?event, "input: keyboard");
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                // RDP scancodes are XT scancodes; X11 keycodes are scancode + 8.
                // Extended (right Ctrl/Alt etc.) prefix 0xE0 maps onto keycode
                // offset 128 in classic X11 layouts; without it most keys work.
                let base = u16::from(code) + 8 + u16::from(extended) * 128;
                if let Ok(kc) = u8::try_from(base) {
                    self.fake_key(kc, true);
                }
            }
            KeyboardEvent::Released { code, extended } => {
                let base = u16::from(code) + 8 + u16::from(extended) * 128;
                if let Ok(kc) = u8::try_from(base) {
                    self.fake_key(kc, false);
                }
            }
            KeyboardEvent::UnicodePressed(code) => self.send_unicode(code),
            KeyboardEvent::UnicodeReleased(_) => {
                // send_unicode emits the full press/release pair on the
                // pressed event; nothing to do on release.
            }
            KeyboardEvent::Synchronize(flags) => self.synchronize(flags),
        }
        let _ = self.conn.flush();
    }

    fn mouse(&mut self, event: MouseEvent) {
        tracing::debug!(?event, "input: mouse");
        match event {
            MouseEvent::Move { x, y } => self.fake_motion(x, y),
            MouseEvent::Button { x, y, button, pressed } => {
                self.fake_motion(x, y);
                let b = match button {
                    MouseButton::Left => 1,
                    MouseButton::Middle => 2,
                    MouseButton::Right => 3,
                    _ => 0,
                };
                if b != 0 {
                    self.fake_button(b, pressed);
                }
            }
            MouseEvent::ButtonRel { .. } | MouseEvent::RelMove { .. } => {
                // Relative mode needs pointer warping with accumulated deltas;
                // absolute mode is negotiated by default (RDP_CAPSET_POINTER).
            }
            MouseEvent::VerticalScroll { value } => {
                // Positive value = wheel up (button 4), negative = down (5).
                let steps = value.unsigned_abs().clamp(1, 10);
                let b = if value >= 0 { 4 } else { 5 };
                for _ in 0..steps {
                    self.fake_button(b, true);
                    self.fake_button(b, false);
                }
            }
            MouseEvent::HorizontalScroll { value } => {
                let steps = value.unsigned_abs().clamp(1, 10);
                let b = if value >= 0 { 7 } else { 6 };
                for _ in 0..steps {
                    self.fake_button(b, true);
                    self.fake_button(b, false);
                }
            }
            MouseEvent::Scroll { .. } => {}
            _ => {}
        }
        let _ = self.conn.flush();
    }
}
