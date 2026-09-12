//! Input injection: keyboard and mouse events from the RDP client are fed
//! into the X11 server via XTEST (x11rb, pure Rust — no external binaries),
//! so the remote desktop reacts exactly like a local console session.

use std::collections::HashSet;
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

/// Translate an RDP scancode (XT set 1, MS-RDPBCGR 2.2.8.1.1.3.1.1.1) to an
/// X keycode on the evdev layout every modern X server uses (X keycode =
/// Linux input keycode + 8). Non-extended scancodes keep the identity
/// `scancode + 8` because the Linux main-block keycodes equal set 1
/// scancodes. Extended (0xE0-prefixed) keys do NOT: the kernel assigned
/// them dedicated numbers (KEY_LEFT=105 etc.), so they need this table.
/// The old `+128` offset only fits the pre-evdev "kbd" driver layout.
fn keycode_for(code: u8, extended: bool) -> Option<u8> {
    if !extended {
        return u8::try_from(u16::from(code) + 8).ok();
    }
    match code {
        0x1C => Some(104), // KP_Enter
        0x1D => Some(105), // Control_R
        0x35 => Some(106), // KP_Divide
        0x37 => Some(107), // PrintScreen
        0x38 => Some(108), // AltGr (Alt_R)
        0x47 => Some(110), // Home
        0x48 => Some(111), // Up
        0x49 => Some(112), // PageUp
        0x4B => Some(113), // Left
        0x4D => Some(114), // Right
        0x4F => Some(115), // End
        0x50 => Some(116), // Down
        0x51 => Some(117), // PageDown
        0x52 => Some(118), // Insert
        0x53 => Some(119), // Delete
        0x5B => Some(133), // Super_L
        0x5C => Some(134), // Super_R
        0x5D => Some(135), // Menu
        // Unknown 0xE0-prefixed scancode: keep the legacy +128 offset as a
        // last resort; on evdev layouts those keycodes are unassigned, so
        // the event is simply a no-op rather than a wrong key.
        _ => u8::try_from(u16::from(code) + 8 + 128).ok(),
    }
}

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
    /// X keycodes the client currently holds down, so a client
    /// SynchronizeEvent (which resynchronizes keyboard state) can release
    /// them — a lost key-release must not leave a key stuck down forever
    /// (the repeating-key symptom KRdp guards against the same way).
    pressed_keys: HashSet<u8>,
    /// Rate limit for reconnect attempts while the X server is down, so a
    /// client streaming mouse moves cannot turn into a log/reconnect storm.
    last_reconnect_attempt: Option<std::time::Instant>,
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
            pressed_keys: HashSet::new(),
            last_reconnect_attempt: None,
        })
    }

    /// The desktop X server (Xvfb) is a separate systemd unit that can crash
    /// and come back at any moment — requests against the stale socket all
    /// fail, which the user experiences as a frozen picture that ignores
    /// every click and keystroke. Re-establish the connection on demand; the
    /// caller retries the event once when this succeeds. Rate-limited to one
    /// attempt per second while the X server stays unreachable.
    fn reconnect(&mut self) -> bool {
        if let Some(last) = self.last_reconnect_attempt {
            if last.elapsed() < std::time::Duration::from_secs(1) {
                return false;
            }
        }
        self.last_reconnect_attempt = Some(std::time::Instant::now());
        let display_name = std::env::var("DISPLAY").unwrap_or_else(|_| ":99".to_owned());
        match x11rb::rust_connection::RustConnection::connect(Some(display_name.as_str())) {
            Ok((conn, screen_num)) => {
                let Some(screen) = conn.setup().roots.get(screen_num) else {
                    return false;
                };
                self.root = screen.root;
                self.conn = Arc::new(conn);
                // Fresh server = fresh keyboard mapping: the scratch keycode
                // must be rediscovered before the next TS_UNICODE event.
                self.unicode_keycode = None;
                tracing::warn!("X server connection for input was dead — reconnected");
                true
            }
            Err(_) => false,
        }
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

    /// TS_SYNC_FLAGS (2.2.8.1.1.3.1.1.5): the client is resynchronizing its
    /// keyboard state. Release every key we still believe is held — a lost
    /// key-release (network hiccup, client crash mid-press) must not leave a
    /// key stuck down on the X server — then bring the lock states in line
    /// with the client's by toggling the corresponding lock keys.
    fn synchronize(&mut self, want: SynchronizeFlags) {
        if !self.pressed_keys.is_empty() {
            tracing::debug!(
                count = self.pressed_keys.len(),
                "keyboard synchronize: releasing held key(s)"
            );
        }
        for keycode in std::mem::take(&mut self.pressed_keys) {
            self.fake_key(keycode, false);
        }

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

    fn fake_key(&mut self, keycode: u8, pressed: bool) {
        let ty = if pressed { FAKE_KEY_PRESS } else { FAKE_KEY_RELEASE };
        let err = match self.conn.xtest_fake_input(ty, keycode, 0, self.root, 0, 0, XTEST_DEVICE_ID) {
            Ok(_) => None,
            Err(e) => Some(e),
        };
        if let Some(e) = err {
            tracing::warn!(error = %e, keycode, "XTEST key event failed");
            if self.reconnect() {
                let _ = self.conn.xtest_fake_input(ty, keycode, 0, self.root, 0, 0, XTEST_DEVICE_ID);
            }
        }
    }

    fn fake_button(&mut self, button: u8, pressed: bool) {
        let ty = if pressed { FAKE_BUTTON_PRESS } else { FAKE_BUTTON_RELEASE };
        let err = match self.conn.xtest_fake_input(ty, button, 0, self.root, 0, 0, XTEST_DEVICE_ID) {
            Ok(_) => None,
            Err(e) => Some(e),
        };
        if let Some(e) = err {
            tracing::warn!(error = %e, button, "XTEST button event failed");
            if self.reconnect() {
                let _ = self.conn.xtest_fake_input(ty, button, 0, self.root, 0, 0, XTEST_DEVICE_ID);
            }
        }
    }

    fn fake_motion(&mut self, x: u16, y: u16) {
        let (mx, my) = (i16::try_from(x).unwrap_or(i16::MAX), i16::try_from(y).unwrap_or(i16::MAX));
        let err = match self.conn.xtest_fake_input(FAKE_MOTION, 0, 0, self.root, mx, my, XTEST_DEVICE_ID) {
            Ok(_) => None,
            Err(e) => Some(e),
        };
        if let Some(e) = err {
            tracing::warn!(error = %e, "XTEST motion failed");
            if self.reconnect() {
                let _ = self.conn.xtest_fake_input(FAKE_MOTION, 0, 0, self.root, mx, my, XTEST_DEVICE_ID);
            }
        }
    }
}

impl RdpServerInputHandler for X11InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        tracing::debug!(?event, "input: keyboard");
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                if let Some(kc) = keycode_for(code, extended) {
                    self.pressed_keys.insert(kc);
                    self.fake_key(kc, true);
                }
            }
            KeyboardEvent::Released { code, extended } => {
                if let Some(kc) = keycode_for(code, extended) {
                    self.pressed_keys.remove(&kc);
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

#[cfg(test)]
mod tests {
    use super::keycode_for;

    // Expected keycodes verified against the live Xvfb keymap (evdev
    // layout, `xmodmap -pk`): Up=111, Left=113, Right=114, Down=116.
    #[test]
    fn extended_keys_map_to_evdev_keycodes() {
        assert_eq!(keycode_for(0x48, true), Some(111)); // Up
        assert_eq!(keycode_for(0x4B, true), Some(113)); // Left
        assert_eq!(keycode_for(0x4D, true), Some(114)); // Right
        assert_eq!(keycode_for(0x50, true), Some(116)); // Down
        assert_eq!(keycode_for(0x1D, true), Some(105)); // Control_R
        assert_eq!(keycode_for(0x38, true), Some(108)); // AltGr
        assert_eq!(keycode_for(0x53, true), Some(119)); // Delete
    }

    #[test]
    fn plain_keys_stay_scancode_plus_eight() {
        assert_eq!(keycode_for(0x1E, false), Some(38)); // 'a'
        assert_eq!(keycode_for(0x3A, false), Some(66)); // CapsLock
    }
}
