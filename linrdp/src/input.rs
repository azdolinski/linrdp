//! Input injection: keyboard and mouse events from the RDP client are fed
//! into the X11 server via XTEST (x11rb, pure Rust — no external binaries),
//! so the remote desktop reacts exactly like a local console session.

use std::sync::Arc;

use anyhow::Context as _;
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;

use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler};

// XTEST FakeInput event types (X.Org xtest protocol).
const FAKE_KEY_PRESS: u8 = 2;
const FAKE_KEY_RELEASE: u8 = 3;
const FAKE_BUTTON_PRESS: u8 = 4;
const FAKE_BUTTON_RELEASE: u8 = 5;
const FAKE_MOTION: u8 = 6;
// XTEST uses a special device id for synthesized input.
const XTEST_DEVICE_ID: u8 = 0;

#[derive(Debug, Clone)]
pub(crate) struct X11InputHandler {
    conn: Arc<x11rb::rust_connection::RustConnection>,
    root: u32,
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
        })
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
            KeyboardEvent::UnicodePressed(_) | KeyboardEvent::UnicodeReleased(_) => {
                // No direct unicode path via XTEST; keysym mapping is out of
                // scope for this build — ignore silently.
            }
            KeyboardEvent::Synchronize(_) => {}
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
