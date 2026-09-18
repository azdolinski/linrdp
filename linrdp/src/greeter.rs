//! The server-drawn logon screen.
//!
//! An RDP client that does not use NLA sends no credentials: it connects and
//! waits for the server to show a login screen, the way Winlogon does on
//! Windows and xrdp's own dialog does on Linux. Without one, such a client is
//! simply refused — mstsc reports 0x904 the moment you press Connect.
//!
//! This is that screen, and it is the path for deployments that want nothing
//! to do with PAM integration: no password is ever stored, nothing is
//! provisioned, and what the form collects goes straight to `/etc/shadow` and
//! PAM.
//!
//! It is drawn on **its own X server**, not into frames built by hand, and
//! that is the whole design:
//!
//! * The text is drawn by X with a core font, so linrdp carries no font of
//!   its own.
//! * Keystrokes arrive as RDP scancodes, are injected with XTEST, and come
//!   back out as keysyms that **XKB** has translated. A password with
//!   characters that depend on the layout works, which a hand-rolled
//!   scancode table would get wrong.
//! * Capture and input are the paths that already exist; nothing about the
//!   graphics pipeline has to know a logon screen exists.
//!
//! Nobody's session is on that X server, so showing it before anyone has
//! authenticated reveals nothing. Only after the form succeeds does the gate
//! move this worker to the user's own desktop (`session::gate::Binding`).

use anyhow::Context as _;
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::{self, ConnectionExt as _};

use crate::session::{display_alloc, keeper, privilege, runtime_dir, xauth};

/// Field the caret is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Field {
    Username,
    Password,
}

impl Field {
    fn other(self) -> Self {
        match self {
            Self::Username => Self::Password,
            Self::Password => Self::Username,
        }
    }
}

/// What the form is holding right now.
#[derive(Default, Debug)]
pub(crate) struct Form {
    username: String,
    password: String,
    error: Option<String>,
}

/// One keystroke's effect on the form.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Key {
    /// A character to append to the focused field.
    Char(char),
    Backspace,
    /// Move to the other field.
    Tab,
    /// Try to log in.
    Submit,
    /// Nothing this form cares about.
    Ignored,
}

/// Translate a keysym into what the form does with it.
///
/// Latin-1 keysyms are their own character and Unicode keysyms carry theirs in
/// the low bits, which together cover every printable character a keyboard
/// layout can produce. Everything else — function keys, modifiers, arrows — is
/// ignored rather than guessed at.
pub(crate) fn key_for(keysym: u32) -> Key {
    match keysym {
        0xFF08 => Key::Backspace,
        0xFF09 | 0xFE20 => Key::Tab, // Tab, ISO_Left_Tab
        0xFF0D | 0xFF8D => Key::Submit,                  // Return, KP_Enter
        // Latin-1: the keysym IS the code point, minus the control range.
        0x20..=0x7E | 0xA0..=0xFF => char::from_u32(keysym).map_or(Key::Ignored, Key::Char),
        // Unicode keysyms: 0x01000000 | code point.
        0x0100_0020..=0x0110_FFFF => char::from_u32(keysym & 0x00FF_FFFF).map_or(Key::Ignored, Key::Char),
        _ => Key::Ignored,
    }
}

impl Form {
    /// Apply a keystroke. Returns true when the user asked to log in.
    pub(crate) fn apply(&mut self, key: Key, focus: &mut Field) -> bool {
        match key {
            Key::Char(c) => {
                // A field that grows without limit is a way to make the server
                // allocate; a login name or password past this is not real.
                let target = match focus {
                    Field::Username => &mut self.username,
                    Field::Password => &mut self.password,
                };
                if target.chars().count() < 128 {
                    target.push(c);
                }
                self.error = None;
            }
            Key::Backspace => {
                match focus {
                    Field::Username => self.username.pop(),
                    Field::Password => self.password.pop(),
                };
                self.error = None;
            }
            Key::Tab => *focus = focus.other(),
            // Enter in the username field moves on rather than submitting an
            // empty password, which is what every login form does.
            Key::Submit if *focus == Field::Username && self.password.is_empty() => {
                *focus = Field::Password;
            }
            Key::Submit => return true,
            Key::Ignored => {}
        }
        false
    }

    /// What the password field shows: never the password.
    fn masked(&self) -> String {
        "•".repeat(self.password.chars().count())
    }
}

/// An X server that exists only to show the logon screen.
pub(crate) struct Greeter {
    pub(crate) display: u16,
    pub(crate) xauthority: String,
    pub(crate) runtime_dir: String,
    x_pid: i32,
    _lease: display_alloc::DisplayLease,
}

impl Greeter {
    /// Start the logon screen's X server.
    ///
    /// It runs as root with a 0600 cookie of its own, exactly like a session's
    /// server: no other account on the machine can read the screen somebody is
    /// typing a password into, or inject into it.
    pub(crate) fn start(
        state_dir: &std::path::Path,
        range: core::ops::RangeInclusive<u16>,
        size: (u16, u16),
    ) -> anyhow::Result<Self> {
        runtime_dir::ensure_state_dir(state_dir).context("prepare the session state directory")?;
        let lease = display_alloc::allocate(state_dir, range).context("no free display for the logon screen")?;
        let display_number = lease.number;

        let owner = privilege::lookup_user("root").context("look up root for the logon screen")?;
        // Its own runtime directory, not root's: the greeter's cookie must not
        // sit where a real root session keeps its own.
        //
        // Created here, by the half of the code that owns this directory's
        // lifecycle — `Drop` removes it again a few lines below. `write_cookie`
        // creates only the `linrdp` directory *inside* a runtime that already
        // exists, because for a real session that runtime is `pam_systemd`'s to
        // make and a cookie writer has no business creating one. The logon
        // screen has no PAM session, so nobody else would.
        let runtime = state_dir.join(format!("greeter-{display_number}"));
        std::fs::create_dir_all(&runtime)
            .with_context(|| format!("create the logon screen's runtime directory {}", runtime.display()))?;
        std::fs::set_permissions(&runtime, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", runtime.display()))?;
        let runtime = runtime.to_string_lossy().into_owned();
        let cookie = xauth::write_cookie(&runtime, display_number, &owner).context("write the logon screen's cookie")?;
        let xauthority = cookie.to_string_lossy().into_owned();

        let log = state_dir.join(format!("display-{display_number}.log"));
        let cmd = keeper::xvfb_command(display_number, &xauthority, size);
        let env = vec![("DISPLAY".to_owned(), format!(":{display_number}"))];
        keeper::clear_stale_display(display_number);
        let x_pid = keeper::spawn_child(&cmd, &env, &owner, &log).context("start the logon screen's X server")?;
        keeper::wait_for_display(display_number, core::time::Duration::from_secs(10)).inspect_err(|_| {
            // SAFETY: signalling a child we just forked.
            unsafe { libc::kill(x_pid, libc::SIGKILL) };
        })?;

        tracing::info!(display = display_number, "logon screen ready");
        Ok(Self {
            display: display_number,
            xauthority,
            runtime_dir: runtime,
            x_pid,
            _lease: lease,
        })
    }
}

impl Drop for Greeter {
    fn drop(&mut self) {
        // SAFETY: our own child; an already-dead pid fails harmlessly.
        unsafe {
            libc::kill(self.x_pid, libc::SIGTERM);
        }
        let mut status = 0;
        // SAFETY: reaping our own child.
        unsafe {
            libc::waitpid(self.x_pid, &mut status, 0);
        }
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
        tracing::info!(display = self.display, "logon screen torn down");
    }
}

/// Colours, as 0xRRGGBB.
const BACKGROUND: u32 = 0x0F_1B_2A;
const PANEL: u32 = 0x1B_2A_3D;
const TEXT: u32 = 0xE6_ED_F5;
const DIM: u32 = 0x8D_9C_AF;
const ACCENT: u32 = 0x4C_9A_FF;
const ERROR: u32 = 0xFF_6B_6B;

/// Draw the form and collect a username and password from it.
///
/// Blocks until the credentials `verify` accepts, so it runs on a thread of
/// its own. Returns `None` when the X connection dies — the client hung up.
pub(crate) fn run_form(
    conn: &x11rb::rust_connection::RustConnection,
    screen_num: usize,
    verify: &dyn Fn(&str, &str) -> bool,
) -> anyhow::Result<Option<(String, String)>> {
    let screen = conn.setup().roots.get(screen_num).context("no X screen")?;
    let root = screen.root;
    let (width, height) = (screen.width_in_pixels, screen.height_in_pixels);

    let window = conn.generate_id().context("window id")?;
    conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        window,
        root,
        0,
        0,
        width,
        height,
        0,
        xproto::WindowClass::INPUT_OUTPUT,
        x11rb::COPY_FROM_PARENT,
        &xproto::CreateWindowAux::new()
            .background_pixel(BACKGROUND)
            .override_redirect(1)
            .event_mask(xproto::EventMask::KEY_PRESS | xproto::EventMask::EXPOSURE),
    )
    .context("create the logon window")?
    .check()
    .context("logon window")?;
    conn.map_window(window).context("map")?.check().context("map the logon window")?;
    conn.set_input_focus(xproto::InputFocus::PARENT, window, x11rb::CURRENT_TIME)
        .context("focus")?
        .check()
        .context("focus the logon window")?;

    let font = open_font(conn);
    let gc = conn.generate_id().context("gc id")?;
    conn.create_gc(
        gc,
        window,
        &xproto::CreateGCAux::new().foreground(TEXT).background(BACKGROUND),
    )
    .context("create gc")?
    .check()
    .context("logon gc")?;
    if let Some(font) = font {
        let _ = conn.change_gc(gc, &xproto::ChangeGCAux::new().font(font));
    }

    let setup = conn.setup();
    let first_keycode = setup.min_keycode;
    let keycode_count = setup.max_keycode.saturating_sub(first_keycode).saturating_add(1);
    let keymap = conn
        .get_keyboard_mapping(first_keycode, keycode_count)
        .context("keyboard mapping request")?
        .reply()
        .context("keyboard mapping")?;

    let mut form = Form::default();
    let mut focus = Field::Username;
    draw(conn, window, gc, width, height, &form, focus)?;
    conn.flush().context("flush")?;

    loop {
        let event = match conn.wait_for_event() {
            Ok(event) => event,
            // The client hung up and the worker is tearing down.
            Err(_) => return Ok(None),
        };
        match event {
            x11rb::protocol::Event::Expose(_) => {}
            x11rb::protocol::Event::KeyPress(press) => {
                let shifted = press.state.contains(xproto::KeyButMask::SHIFT);
                let keysym = keysym_for(&keymap, first_keycode, press.detail, shifted);
                if form.apply(key_for(keysym), &mut focus) {
                    if form.username.is_empty() {
                        form.error = Some("Enter a user name".to_owned());
                    } else if verify(&form.username, &form.password) {
                        tracing::info!(user = %form.username, "logon screen: accepted");
                        return Ok(Some((form.username.clone(), form.password.clone())));
                    } else {
                        tracing::warn!(user = %form.username, "logon screen: rejected");
                        // Never say which half was wrong.
                        form.error = Some("Wrong user name or password".to_owned());
                        form.password.clear();
                        focus = Field::Password;
                    }
                }
            }
            _ => continue,
        }
        draw(conn, window, gc, width, height, &form, focus)?;
        conn.flush().context("flush")?;
    }
}

/// Rate limit for logon-screen attempts.
///
/// The form reads key events as fast as the client can send them, so without
/// this a client could walk a password list through it at network speed. PAM
/// counts failures when it is the backend, but the `/etc/shadow` fallback
/// counts nothing at all, and neither one slows down the *first* few guesses.
///
/// A flat delay before every attempt plus a growing one after each failure:
/// the first login costs a fraction of a second, the twentieth guess costs
/// seconds. Successful logins reset it, so a user who mistypes once is not
/// punished for the rest of the session.
#[derive(Debug, Default)]
pub(crate) struct AttemptThrottle {
    failures: std::cell::Cell<u32>,
}

impl AttemptThrottle {
    /// The floor: applied even to the first attempt, so a single round trip
    /// is never free.
    const FLOOR: core::time::Duration = core::time::Duration::from_millis(300);
    /// The ceiling, so a long-lived connection cannot be made to hold a
    /// thread forever.
    const CEILING: core::time::Duration = core::time::Duration::from_secs(5);

    /// Wait out this attempt's share of the delay. Call before verifying.
    pub(crate) fn before_attempt(&self) {
        std::thread::sleep(Self::delay(self.failures.get()));
    }

    /// Record how the attempt went.
    pub(crate) fn after_attempt(&self, accepted: bool) {
        self.failures.set(if accepted { 0 } else { self.failures.get().saturating_add(1) });
    }

    /// The delay owed after `failures` consecutive failures.
    fn delay(failures: u32) -> core::time::Duration {
        let scaled = Self::FLOOR.saturating_mul(1u32 << failures.min(8));
        scaled.min(Self::CEILING)
    }
}

/// The largest core font that is certainly present (`xfonts-base`), falling
/// back to whatever the server offers.
fn open_font(conn: &x11rb::rust_connection::RustConnection) -> Option<xproto::Font> {
    for name in ["10x20", "9x15bold", "fixed"] {
        let Ok(font) = conn.generate_id() else { continue };
        if conn.open_font(font, name.as_bytes()).is_ok_and(|c| c.check().is_ok()) {
            return Some(font);
        }
    }
    None
}

/// The keysym a keycode produces, honouring shift.
fn keysym_for(mapping: &xproto::GetKeyboardMappingReply, first: u8, keycode: u8, shifted: bool) -> u32 {
    let per = usize::from(mapping.keysyms_per_keycode);
    if per == 0 {
        return 0;
    }
    let index = usize::from(keycode.saturating_sub(first)) * per;
    let column = usize::from(shifted).min(per - 1);
    mapping.keysyms.get(index + column).copied().unwrap_or(0)
}

/// Repaint the whole form.
fn draw(
    conn: &x11rb::rust_connection::RustConnection,
    window: xproto::Window,
    gc: xproto::Gcontext,
    width: u16,
    height: u16,
    form: &Form,
    focus: Field,
) -> anyhow::Result<()> {
    let fill = |colour: u32, rects: &[xproto::Rectangle]| -> anyhow::Result<()> {
        conn.change_gc(gc, &xproto::ChangeGCAux::new().foreground(colour))?;
        conn.poly_fill_rectangle(window, gc, rects)?;
        Ok(())
    };
    let text = |colour: u32, x: i16, y: i16, s: &str| -> anyhow::Result<()> {
        conn.change_gc(gc, &xproto::ChangeGCAux::new().foreground(colour))?;
        // Core text is 8-bit; anything outside Latin-1 (the password mask)
        // is drawn as a stand-in rather than dropped.
        let bytes: Vec<u8> = s.chars().map(|c| u8::try_from(u32::from(c)).unwrap_or(b'*')).collect();
        conn.image_text8(window, gc, x, y, &bytes)?;
        Ok(())
    };

    let (pw, ph) = (440i16, 220i16);
    let px = (i16::try_from(width).unwrap_or(1024) - pw) / 2;
    let py = (i16::try_from(height).unwrap_or(768) - ph) / 2;

    fill(
        BACKGROUND,
        &[xproto::Rectangle {
            x: 0,
            y: 0,
            width,
            height,
        }],
    )?;
    fill(
        PANEL,
        &[xproto::Rectangle {
            x: px,
            y: py,
            width: u16::try_from(pw).unwrap_or(440),
            height: u16::try_from(ph).unwrap_or(220),
        }],
    )?;

    text(TEXT, px + 24, py + 40, "Log in")?;
    text(DIM, px + 24, py + 80, "User name")?;
    text(DIM, px + 24, py + 140, "Password")?;

    for (field, value, row) in [
        (Field::Username, form.username.clone(), py + 104),
        (Field::Password, form.masked(), py + 164),
    ] {
        let focused = field == focus;
        fill(
            if focused { ACCENT } else { DIM },
            &[xproto::Rectangle {
                x: px + 24,
                y: row + 6,
                width: u16::try_from(pw - 48).unwrap_or(392),
                height: 2,
            }],
        )?;
        let shown = if focused { format!("{value}_") } else { value };
        text(TEXT, px + 24, row, &shown)?;
    }

    if let Some(message) = &form.error {
        text(ERROR, px + 24, py + ph - 16, message)?;
    } else {
        text(DIM, px + 24, py + ph - 16, "Tab to switch field, Enter to log in")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Guessing must cost more each time. Without this the form accepted
    /// attempts as fast as a client could type them, and on the /etc/shadow
    /// fallback path nothing anywhere counted them.
    #[test]
    fn repeated_failures_cost_progressively_more() {
        use super::AttemptThrottle;
        assert!(AttemptThrottle::delay(0) >= AttemptThrottle::FLOOR, "even the first attempt waits");
        assert!(
            AttemptThrottle::delay(3) > AttemptThrottle::delay(0),
            "a fourth guess must cost more than the first"
        );
        assert_eq!(
            AttemptThrottle::delay(64),
            AttemptThrottle::CEILING,
            "the delay is capped, so a client cannot pin the thread forever"
        );
    }

    /// A user who mistypes once and then succeeds starts clean.
    #[test]
    fn a_successful_login_clears_the_penalty() {
        use super::AttemptThrottle;
        let throttle = AttemptThrottle::default();
        throttle.after_attempt(false);
        throttle.after_attempt(false);
        throttle.after_attempt(true);
        assert_eq!(throttle.failures.get(), 0);
    }

    use super::*;

    /// The password must never reach the screen.
    #[test]
    fn the_password_field_shows_only_a_mask() {
        let mut form = Form::default();
        let mut focus = Field::Password;
        for c in "hunter2".chars() {
            form.apply(Key::Char(c), &mut focus);
        }
        let masked = form.masked();
        assert_eq!(masked.chars().count(), 7, "one mark per character");
        assert!(!masked.contains('h') && !masked.contains('2'), "got {masked}");
    }

    /// Latin-1 and Unicode keysyms both carry their character; the keys a
    /// login form has no use for are ignored rather than guessed at.
    #[test]
    fn keysyms_become_characters() {
        assert_eq!(key_for(0x61), Key::Char('a'));
        assert_eq!(key_for(0x41), Key::Char('A'));
        assert_eq!(key_for(0x33), Key::Char('3'));
        assert_eq!(key_for(0x21), Key::Char('!'));
        // ą — the kind of character a Polish layout produces with AltGr, and
        // exactly what a hand-rolled scancode table would get wrong.
        assert_eq!(key_for(0x01000105), Key::Char('ą'));
        assert_eq!(key_for(0xFF08), Key::Backspace);
        assert_eq!(key_for(0xFF0D), Key::Submit);
        assert_eq!(key_for(0xFF09), Key::Tab);
        // F1, Shift, Left — nothing the form should invent a character for.
        assert_eq!(key_for(0xFFBE), Key::Ignored);
        assert_eq!(key_for(0xFFE1), Key::Ignored);
        assert_eq!(key_for(0xFF51), Key::Ignored);
    }

    /// Enter in the user name field moves on instead of submitting an empty
    /// password, and Tab walks between the two.
    #[test]
    fn enter_on_the_user_name_moves_to_the_password() {
        let mut form = Form::default();
        let mut focus = Field::Username;
        form.apply(Key::Char('r'), &mut focus);
        assert!(!form.apply(Key::Submit, &mut focus), "must not submit yet");
        assert_eq!(focus, Field::Password);

        form.apply(Key::Char('x'), &mut focus);
        assert!(form.apply(Key::Submit, &mut focus), "now it submits");

        form.apply(Key::Tab, &mut focus);
        assert_eq!(focus, Field::Username);
    }

    /// Backspace edits the focused field and nothing else.
    #[test]
    fn backspace_only_touches_the_focused_field() {
        let mut form = Form::default();
        let mut focus = Field::Username;
        for c in "root".chars() {
            form.apply(Key::Char(c), &mut focus);
        }
        form.apply(Key::Tab, &mut focus);
        for c in "pw".chars() {
            form.apply(Key::Char(c), &mut focus);
        }
        form.apply(Key::Backspace, &mut focus);
        assert_eq!(form.username, "root");
        assert_eq!(form.password, "p");
    }

    /// A field that grows without limit is a way to make the server allocate.
    #[test]
    fn fields_are_bounded() {
        let mut form = Form::default();
        let mut focus = Field::Username;
        for _ in 0..500 {
            form.apply(Key::Char('a'), &mut focus);
        }
        assert_eq!(form.username.chars().count(), 128);
    }
}
