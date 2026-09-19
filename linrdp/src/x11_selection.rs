//! Owning the X11 CLIPBOARD selection with arbitrary MIME targets.
//!
//! arboard can only publish text/images and, on `Drop`, hands its data to an
//! X11 clipboard manager — on desktops without one the clipboard silently
//! empties. This module takes ownership of the CLIPBOARD selection on a
//! dedicated thread that lives until another client copies something, and
//! serves any target it is asked for (`text/uri-list`,
//! `x-special/gnome-copied-files`, `image/png`, `UTF8_STRING`, …), which is
//! what makes file and image paste into Linux applications work.

use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, CreateWindowAux, EventMask, PropMode, SelectionNotifyEvent, SelectionRequestEvent,
    WindowClass, SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::CURRENT_TIME;

/// One offered clipboard target: X11 atom name → payload bytes.
pub(crate) type SelectionTarget = (String, Vec<u8>);

/// Emit at most one selection-request summary per this interval.
const REQUEST_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Rate limiter for the selection-request log.
///
/// Desktop clipboard managers poll the selection owner continuously — a real
/// session produced ~3 requests every 0.7 s, non-stop, even with no RDP client
/// connected: 390k lines and 1.5 GB of log in five days, which buried every
/// WARN that mattered. `docs/learnings.md`: rate-limit every periodic debug
/// line.
#[derive(Default)]
struct RequestLog {
    served: u64,
    refused: u64,
    /// Target names seen since the last summary (bounded; diagnostics only).
    targets: Vec<String>,
    last: Option<Instant>,
}

impl RequestLog {
    fn record(&mut self, target: &str, served: bool) {
        if served {
            self.served += 1;
        } else {
            self.refused += 1;
        }
        if self.targets.len() < 16 && !self.targets.iter().any(|t| t == target) {
            self.targets.push(target.to_owned());
        }

        let now = Instant::now();
        let due = self.last.is_none_or(|last| now.duration_since(last) >= REQUEST_LOG_INTERVAL);
        if due {
            self.last = Some(now);
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.served == 0 && self.refused == 0 {
            return;
        }
        tracing::debug!(
            served = self.served,
            refused = self.refused,
            targets = ?self.targets,
            "clipboard: X11 selection requests"
        );
        self.served = 0;
        self.refused = 0;
        self.targets.clear();
    }
}

/// Resolve an atom back to the name we interned for it (diagnostics only).
fn atom_name(atoms: &[(Atom, String, Vec<u8>)], atom: Atom) -> String {
    atoms
        .iter()
        .find(|(known, _, _)| *known == atom)
        .map(|(_, name, _)| name.clone())
        .unwrap_or_else(|| format!("#{}", atom))
}

/// Act as an ordinary X11 client: request `target_name` from the CLIPBOARD
/// selection on `display` and return the property bytes (bounded wait).
///
/// Used by the poller to read file-manager targets (`x-special/gnome-copied-files`,
/// `text/uri-list`) that arboard's text API cannot see.
pub(crate) fn read_selection_target(display: &str, target_name: &str) -> Option<Vec<u8>> {
    read_selection_target_with_auth(display, "", target_name)
}

pub(crate) fn read_selection_target_with_auth(display: &str, xauthority: &str, target_name: &str) -> Option<Vec<u8>> {
    let (conn, screen_num) = if xauthority.is_empty() {
        x11rb::connect(if display.is_empty() { None } else { Some(display) }).ok()?
    } else {
        let mut parts = display.strip_prefix(':')?.split('.');
        let number = parts.next()?.parse::<u16>().ok()?;
        let screen = parts.next().unwrap_or("0").parse::<usize>().ok()?;
        let socket = std::os::unix::net::UnixStream::connect(format!("/tmp/.X11-unix/X{number}")).ok()?;
        let (stream, _) = x11rb::rust_connection::DefaultStream::from_unix_stream(socket).ok()?;
        let (name, data) = crate::session::xauth::cookie_for(std::path::Path::new(xauthority), number).ok()?;
        (RustConnection::connect_to_stream_with_auth_info(stream, screen, name, data).ok()?, screen)
    };
    let screen = &conn.setup().roots[screen_num];
    let win = conn.generate_id().ok()?;
    conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        win,
        screen.root,
        -1,
        -1,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
    )
    .ok()?;
    conn.flush().ok()?;
    let target = intern(&conn, target_name.as_bytes());
    let clipboard = intern(&conn, b"CLIPBOARD");
    let property = intern(&conn, b"LINRDP_READ_SELECTION");
    conn.convert_selection(win, clipboard, target, property, CURRENT_TIME).ok()?;
    conn.flush().ok()?;

    // poll_for_event never blocks; bound the total wait so a misbehaving
    // selection owner cannot hang the poller thread.
    let incr = intern(&conn, b"INCR");
    let mut chunks: Option<Vec<u8>> = None;
    let mut deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
    loop {
        match conn.poll_for_event() {
            Ok(Some(Event::SelectionNotify(notify))) => {
                if notify.property == x11rb::NONE {
                    return None;
                }
                let reply = conn.get_property(true, win, property, AtomEnum::ANY, 0, 2 * 1024 * 1024).ok()?.reply().ok()?;
                if reply.type_ == incr {
                    // ICCCM INCR: deleting each property acknowledges a chunk.
                    chunks = Some(Vec::new());
                    deadline = Instant::now() + Duration::from_secs(3);
                    conn.flush().ok()?;
                } else {
                    return (reply.bytes_after == 0).then_some(reply.value);
                }
            }
            Ok(Some(Event::PropertyNotify(event))) if chunks.is_some()
                && event.atom == property && event.state == x11rb::protocol::xproto::Property::NEW_VALUE => {
                let reply = conn.get_property(true, win, property, AtomEnum::ANY, 0, 2 * 1024 * 1024).ok()?.reply().ok()?;
                // Ignore a queued notification for the initial INCR property
                // that was already deleted by SelectionNotify handling.
                if reply.type_ == x11rb::NONE { continue; }
                if reply.bytes_after != 0 { return None; }
                let data = chunks.as_mut()?;
                if reply.value.is_empty() { return chunks; }
                if data.len().checked_add(reply.value.len())? > 8 * 1024 * 1024 { return None; }
                data.extend_from_slice(&reply.value);
                conn.flush().ok()?;
            }
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Take ownership of the CLIPBOARD selection on `display`, serving `targets`.
///
/// Ownership lasts until another client copies (we then receive
/// SelectionClear and the thread exits), so calling this again with new data
/// transparently replaces the previous contents.
pub(crate) fn take_ownership(display: String, targets: Vec<SelectionTarget>) {
    let spawn = std::thread::Builder::new().name("linrdp-cliprdr-x11sel".into()).spawn(move || {
        run(&display, targets);
    });
    if spawn.is_err() {
        tracing::warn!("clipboard: failed to spawn X11 selection owner thread");
    }
}

fn run(display: &str, targets: Vec<SelectionTarget>) {
    let dpy = if display.is_empty() { None } else { Some(display) };
    let (conn, screen_num) = match x11rb::connect(dpy) {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(%e, "clipboard: X11 selection owner cannot connect");
            return;
        }
    };
    let screen = &conn.setup().roots[screen_num];

    let clipboard = intern(&conn, b"CLIPBOARD");
    let targets_atom = intern(&conn, b"TARGETS");
    let atoms: Vec<(Atom, String, Vec<u8>)> = targets
        .iter()
        .map(|(name, data)| (intern(&conn, name.as_bytes()), name.clone(), data.clone()))
        .collect();

    let win = match conn.generate_id() {
        Ok(win) => win,
        Err(e) => {
            tracing::warn!(%e, "clipboard: cannot allocate X11 window id");
            return;
        }
    };
    if let Err(e) = conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        win,
        screen.root,
        -1,
        -1,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new(),
    ) {
        tracing::warn!(%e, "clipboard: cannot create X11 window for selection ownership");
        return;
    }
    if let Err(e) = conn.set_selection_owner(win, clipboard, CURRENT_TIME) {
        tracing::warn!(%e, "clipboard: cannot take X11 CLIPBOARD ownership");
        return;
    }
    if let Err(e) = conn.flush() {
        tracing::warn!(%e, "clipboard: cannot flush X11 connection");
        return;
    }
    let acquired = match conn.get_selection_owner(clipboard) {
        Ok(cookie) => matches!(cookie.reply(), Ok(reply) if reply.owner == win),
        Err(_) => false,
    };
    if !acquired {
        tracing::warn!("clipboard: another client kept the X11 CLIPBOARD ownership");
        return;
    }
    tracing::debug!(count = atoms.len(), "clipboard: owning X11 CLIPBOARD selection");

    let mut request_log = RequestLog::default();
    loop {
        let event = match conn.wait_for_event() {
            Ok(event) => event,
            Err(e) => {
                tracing::debug!(%e, "clipboard: X11 selection owner connection closed");
                break;
            }
        };
        match event {
            Event::SelectionRequest(request) => {
                handle_request(&conn, clipboard, targets_atom, &atoms, request, &mut request_log);
            }
            Event::SelectionClear(_) => {
                tracing::debug!("clipboard: X11 CLIPBOARD ownership lost (new copy elsewhere)");
                break;
            }
            _ => {}
        }
    }
    request_log.flush();
}

fn intern(conn: &RustConnection, name: &[u8]) -> Atom {
    conn.intern_atom(false, name)
        .ok()
        .and_then(|cookie| cookie.reply().ok())
        .map(|reply| reply.atom)
        .unwrap_or(x11rb::NONE)
}

fn handle_request(
    conn: &RustConnection,
    clipboard: Atom,
    targets_atom: Atom,
    atoms: &[(Atom, String, Vec<u8>)],
    request: SelectionRequestEvent,
    log: &mut RequestLog,
) {
    // ICCCM 2.3.1: a property of None means the requestor supports only the
    // (obsolete) pre-ICCCM protocol — answer on the target atom instead.
    let property = if request.property == x11rb::NONE {
        request.target
    } else {
        request.property
    };

    let mut served = false;
    if request.selection == clipboard {
        if request.target == targets_atom {
            let list: Vec<u32> = atoms.iter().map(|(atom, _, _)| *atom).collect();
            served = conn
                .change_property32(PropMode::REPLACE, request.requestor, property, AtomEnum::ATOM, &list)
                .is_ok();
        } else if let Some((_, _, data)) = atoms.iter().find(|(atom, _, _)| *atom == request.target) {
            served = conn
                .change_property8(PropMode::REPLACE, request.requestor, property, request.target, data)
                .is_ok();
        }
    }
    log.record(&atom_name(atoms, request.target), served);

    let notify = SelectionNotifyEvent {
        response_type: SELECTION_NOTIFY_EVENT,
        sequence: 0,
        time: request.time,
        requestor: request.requestor,
        selection: request.selection,
        target: request.target,
        property: if served { property } else { x11rb::NONE },
    };
    if let Err(e) = conn.send_event(false, request.requestor, EventMask::NO_EVENT, notify) {
        tracing::debug!(%e, "clipboard: failed to send SelectionNotify");
    }
    if let Err(e) = conn.flush() {
        tracing::debug!(%e, "clipboard: failed to flush X11 connection");
    }
}

/// Serializes tests that touch the (per-display, process-global) CLIPBOARD
/// selection — cargo-test runs them on parallel threads otherwise.
#[cfg(test)]
pub(crate) static X11_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn have_display() -> bool {
        std::env::var("DISPLAY").unwrap_or_default().contains(':')
    }

    #[test]
    fn selection_owner_serves_image_targets() {
        let _guard = X11_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !have_display() {
            eprintln!("skipping: no X11 display");
            return;
        }
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3].to_vec();
        take_ownership(
            std::env::var("DISPLAY").unwrap_or_default(),
            vec![("image/png".to_owned(), png.clone())],
        );
        std::thread::sleep(std::time::Duration::from_millis(400));

        assert_eq!(read_selection_target("", "image/png").as_deref(), Some(png.as_slice()));
        assert!(
            read_selection_target("", "image/not-offered").is_none(),
            "unknown target must be declined"
        );

        // TARGETS must advertise the atom list (format 32 = u32 atoms).
        let targets = read_selection_target("", "TARGETS").expect("TARGETS served");
        let atoms: Vec<u32> = targets
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        let (conn, _) = x11rb::connect(None).ok().unwrap();
        let png_atom = intern(&conn, b"image/png");
        assert!(atoms.contains(&png_atom), "TARGETS must list image/png, got {atoms:?}");

        // Cross-check with an independent X11 client if xclip is available.
        let xclip = std::process::Command::new("xclip")
            .args(["-o", "-selection", "clipboard", "-t", "image/png"])
            .output();
        if let Ok(output) = xclip {
            if output.status.success() {
                assert_eq!(output.stdout, png, "xclip must read the same PNG bytes");
            } else {
                eprintln!("skipping xclip cross-check: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
    }

    #[test]
    fn selection_owner_serves_gnome_copied_files() {
        let _guard = X11_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !have_display() {
            eprintln!("skipping: no X11 display");
            return;
        }
        let payload = b"copy\nfile:///tmp/linrdp-paste-0/a.txt".to_vec();
        take_ownership(
            std::env::var("DISPLAY").unwrap_or_default(),
            vec![("x-special/gnome-copied-files".to_owned(), payload.clone())],
        );
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert_eq!(
            read_selection_target("", "x-special/gnome-copied-files").as_deref(),
            Some(payload.as_slice())
        );
    }
}
