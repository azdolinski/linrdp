//! Empirical probe: does a DAMAGE object on the ROOT window of Xvfb fire
//! when a child window redraws? (XDamage root-propagation assumption for
//! damage-driven screen capture.)
//!
//! Creates a root-window damage, maps a child window on :99, repaints it in
//! a loop, and counts root damage notifications for 5 seconds. Run with the
//! display already running:
//!
//! ```text
//! cargo run --release -p linrdp --example damage_probe -- :99
//! ```

#![allow(clippy::print_stdout)]

use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::connection::Connection as _;
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{ChangeGCAux, ConnectionExt as _, CreateGCAux, CreateWindowAux, Rectangle, WindowClass};
use x11rb::rust_connection::RustConnection;

fn main() -> anyhow::Result<()> {
    let display = std::env::args().nth(1).unwrap_or_else(|| ":99".to_owned());
    let (conn, screen_num) = RustConnection::connect(Some(&display))?;
    let screen = conn.setup().roots.get(screen_num).expect("screen");
    let root = screen.root;
    let white = conn.generate_id()?;
    conn.create_gc(white, root, &CreateGCAux::new())?;

    // Announce the DAMAGE extension and create a root-window damage object.
    damage::query_version(&conn, 1, 1)?.reply()?;
    let dmg = conn.generate_id()?;
    conn.damage_create(dmg, root, damage::ReportLevel::NON_EMPTY)?.check()?;
    println!("root damage created (id {dmg}), level NON_EMPTY");

    // A child window on top of the root.
    let win = conn.generate_id()?;
    let (w, h) = (400u16, 300u16);
    conn.create_window(
        x11rb::COPY_FROM_PARENT as u8,
        win,
        root,
        100,
        100,
        w,
        h,
        0,
        WindowClass::INPUT_OUTPUT,
        x11rb::COPY_FROM_PARENT,
        &CreateWindowAux::new().background_pixel(screen.white_pixel),
    )?
    .check()?;
    conn.map_window(win)?.check()?;
    conn.flush()?;
    std::thread::sleep(Duration::from_millis(300));

    let mut events = 0u64;
    let mut paints = 0u64;
    let started = Instant::now();
    let mut next_paint = Instant::now();
    let mut color = 0x000000u32;
    while started.elapsed() < Duration::from_secs(5) {
        // Repaint the child every 150 ms (contents change -> child damaged).
        if next_paint <= Instant::now() {
            color = (color + 0x111111) & 0xffffff;
            let gc = white;
            conn.change_gc(gc, &ChangeGCAux::new().foreground(color))?;
            conn.poly_rectangle(win, gc, &[Rectangle { x: 10, y: 10, width: w - 20, height: h - 20 }])?;
            conn.flush()?;
            paints += 1;
            next_paint = Instant::now() + Duration::from_millis(150);
        }

        // Drain any pending events, counting root damage notifications.
        loop {
            match conn.poll_for_event()? {
                Some(event) => {
                    if let x11rb::protocol::Event::DamageNotify(_) = event {
                        events += 1;
                    }
                }
                None => break,
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    println!("painted {paints}x, root damage notifications: {events}");
    if events > 0 {
        println!("RESULT: root-window damage catches child-window redraws on this server");
    } else {
        println!("RESULT: root-window damage does NOT propagate child redraws — damage must be per-window");
    }

    conn.damage_destroy(dmg)?.check()?;
    conn.destroy_window(win)?.check()?;
    conn.flush()?;
    Ok(())
}
