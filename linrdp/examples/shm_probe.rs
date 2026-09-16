//! Probe whether MIT-SHM actually works between this process and the X
//! server, and with which segment permissions.
//!
//! The capture path falls back to a full core-protocol GetImage per poll
//! whenever the SHM attach fails, which at 2880x1800 is ~20 MB per grab.
//! This isolates the attach itself: same segment mode the grabber uses
//! (0600), then a permissive one, so a uid mismatch between linrdp and the
//! X server shows up as "0600 fails, 0666 works".
//!
//! Run as the same user linrdp runs as:
//!   sudo env DISPLAY=:99 XAUTHORITY=/home/user/.Xauthority \
//!     cargo run -p linrdp --example shm_probe

use std::sync::Arc;

use x11rb::connection::Connection as _;
use x11rb::protocol::shm;

fn try_mode(conn: &Arc<x11rb::rust_connection::RustConnection>, size: usize, mode: i32) -> Result<(), String> {
    // SAFETY: plain SysV shmget with a private key; failure is a negative return.
    let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, size, mode | libc::IPC_CREAT) };
    if shmid < 0 {
        return Err(format!("shmget: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: attaching the segment just created; only failure is MAP_FAILED.
    let addr = unsafe { libc::shmat(shmid, core::ptr::null(), 0) };
    if addr == libc::MAP_FAILED {
        // SAFETY: valid id, never attached.
        unsafe { libc::shmctl(shmid, libc::IPC_RMID, core::ptr::null_mut()) };
        return Err(format!("shmat: {}", std::io::Error::last_os_error()));
    }

    let seg = conn.generate_id().map_err(|e| format!("generate_id: {e}"))?;
    let result = shm::attach(conn, seg, u32::try_from(shmid).unwrap(), false)
        .map_err(|e| format!("attach send: {e}"))
        .and_then(|cookie| cookie.check().map_err(|e| format!("attach: {e:?}")));

    if result.is_ok() {
        if let Ok(cookie) = shm::detach(conn, seg) {
            let _ = cookie.check();
        }
    }
    // SAFETY: detaching our mapping exactly once, then destroying the segment.
    unsafe { libc::shmdt(addr) };
    // SAFETY: valid id; both mappings are gone by now.
    unsafe { libc::shmctl(shmid, libc::IPC_RMID, core::ptr::null_mut()) };
    result
}

fn main() {
    let display = std::env::var("DISPLAY").unwrap_or_default();
    println!("uid={} euid={} DISPLAY={display}", unsafe { libc::getuid() }, unsafe {
        libc::geteuid()
    });

    let (conn, screen_num) = x11rb::connect(None).expect("connect to X");
    let conn = Arc::new(conn);
    let screen = &conn.setup().roots[screen_num];
    let (w, h) = (screen.width_in_pixels, screen.height_in_pixels);
    let size = usize::from(w) * usize::from(h) * 4;
    println!("screen {w}x{h}, segment {size} bytes");

    match shm::query_version(&*conn).map_err(|e| format!("{e}")).and_then(|c| c.reply().map_err(|e| format!("{e}"))) {
        Ok(v) => println!("MIT-SHM extension: present (v{}.{}, shared_pixmaps={})", v.major_version, v.minor_version, v.shared_pixmaps),
        Err(e) => {
            println!("MIT-SHM extension: ABSENT ({e})");
            return;
        }
    }

    for (label, mode) in [("0600 (what the grabber uses)", 0o600), ("0666", 0o666)] {
        match try_mode(&conn, size, mode) {
            Ok(()) => println!("  attach with {label}: OK"),
            Err(e) => println!("  attach with {label}: FAILED — {e}"),
        }
    }
}
