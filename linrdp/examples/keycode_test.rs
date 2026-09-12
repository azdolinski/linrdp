//! Probe: XTEST-inject raw keycodes exactly like the input handler does —
//! verifies the server-side keymap (e.g. AltGr keycode 108 + c keycode 54
//! resolving to "ć" on the Polish programmer layout).

use x11rb::connection::Connection as _;
use x11rb::protocol::xtest::ConnectionExt as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, screen) = x11rb::connect(None)?;
    let root = conn.setup().roots[screen].root;
    // (keycode, press) pairs straight from the command line, e.g.
    // `keycode_test 108 54` presses 108 and 54, then releases both in reverse.
    let seq: Vec<u8> = std::env::args()
        .skip(1)
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;
    let mut pressed: Vec<u8> = Vec::new();
    for &kc in &seq {
        conn.xtest_fake_input(2, kc, 0, root, 0, 0, 0)?; // KeyPress
        conn.flush()?;
        pressed.push(kc);
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
    for kc in pressed.into_iter().rev() {
        conn.xtest_fake_input(3, kc, 0, root, 0, 0, 0)?; // KeyRelease
        conn.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
    println!("XTEST key sequence: {seq:?}");
    Ok(())
}
