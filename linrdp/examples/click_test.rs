//! Probe: XTEST press (type 4) then release (type 5) — like xdotool click.
use x11rb::connection::Connection as _;
use x11rb::protocol::xtest::ConnectionExt as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let x: i16 = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(200);
    let y: i16 = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(200);
    let (conn, screen) = x11rb::connect(None)?;
    let root = conn.setup().roots[screen].root;
    conn.xtest_fake_input(6, 0, 0, root, x, y, 0)?; // MotionNotify
    conn.flush()?;
    std::thread::sleep(std::time::Duration::from_millis(120));
    conn.xtest_fake_input(4, 1, 0, root, x, y, 0)?; // ButtonPress
    conn.flush()?;
    std::thread::sleep(std::time::Duration::from_millis(80));
    conn.xtest_fake_input(5, 1, 0, root, x, y, 0)?; // ButtonRelease
    conn.flush()?;
    println!("XTEST click (press+release) at ({x},{y})");
    Ok(())
}
