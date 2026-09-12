//! Wayland capture path (cargo feature `wayland`, off by default until it has
//! been exercised on a real Wayland session).
//!
//! This is the KRdp architecture ported to Rust, adapted to this server's
//! display pipeline:
//!
//! - `portal` — xdg-desktop-portal RemoteDesktop + ScreenCast client over
//!   the session bus (zbus): CreateSession → SelectDevices → SelectSources →
//!   Start → OpenPipeWireRemote (capture fd) + ConnectToEIS (input fd).
//! - `pipewire` — the screencast stream, driven through `dlopen`'d
//!   libpipewire (no build-time C dependency; raw BGRx frames into the same
//!   damage/EGFX machinery the X11 path uses).
//! - `ei` — input injection through `dlopen`'d libei over the portal's EIS
//!   fd (absolute pointer, buttons, discrete scroll, evdev keyboard; the
//!   text-keysym device is used opportunistically on libei ≥ 1.4).
//!
//! Nothing here links against libpipewire/libei at build time: missing
//! libraries degrade to a clear runtime error instead of a build failure,
//! keeping the single-binary property of the server.

pub(crate) mod ei;
pub(crate) mod pipewire;
pub(crate) mod portal;
