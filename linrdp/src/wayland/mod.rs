//! Wayland desktops (cargo feature `wayland`, on by default).
//!
//! Two ways into a Wayland desktop, `mutter` and `portal`, sharing the rest:
//!
//! - `mutter` — GNOME: Mutter's own remote-desktop and screencast API on the
//!   account's session bus, which asks nobody for consent. This is what
//!   serves GNOME logins (`session::backends`); `display_mode` rearranges
//!   the monitors for it.
//! - `portal` — xdg-desktop-portal RemoteDesktop + ScreenCast over the
//!   session bus (zbus), the KRdp architecture ported to Rust: CreateSession
//!   → SelectDevices → SelectSources → Start → OpenPipeWireRemote (capture
//!   fd) + ConnectToEIS (input fd). Behind `features.wayland`, for the
//!   single desktop linrdp itself runs in.
//! - `pipewire` — the screencast stream, driven through `dlopen`'d
//!   libpipewire (no build-time C dependency; raw BGRx frames into the same
//!   damage/EGFX machinery the X11 path uses).
//! - `ei` — input injection through `dlopen`'d libei over the portal's EIS
//!   fd (absolute pointer, buttons, discrete scroll, evdev keyboard; the
//!   text-keysym device is used opportunistically on libei ≥ 1.4).
//! - `compositor` — the one desktop a worker serves through its compositor,
//!   which the display, input and clipboard paths follow without knowing
//!   which compositor it is.
//!
//! Nothing here links against libpipewire/libei at build time: missing
//! libraries degrade to a clear runtime error instead of a build failure,
//! keeping the single-binary property of the server.

pub(crate) mod compositor;
pub(crate) mod display_mode;
pub(crate) mod ei;
pub(crate) mod mutter;
pub(crate) mod pipewire;
pub(crate) mod portal;
