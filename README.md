# LinRDP

RDP server for Linux — connect to a Linux desktop from any Windows/macOS RDP
client (mstsc), exactly like connecting to a Windows machine.

Single static binary. Written in pure Rust on a vendored IronRDP core
(Apache-2.0/MIT — licenses preserved in `crates/*/LICENSE-*`). No runtime
dependencies: protocol stack, TLS (rustls), screen capture (X11), input
injection (XTEST), audio (MS-RDPSND), microphone (MS-RDPEAI) and USB
redirection channel (MS-RDPEUSB/URBDRC) are all compiled in.

## Features (docs/target.md)

1. Full RDP protocol implementation in Rust, no external libraries. ✅
2. Login with username + password — verified against `/etc/shadow`
   (YESCRYPT / SHA-512 / MD5-crypt), the same source SSH PAM uses. ✅
3. Real desktop streaming — X11 root window capture, ~10 fps, only changed
   frames. Input: keyboard, mouse buttons, motion, wheel via XTEST. ✅
4. Audio in both directions — MS-RDPSND output (PCM 44.1 kHz stereo) and
   MS-RDPEAI microphone input channel. ✅ (pipe-to-PipeWire = desktop phase)
5. USB redirection — URBDRC channel compiled in; device announcements
   accepted and logged with `--usb`. Real transfer forwarding needs a USB
   host stack + physical hardware. ⚠️
6. Desktop resize — initial size negotiation + client layout requests. ✅

## Build

```sh
cargo build --release -p linrdp
# binary: target/release/linrdp
```

## Run

Needs read access to `/etc/shadow` (root) and the X display to serve:

```sh
sudo env DISPLAY=:99 XAUTHORITY=/home/user/.Xauthority \
  LINRDP_LOG=info ./target/release/linrdp
# options: --bind-addr 0.0.0.0:3389   --usb   (USB redirection)
#          --lock-session       lock the logind session when the last client
#                                disconnects, unlock on reconnect
#          --switch-to-greeter  flip the seat to the greeter when a client
#                                takes over (linrdp owns the seat)
#          --fixed-size WxH     pin the desktop size (clients scale locally)
#          --wayland            xdg-desktop-portal capture + libei input
#                                (binary built with --features wayland)
```

On first start it generates a self-signed TLS certificate
(`linrdp-cert.pem` / `linrdp-key.pem` next to the crate) and reuses it.

## Connect

From any RDP client (mstsc on Windows):

- address: the Linux machine's IP (port 3389)
- credentials: any Linux system account (e.g. `root` / its password)
- accept the self-signed certificate warning on first connect

You get the real Linux desktop: screen updates, keyboard, mouse, wheel;
the server plays a short beep every ~4 s (audio channel test); client
microphone packets reach the server.

## Design

- `deploy/` — example systemd units (`linrdp-xvfb.service` +
  `linrdp.service`) for a headless Xvfb desktop with auto-restart
- `linrdp/src/session_ctl.rs` — logind lock/unlock + greeter switch on
  connect/disconnect (KRdp SessionController pattern, via zbus)
- `linrdp/src/pam.rs` — PAM fallback authentication (dlopen libpam; used
  when /etc/shadow cannot answer: unknown user, unsupported hash scheme,
  LDAP/SSSD setups)
- `linrdp/src/wayland/` — feature `wayland`: xdg-desktop-portal session
  (zbus), PipeWire screencast frames, libei input — all dlopen'ed at
  runtime, no build-time C dependencies
- `crates/` — vendored IronRDP protocol crates (PDU, connector, acceptor,
  server skeleton, codecs, virtual channels)
- `linrdp/src/main.rs` — binary: builder wiring (TLS + HYBRID-capable,
  shadow auth, cliprdr, rdpsnd, RDPEAI, URBDRC)
- `linrdp/src/auth.rs` — `/etc/shadow` credential validator
- `linrdp/src/capture.rs` — X11 capture → bitmap updates
- `linrdp/src/input.rs` — XTEST input injection
- `linrdp/src/sound.rs` — RDPSND audio output
- `linrdp/src/mic.rs` — RDPEAI microphone input
- `linrdp/src/usb.rs` — URBDRC device factory
- `linrdp/src/tls.rs` — self-signed identity generation/loading

Protocol conformance follows Microsoft [MS-RDPBCGR] and friends (X.224
negotiation, TLS/CredSSP security, capability exchange, virtual channels)
— the vendored stack implements these per spec.
