# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releasing is driven by this file: a push to `main` that adds a new
`## [X.Y.Z]` section here creates the matching Git tag, GitHub Release and
`.deb`/`.pkg.tar.zst`/`.tar.gz` packages automatically — see
`.github/workflows/detect-release.yml` and
`.github/workflows/release-packages.yml`.

## [Unreleased]

---

## [0.1.2] - 2026-10-01

Reconnecting after a restart or an upgrade could show a black screen with the
desktop still running behind it. Sessions outlive the connection by design, and
after this they outlive a restart of linrdp as well: the client reattaches to
the desktop it left open, with its applications still running.

### Fixed

#### Reattaching after a restart or upgrade
- **A desktop that outlived its keeper is adopted, not rebuilt.** Session
  liveness was read off the display `flock`, which belongs to the keeper — and
  the keeper and the desktop have separate lifetimes on purpose. The desktop
  runs in its own logind scope and `KillMode=process` is in the unit precisely
  so it survives a supervisor restart; the keeper lives in linrdp's own control
  group and does not have to. A restart that outlived its keepers therefore
  looked exactly like a dead session.

  What followed was deterministic: the record of a *running* desktop was
  deleted, a second session was built on the number that desktop still held,
  the new X server died on "server already running" three milliseconds later,
  the client was routed to the survivor anyway, and — because the new session
  had already written a fresh cookie — every grab and every keystroke failed
  with "Invalid MIT-MAGIC-COOKIE-1 key". Audio, clipboard and EGFX negotiated
  normally, so the session looked connected and showed nothing.

  Liveness is now a property of the desktop: the X11 setup the capture path is
  about to perform anyway, connecting to the display and authenticating with
  the cookie the session record names. That settles both halves at once —
  something is listening, and it is this session's, because only this session's
  server accepts this cookie. `/tmp/.X11-unix` is world-writable, so the second
  half is what keeps a squatted socket from being adopted as another account's
  desktop.
- **A display number whose X server is still answering is no longer handed
  out.** The allocator vetoes such a number rather than starting a server on it
  that dies immediately. A veto only, never a grant: the `flock` remains the
  sole thing that awards a number, so the world-writable socket path cannot be
  used to steer an allocation.
- **A keeper no longer adopts a foreign X server.** Waiting for the display
  treated any socket that accepted as proof that the keeper's own server had
  started, so a keeper could publish a record for somebody else's display and
  report the session ready while its own X server was already gone. It now
  watches its own process alongside the socket.
- **A session that does not survive start-up is reported as an error** instead
  of being served as an empty screen. A record published moments before its
  keeper tore itself down was previously read by the waiting worker and routed
  to.

---

## [0.1.1] - 2026-09-30

GNOME on Wayland, working UDP transport and a round of protocol compliance
work. The GNOME desktop now gets real sessions: one per account, plus the
console through `mstsc /admin`. mstsc now stays on UDP, with its connection
statistics, and several clients can use it at once. The microphone works. The
server's behaviour on the wire was checked against the Microsoft RDP
specifications (#7), and the fixes below cite the section each one follows.
Packages: `.deb`, Arch `.pkg.tar.zst` (new) and `.tar.gz`.

### Highlights
- **GNOME on Wayland:** a headless GNOME session per login, and the console
  session through `mstsc /admin`.
- **UDP transport that holds up with mstsc:**
  - all dynamic channels move to UDP;
  - one port serves every client;
  - a lost packet is recovered within a round trip, not after seconds;
  - no more 0xC06 or E_ABORT disconnects;
  - mstsc shows RTT and bandwidth.
- **Microphone:** it works, and the client's microphone is in use only while
  an application in the session records.
- **Graphics pipeline:**
  - frames in flight are limited by size;
  - a slow client no longer triggers full-screen repaints;
  - no more 0xD06 after the client renegotiates.
- **Arch Linux package** with every release.

### Added
- **GNOME on Wayland** (#1):
  - **Sessions:** every login gets a headless GNOME session of its own
    (`gnome-shell --headless` on a private bus, with a virtual monitor at the
    client's exact size).
    - It is kept running and locked between connections.
    - It is the GNOME counterpart of the per-user X session, and the only way
      to a desktop on GNOME 49+, which has no X11 session.
    - The account's keyring is relayed into the session.
    - If the same account is at the console, the console is locked while the
      account is in use remotely.
  - **Console:** `mstsc /admin` reaches the console's GNOME session.
    - Only the account logged in at the console can use it; anyone else is
      refused.
    - It is shown at the client's exact resolution, and the desk stays dark
      while connected.
    - Afterwards the desk gets its own layout back and is locked again.
  - **Clipboard:** text, images and files, through Mutter's remote-desktop
    clipboard.
  - **Session type:** `session.backend: auto | x11 | gnome` chooses the kind
    of session a login gets. See `docs/desktop-cases.md` for the scenario
    matrix.
  - **Containers** (distrobox, toolbox, Vanilla OS apx):
    - GNOME sessions are started on the host through `host-spawn`;
    - the host's buses and PipeWire are reached under `/run/host`;
    - `linrdp doctor` explains what the container means for passwords and
      polkit.
  - **`linrdp doctor`:**
    - reports how GNOME sessions are started and who is at the console;
    - no longer calls a missing X server a blocker where GNOME can serve
      logins.
- **Arch Linux package:** each release carries
  `linrdp-<version>-1-x86_64.pkg.tar.zst` (install with `pacman -U`). Like
  the `.deb`, it runs `linrdp service install` on install and upgrade, and
  `service uninstall` on removal.
- **Console requests:** Client Cluster Data (MS-RDPBCGR 2.2.1.3.5) reaches
  the connection handler, so a request for the console session is recognised
  (#1).

### Fixed

#### UDP transport (MS-RDPEUDP, MS-RDPEUDP2, MS-RDPEMT, MS-RDPEDYC) (#7)
- **One UDP port serves every connection** (MS-RDPEUDP 2.1).
  - The supervisor holds the port. It hands each client's datagrams to the
    connection whose multitransport request the client's SYN names by its
    cookieHash. This is the Connection Store of MS-RDPEMT 3.2.1.
  - Before, each connection bound the port itself. One of mstsc's short
    probe connections often held it, and the real session failed with
    E_ABORT. Only one of several simultaneous clients could ever have UDP.
- **All dynamic channels move to UDP, graphics included** (MS-RDPEDYC
  3.1.5.3, 3.3.5.3).
  - The Soft-Sync is offered only when both sides announce it.
  - It waits for the client's Multitransport Response and for every channel
    to be created.
  - Data for the moved channels is held until the client's Soft-Sync
    Response.
  - Channels opened later stay on TCP.
  - Unexpected tunnel data no longer ends the session.
- **Throughput:**
  - RDP-UDP sends as much as the client's announced window allows
    (MS-RDPEUDP2 2.2.1.1), not a fixed 64 packets, which used to cap a LAN
    at about 45 Mbit/s.
  - A full tunnel queue neither drops graphics data (MS-RDPEGFX 2.1) nor
    stalls the connection.
- **Loss recovery:** when the retransmit timer fires, every packet that is
  overdue is declared lost, not just the oldest (MS-RDPEUDP2 3.1.1.2.3).
  - The retransmit timeout starts at 100 ms and drops back once the client
    acknowledges again.
  - Keepalives go out every 4 s.
  - A few lost packets used to freeze the screen for seconds.
- **No more 0xC06 (decryption error):** channel sequence number 0 is skipped,
  as Windows does (MS-RDPEUDP2 3.1.1.2.4.2). Before, a busy session
  disconnected after about 65,536 packets.
- **Connection statistics:** mstsc shows RTT and bandwidth.
  - Connect-Time Auto-Detection runs before licensing (MS-RDPBCGR 1.3.1.1).
  - On UDP, the Network Characteristics Result travels in the tunnel's
    sub-header (MS-RDPBCGR 1.3.9, MS-RDPEMT 2.2.1.1.1).
  - Probes go only to clients that announce support for them.
- **Tunnel lifetime:** losing the tunnel after channels moved to it ends the
  session, so the client reconnects instead of keeping silent channels
  (MS-RDPEMT 1.3.3). A reactivation keeps the tunnel.
- **Protocol negotiation:**
  - A client that offers only RDP-UDP version 1 or 2 stays on TCP.
  - The SYN+ACK carries the negotiated MTUs (MS-RDPEUDP 3.1.5.1.3,
    3.1.1.3).
  - The Initiate Multitransport Request goes out during the connection
    sequence, after licensing, once (MS-RDPBCGR 1.3.1.1).

#### Graphics (MS-RDPEGFX, MS-RDPEDISP, MS-RDPBCGR) (#7)
- **Throttling:** frames in flight are limited by size, about 2 MB of
  unacknowledged frames, not only by count (3.2.5.13).
  - A client that reports no queue depth is treated as busy.
  - A slow client gets only the changed area again, never a whole-screen
    lossless repaint.
  - An area whose H.264 frame failed to send is not forgotten.
- **Renegotiation:** a client that renegotiates its capabilities no longer
  receives frames for surfaces it has just discarded, which caused protocol
  error 0xD06 (3.2.5.18).
- **Capability negotiation:**
  - A malformed capability set is skipped.
  - With no set in common, the session falls back to bitmaps (3.2.5.18–19).
  - The negotiation response announces the graphics pipeline (MS-RDPBCGR
    2.2.1.2.1).
- **Frame acknowledgements:** suspending and resuming them no longer freezes
  the display (3.2.5.13).
- **ClearCodec:** a glyph dropped under backpressure is no longer used later
  as a cache hit, which could garble small bitmaps (2.2.4.1).
- **ResetGraphics:** the monitor is described with inclusive bounds, and never
  as an empty list (2.2.2.14).
- **Display Control** (MS-RDPEDISP 3.1.5.2, 1.3):
  - Invalid monitor layouts are ignored.
  - The primary monitor is used.
  - The advertised maximum is 3840x2160.
  - A resize without the graphics pipeline runs the Deactivation-Reactivation
    Sequence.
- **Redraw requests:** Refresh Rect and resuming after Suppress Output redraw
  the requested area (MS-RDPBCGR 3.3.5.11).
- **Slow-path output:** clients without fast-path output get it in the form
  MS-RDPBCGR 2.2.9.1.1 defines:
  - bitmap updates without a duplicated update type;
  - pointers as Pointer PDUs;
  - no surface commands.
- **PipeWire capture** (`features.wayland`) never worked. It does now (#1):
  - `pw_init` is called;
  - the `spa_hook` layout is correct;
  - the SPA constants are the ones the C headers give;
  - format parsing handles `Choice`-wrapped values;
  - padded strides are honoured.
  - On machines without a system `client.conf`, linrdp supplies a minimal
    one.

#### Audio (MS-RDPEAI) (#1, #7)
- **Microphone:** the server now plays the recording side of MS-RDPEAI
  (3.3.5.1).
  - The AUDIO_INPUT channel opens only while an application in the session
    records from `linrdp_mic`, and closes 2 s after the last one stops
    (3.1.4.1).
  - The client's audio is converted to the 48 kHz stereo the session reads.
- **Sound server:**
  - A microphone source the sound server refuses no longer takes the
    session's sound with it.
  - The FIFO path is given in the host's spelling when linrdp runs in a
    container.
  - A sound server shared with another session gets its default output back
    on disconnect.

#### Connection and input (MS-RDPBCGR, MS-RDPEDYC) (#1, #7)
- **Server PDUs:** every PDU the server sends names the MCS server channel
  (0x03EA) as its initiator (2.2.6.1).
- **Refused logins:** a refused login, such as a wrong password over TLS,
  reaches the client as a proper Set Error Info PDU (2.2.5.1.1). It used to
  be four bytes no client could parse.
- **Auto-reconnect:** a cookie that does not verify, typically after a server
  restart, no longer refuses the connection. The credentials are checked as
  for any logon (3.3.5.3.11).
- **Dynamic channels opened by the server** wait for the client's
  Capabilities Response. Closing one works in any state (MS-RDPEDYC 2.2.1).
- **Early disconnect:** an occasional disconnect right after login no longer
  happens. The Soft-Sync was sent before the client's Multitransport
  Response.
- **Relative mouse movement**, which the server announces, works on X11 and
  libei.

### Changed
- The `wayland` cargo feature is on by default. It adds no build-time
  dependency, because PipeWire is loaded at runtime. The `.deb` recommends
  `libpipewire-0.3-modules` (#1).

## [0.1.0] - 2026-09-22

### Added
- Full RDP server for Linux: X.224/TLS/CredSSP negotiation, capability
  exchange and virtual channels per MS-RDPBCGR and friends, on a vendored
  pure-Rust IronRDP core.
- Login with the account's own system password, verified against
  `/etc/shadow` (YESCRYPT / SHA-512 / MD5-crypt) and the system PAM stack —
  nothing to provision.
- Real desktop streaming: X11 root window capture with damage tracking,
  keyboard/mouse/wheel input via XTEST, RandR-based resize so one desktop can
  be reattached from a different monitor.
- Software H.264 encoding for EGFX-capable clients (vendored x264, High
  4:4:4 profile) with a bitmap fallback for clients that cannot do EGFX.
- Audio in both directions: MS-RDPSND output and MS-RDPEAI microphone input.
- USB redirection channel (MS-RDPEUSB/URBDRC) compiled in.
- Multi-session support: one `Xvfb`, cookie and PAM session per connection,
  sessions outlive the connection and lock on disconnect.
- `linrdp service install`/`uninstall` — writes the systemd unit,
  `/etc/linrdp/config.yaml`, the PAM capture line and the required
  directories in one command, and takes back exactly that.
- `linrdp doctor` / `linrdp doctor <account>` — machine- and account-level
  diagnostics for PAM, logind, screen lockers and audio.
- `linrdp config` — a browsable settings tree with every key documented in
  place.
- `linrdp debug` / `linrdp daemon` — foreground and non-systemd operation.

### Security
- Captured passwords are sealed at rest with a machine-bound key (HKDF-SHA256
  over the DMI product UUID and `/etc/machine-id`) rather than stored in the
  clear.
- A budget for unauthenticated clients, a login-policy check applied
  consistently to console mode, and clipboard file transfers that open under
  the session's own user rather than root.

[Unreleased]: https://github.com/azdolinski/linrdp/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/azdolinski/linrdp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/azdolinski/linrdp/releases/tag/v0.1.0
