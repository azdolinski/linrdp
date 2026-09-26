# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releasing is driven by this file: a push to `main` that adds a new
`## [X.Y.Z]` section here creates the matching Git tag, GitHub Release and
`.deb`/`.tar.gz` packages automatically — see
`.github/workflows/detect-release.yml` and
`.github/workflows/release-packages.yml`.

## [Unreleased]

### Added
- GNOME on Wayland: every login gets a headless GNOME session of its own
  (`gnome-shell --headless` on a private bus, a virtual monitor at the
  client's exact size per connection), kept running and locked between
  connections — the GNOME counterpart of the per-user X session, and the only
  way to a desktop on GNOME 49+, which has no X11 session. If the same
  account is at the console, the console is locked while it is in use
  remotely. Apps open in the session; the account's keyring is relayed into
  it (#1).
- `mstsc /admin` reaches the console's GNOME session — only for the account
  logged in at the console; anyone else is refused. The console is shown at
  the client's exact resolution (a virtual monitor replaces the desk's while
  connected), the desk is kept dark, and afterwards the desk gets its own
  layout back and the session is locked again (#1).
- Clipboard (text, images, files) for GNOME sessions, through Mutter's
  remote-desktop clipboard (#1).
- `session.backend: auto | x11 | gnome` — which kind of session of its own a
  login gets. Desktops are cases (`session::backends`) behind one
  compositor interface (`wayland::compositor`); see `docs/desktop-cases.md`
  for the cases and the scenario matrix (#1).
- Containers (distrobox, toolbox, Vanilla OS apx): GNOME sessions are
  started on the host through `host-spawn`, and the host's buses and PipeWire
  are reached under `/run/host`; `linrdp doctor` names the container and what
  it means for passwords and polkit (#1).
- `linrdp doctor` reports how GNOME sessions are started and who is at the
  console, and no longer calls a missing X server a blocker where GNOME can
  serve logins (#1).
- Client Cluster Data (MS-RDPBCGR 2.2.1.3.5) reaches the connection handler
  (`ConnectionInfo::client_cluster`, `requests_console`), so a request for
  the console session (`mstsc /admin`) can be recognised (#1).

### Fixed
- Sound: a microphone source the sound server refuses no longer takes the
  session's sound with it; the FIFO path is given to a host's sound server in
  the host's own spelling (linrdp in a distrobox/apx container); a sound
  server shared with another session gets its default output back on
  disconnect (#1).
- PipeWire capture (`features.wayland`) never worked: `pw_init` was never
  called, `spa_hook` was one pointer short (heap corruption), four SPA
  constants were hand-counted wrong (`pw_stream_connect` → `-EPROTO`),
  `Choice`-wrapped format values were not parsed, the stream error state was
  compared against the wrong value, a format without a frame yet produced an
  empty grab, and a padded stride was not honoured. Every constant is now the
  value the C headers give (#1).
- An occasional disconnect right after login (`Connection reset by peer`
  from mstsc, under half a second in): the DVC Soft-Sync to the UDP transport
  was sent before the client's Initiate Multitransport Response, which
  MS-RDPEDYC 3.3.5.3.1 forbids; it now waits for it. A disconnect's cause is
  logged with it (#1).
- PipeWire capture on machines without a system `client.conf` (a container
  with only the library installed): linrdp brings a minimal one (#1).
- A dynamic channel the server opens during a session is requested only after
  the client has answered the DVC Capabilities Request (MS-RDPEDYC 2.2.1), and
  closing one works in every state: a channel the client never heard of is
  simply dropped, and one whose creation is still unanswered is closed as soon
  as the client confirms it (#7).

### Changed
- The `wayland` cargo feature is on by default. It adds no build-time
  dependency: PipeWire is loaded at runtime. The `.deb` recommends
  `libpipewire-0.3-modules` (#1).

---

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

[Unreleased]: https://github.com/azdolinski/linrdp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/azdolinski/linrdp/releases/tag/v0.1.0
