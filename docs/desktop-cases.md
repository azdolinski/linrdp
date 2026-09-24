# Desktop cases

Which kind of desktop serves a login depends on the distribution, on what is
installed, and on the account. Every combination linrdp supports is one
**case** — a `DesktopBackend` in `session::backends::REGISTRY` — chosen by one
pure function, `session::backends::choose`, from what each case's probe finds.
A new distribution or desktop is a new case and a new test row, never a
special branch somewhere else.

`linrdp doctor` shows which cases this machine offers; `session.backend`
(`auto | x11 | gnome`) picks one explicitly.

## Cases

| case             | when                                                    | serves                                        | code |
|------------------|---------------------------------------------------------|-----------------------------------------------|------|
| `gnome-headless` | GNOME Shell can be started (natively, or on the host)   | a GNOME session of the account's own          | `session/backends/gnome_headless.rs`, `wayland/mutter.rs` |
| `x11`            | Xvfb or Xorg is installed                               | an X session of the account's own             | `session/backends/x11.rs`, `capture.rs`, `input.rs` |
| `gnome-console`  | the client asks for the console (`mstsc /admin`) and the account is the one logged in at it | the console's GNOME session | `session/backends/gnome_console.rs`, `wayland/mutter.rs`, `wayland/display_mode.rs` |

A login gets a session of its own, as on Windows Server. `auto` prefers
GNOME where GNOME Shell can be started. The console is reached only with
`/admin` (Client Cluster Data, `REDIRECTED_SESSIONID_FIELD_VALID` with
session 0), and only by the account logged in at it — anyone else is
refused.

### gnome-headless

- The keeper starts a private `dbus-daemon` and `gnome-shell --headless`
  with no monitor. Each connection adds a virtual monitor at exactly the
  client's size (`RecordVirtual`); it goes away with the connection.
- The session keeps running after a disconnect and is locked; the next
  verified login unlocks it and gets it at its own size.
- If the same account is logged in at the console, the console is locked
  while the remote session is in use.
- Apps open in the session because the private bus's activation
  environment names its Wayland display.
- The account's keyring is relayed onto the private bus
  (`linrdp --secrets-bridge`), so there is one keyring for both places.
- Launcher: `native` (in the keeper's PAM/logind session) or `host`
  (from a distrobox/toolbox/apx container, through `host-spawn`). The host
  launcher cannot create a logind session, so polkit prompts do not reach
  that session.

### gnome-console (`/admin`)

- Unlocked after the verified login, locked again on disconnect.
- Shown at the client's exact size: a virtual monitor (`RecordVirtual`)
  becomes the layout's only monitor while connected, and the desk's own
  layout — its own resolution — is put back afterwards. The stream is stopped
  *before* the layout is restored: the other order crashed GNOME Shell 50.
  If the worker dies, Mutter restores the desk's monitor by itself (checked
  with `kill -9`).
- If the virtual monitor cannot replace the desk's, the monitor is switched to
  the mode that best fits the client instead.
- The physical monitors are kept off while connected, and switched off again
  if woken at the desk.

### Clipboard (both GNOME cases)

- Through Mutter's remote-desktop clipboard (`EnableClipboard`,
  `SetSelection`/`SelectionTransfer`, `SelectionOwnerChanged`/
  `SelectionRead`) — the Wayland clipboard, not an X selection. The RDP side
  (formats, echo guard, files) is the same code as for X11 (`clipboard::Board`).
- Mutter 50 sends `mime-types` as `(as)`, and hands out non-blocking pipes;
  both are handled.
- Files pasted from the client into a session started on a container's host
  go to `~/.cache/linrdp/` (the container's `/tmp` does not exist on the
  host).

## How a case plugs in

A login reaches its desktop in three places, and only the first knows which
case it is:

- **Choosing and binding** (`session::backends`). The router hands every
  verified login to `choose`, which probes the cases in `REGISTRY` order —
  the console cases for `/admin`, the rest otherwise, only the named one for
  an explicit `session.backend` — and stops at the first that can serve it.
  The probe returns how to bind the login, and the router runs that.
- **Serving** (the worker). An X session is reached through the session gate
  (`session::gate`), as before. A desktop reached through its compositor
  implements `wayland::compositor::CompositorDesktop` — frames, input,
  clipboard, relock — and is attached once per worker; the display factory,
  the input handler, the clipboard and the disconnect path follow it without
  naming a compositor.
- **Keeping** (the keeper). A case that starts sessions of its own gets the
  keeper with its PAM session open (`keeper_main::Keeper`) and runs the
  session in `serve_session`; the worker names the case with
  `--keeper-backend`, and the session record keeps it (`backend=`), so a
  reconnect is served the same way.

Adding a case — KWin or a wlroots compositor, say:

1. a module in `session/backends/` implementing `DesktopBackend`: `probe`
   (can it serve this login, and how to bind it) and, if it starts sessions
   of its own, `serve_session`;
2. if its desktop is not an X display, a `CompositorDesktop` for it;
3. one line in `REGISTRY` — its position is its `auto` preference;
4. a `session.backend` value (`BackendChoice`), if operators may ask for it
   by name;
5. what `linrdp doctor` should say about it (`session::detect`);
6. a row in the scenario matrix in `session/backends/mod.rs` and below.

## Scenario matrix

Status: ✅ verified on real hardware/VM · 🧪 covered by unit tests only · ⬜ not yet checked.

| # | machine                                         | expected case | status |
|---|-------------------------------------------------|---------------|--------|
| 1 | Debian 13 + XFCE, Xvfb, nobody logged in         | `x11`         | ✅ (0.1.0) |
| 2 | Vanilla OS 3 (GNOME 50, no X), apx container, account also at the console | `gnome-headless` (host launcher) | 🧪 pieces verified live (headless shell, RecordVirtual, lock/unlock, app launch, keyring relay); RDP end-to-end pending |
| 2a| same machine, `mstsc /admin` as the console's account | `gnome-console` | ✅ served before `/admin` existed (as the default then) |
| 2b| same machine, `mstsc /admin` as another account | refused | 🧪 |
| 3 | GNOME-only, nobody at the console                 | `gnome-headless` | ⬜ |
| 4 | Ubuntu 24.04/26.04 GNOME + Xvfb installed        | `gnome-headless` (native) | ⬜ |
| 5 | Ubuntu, `session.backend: x11`                    | `x11`         | ⬜ |
| 6 | Fedora Workstation (GNOME), native install        | `gnome-headless` (native) | ⬜ |
| 7 | Arch + GNOME                                      | `gnome-headless` (native) | ⬜ |
| 8 | Arch/Debian + KDE Plasma (Wayland)               | no case yet — needs a KWin case | ⬜ |
| 9 | wlroots (Sway, Hyprland)                          | no case yet — needs a wlroots case | ⬜ |
| 10| GNOME, real GPU (KMS), `/admin`: capture while monitors are powered off | `gnome-console` | ⬜ (verified only on a VM) |
| 11| GNOME, native install: polkit prompt inside the RDP session | `gnome-headless` | ⬜ |

## Checking a machine

```sh
linrdp doctor                    # which cases this machine offers
cargo test -p linrdp live_gnome_session -- --ignored --nocapture
sudo env LINRDP_LIVE_USER=<account> target/release/deps/linrdp-<hash> live_gnome_session --ignored --nocapture
LINRDP_LIVE_PNG=/tmp/frame.png   # keep the captured frame
LINRDP_LIVE_BLANK=1              # also check capture with the monitors off
LINRDP_LIVE_VIRTUAL=1920x1080    # a virtual monitor (the gnome-headless way)
LINRDP_LIVE_RUNTIME=<dir>        # dir holding `bus` + `pipewire-0` of another GNOME instance
LINRDP_LIVE_CLICKS="x,y;x,y"     # click, then keep the newest frame
```

## Not done yet

- audio for the GNOME cases: sound works, but the account's sound server
  is shared by the console and the remote session, so while connected all of
  the account's audio goes to the client (the default output is given back
  on disconnect) — to verify on a machine with a real sound card;
- resizing the virtual monitor when the client window is resized
  mid-session (today: at connect);
- configuration keys for unlock / relock / blanking / console lock (on by
  default today);
- KWin and wlroots cases;
- the xdg-desktop-portal path (`features.wayland`) is not a case: it is
  chosen for the whole process at start and runs on the ambient session bus,
  where the portal asks the person at the desk for consent. As a case it
  would need the account's own bus and a restore token per account.
