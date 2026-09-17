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
2. Login with username + password — the account's own **system** password,
   verified against `/etc/shadow` (YESCRYPT / SHA-512 / MD5-crypt) with the
   system PAM stack behind it. Nothing to provision; see Authentication. ✅
3. Real desktop streaming — X11 root window capture, ~10 fps, only changed
   frames. Input: keyboard, mouse buttons, motion, wheel via XTEST. ✅
4. Audio in both directions — MS-RDPSND output (PCM 44.1 kHz stereo) and
   MS-RDPEAI microphone input channel. ✅ (pipe-to-PipeWire = desktop phase)
5. USB redirection — URBDRC channel compiled in; device announcements
   accepted and logged with `--usb`. Real transfer forwarding needs a USB
   host stack + physical hardware. ⚠️
6. Desktop resize — the session's screen is created at the largest desktop
   served and scaled to each client over RandR, so the same desktop can be
   reattached from a different monitor. ✅
7. Multi-session — one worker and one desktop per connection, like Windows
   RDP: each user gets their own `Xvfb`, cookie and PAM session, sessions
   outlive the connection, and a disconnect locks them. ✅

## Build

```sh
cargo build --release -p linrdp
# binary: target/release/linrdp
```

## Install

```sh
sudo install -m755 target/release/linrdp /usr/local/bin/linrdp
sudo install -m644 deploy/pam.d-linrdp /etc/pam.d/linrdp
```

## Authentication — one required step

**Without this, every login is refused with "invalid username".**

You log in with the account's own system password. There is no linrdp
password, and no command that sets one. But RDP clients authenticate with NLA
(CredSSP/NTLMv2) out of the box, and NTLM makes the *server* compute the
expected response from the account secret (MS-NLMP) — a one-way
`/etc/shadow` hash cannot produce it. That is the protocol, not a design
choice; it is why xrdp offers no NLA for local accounts.

So linrdp is handed each password by the system's own authentication, the way
Samba's `pam_smbpass` kept its database in step. Add this line to the PAM
stack (`deploy/pam-capture` explains every part of it, including how to undo
it):

```sh
sudo sh -c 'cat deploy/pam-capture >> /etc/pam.d/common-auth'
```

```
auth      optional  pam_exec.so expose_authtok quiet /usr/local/bin/linrdp --capture-credential
```

On RHEL/SUSE-style stacks the file is `/etc/pam.d/system-auth`. To follow
password changes too, add the same call as a `password` line in
`/etc/pam.d/common-password`.

From then on, whenever an account authenticates (`su -`, `ssh`, console
login) the password PAM just verified is handed to linrdp, **re-verified
against `/etc/shadow`**, and kept for NLA. A mistyped password is discarded,
not stored. The copy cannot drift from the system password, because it is the
system password, refreshed on every login.

Authenticate once so the account is known:

```sh
su -          # or log in over ssh
sudo linrdp doctor   # the account should now appear under "NLA accounts"
```

What this costs, stated plainly: the password ends up stored recoverably in
`/var/lib/linrdp/sam` (mode 0600, root-owned — the trust model of
`/etc/shadow` itself, which does *not* store it recoverably). That is
inherent to NLA. If that trade or the PAM edit is unacceptable, use the
second option below instead.

### `--auth` — what each port accepts

The default is `both`: a port advertises TLS **and** CredSSP, and each client
negotiates the strongest it supports (MS-RDPBCGR 5.4.5.1). There is no wrong
port to connect to.

| mode | advertises | client | needs the capture above |
|---|---|---|---|
| `both` (default) | TLS + CredSSP | every client: mstsc takes NLA, others take TLS | only for the clients that choose NLA |
| `nla` | CredSSP only | every client | yes |
| `system` | TLS only | only clients that send credentials without NLA (FreeRDP, Remmina, most mobile apps) — **not mstsc** | no, and nothing is ever stored |
| `greeter` | TLS only | every client, mstsc included | no, and nothing is ever stored |

### `greeter` — a logon screen, and no PAM integration at all

```sh
sudo /usr/local/bin/linrdp --supervisor --auth greeter --bind-addr 0.0.0.0:3390
```

The client connects without sending anything, linrdp draws a login form, and
what you type there goes straight to `/etc/shadow` and PAM. Nothing is stored,
nothing is provisioned, no PAM stack is edited — and every client works,
mstsc included, because a server-drawn logon screen is exactly what a client
expects when NLA is not offered.

The form is drawn on **an X server of its own**, owned by linrdp with a 0600
cookie and nobody's session on it, so showing it before anyone has
authenticated reveals nothing. The text is drawn by X with a core font, and
keystrokes are translated by XKB — so a password with characters that depend
on the keyboard layout works, which a hand-rolled scancode table would get
wrong. Only once the form accepts does the worker move to the user's own
desktop, and the session gate allows that move in one direction only.

`deploy/linrdp-alt-port.service` runs this on port 3390.

Under `system` a client that only speaks NLA sends no credentials at all and
is refused: mstsc reports **0x904** the moment you press Connect. MS-RDPBCGR
offers no way to ask a client to prompt — `LOGON_FAILED_BAD_PASSWORD`
(2.2.5.1.2) directs the user to the server's own logon screen, which linrdp
does not draw. So `system` is for deployments that would rather refuse mstsc
than store anything.

`deploy/linrdp-alt-port.service` runs a second listener on 3390 for
deployments that want another address. Both instances share `/run/linrdp` and
the display range on purpose: display numbers are handed out under a `flock`,
so a user arriving on either port lands on their own single session, and
moving between ports returns to the same desktop.

## Run

Multi-session: one worker per connection, each serving its own user's desktop.

```sh
sudo /usr/local/bin/linrdp --supervisor --bind-addr 0.0.0.0:3389
# or: sudo systemctl enable --now linrdp   (deploy/linrdp.service)
```

```
--auth both|nla|system|greeter  what the port accepts (default both; see above)
--display-range L-H    X display numbers workers may allocate (default 10-99)
--console              attach to $DISPLAY instead of a per-user session
                       (the mstsc /admin equivalent, for a shared screen)
--fixed-size WxH       pin every session's screen instead of following the
                       connecting client
--usb                  USB device redirection (MS-RDPEUSB)
--lock-session         lock the logind session when the last client leaves
--switch-to-greeter    flip the seat to the greeter when a client takes over
--wayland              xdg-desktop-portal capture + libei input
                       (binary built with --features wayland)
```

Each session gets its own `Xvfb`, its own MIT-MAGIC-COOKIE and its own PAM
session, and outlives the connection: reconnecting returns to the same
desktop, and disconnecting locks it. A session's screen is created at the
largest desktop linrdp serves and scaled down to each client, so the same
desktop can be reattached from a different monitor.

`linrdp doctor` reports what the machine can do — X servers, desktop sessions
and whether their programs exist, PAM, logind, screen lockers, and whether
credential capture is wired.

`sudo linrdp doctor <account>` asks the narrower question the machine report
cannot answer: will *this* account work here? It reports the account's uid and
home, whether its password is usable at all (a locked account refuses every
login however the server is configured), which listener needs a captured
password and which does not, and whether the account can have audio — with the
commands to fix it when it cannot. A desktop served as root, for instance, has
no sound at all, because systemd's own `pulseaudio.socket` carries
`ConditionUser=!root` and never starts a sound server for uid 0.

Upgrading in place is safe: replace `/usr/local/bin/linrdp` and the running
supervisor execs the new binary for the next connection. (Restart the unit
too if you want the supervisor itself on the new code.)

On first start it generates a self-signed TLS certificate
(`linrdp-cert.pem` / `linrdp-key.pem` next to the crate) and reuses it.

## Connect

From any RDP client (mstsc on Windows):

- address: the Linux machine's IP (port 3389)
- credentials: any Linux system account and its **system** password — the same
  one `su -` accepts (see Authentication above; the account has to have
  authenticated once on the machine)
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
