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
sudo linrdp service install
```

`service install` writes one systemd unit, creates `/etc/linrdp/config.yaml`
(only if there is none — re-running it to upgrade the binary leaves your
settings alone), installs `/etc/pam.d/linrdp`, creates `/etc/linrdp/cert`,
`/var/lib/linrdp` and `/var/log/linrdp`, wires the credential capture into the system PAM stack
(see **Authentication** below), and starts the service. `sudo linrdp service
uninstall` takes back exactly that and leaves the configuration, the TLS
identity and the logs where they are.

Day to day:

| | |
|---|---|
| `sudo linrdp service start` | start it |
| `sudo linrdp service stop` | stop it — running desktops survive, see `KillMode=process` |
| `sudo linrdp service restart` | restart it, picking up a changed configuration |
| `linrdp service status` | what systemd says, then the listeners in effect |

`status` is worth the extra line over `systemctl status linrdp`: the unit
carries no arguments, so systemd cannot tell you which ports are served or how
they authenticate. That answer is in the configuration file, and `status`
prints both halves — including the parse error, when there is one, which is the
usual reason the service came up and stopped again.

## Configuration

Everything is in `/etc/linrdp/config.yaml`. The unit takes no arguments and
sets no environment, so there is nowhere else for a setting to be.

```yaml
listeners:
  - bind: 0.0.0.0:3389
    auth: both              # both | nla | system | greeter
  - bind: 0.0.0.0:3390
    auth: greeter
    overrides:
      features: { usb: true }

session:
  display_range: 10-99      # service-wide; see below
  fixed_size: null          # e.g. 2880x1800 to pin every session's screen
  lock_on_disconnect: false
  switch_to_greeter: false
  console:
    enabled: false          # serve one shared screen instead of per-user sessions
    display: null           # required when enabled — there is no default
    xauthority: null

features:
  usb: false                # USB redirection (MS-RDPEUSB)
  udp: true                 # UDP transport (MS-RDPEMT) alongside TCP
  avc444v2: true            # full-resolution chroma where the client negotiates it
  wayland: false            # portal + PipeWire + libei instead of X

tls:
  cert: null                # null keeps a self-signed identity in /etc/linrdp/cert
  key:  null

log:
  level: info
  file:  /var/log/linrdp/linrdp.log
```

The file written on install carries every key's description and every value's
consequences as comments, so `less /etc/linrdp/config.yaml` is the reference.

```sh
sudo linrdp config          # the same, browsable: tree on the left, help on the right
linrdp config --print       # the commented file on stdout, for a pipe or a bug report
```

A listener may override any key in `session`, `features` or `tls` for itself.
Two keys are service-wide and refuse to be overridden, with the reason
attached: `log`, because one process writes one log, and
`session.display_range`, because display numbers are handed out under a single
`flock` in `/run/linrdp` — and that is exactly what makes a user arriving on
either port land on the same desktop.

Changing the set of listeners takes effect on `systemctl restart linrdp`;
every other key is read again for each new connection. A key linrdp cannot
make sense of stops the service rather than being quietly dropped: the quiet
outcome of dropping `auth` would be `both`, which is weaker than anything you
would have written.

## Authentication — one required step

**Without this, every login is refused with "invalid username".**

You log in with the account's own system password. There is no linrdp
password, and no command that sets one. But RDP clients authenticate with NLA
(CredSSP/NTLMv2) out of the box, and NTLM makes the *server* compute the
expected response from the account secret (MS-NLMP) — a one-way
`/etc/shadow` hash cannot produce it. That is the protocol, not a design
choice; it is why xrdp offers no NLA for local accounts.

So linrdp is handed each password by the system's own authentication, the way
Samba's `pam_smbpass` kept its database in step. `sudo linrdp service install`
adds this line for you — to `common-auth` and `common-password` on Debian, to
`system-auth` and `password-auth` on RHEL/SUSE, whichever exist:

```
auth      optional  pam_exec.so expose_authtok quiet /usr/local/bin/linrdp --capture-credential
```

`optional` is the word that matters: PAM ignores the result, so a linrdp that
is missing, broken or slow can never keep anyone out of the machine. The line
is marked as linrdp's, so `service uninstall` removes exactly it and leaves
any `pam_exec` line of yours alone; the file is backed up before it is
touched; and running `install` again does not add it twice.
`deploy/pam-capture` explains every part of it, including how to undo it by
hand.

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

### `auth` — what each port accepts

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

```yaml
listeners:
  - bind: 0.0.0.0:3390
    auth: greeter
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

One process serves it alongside the NLA port; both are listeners in the same
file.

Under `system` a client that only speaks NLA sends no credentials at all and
is refused: mstsc reports **0x904** the moment you press Connect. MS-RDPBCGR
offers no way to ask a client to prompt — `LOGON_FAILED_BAD_PASSWORD`
(2.2.5.1.2) directs the user to the server's own logon screen, which linrdp
does not draw. So `system` is for deployments that would rather refuse mstsc
than store anything.

Running both at once is the usual shape — `auth: both` on 3389 for every
client, `auth: greeter` on 3390 for deployments that want nothing to do with
PAM. They are one process and one display range on purpose: numbers are handed
out under a `flock`, so a user arriving on either port lands on their own
single session, and moving between ports returns to the same desktop.

## Run

```sh
sudo systemctl enable --now linrdp    # `service install` has already done this
```

One process binds every listener in the configuration and forks a worker per
connection, each serving its own user's desktop. There are no service flags:
the only arguments linrdp takes are `--config <PATH>` to read a file somewhere
else, and `--listener <ADDRESS:PORT>` to serve one listener in the foreground
without forking, which is the shape to use while working on the code.

An argument linrdp does not recognise stops it rather than being ignored — a
machine still carrying an old unit that said `--auth system` would otherwise
have quietly served `both`.

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
supervisor execs the new binary for the next connection. (Restart the unit too
if you want the supervisor itself on the new code.) Re-running
`sudo linrdp service install` refreshes the unit and leaves
`/etc/linrdp/config.yaml` exactly as it is.

On first start it generates a self-signed TLS certificate as
`/etc/linrdp/cert/default.cert` (with its key beside it, mode 0600) and
reuses it, so a client that accepted it once goes on accepting it. That
`.cert` file is the one to import into a client's trust store — it carries
SANs for the machine's hostnames and interface IPs, so connecting by raw IP
validates too. Setting `tls.cert` and `tls.key` means you are providing an
identity instead: a path that is not there then stops the service rather than
being replaced by a fresh self-signed certificate under your filename, which
would break pinning on every client at once.

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

- `linrdp/src/config/` — `/etc/linrdp/config.yaml`: the types, the two
  loaders, the validator, and the metadata table every description in the file
  and in `linrdp config` is rendered from
- `linrdp/src/service/` — `service install` / `uninstall`: the unit, the
  directories, and the PAM stack edit
- `linrdp/src/configtui/` — `linrdp config`: the settings tree and its help
- `deploy/` — `linrdp-xvfb.service` for a headless Xvfb desktop, and
  `pam-capture`, which explains the credential-capture line in full
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
