# Multi-session support — per-user desktops with Windows RDP semantics

Status: design, awaiting review
Date: 2026-09-16

## Why

linrdp today serves exactly one desktop. `RdpServer` holds a single
`display: Arc<Mutex<Box<dyn RdpServerDisplay>>>`
(`crates/ironrdp-server/src/server.rs:549`) and the display trait carries no
connection identity, so `size()`, `request_initial_size()` and
`request_layout()` are called on one shared object. Audio (`PULSE_SERVER`),
clipboard, and input injection are likewise bound to the one `$DISPLAY`.
Every client therefore sees the same screen — the "console session"
behaviour, not multi-session.

The goal is Windows RDP semantics: a user logs in and gets *their own*
desktop, running as *their own* Unix user; several people work at once
without seeing or disturbing each other; a disconnect leaves the desktop
running and a reconnect returns to it.

## Decisions taken

| Question | Decision |
|---|---|
| Disconnect behaviour | The desktop keeps running; reconnecting to the same account returns to it. |
| Who owns the desktop processes | Full logind / PAM integration — a real PAM session per user, registered with logind via `pam_systemd`. |
| The existing shared `:99` | Per-user sessions by default, plus an explicit console mode that attaches to `:99` (the `mstsc /admin` equivalent) for Selkies/VNC parity. |
| Secret and state locations | Per-user secrets in `$XDG_RUNTIME_DIR`; supervisor state in `/run/linrdp/`. Never `/tmp`, never a home directory. |

## Architecture: process per connection, sessions outlive connections

Two lifetimes that must not be conflated:

- **Connection** — one TCP connection from one client. Dies when the client
  goes away.
- **Session** — one user's desktop: an X server, a desktop environment, and
  a logind session. Survives disconnects.

`linrdp` splits into two roles in one binary:

**Supervisor** (`--supervisor`, the systemd unit's entry point) binds 3389
and does nothing but accept and fork. It never speaks RDP.

**Worker** (the forked child) is today's linrdp almost unchanged: it owns
exactly one connection end to end, authenticates it, attaches to the right
session, and serves. Because isolation is by process, the display, audio,
clipboard and input paths stay single-tenant and the vendored
`ironrdp-server` is not modified at all.

Forking before any protocol runs removes the routing problem entirely: the
child learns the username from its own CredSSP exchange, not from the
client-supplied X.224 `mstshash` cookie, which is unauthenticated and must
never decide which desktop someone reaches.

```
supervisor (root, listens :3389)
  └─ fork per connection
       worker (root → setuid user after PAM)
         ├─ CredSSP: learns and verifies the username
         ├─ SessionManager: find or create this user's session
         └─ serves that session's display / audio / clipboard / input

session (independent lifetime, per user)
  ├─ logind session (pam_systemd)
  ├─ Xvfb :N -auth $XDG_RUNTIME_DIR/linrdp/Xauthority   (no -ac)
  └─ desktop environment
```

## Components

### `SessionManager`

Owns the mapping from Unix user to running session. Authoritative state is
logind plus the display lock files; the in-memory map is a cache that can be
rebuilt, so a supervisor restart never orphans or double-allocates a
session.

Interface:

- `attach_or_create(user) -> Session` — returns the user's running session,
  or creates one.
- `release(session)` — a worker detached; the session stays up.
- `terminate(user)` — explicit logout: close the PAM session, stop the
  desktop, drop the display lock.

A `Session` carries: display number, `XDG_RUNTIME_DIR`, Xauthority path,
logind session id, and the uid/gid it runs as.

### `DisplayAllocator`

Hands out display numbers without races. For a candidate `N`:

1. Open `/run/linrdp/display-<N>.lock` (`O_CREAT`, mode 0600, root-only
   directory) and take an exclusive non-blocking `flock`.
2. If the lock is taken, `N` is in use — try the next.
3. Hold the lock for the session's lifetime. It is released automatically if
   the holder dies, so a crash cannot leak a number.

`/tmp/.X11-unix/X<N>` is *not* used for allocation. It is world-writable by
design, so an unprivileged user could pre-create an entry there and steer
allocation. The socket still appears there because X11 mandates it; what
protects the session is the cookie, not the path.

Range: 10–99 by default, skipping any display already present, configurable
via `--display-range`.

### PAM session flow

`linrdp/src/pam.rs` already dlopens libpam and performs `pam_start`,
`pam_authenticate`, `pam_acct_mgmt`, `pam_end` (service `login`). It gains
the session half, against a dedicated `/etc/pam.d/linrdp` stack that
includes `pam_systemd.so`:

```
pam_start("linrdp", user)
pam_authenticate          → credentials
pam_acct_mgmt             → account valid, not expired
pam_setcred(ESTABLISH_CRED)
pam_open_session          → pam_systemd registers a logind session,
                            creates /run/user/<uid> (0700, user-owned)
pam_getenvlist            → XDG_RUNTIME_DIR, XDG_SESSION_ID, …
  … session runs …
pam_close_session
pam_setcred(DELETE_CRED)
pam_end
```

The PAM handle must live as long as the session, so it is held by the
session, not by the worker that created it.

### Privilege drop

After `pam_open_session`, the child that launches the desktop:

`initgroups(user, gid)` → `setgid(gid)` → `setuid(uid)`, verifying that
`setuid` actually took effect before `exec`. The worker serving the
connection drops to the same uid once it has attached, so the RDP session
cannot read another user's files even if the worker is compromised.

### Secrets

- Xauthority: `$XDG_RUNTIME_DIR/linrdp/Xauthority`, mode 0600, owned by the
  user. `/run/user/<uid>` is tmpfs, 0700, created and torn down by
  `pam_systemd` — so the cookie never touches disk, never outlives the
  session, and cannot land on NFS or inherit loose home-directory
  permissions.
- A fresh MIT-MAGIC-COOKIE per session; Xvfb is started with `-auth` and
  **never** `-ac`.
- Supervisor state lives in `/run/linrdp/` (root, 0700). It is root's record
  about all users, so it must not be writable by any of them — putting it in
  a home directory would let a user edit their own entry.

Note for deployment: the current `:99` runs `Xvfb -ac` with no authority
file, so any local user can screenshot it and inject input. The console mode
inherits whatever `:99` is configured to do; fixing that is a separate,
recommended change to `start-desktop.sh`.

### Console mode

`--console` (and a per-connection opt-in) skips `SessionManager` entirely
and attaches to the display named by `$DISPLAY`, reproducing today's
behaviour for the Selkies/VNC-shared `:99`. It performs authentication but
no PAM session and no privilege drop, exactly as today.

## Error handling

| Failure | Behaviour |
|---|---|
| Authentication fails | Worker exits; no session created; no display allocated. |
| `pam_open_session` fails | Report a logon failure to the client, unwind `setcred`, free the display lock. |
| Xvfb fails to start | Release the lock and the PAM session, fail the connection with a diagnostic; do not leave a half-session in the map. |
| Desktop environment dies, X alive | Session stays; reconnect gets a bare X. Logged, not fatal. |
| X dies | Session is torn down and removed; the next connection creates a fresh one. |
| Worker crashes | Session survives (that is the point). The supervisor reaps the child. |
| Supervisor restarts | Sessions survive. The map is rebuilt from logind plus the display locks on first use. |
| Same user connects twice | Second connection attaches to the same session. Concurrent workers on one display are rejected for now — the first holder wins — because two workers injecting input into one X server is a separate feature (shadowing). |

## Testing

Unit, no X or PAM required:

- `DisplayAllocator`: two allocators in one process never hand out the same
  number; a released lock is reusable; a held lock is skipped; exhaustion of
  the range is an error, not a panic.
- `SessionManager`: attach-then-attach returns the same session; release
  does not stop it; terminate does; rebuilding the map from a simulated
  logind listing reproduces the same state.
- PAM flow: the call sequence is driven through a mock `PamApi` (the dlopen
  indirection in `pam.rs` already makes this injectable), asserting order
  and that `close_session`/`setcred(DELETE)` run on every failure path.

Integration, on this host:

- Two different Unix accounts connect at once; each sees its own desktop;
  `loginctl list-sessions` shows two sessions with the right uids; neither
  can read the other's X (verified by an `xwd` attempt with the wrong
  cookie, which must fail).
- Disconnect and reconnect: the same windows are still open.
- Supervisor restart with a live session: reconnect still lands on it.
- `--console` still reaches `:99` alongside Selkies.
- Privilege check: a worker's `/proc/<pid>/status` shows the target uid, not
  0, once attached.

## Out of scope

Session shadowing (two clients on one desktop), per-session audio device
routing beyond a per-session PulseAudio, RemoteApp, and any change to the
`:99` Selkies/VNC stack other than the console-mode hook.
