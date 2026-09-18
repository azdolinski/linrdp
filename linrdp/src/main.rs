//! LinRDP — RDP server for Linux.
//!
//! Serves a test-pattern desktop on 0.0.0.0:3389, compatible with mstsc
//! (Windows Remote Desktop client). Connection sequence, capability
//! negotiation and security follow [MS-RDPBCGR].

#![allow(clippy::print_stdout)]

mod atomic;
mod auth;
mod build_info;
mod capture;
mod clipboard;
mod config;
mod configtui;
mod doctor;
mod greeter;
mod gfx;
mod gfx_display;
mod input;
mod mic;
mod pam;
mod sam;
mod cli;
mod daemon;
mod logging;
mod service;
mod sound;
mod sound_real;
mod tls;
mod x264_encoder;
mod udp;
mod usb;
mod session;
mod supervisor;
mod session_ctl;
#[cfg(feature = "wayland")]
mod wayland;
mod x11_selection;

use core::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use ironrdp_server::{CliprdrServerFactory, RdpServer};

use crate::capture::X11Display;
use crate::input::X11InputHandler;


/// Supervisor mode forks per connection, and `fork` in a multi-threaded
/// runtime leaves only the calling thread alive in the child. So the argv is
/// inspected before any runtime exists, and the supervisor never builds one.
fn main() -> anyhow::Result<()> {
    // `doctor` answers "what is this machine, and what may linrdp do on it?"
    // before anything is started, so a missing piece is a report rather than
    // a runtime failure with no explanation.
    //
    // With an account name it answers the narrower question instead — "will
    // *this* account work here?" — which the machine report cannot, because
    // everything that decides it is per-account: the runtime directory the
    // session gets, whether the password is usable, and whether systemd will
    // start a sound server for that uid at all.
    // Every branch below this line prints and exits; none of them serves a
    // socket. `debug` is the exception and is dispatched further down, where
    // this has not been done.
    if std::env::args().nth(1).as_deref().is_some_and(|word| {
        cli::meta::is_a_top_level_command(word) && word != "debug"
    }) || std::env::args().any(|arg| arg == "-h" || arg == "--help" || cli::meta::is_the_version_flag(&arg))
    {
        cli::die_quietly_on_a_closed_pipe();
    }

    // Asking for help never runs the command: `linrdp config --help` opening
    // a full-screen editor instead of answering the question is the kind of
    // surprise a tree advertising its commands invites.
    if std::env::args().any(|arg| arg == "-h" || arg == "--help") {
        match std::env::args().nth(1).as_deref() {
            Some(word) if cli::meta::is_a_top_level_command(word) => print!("{}", cli::subtree(word)),
            _ => print!("{}", cli::help()),
        }
        return Ok(());
    }

    // `--version`, `-V` and the `version` command are one question with one
    // answer, answered here rather than in three places. Like `--help`, the
    // flag is honoured wherever it appears: `linrdp service --version` is
    // somebody asking what this binary is, not asking to start anything.
    if std::env::args().any(|arg| cli::meta::is_the_version_flag(&arg))
        || std::env::args().nth(1).as_deref() == Some("version")
    {
        println!("{}", build_info::version_line());
        return Ok(());
    }

    match std::env::args().nth(1).as_deref() {
        Some("doctor") => {
            return match std::env::args().nth(2) {
                Some(account) => doctor::run_account(&account),
                None => doctor::run(),
            };
        }
        Some("config") => return configtui::run(std::env::args().any(|arg| arg == "--print")),
        Some("service") => return service::run(std::env::args().nth(2).as_deref()),
        Some("daemon") => return daemon::run(std::env::args().nth(2).as_deref()),
        Some("debug") => {
            // The level is the argument so that `linrdp debug trace` and
            // `linrdp debug info,ironrdp=trace` both work: the filter is the
            // useful knob, and naming one level would only mean adding the
            // next one later.
            logging::set_override(std::env::args().nth(2).as_deref().unwrap_or("debug"));
            // Past the program name *and* past `debug` and its level: what
            // follows is the supervisor's own arguments, and `refuse_leftovers`
            // rejects anything it does not recognise — including, without this,
            // the word that got us here.
            let rest = std::env::args_os().skip(if std::env::args().nth(2).is_some() { 3 } else { 2 });
            return supervisor_main(pico_args::Arguments::from_vec(rest.collect()));
        }
        Some("tree") => {
            print!("{}", cli::tree());
            return Ok(());
        }
        // A word that is not a flag and not in the table. Without this it
        // would fall through to the supervisor and be refused as a stray
        // argument, which says nothing about what could have been typed.
        Some(word) if !word.starts_with('-') && !cli::meta::is_a_top_level_command(word) => {
            print!("{}", cli::tree());
            anyhow::bail!("`linrdp {word}` is not a command");
        }
        _ => {}
    }
    if std::env::args().any(|arg| arg == "--keeper") {
        return keeper_main();
    }

    // Credential capture, invoked by `pam_exec` from the system PAM stack on
    // every authentication this machine performs. Handled here, before any
    // runtime is built: a `su` at the console should not be paying for a
    // multi-threaded tokio runtime to hash one password.
    if std::env::args().any(|arg| arg == "--capture-credential") {
        capture_credential();
        return Ok(());
    }

    // Serving one connection means a worker the supervisor forked
    // (`--serve-fd`); serving one address in this very process means somebody
    // working on linrdp (`--listener` alone). Everything else — which is to
    // say the systemd unit, whose ExecStart carries no arguments at all — is
    // the supervisor.
    let serves_a_connection = std::env::args().any(|arg| arg == "--serve-fd" || arg == "--listener");
    if !serves_a_connection {
        return supervisor_main(pico_args::Arguments::from_env());
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?
        .block_on(serve())
}

/// Refuse arguments nothing recognised.
///
/// pico_args leaves unclaimed arguments behind and this crate never looked at
/// them, so an unknown flag was silently dropped. After the move to a
/// configuration file that silence is dangerous rather than merely untidy: a
/// machine still carrying a stale unit that says `--auth system` would have
/// got a server serving `both` — weaker than the operator wrote — with
/// nothing anywhere saying so.
fn refuse_leftovers(args: pico_args::Arguments) -> anyhow::Result<()> {
    let leftovers = args.finish();
    if leftovers.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = leftovers.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    anyhow::bail!(
        "unrecognised argument(s): {}\n\nlinrdp is configured by {} alone — the settings \
         that used to be flags are keys in that file, and `linrdp config` edits it.",
        names.join(" "),
        config::path().display()
    )
}

/// Own one user's session for its whole life (see `session::keeper_main`).
fn keeper_main() -> anyhow::Result<()> {
    let mut args = pico_args::Arguments::from_env();
    let _ = args.contains("--keeper");
    let user: String = args.value_from_str("--keeper-user")?;
    let display_number: u16 = args.value_from_str("--keeper-display")?;
    let state_dir = session::keeper_main::state_dir_from(args.opt_value_from_str("--keeper-state-dir")?);
    let size_spec: String = args.opt_value_from_str("--keeper-size")?.unwrap_or_else(|| "1920x1080".to_owned());
    let session_exec: String = args.opt_value_from_str("--keeper-exec")?.unwrap_or_default();
    if let Some(path) = args.opt_value_from_str::<_, PathBuf>("--config")? {
        config::set_path(path);
    }

    // The one place a bad configuration is not fatal. A worker that cannot
    // read the file drops its connection; a keeper that refused to start would
    // deny somebody their desktop over a typo in a key it does not even use.
    // It reads the log block and nothing else, and says so when it falls back.
    let (log, complaint) = match config::load_strict(config::path()) {
        Ok(config) => (config.log, None),
        Err(error) => (config::Log::default(), Some(format!("{error:#}"))),
    };
    logging::setup(&log);
    if let Some(complaint) = complaint {
        tracing::warn!(
            error = %complaint,
            "keeper: cannot read the configuration — logging with the built-in defaults, and starting the session anyway"
        );
    }

    let size = match size_spec.split_once(['x', 'X']) {
        Some((w, h)) => (
            w.trim().parse().context("--keeper-size width")?,
            h.trim().parse().context("--keeper-size height")?,
        ),
        None => anyhow::bail!("--keeper-size expects <WIDTHxHEIGHT>"),
    };

    // Detach from the worker that spawned us: the session must outlive the
    // connection, and a keeper still in the worker's process group would be
    // torn down with it.
    //
    // setsid alone is not enough. This process is the worker's direct child,
    // so the worker's wait() would block for the whole session — the login
    // would hang before it ever checked whether the session came up. Fork
    // once more: the parent exits so that wait() returns immediately, and the
    // real keeper is re-parented to init.
    // SAFETY: fork from a single-threaded process that has not started a
    // runtime; the child inherits a consistent address space.
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork the keeper: {}", std::io::Error::last_os_error()),
        0 => {
            // SAFETY: the child is not a group leader, so setsid succeeds.
            unsafe { libc::setsid() };
        }
        // SAFETY: _exit avoids running atexit handlers and flushing buffers
        // this forked copy shares with the worker.
        _ => unsafe { libc::_exit(0) },
    }

    let args = session::keeper_main::KeeperArgs {
        user,
        display: display_number,
        state_dir,
        size,
        session_exec,
    };
    let user_for_log = args.user.clone();
    // Log the failure before returning it. The worker spawns this process
    // with stdout and stderr on /dev/null, so an Err out of main goes nowhere
    // — which is exactly why a failed session reported only "start the
    // session keeper for <user>" with no cause attached.
    session::keeper_main::run(&args).inspect_err(|error| {
        tracing::error!(
            user = %user_for_log,
            display = display_number,
            error = format!("{error:#}"),
            "session keeper failed"
        );
    })
}

/// Report what linrdp can do on this machine.

/// An empty SAM makes every login fail as "invalid username", which reads
/// like the user typed the wrong name.
///
/// NLA needs the account secret (MS-NLMP), so `/etc/shadow` cannot serve it
/// and linrdp keeps a copy it learns from the system's own PAM stack. Until
/// that stack has handed one over, CredSSP denies every logon with a message
/// about the *name*, and nothing anywhere says why. Say it at startup, where
/// it is cheap to read.
fn warn_if_no_accounts() {
    if sam::account_names().is_empty() {
        tracing::warn!(
            store = %sam::sam_path().display(),
            "no account's system password has been captured yet — every NLA login will be \
             denied as 'invalid username'. Check `linrdp doctor`: if PAM capture is wired, \
             authenticate once on this machine (su -, ssh, console) and it will be learned"
        );
    }
}


/// Store the password the system just verified, so NLA can use it.
///
/// Run as `auth optional pam_exec.so expose_authtok quiet /usr/local/bin/linrdp
/// --capture-credential`: `pam_exec` hands us the account name in `PAM_USER`
/// and the typed password on stdin.
///
/// Two rules keep this honest:
///
/// * **Never fail.** This sits in the system authentication stack; anything it
///   returns other than success is a chance to lock someone out of their own
///   machine. Every path here ends in a log line and a zero exit.
/// * **Never keep an unverified password.** The module runs whether or not the
///   authentication that carried it succeeded, so a typo at a `su` prompt
///   would otherwise poison the store and break RDP until the next correct
///   login. The password is checked against `/etc/shadow`/PAM first, and a
///   password that does not authenticate is discarded.
fn capture_credential() {
    use std::io::Read as _;

    // Logging comes first, before the first line worth recording, and it is
    // this helper's own — not `setup_logging`. `setup_logging` announces itself
    // ("linrdp: logging to <path>") and falls back to stderr when the file will
    // not open; both are fine for a server started by systemd and both are a
    // line on the terminal of every `su`, `ssh`, `sudo` and console login,
    // because pam_exec runs this on the machine's own authentication stack.
    //
    // The config is read the tolerant way the keeper reads it: a typo in a key
    // this helper does not even use must never keep it from running — and, here,
    // must never make it say so on a terminal.
    let mut args = pico_args::Arguments::from_env();
    let _ = args.contains("--capture-credential");
    if let Ok(Some(path)) = args.opt_value_from_str::<_, PathBuf>("--config") {
        config::set_path(path);
    }
    let (log, complaint) = match config::load_strict(config::path()) {
        Ok(config) => (config.log, None),
        Err(error) => (config::Log::default(), Some(format!("{error:#}"))),
    };
    setup_helper_logging(&log);
    if let Some(complaint) = complaint {
        tracing::warn!(
            error = %complaint,
            "credential capture: cannot read the configuration — logging with the built-in defaults"
        );
    }

    let Ok(username) = std::env::var("PAM_USER") else {
        tracing::debug!("credential capture: no PAM_USER — not called from pam_exec");
        return;
    };
    let service = std::env::var("PAM_SERVICE").unwrap_or_default();
    let mut password = String::new();
    if std::io::stdin().read_to_string(&mut password).is_err() {
        tracing::warn!(%username, "credential capture: could not read the token from pam_exec");
        return;
    }
    // pam_exec terminates the token with NUL; some stacks add a newline.
    let password = password.trim_end_matches(['\0', '\n', '\r']);
    if password.is_empty() {
        tracing::debug!(%username, %service, "credential capture: empty token (passwordless path)");
        return;
    }

    match auth::verify_system_password(&username, password) {
        Ok(true) => match sam::set_password(&username, password) {
            Ok(()) => tracing::info!(
                %username,
                %service,
                "captured this account's system password — NLA logins will use it"
            ),
            Err(error) => tracing::warn!(%username, %error, "credential capture: could not write the store"),
        },
        // The common case, not an error: a mistyped password, or a PAM stack
        // where this module runs before the one that would have rejected it.
        Ok(false) => tracing::debug!(%username, %service, "credential capture: token did not authenticate — discarded"),
        Err(reason) => tracing::debug!(%username, %service, %reason, "credential capture: no verdict — discarded"),
    }
}



/// Bind every listener the configuration names and fork a worker per
/// connection.
fn supervisor_main(mut args: pico_args::Arguments) -> anyhow::Result<()> {
    if let Some(path) = args.opt_value_from_str::<_, PathBuf>("--config")? {
        config::set_path(path);
    }
    refuse_leftovers(args)?;

    let loaded = config::load_or_default(config::path())?;
    logging::setup(&loaded.config.log);
    if loaded.from_defaults {
        tracing::info!(
            path = %config::path().display(),
            "no configuration file — serving the built-in defaults; `linrdp service install` writes one"
        );
    }

    // Seal a legacy cleartext SAM once, here in the long-lived root supervisor,
    // before any worker is forked. No-op when the store is missing or already
    // sealed. The workers inherit the sealed file and never re-migrate.
    sam::migrate_plaintext();

    session::runtime_dir::ensure_state_dir(std::path::Path::new(session::runtime_dir::STATE_DIR))
        .context("prepare the supervisor state directory")?;

    // Whatever happened to the previous supervisor, the desktops it left
    // behind must not be reachable unlocked: the process that would have
    // locked them on disconnect is precisely the one that went away.
    let locked = session::registry::lock_all(
        std::path::Path::new(session::runtime_dir::STATE_DIR),
        loaded.config.session.display_range.range(),
    );
    if locked > 0 {
        tracing::info!(sessions = locked, "locked sessions inherited from a previous supervisor");
    }

    // Before the first connection, so the certificate an operator has to
    // import into their clients exists the moment the service is up.
    tls::ensure_default_identity(&loaded.config.tls).context("failed to prepare the TLS identity")?;

    // Before the bind, not after it. A second server is not a failure to
    // discover halfway through opening sockets: it is a reason not to start,
    // and saying so first — with the process that is already there — is the
    // difference between an answer and two lines of errno with the answer
    // underneath them.
    if let Some(found) = daemon::look(&daemon::ports_of(&loaded.config)) {
        anyhow::bail!("{}", daemon::already_running(&found));
    }

    let bound = supervisor::bind_all(&loaded.config)?;

    // After the bind, so a supervisor that was refused leaves no record
    // claiming it is running.
    daemon::write_pid_file();

    supervisor::run(bound)
}

async fn serve() -> anyhow::Result<()> {
    let mut args = pico_args::Arguments::from_env();

    // `--serve-fd` marks a worker the supervisor forked: it serves exactly the
    // one connection on that descriptor. `--listener` names which listener in
    // the configuration this process is, and is the only thing a worker is
    // ever told — every setting comes from the file both processes read.
    let serve_fd: Option<i32> = args.opt_value_from_str("--serve-fd")?;
    let listener: String = args
        .opt_value_from_str("--listener")?
        .context("--listener <ADDRESS:PORT> says which listener from the configuration to serve")?;
    if let Some(path) = args.opt_value_from_str::<_, PathBuf>("--config")? {
        config::set_path(path);
    }
    // Set by a supervisor that was started with `linrdp debug`, and by nothing
    // else. It changes how loud this worker is and nothing about what it
    // serves — every such setting still comes from the file.
    if let Some(filter) = args.opt_value_from_str::<_, String>("--log-level")? {
        logging::set_override(&filter);
    }
    refuse_leftovers(args)?;

    // A worker is answering "what did the operator ask for on this port?", and
    // there is no safe guess at that: it loads strictly, and refuses the
    // connection rather than serving one it invented. Without `--serve-fd`
    // this process is somebody running linrdp by hand on a machine that may
    // never have been configured, which is what the defaults are for.
    let config = if serve_fd.is_some() {
        config::load_strict(config::path())?
    } else {
        let loaded = config::load_or_default(config::path())?;
        if loaded.from_defaults {
            eprintln!("linrdp: no {} — using the built-in defaults", config::path().display());
        }
        loaded.config
    };

    // The log block is service-wide and cannot be overridden, so it is
    // readable before we know which listener this is — which matters, because
    // failing to find the listener is exactly the failure that must not be
    // silent.
    logging::setup(&config.log);

    let effective = match config.effective(&listener) {
        Ok(effective) => effective,
        Err(error) => {
            // Name the client. "Connection reset with nothing in the log" is
            // the failure this whole file has fought before.
            let peer = serve_fd.and_then(|fd| {
                // SAFETY: the supervisor placed an accepted socket on this
                // descriptor and this process owns it. Taking it here closes
                // it on the way out, which is the intent: the connection is
                // being refused.
                let stream = unsafe { <std::net::TcpStream as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                stream.peer_addr().ok()
            });
            tracing::error!(
                listener = %listener,
                config = %config::path().display(),
                peer = peer.map(|p| p.to_string()).unwrap_or_default(),
                error = format!("{error:#}"),
                "refusing the connection: this listener is not in the configuration"
            );
            return Err(error);
        }
    };

    let auth_mode = effective.auth;
    let greeter_mode = auth_mode.is_greeter();
    let enable_usb = effective.features.usb;
    let console_mode = effective.session.console.enabled;
    let display_range = effective.session.display_range.range();
    let lock_session = effective.session.lock_on_disconnect;
    let switch_to_greeter = effective.session.switch_to_greeter;
    let fixed_size: Option<(u16, u16)> = effective.session.fixed_size.map(|s| (s.width, s.height));
    let bind_addr: SocketAddr = effective
        .bind
        .parse()
        .with_context(|| format!("listener `{}` is not an address and port", effective.bind))?;

    // Console mode serves one screen that already exists. Which screen is a
    // configuration answer and deliberately not an environment one: the unit
    // carries no Environment=, and the fallback an absent $DISPLAY used to
    // reach was `:99` — either somebody else's screen or nobody's.
    if console_mode {
        let display = effective.session.console.display.clone().context(
            "session.console.enabled is set without session.console.display — there is no \
             default for it, because guessing which screen to share serves somebody else's \
             desktop to whoever connects",
        )?;
        session::gate::set_console(display, effective.session.console.xauthority.clone());
    }

    // Seal a legacy cleartext store, once. In the supervisor the migration
    // already ran there before any worker forked (see `supervisor_main`); only
    // the direct, single-process path needs it here. Guarding on `serve_fd`
    // keeps per-connection workers from re-reading the file on every login.
    if serve_fd.is_none() {
        sam::migrate_plaintext();
    }

    // Matched on the enum, not on a string with a catch-all: a mode added
    // later must be a compile error here rather than quietly inheriting
    // whatever `both` does.
    match auth_mode {
        config::Auth::Nla => {
            tracing::info!(%bind_addr, "LinRDP starting — auth: NLA only (CredSSP/NTLM)");
            warn_if_no_accounts();
        }
        config::Auth::System => {
            tracing::info!(%bind_addr, "LinRDP starting — auth: system password only (TLS, no NLA)");
        }
        config::Auth::Greeter => {
            tracing::info!(%bind_addr, "LinRDP starting — auth: server-drawn logon screen (TLS, no NLA)");
        }
        config::Auth::Both => {
            tracing::info!(
                %bind_addr,
                "LinRDP starting — auth: NLA or TLS, whichever the client negotiates"
            );
            warn_if_no_accounts();
        }
    }

    let identity = tls::load_or_generate_identity(&effective.tls).context("failed to prepare TLS identity")?;
    let acceptor = identity.make_acceptor().context("failed to build TLS acceptor")?;

    // Multi-session: the worker binds itself to the authenticated user's
    // desktop. The account is recorded by the credential resolver below
    // (CredSSP's SAM lookup) and turned into a session in
    // `on_connection_info`, which only runs once CredSSP has succeeded.
    let multi_session = serve_fd.is_some() && !console_mode;
    let pending_identity = Arc::new(session::router::PendingIdentity::default());

    // The validator feeds the session router in `system` mode: there is no
    // CredSSP resolver on that path, so the account it just verified is the
    // only authenticated identity the connection will ever produce.
    let validator: Arc<dyn ironrdp_server::CredentialValidator> =
        Arc::new(auth::ShadowValidator::new(Some(Arc::clone(&pending_identity))).deferring_to_greeter(greeter_mode));

    if multi_session {
        session::runtime_dir::ensure_state_dir(std::path::Path::new(session::runtime_dir::STATE_DIR))
            .context("prepare the session state directory")?;
        // From here on this process may not touch any display until a session
        // is bound — there is no ambient fallback to fall back to.
        session::gate::arm();
    }

    // NLA per MS-RDPBCGR 5.4.2: NTLM verifies the client's typed password
    // against the account secret from our SAM (the Linux analogue of Windows
    // SAM). The ShadowValidator then re-checks the delegated credentials.
    let sam_resolver: std::sync::Arc<dyn Fn(&str) -> std::io::Result<ironrdp_server::Credentials> + Send + Sync> =
        std::sync::Arc::new({
            let pending = Arc::clone(&pending_identity);
            move |account: &str| match sam::lookup(account)? {
            Some(password) => {
                // Record, do not act: this is the account CredSSP is about to
                // verify, not one it has verified. The session is created
                // later, from on_connection_info, which only runs on success.
                pending.record(account, &password);
                Ok(ironrdp_server::Credentials {
                username: account.to_owned(),
                password,
                domain: None,
            })
            },
            None => Err(std::io::Error::other("invalid username")),
        }});

    let cliprdr: Box<dyn CliprdrServerFactory> =
        Box::new(clipboard::X11CliprdrServerFactory::default());

    // Graphics pipeline (MS-RDPEGFX): H.264 video + lossless ClearCodec for
    // text on clients that negotiate it (mstsc). The shared session carries
    // the per-connection pipeline handle from the DVC side to the display
    // loop; the suppressed flag is shared so the backend stops emitting
    // frames while the client is minimized.
    let gfx_session = Arc::new(gfx::GfxSession::new());
    let display_suppressed = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Shared auto-detect handles (MS-RDPBCGR 2.2.14): the server's probe
    // loop writes the measured RTT / session-minimum RTT here, and the EGFX
    // display loop reads them to size its in-flight window from the
    // bandwidth-delay product. The pointer-cache handle carries the client's
    // negotiated pointerCacheSize for the cursor-shape LRU.
    let autodetect_rtt = Arc::new(std::sync::atomic::AtomicU32::new(u32::MAX));
    let autodetect_baseline = Arc::new(std::sync::atomic::AtomicU32::new(u32::MAX));
    // Measured goodput (kbit/s) from the client's Bandwidth Measure Results —
    // drives the adaptive H.264 bitrate in the EGFX display loop.
    let autodetect_bw = Arc::new(std::sync::atomic::AtomicU32::new(u32::MAX));
    let pointer_cache = Arc::new(std::sync::atomic::AtomicU16::new(0));

    // Capture/input backends. X11 is the default; `features.wayland` (cargo
    // feature "wayland") negotiates an xdg-desktop-portal session instead:
    // PipeWire screencast for frames, libei over EIS for input.
    //
    // A build without the feature warns rather than refusing, so one
    // configuration file can be deployed to a fleet of mixed builds.
    #[cfg(feature = "wayland")]
    let use_wayland = effective.features.wayland;
    #[cfg(not(feature = "wayland"))]
    let use_wayland = {
        if effective.features.wayland {
            tracing::warn!("features.wayland ignored: this binary was built without the \"wayland\" feature");
        }
        false
    };

    #[allow(clippy::redundant_clone)]
    let (input_handler, display_factory): (
        AnyInput,
        Arc<dyn gfx_display::DisplaySourceFactory>,
    ) = if use_wayland {
        #[cfg(feature = "wayland")]
        {
            tracing::info!("negotiating xdg-desktop-portal session (Wayland)");
            let restore_token = std::fs::read_to_string("/var/lib/linrdp/portal-restore-token").ok();
            let handles = wayland::portal::PortalSession::connect(restore_token.as_deref())
                .await
                .expect("portal session failed");
            let capture =
                wayland::pipewire::PwCapture::start(handles.pipewire_fd, handles.stream.node_id, None)
                    .expect("pipewire capture failed");
            let input = match handles.eis_fd {
                Some(fd) => wayland::ei::EiInputHandler::new(
                    fd,
                    (handles.stream.width, handles.stream.height),
                )
                .expect("libei setup failed"),
                None => {
                    anyhow::bail!("portal has no ConnectToEIS - Wayland input unavailable (update xdg-desktop-portal)");
                }
            };
            (
                AnyInput::Wayland(input),
                Arc::new(wayland::pipewire::PwDisplayFactory::new(capture.shared())),
            )
        }
        #[cfg(not(feature = "wayland"))]
        {
            unreachable!("features.wayland without the wayland feature is refused above")
        }
    } else {
        (
            if multi_session {
                // Deferred for the same reason as the display: connecting now
                // would bind input to the shared desktop, and a worker that
                // later failed to bind a session would be typing into it.
                AnyInput::DeferredX11(None, DeferredInputLog::default(), session::gate::generation())
            } else {
                AnyInput::X11(X11InputHandler::connect().expect("X11 unavailable for input"))
            },
            if serve_fd.is_some() && !console_mode {
                // A worker must not bind to a display before it knows whose
                // desktop it serves; the factory connects on the first frame,
                // after the router has set $DISPLAY.
                Arc::new(capture::X11DisplayFactory::deferred(fixed_size))
            } else {
                Arc::new(capture::X11DisplayFactory::new(
                    X11Display::connect(fixed_size).expect("X11 display unavailable"),
                ))
            },
        )
    };

    // Every arm lands on the same builder state; only the advertised security
    // protocol differs (MS-RDPBCGR 5.4.5.1 negotiation).
    let builder = RdpServer::builder().with_addr(bind_addr);
    let secured = match auth_mode {
        config::Auth::Nla => builder.with_hybrid(acceptor, identity.pub_key.clone()),
        config::Auth::System | config::Auth::Greeter => builder.with_tls(acceptor),
        config::Auth::Both => builder.with_hybrid_or_tls(acceptor, identity.pub_key.clone()),
    };
    let mut server = secured
        .with_input_handler(input_handler)
        .with_display_handler(gfx_display::EgfxDisplay::new(
            display_factory,
            Arc::clone(&gfx_session),
            Arc::clone(&display_suppressed),
            Arc::clone(&autodetect_rtt),
            Arc::clone(&autodetect_baseline),
            Arc::clone(&autodetect_bw),
            Arc::clone(&pointer_cache),
            effective.features.avc444v2,
        ))
        .with_gfx_factory(Some(Box::new(gfx::LinrdpGfxFactory::new(Arc::clone(
            &gfx_session,
        )))))
        .with_display_suppressed_handle(display_suppressed)
        // Preempt any live session when an authenticated client connects.
        // Without this the accept loop blocks on the running session and
        // every new TCP connection hangs silently in the kernel backlog
        // (verified: four probes, zero accepts, zero logs) — a reconnecting
        // mstsc stares at a black screen until the old session ends. With
        // preemption, the newcomer negotiates as a candidate and evicts the
        // old session, so "reconnect while a session lives" just works.
        .with_preempt_existing_session(true)
        .with_honor_client_desktop_size(Some(ironrdp_server::DesktopSize {
            width: session::SESSION_SCREEN_MAX.0,
            height: session::SESSION_SCREEN_MAX.1,
        }))
        .with_ainput(false)
        .with_credential_resolver(sam_resolver)
        .with_autodetect_rtt_handle(autodetect_rtt)
        .with_autodetect_baseline_rtt_handle(autodetect_baseline)
        .with_autodetect_bandwidth_handle(autodetect_bw)
        .with_pointer_cache_handle(pointer_cache)
        .with_dynamic_channel_attacher(|dvc| {
            // Write client mic audio into the PulseAudio pipe-source FIFO so
            // Linux applications see it as a microphone (USB-sound-card model).
            //
            // The FIFO belongs to the session, so it is resolved when packets
            // arrive rather than here: this channel is attached before the
            // logon screen has accepted anyone, when no session exists yet.
            let mut fifo = mic::MicFifo::new();
            let channel = mic::MicInputChannel::new(Box::new(move |packet: Vec<u8>| {
                fifo.write(&packet);
            }));
            *dvc = std::mem::replace(
                dvc,
                ironrdp_dvc::DrdynvcServer::new(),
            )
            .with_dynamic_channel(channel);
        })
        .with_usb_factory(enable_usb.then(|| Box::new(usb::LoggingUsbDeviceFactory) as Box<dyn ironrdp_server::DeviceFactory>))
        .with_bitmap_codecs(ironrdp_pdu::rdp::capability_sets::BitmapCodecs(vec![
            ironrdp_pdu::rdp::capability_sets::Codec {
                id: 0,
                property: ironrdp_pdu::rdp::capability_sets::CodecProperty::NsCodec(
                    ironrdp_pdu::rdp::capability_sets::NsCodec {
                        is_dynamic_fidelity_allowed: true,
                        is_subsampling_allowed: true,
                        // Server preference: minimal chroma loss. The
                        // client's capability is a ceiling, not a target —
                        // see the encoder selection in ironrdp-server.
                        color_loss_level: 1,
                    },
                ),
            },
            // RemoteFX image mode (MS-RDPRFX): what a Windows server
            // negotiates with mstsc-class clients. The encoder priority in
            // ironrdp-server picks it over NSCodec whenever the client
            // offers it; NSCodec stays as the fallback for NSCodec-only
            // clients (macOS Microsoft Remote Desktop / Windows App).
            ironrdp_pdu::rdp::capability_sets::Codec {
                id: 5,
                property: ironrdp_pdu::rdp::capability_sets::CodecProperty::ImageRemoteFx(
                    ironrdp_pdu::rdp::capability_sets::RemoteFxContainer::ServerContainer(4),
                ),
            },
        ]))
        .with_remotefx_entropy_coder(Some(ironrdp_pdu::rdp::capability_sets::EntropyBits::Rlgr3))
        .with_cliprdr_factory(Some(cliprdr))
        .with_sound_factory(Some(Box::new(sound_real::SystemSoundFactory::default())))
        .with_credential_validator(Some(validator))
        .with_connection_handler(Some({
            let lifecycle: Box<dyn ironrdp_server::ConnectionHandler> =
                Box::new(session_ctl::SessionController::new(lock_session, switch_to_greeter));
            if multi_session {
                Box::new(session::router::SessionRouter::new(
                    lifecycle,
                    Arc::clone(&pending_identity),
                    std::path::PathBuf::from(session::runtime_dir::STATE_DIR),
                    display_range.clone(),
                    console_mode,
                    fixed_size,
                    greeter_mode,
                )) as Box<dyn ironrdp_server::ConnectionHandler>
            } else {
                lifecycle
            }
        }))
        .build();

    // Protocol-level network auto-detect (MS-RDPBCGR 2.2.14) and server
    // heartbeat (2.2.16.1): both were implemented in ironrdp-server but never
    // enabled by the binary. Auto-detect feeds the RTT/bandwidth handles the
    // display pacing uses; heartbeat lets clients detect dead connections.
    server.enable_autodetect();
    server.enable_heartbeat(ironrdp_server::heartbeat::HeartbeatConfig::default());

    // Continuous auto-detect (1.3.9): periodic RTT probes keep the RTT and
    // bandwidth estimates fresh, and the bandwidth window they pace doubles as
    // the goodput signal the adaptive H.264 encoder consumes. KRdp probes at
    // this same 70 ms cadence; the bandwidth Start/Stop state machine ticks
    // here too (one Start roughly every 2 s, window open ~500 ms), so a slow
    // event loop just widens the spacing instead of flooding the client.
    {
        let events = server.event_sender().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(70));
            // A stalled loop must not burst-replay missed probes; the next one
            // fires 70 ms after the wake-up instead.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // first tick fires immediately; skip it
            loop {
                interval.tick().await;
                let _ = events.send(ironrdp_server::ServerEvent::AutoDetectRttRequest);
            }
        });
    }

    // UDP multitransport (MS-RDPEMT): the request parameters are shared by
    // the TCP bootstrap PDU and the UDP accept loop, binding the two
    // transports to one session via the security cookie. The event channel
    // connects the tunnel to the session (Soft-Sync + DVC data pump).
    // `features.udp: false` skips the listener entirely — TCP-only sessions,
    // kept as a bisect switch for transport bugs.
    //
    // It once carried a note blaming UDP for mstsc's CapsAdvertise decoder
    // recovery ("a corrupted big frame over the fresh UDP tunnel"). That was
    // a misattribution: the recovery came from the ClearCodec seqNumber
    // restarting on every encoder rebuild (MS-RDPEGFX 2.2.4.1) and from two
    // H.264 encoders feeding the client's single AVC444v2 decoder (2.2.4.6).
    // With those fixed, UDP was verified working end to end — mstsc reports
    // "transport protocol: UDP" over a 100 s session with no recovery and no
    // reset. Do not disable UDP to chase a graphics fault.
    let multitransport = if effective.features.udp {
        // The UDP socket has to carry the same port as the TCP connection the
        // client arrived on (MS-RDPEMT 3.1.1), and each worker binds its own —
        // so a worker forked from the 3390 listener binds UDP 3390. Getting
        // that wrong fails quietly: the error below is a warning and the
        // session simply runs over TCP.
        match udp::spawn(bind_addr, &identity, server.event_sender().clone()) {
            Ok(request) => Some(request),
            Err(error) => {
                tracing::warn!(%error, "RDP-UDP listener unavailable; serving TCP-only");
                None
            }
        }
    } else {
        tracing::info!("features.udp is off — serving TCP-only");
        None
    };
    server.set_multitransport(multitransport);

    if let Some(fd) = serve_fd {
        // Worker: the supervisor already accepted this connection and handed
        // it over on `fd`. Serving it directly keeps the accept loop — and
        // the fork decision — in exactly one place.
        tracing::info!(fd, "worker serving one connection from the supervisor");
        // SAFETY: the supervisor dup2'd the accepted socket onto this
        // descriptor immediately before exec, and nothing else in this
        // process touches it.
        let std_stream = unsafe { <std::net::TcpStream as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        std_stream.set_nonblocking(true).context("set the handed-over socket non-blocking")?;
        let stream = tokio::net::TcpStream::from_std(std_stream).context("adopt the handed-over socket")?;
        server.run_connection(stream).await?;
        return Ok(());
    }

    tracing::info!("listening — connect with any RDP client");
    server.run().await?;
    Ok(())
}


/// Input backend selector for `features.wayland`: `with_input_handler` is generic,
/// so the variants are dispatched through one implementing type.
enum AnyInput {
    X11(X11InputHandler),
    /// A multi-session worker that has not connected yet.
    ///
    /// Connecting at startup would bind input to the ambient display — the
    /// shared desktop — and a worker whose session later failed to start
    /// would be typing into it. Input only arrives after authentication, by
    /// which time the session gate names the right display, so the
    /// connection is made on the first event and never before.
    DeferredX11(Option<X11InputHandler>, DeferredInputLog, u64),
    #[cfg(feature = "wayland")]
    Wayland(wayland::ei::EiInputHandler),
}


/// Rate limit for the deferred-input failure message.
///
/// Input arrives as fast as the client can send it, and every event retries
/// the connection, so an unreported cause turns into a flood that buries the
/// one line that matters. One line per failure burst, with a count.
#[derive(Default)]
struct DeferredInputLog {
    last: Option<std::time::Instant>,
    suppressed: u64,
}

impl DeferredInputLog {
    const EVERY: core::time::Duration = core::time::Duration::from_secs(5);

    fn report(&mut self, error: &anyhow::Error) {
        let now = std::time::Instant::now();
        if self.last.is_some_and(|at| now.duration_since(at) < Self::EVERY) {
            self.suppressed += 1;
            return;
        }
        self.last = Some(now);
        tracing::warn!(
            error = format!("{error:#}"),
            dropped_since_last = self.suppressed,
            "input: cannot reach the bound display — events dropped"
        );
        self.suppressed = 0;
    }
}

impl AnyInput {
    /// The X11 handler, connecting on first use for a deferred worker.
    /// `None` while no session is bound — input is dropped rather than sent
    /// somewhere it does not belong.
    fn x11(&mut self) -> Option<&mut X11InputHandler> {
        match self {
            Self::X11(handler) => Some(handler),
            Self::DeferredX11(slot, log, generation) => {
                // The gate moved this worker (the logon screen handing over to
                // the desktop it just authenticated): the cached connection
                // still points at the old X server, and would type the user's
                // first keystrokes into a login form nobody is looking at.
                let now = crate::session::gate::generation();
                if *generation != now {
                    *generation = now;
                    *slot = None;
                }
                if slot.is_none() {
                    match X11InputHandler::connect() {
                        Ok(handler) => *slot = Some(handler),
                        Err(error) => {
                            // The whole chain: "connect to X display :10" on
                            // its own says nothing, and a client streaming
                            // mouse moves repeats it hundreds of times a
                            // second — 748 identical lines in one session,
                            // none of them naming the cause.
                            log.report(&error);
                            return None;
                        }
                    }
                }
                slot.as_mut()
            }
            #[cfg(feature = "wayland")]
            Self::Wayland(_) => None,
        }
    }
}

impl ironrdp_server::RdpServerInputHandler for AnyInput {
    fn keyboard(&mut self, event: ironrdp_server::KeyboardEvent) {
        #[cfg(feature = "wayland")]
        if let Self::Wayland(handler) = self {
            handler.keyboard(event);
            return;
        }
        if let Some(handler) = self.x11() {
            handler.keyboard(event);
        }
    }

    fn mouse(&mut self, event: ironrdp_server::MouseEvent) {
        #[cfg(feature = "wayland")]
        if let Self::Wayland(handler) = self {
            handler.mouse(event);
            return;
        }
        if let Some(handler) = self.x11() {
            handler.mouse(event);
        }
    }
}

/// Start logging for the credential-capture helper: the configured file, or
/// nowhere.
///
/// This is `setup_logging` with the two things that reach a terminal taken
/// out. `setup_logging` prints "linrdp: logging to <path>" once it has the file
/// open, and drops back to stderr when it cannot open it or when the filter is
/// malformed. Every one of those writes is correct for a server whose stderr is
/// the journal, and wrong for this helper, which pam_exec runs on every
/// authentication on the machine: the notice would print on every login, and
/// the fallback would turn any misconfiguration into console noise on all of
/// them. So here a bad filter falls back silently, and a file that will not
/// open means no subscriber at all rather than one aimed at the terminal.
fn setup_helper_logging(log: &config::Log) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(&log.level).unwrap_or_else(|_| EnvFilter::new("info,ironrdp=warn"));

    // No file configured means the journal for the server; the helper has no
    // journal of its own, and stderr is the terminal, so it stays silent.
    let Some(path) = log.file.as_ref() else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .compact()
        .with_env_filter(filter)
        .with_writer(std::sync::Mutex::new(file))
        .try_init();
}

