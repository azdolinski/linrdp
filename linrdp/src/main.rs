//! LinRDP — RDP server for Linux.
//!
//! Serves a test-pattern desktop on 0.0.0.0:3389, compatible with mstsc
//! (Windows Remote Desktop client). Connection sequence, capability
//! negotiation and security follow [MS-RDPBCGR].

#![allow(clippy::print_stdout)]

mod auth;
mod capture;
mod clipboard;
mod gfx;
mod gfx_display;
mod input;
mod mic;
mod pam;
mod sam;
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

const HELP: &str = "\
USAGE:
  linrdp [--bind-addr <ADDR>] [--usb] [--log-file <PATH>] [--fixed-size <WxH>]

Serves a real Linux desktop over RDP (auth: system accounts from /etc/shadow).

Commands:
  doctor                report what this machine is and what linrdp may do on
                        it: X servers, desktop sessions (and whether their
                        programs actually exist), PAM, logind, screen lockers

Multi-session:
  --supervisor          accept on the bind address and fork one worker per
                        connection; each worker serves its user's own desktop
  --display-range L-H   X display numbers workers may allocate (default 10-99)
  --console             attach to $DISPLAY instead of a per-user session
                        (the mstsc /admin equivalent, for the shared screen)
  --serve-fd N          internal: serve the connection the supervisor handed
                        over on descriptor N

Default bind: 0.0.0.0:3389. --usb enables USB device redirection (MS-RDPEUSB).
--fixed-size pins the desktop (e.g. 2880x1800): X is resized once at startup
and clients scale locally — recommended with mstsc, which composes EGFX
poorly right after a mid-session RandR resize.

Logging: written to /var/log/linrdp/linrdp.log when that directory can be
created (falling back to the terminal), or to the file given with --log-file.
Verbosity: LINRDP_LOG env var (default \"info,ironrdp=warn\").
";

/// Supervisor mode forks per connection, and `fork` in a multi-threaded
/// runtime leaves only the calling thread alive in the child. So the argv is
/// inspected before any runtime exists, and the supervisor never builds one.
fn main() -> anyhow::Result<()> {
    // `doctor` answers "what is this machine, and what may linrdp do on it?"
    // before anything is started, so a missing piece is a report rather than
    // a runtime failure with no explanation.
    if std::env::args().nth(1).as_deref() == Some("doctor") {
        return doctor();
    }
    if std::env::args().any(|arg| arg == "--keeper") {
        return keeper_main();
    }
    if std::env::args().any(|arg| arg == "--supervisor") {
        return supervisor_main();
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?
        .block_on(serve())
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
    let log_file: Option<String> = args.opt_value_from_str("--log-file")?;
    setup_logging(log_file.as_deref());

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
fn doctor() -> anyhow::Result<()> {
    use session::detect::Verdict;

    let caps = session::detect::probe();
    println!("linrdp doctor");
    println!("  distribution : {}", caps.distro);
    println!(
        "  X servers    : {}",
        if caps.x_servers.is_empty() {
            "none".to_owned()
        } else {
            caps.x_servers.join(", ")
        }
    );
    println!(
        "  logind       : {}",
        if caps.logind { "yes" } else { "no" }
    );
    println!(
        "  PAM service  : {}",
        if caps.pam_service {
            "/etc/pam.d/linrdp"
        } else {
            "missing"
        }
    );
    println!(
        "  lockers      : {}",
        if caps.lockers.is_empty() {
            "none".to_owned()
        } else {
            caps.lockers.join(", ")
        }
    );

    println!("\n  desktop sessions:");
    if caps.sessions.is_empty() {
        println!("    (none found in /usr/share/xsessions or /usr/share/wayland-sessions)");
    }
    for s in &caps.sessions {
        println!(
            "    {:<18} {:<8} {:<10} {}",
            s.id,
            match s.kind {
                session::detect::SessionKind::X11 => "x11",
                session::detect::SessionKind::Wayland => "wayland",
            },
            if s.runnable { "runnable" } else { "MISSING" },
            s.exec
        );
    }

    let verdicts = session::detect::verdicts(&caps);
    println!();
    let mut blockers = 0;
    for verdict in &verdicts {
        match verdict {
            Verdict::Ok(m) => println!("  ok      {m}"),
            Verdict::Warning(m) => println!("  warn    {m}"),
            Verdict::Blocker(m) => {
                blockers += 1;
                println!("  BLOCKER {m}");
            }
        }
    }

    println!();
    if blockers == 0 {
        println!("  Per-user sessions can run on this machine.");
    } else {
        println!("  {blockers} blocker(s): per-user sessions cannot run until these are fixed.");
    }
    Ok(())
}

/// Accept on the bind address and fork a worker per connection.
fn supervisor_main() -> anyhow::Result<()> {
    let mut args = pico_args::Arguments::from_env();
    let _ = args.contains("--supervisor");
    let bind_addr: SocketAddr = args
        .opt_value_from_str("--bind-addr")?
        .unwrap_or_else(|| "0.0.0.0:3389".parse().expect("valid default bind addr"));
    let log_file: Option<String> = args.opt_value_from_str("--log-file")?;
    setup_logging(log_file.as_deref());

    session::runtime_dir::ensure_state_dir(std::path::Path::new(session::runtime_dir::STATE_DIR))
        .context("prepare the supervisor state directory")?;

    // Whatever happened to the previous supervisor, the desktops it left
    // behind must not be reachable unlocked: the process that would have
    // locked them on disconnect is precisely the one that went away.
    let display_range = match std::env::args()
        .position(|a| a == "--display-range")
        .and_then(|i| std::env::args().nth(i + 1))
    {
        Some(spec) => supervisor::parse_display_range(&spec)?,
        None => 10..=99,
    };
    let locked = session::registry::lock_all(
        std::path::Path::new(session::runtime_dir::STATE_DIR),
        display_range,
    );
    if locked > 0 {
        tracing::info!(sessions = locked, "locked sessions inherited from a previous supervisor");
    }

    // Everything except --supervisor is handed to each worker unchanged, so
    // the two roles share one command line.
    let worker_argv: Vec<String> = std::env::args().skip(1).filter(|a| a != "--supervisor").collect();
    supervisor::run(bind_addr, &worker_argv)
}

async fn serve() -> anyhow::Result<()> {
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        println!("{HELP}");
        return Ok(());
    }

    // Account provisioning for NLA (MS-RDPBCGR 5.4.2): the CredSSP/NTLM
    // protocol requires the server to know the account secret, so LinRDP
    // keeps its own SAM (like Windows SAM on a Windows server).
    if let Some(set_password) = args.opt_value_from_str::<_, String>("--set-password")? {
        let (username, password) = match set_password.split_once(':') {
            Some((u, p)) => (u.to_owned(), p.to_owned()),
            None => anyhow::bail!("--set-password expects USER:PASSWORD"),
        };
        sam::set_password(&username, &password).context("failed to write SAM")?;
        println!("LinRDP account '{username}' provisioned for NLA login.");
        return Ok(());
    }

    let enable_usb = args.contains("--usb");

    // Multi-session wiring. `--serve-fd` marks a worker forked by the
    // supervisor: it serves exactly the one connection on that descriptor.
    // `--console` is the mstsc /admin equivalent — attach to the ambient
    // $DISPLAY (the shared screen) instead of a per-user session.
    let serve_fd: Option<i32> = args.opt_value_from_str("--serve-fd")?;
    let console_mode = args.contains("--console");
    let display_range = match args.opt_value_from_str::<_, String>("--display-range")? {
        Some(spec) => supervisor::parse_display_range(&spec)?,
        None => 10..=99,
    };

    let bind_addr: SocketAddr = args
        .opt_value_from_str("--bind-addr")?
        .unwrap_or_else(|| "0.0.0.0:3389".parse().expect("valid default bind addr"));

    let log_file: Option<String> = args.opt_value_from_str("--log-file")?;

    // Session lifecycle (KRdp SessionController pattern): lock the logind
    // session when the last client disconnects / unlock on reconnect, and
    // optionally flip the seat to the greeter when a client takes over.
    let lock_session = args.contains("--lock-session");
    let switch_to_greeter = args.contains("--switch-to-greeter");

    let fixed_size: Option<(u16, u16)> = match args.opt_value_from_str::<_, String>("--fixed-size")? {
        Some(spec) => {
            let Some((w, h)) = spec.split_once(['x', 'X']) else {
                anyhow::bail!("--fixed-size expects <WIDTHxHEIGHT>, e.g. 2880x1800");
            };
            Some((
                w.trim().parse().context("--fixed-size width")?,
                h.trim().parse().context("--fixed-size height")?,
            ))
        }
        None => None,
    };

    setup_logging(log_file.as_deref());

    tracing::info!(%bind_addr, "LinRDP starting — auth: /etc/shadow accounts");

    let identity = tls::load_or_generate_identity().context("failed to prepare TLS identity")?;
    let acceptor = identity.make_acceptor().context("failed to build TLS acceptor")?;

    let validator: Arc<dyn ironrdp_server::CredentialValidator> = Arc::new(auth::ShadowValidator);

    // Multi-session: the worker binds itself to the authenticated user's
    // desktop. The account is recorded by the credential resolver below
    // (CredSSP's SAM lookup) and turned into a session in
    // `on_connection_info`, which only runs once CredSSP has succeeded.
    let multi_session = serve_fd.is_some() && !console_mode;
    let pending_identity = Arc::new(session::router::PendingIdentity::default());
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

    // Capture/input backends. X11 is the default; `--wayland` (cargo
    // feature "wayland") negotiates an xdg-desktop-portal session instead:
    // PipeWire screencast for frames, libei over EIS for input.
    #[cfg(feature = "wayland")]
    let use_wayland = args.contains("--wayland");
    #[cfg(not(feature = "wayland"))]
    let use_wayland = {
        if args.contains("--wayland") {
            tracing::warn!("--wayland ignored: binary built without the \"wayland\" feature");
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
            unreachable!("--wayland without the wayland feature is rejected above")
        }
    } else {
        (
            if multi_session {
                // Deferred for the same reason as the display: connecting now
                // would bind input to the shared desktop, and a worker that
                // later failed to bind a session would be typing into it.
                AnyInput::DeferredX11(None)
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

    let mut server = RdpServer::builder()
        .with_addr(bind_addr)
        .with_hybrid(acceptor, identity.pub_key.clone())
        .with_input_handler(input_handler)
        .with_display_handler(gfx_display::EgfxDisplay::new(
            display_factory,
            Arc::clone(&gfx_session),
            Arc::clone(&display_suppressed),
            Arc::clone(&autodetect_rtt),
            Arc::clone(&autodetect_baseline),
            Arc::clone(&autodetect_bw),
            Arc::clone(&pointer_cache),
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
            width: 3840,
            height: 2160,
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
            let mic_fifo: Option<Arc<std::sync::Mutex<std::io::BufWriter<std::fs::File>>>> =
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/run/user/1000/linrdp/mic.fifo")
                    .map(|f| Arc::new(std::sync::Mutex::new(std::io::BufWriter::new(f))))
                    .ok();
            let channel = mic::MicInputChannel::new(Box::new(move |packet: Vec<u8>| {
                if let Some(w) = &mic_fifo {
                    use std::io::Write as _;
                    let mut guard = w.lock().expect("mic fifo poisoned");
                    let _ = guard.write_all(&packet);
                    let _ = guard.flush();
                }
                tracing::trace!(bytes = packet.len(), "mic packet → linrdp_mic");
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
                    fixed_size.unwrap_or((1920, 1080)),
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
    // LINRDP_NO_UDP=1 skips the listener entirely — TCP-only sessions, kept
    // as a bisect switch for transport bugs.
    //
    // It once carried a note blaming UDP for mstsc's CapsAdvertise decoder
    // recovery ("a corrupted big frame over the fresh UDP tunnel"). That was
    // a misattribution: the recovery came from the ClearCodec seqNumber
    // restarting on every encoder rebuild (MS-RDPEGFX 2.2.4.1) and from two
    // H.264 encoders feeding the client's single AVC444v2 decoder (2.2.4.6).
    // With those fixed, UDP was verified working end to end — mstsc reports
    // "transport protocol: UDP" over a 100 s session with no recovery and no
    // reset. Do not disable UDP to chase a graphics fault.
    let multitransport = if std::env::var("LINRDP_NO_UDP").as_deref() == Ok("1") {
        tracing::warn!("LINRDP_NO_UDP=1 — UDP disabled, serving TCP-only");
        None
    } else {
        match udp::spawn(bind_addr, &identity, server.event_sender().clone()) {
            Ok(request) => Some(request),
            Err(error) => {
                tracing::warn!(%error, "RDP-UDP listener unavailable; serving TCP-only");
                None
            }
        }
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


/// Input backend selector for `--wayland`: `with_input_handler` is generic,
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
    DeferredX11(Option<X11InputHandler>),
    #[cfg(feature = "wayland")]
    Wayland(wayland::ei::EiInputHandler),
}

impl AnyInput {
    /// The X11 handler, connecting on first use for a deferred worker.
    /// `None` while no session is bound — input is dropped rather than sent
    /// somewhere it does not belong.
    fn x11(&mut self) -> Option<&mut X11InputHandler> {
        match self {
            Self::X11(handler) => Some(handler),
            Self::DeferredX11(slot) => {
                if slot.is_none() {
                    match X11InputHandler::connect() {
                        Ok(handler) => *slot = Some(handler),
                        Err(error) => {
                            tracing::warn!(%error, "input: no display bound yet — event dropped");
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

fn setup_logging(log_file: Option<&str>) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_env("LINRDP_LOG").unwrap_or_else(|_| EnvFilter::new("info,ironrdp=warn"));

    // Prefer a file (--log-file, or /var/log/linrdp/linrdp.log when the
    // directory can be created) so logs survive the terminal; the fallback
    // is the terminal itself.
    let default_path = std::path::Path::new("/var/log/linrdp/linrdp.log");
    let path = match log_file {
        Some(path) => std::path::PathBuf::from(path),
        None => {
            let dir = default_path.parent().expect("non-root default log path");
            if std::fs::create_dir_all(dir).is_ok() {
                default_path.to_path_buf()
            } else {
                PathBuf::new()
            }
        }
    };

    let file = if path.as_os_str().is_empty() {
        None
    } else {
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => Some(file),
            Err(error) => {
                eprintln!("linrdp: cannot open {} ({error}); logging to the terminal", path.display());
                None
            }
        }
    };

    match file {
        Some(file) => {
            eprintln!("linrdp: logging to {}", path.display());
            let _ = tracing_subscriber::fmt()
                .compact()
                .with_env_filter(filter)
                .with_writer(std::sync::Mutex::new(file))
                .try_init();
        }
        None => {
            let _ = tracing_subscriber::fmt().compact().with_env_filter(filter).try_init();
        }
    }
}
