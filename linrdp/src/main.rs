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
mod udp;
mod usb;
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
Default bind: 0.0.0.0:3389. --usb enables USB device redirection (MS-RDPEUSB).
--fixed-size pins the desktop (e.g. 2880x1800): X is resized once at startup
and clients scale locally — recommended with mstsc, which composes EGFX
poorly right after a mid-session RandR resize.

Logging: written to /var/log/linrdp/linrdp.log when that directory can be
created (falling back to the terminal), or to the file given with --log-file.
Verbosity: LINRDP_LOG env var (default \"info,ironrdp=warn\").
";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    // NLA per MS-RDPBCGR 5.4.2: NTLM verifies the client's typed password
    // against the account secret from our SAM (the Linux analogue of Windows
    // SAM). The ShadowValidator then re-checks the delegated credentials.
    let sam_resolver: std::sync::Arc<dyn Fn(&str) -> std::io::Result<ironrdp_server::Credentials> + Send + Sync> =
        std::sync::Arc::new(move |account: &str| match sam::lookup(account)? {
            Some(password) => Ok(ironrdp_server::Credentials {
                username: account.to_owned(),
                password,
                domain: None,
            }),
            None => Err(std::io::Error::other("invalid username")),
        });

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
    let pointer_cache = Arc::new(std::sync::atomic::AtomicU16::new(0));

    let mut server = RdpServer::builder()
        .with_addr(bind_addr)
        .with_hybrid(acceptor, identity.pub_key.clone())
        .with_input_handler(X11InputHandler::connect().expect("X11 unavailable for input"))
        .with_display_handler(gfx_display::EgfxDisplay::new(
            Arc::new(capture::X11DisplayFactory::new(
                X11Display::connect(fixed_size).expect("X11 display unavailable"),
            )),
            Arc::clone(&gfx_session),
            Arc::clone(&display_suppressed),
            Arc::clone(&autodetect_rtt),
            Arc::clone(&autodetect_baseline),
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
        .with_connection_handler(Some(Box::new(session_ctl::SessionController::new(
            lock_session,
            switch_to_greeter,
        ))))
        .build();

    // Protocol-level network auto-detect (MS-RDPBCGR 2.2.14) and server
    // heartbeat (2.2.16.1): both were implemented in ironrdp-server but never
    // enabled by the binary. Auto-detect feeds the RTT/bandwidth handles the
    // display pacing uses; heartbeat lets clients detect dead connections.
    server.enable_autodetect();
    server.enable_heartbeat(ironrdp_server::heartbeat::HeartbeatConfig::default());

    // Continuous auto-detect (1.3.9): periodic RTT probes keep the bandwidth
    // estimate fresh. The library emits probes on demand — drive it with a
    // timer.
    {
        let events = server.event_sender().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
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
    let multitransport = match udp::spawn(bind_addr, &identity, server.event_sender().clone()) {
        Ok(request) => Some(request),
        Err(error) => {
            tracing::warn!(%error, "RDP-UDP listener unavailable; serving TCP-only");
            None
        }
    };
    server.set_multitransport(multitransport);

    tracing::info!("listening — connect with any RDP client");
    server.run().await?;
    Ok(())
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
