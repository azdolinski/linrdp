//! LinRDP — RDP server for Linux.
//!
//! Serves a test-pattern desktop on 0.0.0.0:3389, compatible with mstsc
//! (Windows Remote Desktop client). Connection sequence, capability
//! negotiation and security follow [MS-RDPBCGR].

#![allow(clippy::print_stdout)]

mod auth;
mod capture;
mod clipboard;
mod input;
mod mic;
mod sam;
mod sound;
mod sound_real;
mod tls;
mod udp;
mod usb;

use core::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use ironrdp_cliprdr::backend::{CliprdrBackend, CliprdrBackendFactory};
use ironrdp_server::{CliprdrServerFactory, RdpServer, ServerEventSender};
use tokio::sync::mpsc::UnboundedSender;

use crate::capture::X11Display;
use crate::input::X11InputHandler;

const HELP: &str = "\
USAGE:
  linrdp [--bind-addr <ADDR>] [--usb]

Serves a real Linux desktop over RDP (auth: system accounts from /etc/shadow).
Default bind: 0.0.0.0:3389. --usb enables USB device redirection (MS-RDPEUSB).
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

    setup_logging();

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

    let mut server = RdpServer::builder()
        .with_addr(bind_addr)
        .with_hybrid(acceptor, identity.pub_key.clone())
        .with_input_handler(X11InputHandler::connect().expect("X11 unavailable for input"))
        .with_display_handler(X11Display::connect().expect("X11 display unavailable"))
        .with_honor_client_desktop_size(Some(ironrdp_server::DesktopSize {
            width: 3840,
            height: 2160,
        }))
        .with_ainput(false)
        .with_credential_resolver(sam_resolver)
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
                        color_loss_level: 3,
                    },
                ),
            },
        ]))
        .with_cliprdr_factory(Some(cliprdr))
        .with_sound_factory(Some(Box::new(sound_real::SystemSoundFactory::default())))
        .with_credential_validator(Some(validator))
        .build();

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


fn setup_logging() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_env("LINRDP_LOG").unwrap_or_else(|_| EnvFilter::new("info,ironrdp=warn"));
    let _ = tracing_subscriber::fmt().compact().with_env_filter(filter).try_init();
}
