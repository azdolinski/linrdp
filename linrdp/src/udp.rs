//! UDP multitransport (MS-RDPEMT / MS-RDPEUDP): sideband RDP-UDP listener.
//!
//! `ironrdp-server` sends the Initiate Multitransport Request over TCP after
//! the connection sequence completes (see `with_multitransport`); this module
//! owns the other half — the UDP socket on the same port as TCP that accepts
//! the client's RDP-UDP handshake:
//!
//! SYN → SYN+ACK/ACK (RDPEUDP2 reliable UDP) → TLS (our session certificate)
//! → Tunnel Create Request validated against the request_id + security_cookie
//! pair from the TCP bootstrap.
//!
//! The client connects to the UDP port matching the TCP listener address
//! (MS-RDPEMT 3.1.1). One transport is served at a time: the accept loop
//! rebinds after a transport closes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ironrdp_rdpeudp_tokio::{UdpAcceptConfig, accept_udp};
use ironrdp_rdpemt::TunnelConfig;
use ironrdp_server::{MultiTransportRequest, TlsIdentityCtx};
use tokio::net::UdpSocket;
use tokio_rustls::rustls;

/// Generate the multitransport request parameters and spawn the UDP accept
/// loop. `events` is the RDP server's event channel — once a transport is
/// established, the loop asks the server to Soft-Sync its dynamic channels to
/// the tunnel, then pumps DVC frames both directions.
pub(crate) fn spawn(
    bind_addr: SocketAddr,
    identity: &TlsIdentityCtx,
    events: tokio::sync::mpsc::UnboundedSender<ironrdp_server::ServerEvent>,
) -> anyhow::Result<MultiTransportRequest> {
    let mut cookie = [0u8; 16];
    fill_random(&mut cookie)?;
    let request = MultiTransportRequest {
        // Any nonzero value; the low bytes of the cookie keep it unique per run.
        request_id: u32::from_le_bytes([cookie[0], cookie[1], cookie[2], cookie[3] | 1]),
        security_cookie: cookie,
    };

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(identity.certs.clone(), identity.priv_key.clone_key())
        .context("failed to build rustls ServerConfig for RDP-UDP")?;
    let tls_config = Arc::new(server_config);

    tokio::spawn(listen_loop(bind_addr, tls_config, request.clone(), events));
    Ok(request)
}

async fn listen_loop(
    bind_addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    request: MultiTransportRequest,
    events: tokio::sync::mpsc::UnboundedSender<ironrdp_server::ServerEvent>,
) {
    loop {
        // `accept_udp` consumes the socket (it connects it to the accepted
        // peer), so bind fresh each iteration.
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(error) => {
                tracing::warn!(%bind_addr, %error, "RDP-UDP: cannot bind; multitransport disabled");
                return;
            }
        };

        let config = UdpAcceptConfig {
            tls_config: Arc::clone(&tls_config),
            tunnel_config: TunnelConfig {
                request_id: request.request_id,
                security_cookie: request.security_cookie,
            },
            connection_config: Default::default(),
            // Covers the whole accept: waiting for SYN (a TCP-only client
            // never connects) plus handshakes.
            accept_timeout: Duration::from_secs(60),
        };

        match accept_udp(socket, config).await {
            Ok(mut transport) => {
                tracing::info!(request_id = request.request_id, "RDP-UDP transport established");

                // Bind the tunnel to the session: the server sends a DVC
                // Soft-Sync request over TCP; after the client's response,
                // dynamic-channel traffic flows through these channels.
                let (to_tunnel, mut from_server) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
                let _ = events.send(ironrdp_server::ServerEvent::SoftSyncToUdp { to_tunnel });

                // Pump both directions until the transport closes. Incoming
                // frames are unframed DVC PDUs; outgoing likewise.
                loop {
                    tokio::select! {
                        incoming = transport.recv() => {
                            match incoming {
                                Some(frame) => {
                                    tracing::debug!(bytes = frame.len(), "UDP tunnel: client -> server");
                                    let _ = events.send(ironrdp_server::ServerEvent::UdpTunnelData(frame));
                                }
                                None => break,
                            }
                        }
                        outgoing = from_server.recv() => {
                            match outgoing {
                                Some(frame) => {
                                    tracing::debug!(bytes = frame.len(), "UDP tunnel: server -> client");
                                    if transport.send(frame).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
                let _ = transport.shutdown().await;
                tracing::info!("RDP-UDP transport closed");
            }
            Err(error) => {
                // Most common: the accept timed out because the client is
                // TCP-only or UDP is filtered. Log the whole cause chain —
                // "handshake failed" alone hides whether the SYN cookieHash,
                // the TLS exchange or the tunnel negotiation failed.
                tracing::debug!(error = %error_chain(&error), "RDP-UDP accept ended; rebinding");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// Render an error and its whole `source()` chain on one line: the wrapper
/// types' `Display` only prints the top message, which is exactly the part
/// that says nothing useful.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(" <- ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

fn fill_random(buf: &mut [u8]) -> anyhow::Result<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")
        .context("opening /dev/urandom")?
        .read_exact(buf)
        .context("reading /dev/urandom")
}
