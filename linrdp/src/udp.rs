//! UDP multitransport (MS-RDPEMT / MS-RDPEUDP): a worker's RDP-UDP tunnel.
//!
//! `ironrdp-server` sends the Initiate Multitransport Request over TCP during
//! the connection sequence, after licensing (see `with_multitransport`); this
//! module owns the other half: the client's RDP-UDP handshake
//!
//! SYN → SYN+ACK/ACK (RDPEUDP2 reliable UDP) → TLS (our session certificate)
//! → Tunnel Create Request validated against the request_id + security_cookie
//! pair from the TCP bootstrap.
//!
//! The UDP port is not the worker's own. One port carries every connection's
//! RDP-UDP traffic (MS-RDPEUDP 2.1), so the supervisor holds it and hands this
//! worker the datagrams of the client whose SYN carries the cookieHash of this
//! worker's request (MS-RDPEMT 3.2.1; see `udp_dispatch`). The worker answers
//! through a duplicate of the same socket.
//!
//! A connection gets one tunnel: it lasts as long as the main connection
//! (MS-RDPEMT 1.3.3), so once it closes the server is told and nothing further
//! is accepted.

use core::net::SocketAddr;
use core::time::Duration;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::sync::Arc;

use anyhow::Context as _;
use ironrdp_rdpemt::TunnelConfig;
use ironrdp_rdpeudp_tokio::{DatagramPort, UdpAcceptConfig, accept_udp_dispatched, cookie_hash};
use ironrdp_server::{MultiTransportRequest, TlsIdentityCtx};
use tokio::net::{UdpSocket, UnixDatagram};
use tokio::sync::mpsc;
use tokio_rustls::rustls;

use crate::udp_dispatch::{decode_datagram, encode_register};

/// Messages the tunnel queue holds: three full 2880x1800 graphics frames
/// (the pipeline's in-flight limit) cut into 1600-byte DVC chunks, with room
/// to spare.
const TUNNEL_QUEUE: usize = 65_536;

/// Datagrams from the client waiting for the RDP-UDP driver. RDP-UDP
/// retransmits what is lost, so a full queue drops rather than blocks.
const DATAGRAM_QUEUE: usize = 4096;

/// Generate the multitransport request, register it with the supervisor and
/// spawn the tunnel. `channel_fd` and `socket_fd` are the descriptors the
/// supervisor gave this worker (`udp_dispatch::CHANNEL_FD`, `SOCKET_FD`).
/// `events` is the RDP server's event channel: once a transport is
/// established, the tunnel asks the server to Soft-Sync its dynamic channels
/// to it, then pumps DVC frames both directions.
pub(crate) fn spawn(
    channel_fd: i32,
    socket_fd: i32,
    identity: &TlsIdentityCtx,
    events: mpsc::UnboundedSender<ironrdp_server::ServerEvent>,
) -> anyhow::Result<MultiTransportRequest> {
    // SAFETY: the supervisor placed this descriptor for this process alone,
    // and nothing else here takes ownership of it.
    let channel = unsafe { OwnedFd::from_raw_fd(channel_fd) };
    // SAFETY: as above.
    let socket = unsafe { OwnedFd::from_raw_fd(socket_fd) };
    spawn_on(
        std::os::unix::net::UnixDatagram::from(channel),
        std::net::UdpSocket::from(socket),
        identity,
        events,
    )
}

/// [`spawn`] on the channel and the shared socket themselves.
fn spawn_on(
    channel: std::os::unix::net::UnixDatagram,
    socket: std::net::UdpSocket,
    identity: &TlsIdentityCtx,
    events: mpsc::UnboundedSender<ironrdp_server::ServerEvent>,
) -> anyhow::Result<MultiTransportRequest> {
    let mut cookie = [0u8; 16];
    fill_random(&mut cookie)?;
    let request = MultiTransportRequest {
        // Any nonzero value; the low bytes of the cookie keep it unique per run.
        request_id: u32::from_le_bytes([cookie[0], cookie[1], cookie[2], cookie[3] | 1]),
        security_cookie: cookie,
    };
    let tunnel_config = TunnelConfig {
        request_id: request.request_id,
        security_cookie: request.security_cookie,
    };

    // Before the request can reach the client, so its SYN finds us. On the
    // plain socket, while it still blocks: a freshly registered tokio socket
    // reports WouldBlock to `try_send` until the reactor has seen it
    // writable, and the registration was lost that way on the live server.
    channel
        .send(&encode_register(&cookie_hash(&tunnel_config)))
        .context("registering the multitransport request with the supervisor")?;

    channel.set_nonblocking(true).context("RDP-UDP channel")?;
    let channel = UnixDatagram::from_std(channel).context("RDP-UDP channel")?;
    socket.set_nonblocking(true).context("RDP-UDP socket")?;
    let socket = Arc::new(UdpSocket::from_std(socket).context("RDP-UDP socket")?);

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(identity.certs.clone(), identity.priv_key.clone_key())
        .context("failed to build rustls ServerConfig for RDP-UDP")?;

    tokio::spawn(tunnel_loop(
        channel,
        socket,
        Arc::new(server_config),
        tunnel_config,
        events,
    ));
    Ok(request)
}

/// Accept the client's tunnel from the datagrams the supervisor hands over,
/// then carry the session's dynamic channels until it closes.
async fn tunnel_loop(
    channel: UnixDatagram,
    socket: Arc<UdpSocket>,
    tls_config: Arc<rustls::ServerConfig>,
    tunnel_config: TunnelConfig,
    events: mpsc::UnboundedSender<ironrdp_server::ServerEvent>,
) {
    // The client being accepted and the queue its datagrams go into.
    let mut client: Option<(SocketAddr, mpsc::Sender<Vec<u8>>)> = None;
    let mut accepting = None;
    let mut buf = vec![0u8; 9100];

    loop {
        tokio::select! {
            received = channel.recv(&mut buf) => {
                let len = match received {
                    Ok(len) => len,
                    Err(error) => {
                        tracing::debug!(%error, "RDP-UDP: supervisor channel closed");
                        return;
                    }
                };
                let Some((peer, datagram)) = decode_datagram(&buf[..len]) else {
                    continue;
                };
                match &client {
                    Some((served, queue)) if *served == peer => {
                        let _ = queue.try_send(datagram.to_vec());
                    }
                    // A second client with this request's cookie: the
                    // connection has one tunnel at a time.
                    Some(_) => tracing::debug!(%peer, "RDP-UDP: already accepting another client; dropped"),
                    None => {
                        // The supervisor starts a client with its SYN.
                        let (queue, incoming) = mpsc::channel(DATAGRAM_QUEUE);
                        client = Some((peer, queue));
                        let config = UdpAcceptConfig {
                            tls_config: Arc::clone(&tls_config),
                            tunnel_config: tunnel_config.clone(),
                            connection_config: Default::default(),
                            accept_timeout: Duration::from_secs(60),
                        };
                        let port = DatagramPort::dispatched(incoming, Arc::clone(&socket), peer);
                        tracing::debug!(%peer, "RDP-UDP: client SYN; accepting");
                        accepting = Some(Box::pin(accept_udp_dispatched(datagram.to_vec(), port, config)));
                    }
                }
            }

            accepted = async { accepting.as_mut().expect("guarded by the condition").await }, if accepting.is_some() => {
                accepting = None;
                match accepted {
                    Ok(transport) => {
                        tracing::info!(request_id = tunnel_config.request_id, "RDP-UDP transport established");
                        let Some((served, queue)) = client.take() else {
                            return;
                        };
                        // Keep feeding the transport its datagrams while the
                        // tunnel runs.
                        let feeder = tokio::spawn(feed(channel, served, queue));
                        serve_tunnel(transport, &events).await;
                        feeder.abort();
                        return;
                    }
                    Err(error) => {
                        // Most common: the client gave up or UDP is filtered.
                        // Log the whole cause chain — "handshake failed"
                        // alone hides whether the SYN cookieHash, the TLS
                        // exchange or the tunnel negotiation failed. The
                        // client may try again.
                        tracing::debug!(error = %error_chain(&error), "RDP-UDP accept ended");
                        client = None;
                    }
                }
            }
        }
    }
}

/// Hand the served client's datagrams to its transport until the channel or
/// the transport goes away.
async fn feed(channel: UnixDatagram, served: SocketAddr, queue: mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0u8; 9100];
    while let Ok(len) = channel.recv(&mut buf).await {
        if queue.is_closed() {
            return;
        }
        if let Some((peer, datagram)) = decode_datagram(&buf[..len])
            && peer == served
        {
            // Full: dropped like a full socket buffer would; RDP-UDP
            // retransmits.
            let _ = queue.try_send(datagram.to_vec());
        }
    }
}

/// Bind the tunnel to the session and pump both directions until it closes.
async fn serve_tunnel(
    mut transport: ironrdp_rdpeudp_tokio::UdpTransport,
    events: &mpsc::UnboundedSender<ironrdp_server::ServerEvent>,
) {
    // Bind the tunnel to the session: the server sends a DVC Soft-Sync
    // request over TCP; after the client's response, dynamic-channel traffic
    // flows through these channels.
    //
    // The server waits for room in this queue rather than drop data, and
    // while it waits it reads nothing from the client. A 64-message queue held
    // 100 KB of a graphics frame that can be 17 MB in 1600-byte chunks: the
    // connection stalled for seconds on every full frame and mstsc gave up on
    // it. The graphics pipeline limits itself to a few unacknowledged frames,
    // so a queue that takes them whole never fills in practice; the memory is
    // only taken as it is used.
    let (to_tunnel, mut from_server) = mpsc::channel::<Vec<u8>>(TUNNEL_QUEUE);
    // Auto-detect structures for the tunnel's sub-headers (MS-RDPBCGR 1.3.9,
    // MS-RDPEMT 2.2.1.1.1): a handful a second at most.
    let (autodetect_to_tunnel, mut autodetect_from_server) = mpsc::channel::<Vec<u8>>(16);
    let _ = events.send(ironrdp_server::ServerEvent::SoftSyncToUdp {
        to_tunnel,
        autodetect_to_tunnel: Some(autodetect_to_tunnel),
    });

    // Incoming frames are unframed DVC PDUs; outgoing likewise.
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
            Some(structure) = autodetect_from_server.recv() => {
                match sub_header(&structure) {
                    Some(sub_header) => {
                        if transport.send_sub_header(sub_header).await.is_err() {
                            break;
                        }
                    }
                    None => tracing::debug!(bytes = structure.len(), "UDP tunnel: malformed auto-detect structure; not sent"),
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
    // The dynamic channels moved to it cannot come back to TCP, so the
    // server decides whether the connection goes on.
    let _ = events.send(ironrdp_server::ServerEvent::UdpTunnelClosed);
}

/// The RDP_TUNNEL_SUBHEADER carrying an encoded auto-detect structure.
///
/// MS-RDPEMT 2.2.1.1.1: SubHeaderLength counts itself and SubHeaderType, and
/// the structures of [MS-RDPBCGR] 2.2.14 open with exactly those two bytes,
/// headerLength and headerTypeId, so the rest is the SubHeaderData.
fn sub_header(structure: &[u8]) -> Option<ironrdp_rdpemt::TunnelSubHeader> {
    let (&length, rest) = structure.split_first()?;
    let (&kind, data) = rest.split_first()?;
    (usize::from(length) == structure.len()).then(|| ironrdp_rdpemt::TunnelSubHeader {
        sub_header_type: ironrdp_rdpemt::SubHeaderType::from_u8(kind),
        data: data.to_vec(),
    })
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

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, Ordering};

    use ironrdp_rdpeudp_tokio::{UdpTransportConfig, connect_udp};
    use ironrdp_server::ServerEvent;

    use super::*;
    use crate::udp_dispatch::Dispatch;

    fn identity() -> TlsIdentityCtx {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["linrdp".to_owned()]).expect("certificate");
        TlsIdentityCtx {
            certs: vec![cert.cert.der().clone()],
            priv_key: rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key"),
            pub_key: Vec::new(),
        }
    }

    async fn next_event(events: &mut mpsc::UnboundedReceiver<ServerEvent>) -> ServerEvent {
        tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("the event channel open")
    }

    /// MS-RDPEUDP 2.1 and MS-RDPEMT 3.2.1: two connections share one UDP
    /// port. Each client's SYN names its connection's request by cookieHash,
    /// the supervisor's dispatch hands the client to that connection's
    /// worker, and each tunnel carries its own session's data both ways.
    ///
    /// Regression: each worker bound the port itself, so only one connection
    /// at a time could have a tunnel, and often none did.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_connections_share_the_port_and_each_client_reaches_its_own() {
        let identity = identity();
        let port = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        port.set_nonblocking(true).expect("non-blocking");
        let port_addr = port.local_addr().expect("address");

        let mut dispatch = Dispatch::default();
        let mut workers = Vec::new();
        for pid in [100, 200] {
            let (ours, theirs) = Dispatch::channel_pair().expect("channel");
            dispatch.add_worker(pid, 0, ours);
            let (events, received) = mpsc::unbounded_channel();
            let request = spawn_on(theirs, port.try_clone().expect("dup"), &identity, events).expect("spawn");
            workers.push((request, received));
        }

        // The supervisor's loop, by hand.
        let stop = Arc::new(AtomicBool::new(false));
        let supervisor = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    dispatch.read_channel(100);
                    dispatch.read_channel(200);
                    dispatch.read_socket(0, &port);
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };

        for (index, (request, events)) in workers.iter_mut().enumerate() {
            let mut client = connect_udp(UdpTransportConfig::new(
                port_addr,
                "linrdp".to_owned(),
                TunnelConfig {
                    request_id: request.request_id,
                    security_cookie: request.security_cookie,
                },
            ))
            .await
            .expect("the client's tunnel");

            let ServerEvent::SoftSyncToUdp { to_tunnel, .. } = next_event(events).await else {
                panic!("the worker binds its tunnel to its own session");
            };
            let greeting = format!("session {index}").into_bytes();
            to_tunnel.send(greeting.clone()).await.expect("to the client");
            let received = tokio::time::timeout(Duration::from_secs(10), client.recv())
                .await
                .expect("in time");
            assert_eq!(received, Some(greeting));

            client
                .send(format!("client {index}").into_bytes())
                .await
                .expect("to the worker");
            let ServerEvent::UdpTunnelData(frame) = next_event(events).await else {
                panic!("the client's data reaches its own worker");
            };
            assert_eq!(frame, format!("client {index}").into_bytes());
        }

        stop.store(true, Ordering::Relaxed);
        supervisor.join().expect("supervisor thread");
    }

    /// MS-RDPEMT 2.2.1.1.1: an encoded auto-detect structure becomes a
    /// sub-header whose length and type are its first two bytes.
    #[test]
    fn an_auto_detect_structure_maps_onto_a_sub_header() {
        use ironrdp_pdu::rdp::autodetect::AutoDetectRequest;

        let structure =
            ironrdp_core::encode_vec(&AutoDetectRequest::netchar_result(1, 2, 30_000, 3)).expect("encode");
        let sub_header = sub_header(&structure).expect("a sub-header");
        assert_eq!(sub_header.sub_header_type, ironrdp_rdpemt::SubHeaderType::AutoDetectRequest);
        assert_eq!(ironrdp_core::encode_vec(&sub_header).expect("encode"), structure);

        assert!(sub_header_bytes_mismatch(&structure));
    }

    fn sub_header_bytes_mismatch(structure: &[u8]) -> bool {
        let mut wrong = structure.to_vec();
        wrong[0] += 1;
        super::sub_header(&wrong).is_none()
    }
}
