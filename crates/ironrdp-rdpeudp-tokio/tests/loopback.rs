//! End-to-end loopback: `connect_udp` (client) against `accept_udp` (server)
//! in one process, through the full RDP-UDP2 sequence — SYN/SYN-ACK/ACK with
//! the cookieHash check, TLS over the reliable stream, RDPEMT tunnel
//! negotiation, and the frame data pumps.

#![cfg(feature = "rustls-aws-lc-rs")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use ironrdp_rdpemt::TunnelConfig;
use ironrdp_rdpeudp_tokio::{
    accept_udp, connect_udp, UdpAcceptConfig, UdpTlsConfig, UdpTransportConfig,
};

fn server_tls_config() -> Arc<tokio_rustls::rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("rcgen");
    let cert = CertificateDer::from(certified.cert);
    let key = PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());

    Arc::new(
        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .expect("server config"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn client_and_server_establish_a_tunnel_and_exchange_frames() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr: SocketAddr = server_socket.local_addr().expect("local addr");

    let tunnel = TunnelConfig {
        request_id: 42,
        security_cookie: [0xA5; 16],
    };

    let accept = tokio::spawn(accept_udp(
        server_socket,
        UdpAcceptConfig {
            tls_config: server_tls_config(),
            tunnel_config: tunnel.clone(),
            connection_config: Default::default(),
            accept_timeout: Duration::from_secs(15),
        },
    ));

    let mut client = tokio::time::timeout(
        Duration::from_secs(15),
        connect_udp(UdpTransportConfig::new(server_addr, "localhost".to_owned(), tunnel)),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect failed");

    let server_transport = tokio::time::timeout(Duration::from_secs(15), accept)
        .await
        .expect("server accept timed out")
        .expect("server accept failed");
    let mut server = server_transport.expect("server transport");

    // Client -> server frame.
    client
        .send(b"hello udp".to_vec())
        .await
        .expect("client send");
    let frame = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("server recv timed out")
        .expect("server recv");
    assert_eq!(frame, b"hello udp");

    // Server -> client frame.
    server
        .send(b"hello client".to_vec())
        .await
        .expect("server send");
    let back = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("client recv timed out")
        .expect("client recv");
    assert_eq!(back, b"hello client");
}

/// A UDP relay between the client and the server that drops a share of the
/// datagrams in each direction, deterministically.
async fn lossy_relay(server_addr: SocketAddr, drop_one_in: u32) -> SocketAddr {
    lossy_relay_with_burst(server_addr, drop_one_in, None).await
}

/// [`lossy_relay`], and optionally one outage: from the server's
/// `after`-th datagram on, everything it sends for `lasting` is lost, as
/// when a client's socket buffer overflows.
async fn lossy_relay_with_burst(
    server_addr: SocketAddr,
    drop_one_in: u32,
    burst: Option<(u32, Duration)>,
) -> SocketAddr {
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind relay"));
    let relay_addr = relay.local_addr().expect("relay addr");
    let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream"));
    upstream.connect(server_addr).await.expect("connect upstream");
    let client = Arc::new(tokio::sync::OnceCell::<SocketAddr>::new());

    // xorshift: the same losses on every run.
    fn lose(state: &mut u32, one_in: u32) -> bool {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        *state % one_in == 0
    }

    {
        let (relay, upstream, client) = (Arc::clone(&relay), Arc::clone(&upstream), Arc::clone(&client));
        tokio::spawn(async move {
            let mut buf = vec![0u8; 9000];
            let mut state = 0x1234_5678u32;
            let mut seen = 0u32;
            while let Ok((len, from)) = relay.recv_from(&mut buf).await {
                let _ = client.set(from);
                seen += 1;
                // Never the handshake: losing it only tests the retry timer.
                if seen > 3 && lose(&mut state, drop_one_in) {
                    continue;
                }
                let _ = upstream.send(&buf[..len]).await;
            }
        });
    }
    {
        let (relay, upstream, client) = (Arc::clone(&relay), Arc::clone(&upstream), Arc::clone(&client));
        tokio::spawn(async move {
            let mut buf = vec![0u8; 9000];
            let mut state = 0x9abc_def1u32;
            let mut seen = 0u32;
            let mut outage_until: Option<tokio::time::Instant> = None;
            while let Ok(len) = upstream.recv(&mut buf).await {
                seen += 1;
                if let Some((after, lasting)) = burst {
                    if seen == after {
                        outage_until = Some(tokio::time::Instant::now() + lasting);
                    }
                    if outage_until.is_some_and(|until| tokio::time::Instant::now() < until) {
                        continue;
                    }
                }
                if seen > 3 && lose(&mut state, drop_one_in) {
                    continue;
                }
                if let Some(to) = client.get() {
                    let _ = relay.send_to(&buf[..len], *to).await;
                }
            }
        });
    }
    relay_addr
}

/// The reliable stream stays whole under loss: every frame the server sends
/// arrives once, complete and in order, although one datagram in fifty is
/// lost each way (MS-RDPEUDP2 3.1.1.2: retransmission until acknowledged).
///
/// A graphics stream to mstsc failed exactly like this: tens of megabytes a
/// second with occasional retransmits, and the client reported a protocol
/// error a few seconds in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lossy_link_delivers_every_frame_once_and_in_order() {
    transfer_through(|server_addr| lossy_relay(server_addr, 50), 12_500).await;
}

/// MS-RDPEUDP2 3.1.1.1: sequence numbers travel as their lower 16 bits, and
/// the active range is limited so that "the full sequence number can be
/// recovered without ambiguity". A burst of losses must not let new data run
/// so far ahead of a packet awaiting retransmission that its ChannelSeqNum
/// wraps: the receiver would place it in the wrong spot of the stream.
///
/// Regression: a lost packet left the send window while new data kept going;
/// mstsc placed its retransmission 65536 packets off, and TLS failed with
/// 0xC06 (decryption error).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_losses_keeps_the_stream_whole() {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_test_writer().try_init();
    transfer_through(
        |server_addr| lossy_relay_with_burst(server_addr, 1_000_000, Some((2_000, Duration::from_millis(200)))),
        60_000,
    )
    .await;
}

/// MS-RDPEUDP2 3.1.1.2.4.2, note 1: Windows skips channel sequence number
/// zero. A stream long enough to pass it twice arrives whole.
///
/// Regression: the packet whose 16-bit ChannelSeqNum was 0 never reached
/// mstsc's TLS layer, which ended the session with a decryption error
/// (0xC06) about 65536 packets in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_past_the_channel_sequence_wrap_arrives_whole() {
    transfer_through(|server_addr| lossy_relay(server_addr, 1_000_000), 140_000).await;
}

async fn transfer_through<F, Fut>(relay: F, frames: u32)
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: core::future::Future<Output = SocketAddr>,
{
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr: SocketAddr = server_socket.local_addr().expect("local addr");
    let relay_addr = relay(server_addr).await;

    let tunnel = TunnelConfig {
        request_id: 42,
        security_cookie: [0xA5; 16],
    };
    let accept = tokio::spawn(accept_udp(
        server_socket,
        UdpAcceptConfig {
            tls_config: server_tls_config(),
            tunnel_config: tunnel.clone(),
            connection_config: Default::default(),
            accept_timeout: Duration::from_secs(15),
        },
    ));
    let mut client = tokio::time::timeout(
        Duration::from_secs(15),
        connect_udp(UdpTransportConfig::new(relay_addr, "localhost".to_owned(), tunnel)),
    )
    .await
    .expect("client connect timed out")
    .expect("client connect failed");
    let server = accept.await.expect("accept task").expect("accept");

    #[expect(non_snake_case, reason = "reads like the constant it replaced")]
    let FRAMES = frames;
    let sender = tokio::spawn(async move {
        for index in 0..FRAMES {
            let mut frame = vec![(index % 251) as u8; 1600];
            frame[..4].copy_from_slice(&index.to_le_bytes());
            server.send(frame).await.expect("send");
        }
        server
    });

    let received = tokio::time::timeout(Duration::from_secs(120), async {
        let mut next = 0u32;
        while next < FRAMES {
            let frame = client.recv().await.expect("the tunnel stays open");
            assert_eq!(frame.len(), 1600, "frame {next} arrives whole");
            let index = u32::from_le_bytes(frame[..4].try_into().expect("index"));
            assert_eq!(index, next, "frames arrive once and in order");
            assert!(frame[4..].iter().all(|b| *b == (index % 251) as u8), "frame {index} intact");
            next += 1;
        }
        next
    })
    .await
    .expect("every frame within two minutes");
    assert_eq!(received, FRAMES);
    drop(sender.await.expect("sender"));
}

/// MS-RDPEMT 2.2.1.1.1: a sub-header rides in a Tunnel Data PDU's header, on
/// its own when no data follows; the receiving side delivers only data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sub_header_alone_reaches_no_one_and_data_follows() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server_addr: SocketAddr = server_socket.local_addr().expect("local addr");
    let tunnel = TunnelConfig {
        request_id: 42,
        security_cookie: [0xA5; 16],
    };
    let accept = tokio::spawn(accept_udp(
        server_socket,
        UdpAcceptConfig {
            tls_config: server_tls_config(),
            tunnel_config: tunnel.clone(),
            connection_config: Default::default(),
            accept_timeout: Duration::from_secs(15),
        },
    ));
    let mut client = connect_udp(UdpTransportConfig::new(server_addr, "localhost".to_owned(), tunnel))
        .await
        .expect("client connect");
    let server = accept.await.expect("accept task").expect("accept");

    server
        .send_sub_header(ironrdp_rdpemt::TunnelSubHeader {
            sub_header_type: ironrdp_rdpemt::SubHeaderType::AutoDetectRequest,
            data: vec![0, 0, 0xC0, 0x08, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0],
        })
        .await
        .expect("sub-header");
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.send(b"after".to_vec()).await.expect("data");

    let frame = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("in time");
    assert_eq!(frame.as_deref(), Some(&b"after"[..]));
}
