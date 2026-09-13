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
