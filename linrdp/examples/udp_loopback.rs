//! Loopback test of the RDP-UDP (MS-RDPEMT) server path: a client built on
//! `connect_udp` (the same code mstsc-compatible clients use) handshakes
//! against `accept_udp` — SYN/SYN+ACK/ACK, TLS, tunnel Create Request with
//! the security cookie — then exchanges one data frame each way.
//!
//! Run: `cargo run -p linrdp --example udp_loopback`

use std::sync::Arc;
use std::time::Duration;

use ironrdp_rdpeudp_tokio::{UdpAcceptConfig, UdpTransportConfig, accept_udp, connect_udp};
use ironrdp_rdpemt::TunnelConfig;
use ironrdp_server::MultiTransportRequest;
use tokio_rustls::rustls;

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["linrdp".to_owned()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().clone());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("key: {e}"))?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    let server_config = Arc::new(server_config);

    let mut cookie = [0u8; 16];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut cookie)?;
    let request = MultiTransportRequest {
        request_id: 42,
        security_cookie: cookie,
    };

    // Server: bind a UDP socket and accept in the background.
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    let server_addr = socket.local_addr()?;
    println!("server listening on {server_addr}");

    let server = tokio::spawn(async move {
        let config = UdpAcceptConfig {
            tls_config: server_config,
            tunnel_config: TunnelConfig {
                request_id: request.request_id,
                security_cookie: request.security_cookie,
            },
            connection_config: Default::default(),
            accept_timeout: Duration::from_secs(30),
        };
        accept_udp(socket, config).await
    });

    // Client: connect with the same cookie the TCP bootstrap would have
    // delivered.
    let mut client = connect_udp(UdpTransportConfig::new(
        server_addr,
        "linrdp".to_owned(),
        TunnelConfig {
            request_id: request.request_id,
            security_cookie: cookie,
        },
    ))
    .await
    .map_err(|e| anyhow::anyhow!("client connect: {e:#}"))?;

    let mut server_transport = server
        .await
        .map_err(|e| anyhow::anyhow!("server task: {e}"))?
        .map_err(|e| anyhow::anyhow!("server accept: {e:#}"))?;

    println!("tunnel established");

    client.send(b"ping".to_vec()).await?;
    let frame = server_transport.recv().await.expect("frame from client");
    assert_eq!(frame, b"ping");
    println!("server got: {}", String::from_utf8_lossy(&frame));

    server_transport.send(b"pong".to_vec()).await?;
    let frame = client.recv().await.expect("frame from server");
    assert_eq!(frame, b"pong");
    println!("client got: {}", String::from_utf8_lossy(&frame));

    client.shutdown().await.map_err(|e| anyhow::anyhow!("shutdown: {e:#}"))?;
    let _ = server_transport.shutdown().await;
    println!("OK — RDP-UDP loopback (handshake + TLS + tunnel + data) passed");
    Ok(())
}
