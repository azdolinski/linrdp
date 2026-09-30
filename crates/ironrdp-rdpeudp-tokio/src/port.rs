//! Where an RDP-UDP connection's datagrams come from and go to.
//!
//! [MS-RDPEUDP] 2.1: "All of the RDP traffic over UDP is handled by this
//! single port on the terminal server." A server serving several RDP
//! connections therefore reads every client's datagrams from one socket and
//! hands each client's to the connection it belongs to ([MS-RDPEMT] 3.2.1,
//! the Connection Store). Such a connection does not own a socket: its
//! datagrams arrive already sorted out, and it answers through the shared one,
//! addressed to its client.

use core::net::SocketAddr;
use std::io;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// The datagram path of one RDP-UDP connection.
#[derive(Debug)]
pub enum DatagramPort {
    /// A socket of its own, `connect`ed to the peer.
    Connected(UdpSocket),
    /// Datagrams handed over by whoever reads the shared server socket;
    /// answers go out through that socket to `peer`.
    Dispatched {
        incoming: mpsc::Receiver<Vec<u8>>,
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
    },
}

impl DatagramPort {
    /// A port fed by a dispatcher: `incoming` carries the datagrams `peer`
    /// sent to the shared `socket`, which answers go out through.
    pub fn dispatched(incoming: mpsc::Receiver<Vec<u8>>, socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self::Dispatched { incoming, socket, peer }
    }

    /// Receive the next datagram into `buf`, truncating one that does not fit
    /// (as a socket would).
    ///
    /// Cancel safe, like `UdpSocket::recv` and `mpsc::Receiver::recv`: a
    /// cancelled call loses no datagram.
    pub(crate) async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Connected(socket) => socket.recv(buf).await,
            Self::Dispatched { incoming, .. } => {
                let datagram = incoming
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "the dispatcher is gone"))?;
                let len = datagram.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram[..len]);
                Ok(len)
            }
        }
    }

    /// Send one datagram to the peer.
    pub(crate) async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Connected(socket) => socket.send(buf).await,
            Self::Dispatched { socket, peer, .. } => socket.send_to(buf, *peer).await,
        }
    }
}

impl From<UdpSocket> for DatagramPort {
    fn from(socket: UdpSocket) -> Self {
        Self::Connected(socket)
    }
}
