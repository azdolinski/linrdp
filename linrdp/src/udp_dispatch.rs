//! One UDP port for every connection: the supervisor's half of RDP-UDP.
//!
//! [MS-RDPEUDP] 2.1: "All of the RDP traffic over UDP is handled by this
//! single port on the terminal server." Each RDP connection is served by a
//! worker process of its own, so the port cannot belong to any of them: the
//! supervisor binds it once per listener and hands every client's datagrams
//! to the worker serving that client.
//!
//! That is the Connection Store of [MS-RDPEMT] 3.2.1: the server keeps the
//! outstanding multitransport requests and "hands off the incoming
//! multitransport connection to the main RDP connection that requested it".
//! A worker registers the cookieHash of its request when it starts; a client's
//! SYN carries that hash ([MS-RDPEUDP] 3.1.5.1.1), so its first datagram
//! already names the worker, and every later one from the same address follows
//! it. Workers answer through a duplicate of the same socket, so the client
//! hears back from the port it wrote to.
//!
//! Workers used to bind the port themselves. mstsc opens two short probe
//! connections before the real one, each with a worker of its own, and
//! whichever worker bound first held the port: the real connection's worker
//! failed to bind, its client was offered a tunnel nobody would accept, and
//! answered E_ABORT. With several clients at once only one could ever have
//! UDP.

use core::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixDatagram;

/// The descriptor numbers a worker finds its UDP channel and the shared
/// socket on (the TCP connection is on 3).
pub(crate) const CHANNEL_FD: i32 = 4;
pub(crate) const SOCKET_FD: i32 = 5;

/// Worker to supervisor: "datagrams whose SYN carries this cookieHash are
/// mine".
const REGISTER: u8 = b'R';
/// Supervisor to worker: one datagram and the client it came from.
const DATAGRAM: u8 = b'D';
const ADDR_LEN: usize = 1 + 16 + 2;

pub(crate) fn encode_register(cookie_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(33);
    message.push(REGISTER);
    message.extend_from_slice(cookie_hash);
    message
}

fn decode_register(message: &[u8]) -> Option<[u8; 32]> {
    match message.split_first() {
        Some((&REGISTER, hash)) => hash.try_into().ok(),
        _ => None,
    }
}

pub(crate) fn encode_datagram(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + ADDR_LEN + payload.len());
    message.push(DATAGRAM);
    match peer.ip() {
        IpAddr::V4(ip) => {
            message.push(4);
            message.extend_from_slice(&ip.to_ipv6_mapped().octets());
        }
        IpAddr::V6(ip) => {
            message.push(6);
            message.extend_from_slice(&ip.octets());
        }
    }
    message.extend_from_slice(&peer.port().to_be_bytes());
    message.extend_from_slice(payload);
    message
}

pub(crate) fn decode_datagram(message: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let (&DATAGRAM, rest) = message.split_first()? else {
        return None;
    };
    if rest.len() < ADDR_LEN {
        return None;
    }
    let (addr, payload) = rest.split_at(ADDR_LEN);
    let octets: [u8; 16] = addr[1..17].try_into().ok()?;
    let v6 = Ipv6Addr::from(octets);
    let ip = match addr[0] {
        4 => IpAddr::V4(v6.to_ipv4_mapped()?),
        6 => IpAddr::V6(v6),
        _ => return None,
    };
    let port = u16::from_be_bytes([addr[17], addr[18]]);
    Some((SocketAddr::new(ip, port), payload))
}

/// Which worker a datagram belongs to.
#[derive(Debug, Default)]
pub(crate) struct Store {
    /// cookieHash → (worker pid, listener index).
    requests: HashMap<[u8; 32], (i32, usize)>,
    /// (listener index, client address) → worker pid, learned from the SYN.
    clients: HashMap<(usize, SocketAddr), i32>,
}

impl Store {
    pub(crate) fn register(&mut self, pid: i32, listener: usize, cookie_hash: [u8; 32]) {
        self.requests.insert(cookie_hash, (pid, listener));
    }

    /// The worker a datagram from `peer` on `listener` goes to.
    ///
    /// A client already known goes to its worker. Otherwise only a SYN whose
    /// cookieHash a worker of this listener registered starts a route;
    /// anything else, from anyone, is not ours to deliver.
    pub(crate) fn route(
        &mut self,
        listener: usize,
        peer: SocketAddr,
        syn_cookie_hash: impl FnOnce() -> Option<[u8; 32]>,
    ) -> Option<i32> {
        if let Some(pid) = self.clients.get(&(listener, peer)) {
            return Some(*pid);
        }
        let (pid, registered_on) = *self.requests.get(&syn_cookie_hash()?)?;
        if registered_on != listener {
            return None;
        }
        self.clients.insert((listener, peer), pid);
        Some(pid)
    }

    /// Forget a worker that exited: its request and its clients.
    pub(crate) fn remove(&mut self, pid: i32) {
        self.requests.retain(|_, (owner, _)| *owner != pid);
        self.clients.retain(|_, owner| *owner != pid);
    }
}

/// The supervisor's end of the UDP dispatch: the store and each worker's
/// channel.
#[derive(Debug, Default)]
pub(crate) struct Dispatch {
    store: Store,
    /// pid → (channel, listener index).
    channels: HashMap<i32, (UnixDatagram, usize)>,
}

impl Dispatch {
    /// A channel for a worker about to be forked for `listener`: the
    /// supervisor's end and the worker's.
    pub(crate) fn channel_pair() -> io::Result<(UnixDatagram, UnixDatagram)> {
        let (ours, theirs) = UnixDatagram::pair()?;
        ours.set_nonblocking(true)?;
        Ok((ours, theirs))
    }

    pub(crate) fn add_worker(&mut self, pid: i32, listener: usize, channel: UnixDatagram) {
        self.channels.insert(pid, (channel, listener));
    }

    pub(crate) fn remove_worker(&mut self, pid: i32) {
        self.channels.remove(&pid);
        self.store.remove(pid);
    }

    /// The channels to poll, with the pid each belongs to.
    pub(crate) fn channels(&self) -> impl Iterator<Item = (i32, &UnixDatagram)> {
        self.channels.iter().map(|(pid, (channel, _))| (*pid, channel))
    }

    /// Read what a worker sent: its registration.
    pub(crate) fn read_channel(&mut self, pid: i32) {
        let Some((channel, listener)) = self.channels.get(&pid) else {
            return;
        };
        let listener = *listener;
        let mut buf = [0u8; 64];
        loop {
            match channel.recv(&mut buf) {
                Ok(len) => match decode_register(&buf[..len]) {
                    Some(hash) => {
                        tracing::debug!(pid, listener, "RDP-UDP: worker registered its multitransport request");
                        self.store.register(pid, listener, hash);
                    }
                    None => tracing::debug!(pid, len, "RDP-UDP: unrecognised message from a worker"),
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    tracing::debug!(pid, %error, "RDP-UDP: worker channel failed");
                    return;
                }
            }
        }
    }

    /// Take every datagram waiting on `socket` (listener `listener`) and hand
    /// each to its worker.
    pub(crate) fn read_socket(&mut self, listener: usize, socket: &std::net::UdpSocket) {
        let mut buf = vec![0u8; 9000];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // ICMP port-unreachable from a client that went away surfaces
                // here on Linux; it concerns one peer, not the socket.
                Err(error) => {
                    tracing::debug!(%error, "RDP-UDP: receive failed");
                    continue;
                }
            };
            let datagram = &buf[..len];
            let Some(pid) = self
                .store
                .route(listener, peer, || ironrdp_rdpeudp_tokio::syn_cookie_hash(datagram))
            else {
                tracing::debug!(%peer, len, "RDP-UDP: datagram for no connection; dropped");
                continue;
            };
            let Some((channel, _)) = self.channels.get(&pid) else {
                continue;
            };
            // A worker that cannot keep up loses the datagram, as a full
            // socket buffer would: RDP-UDP retransmits.
            if let Err(error) = channel.send(&encode_datagram(peer, datagram)) {
                tracing::trace!(pid, %error, "RDP-UDP: worker channel full or gone; datagram dropped");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("address")
    }

    #[test]
    fn datagrams_carry_their_client_address() {
        for peer in [addr("192.168.1.1:50523"), addr("[2001:db8::7]:61000")] {
            let message = encode_datagram(peer, b"payload");
            assert_eq!(decode_datagram(&message), Some((peer, &b"payload"[..])));
        }
        assert_eq!(decode_datagram(&encode_register(&[1; 32])), None);
        assert_eq!(decode_register(&encode_register(&[1; 32])), Some([1; 32]));
    }

    /// MS-RDPEMT 3.2.1: a client's first datagram, a SYN carrying the
    /// cookieHash of a request, goes to the worker that registered it, and
    /// everything later from that client follows it; several connections
    /// share the port.
    #[test]
    fn each_client_reaches_the_worker_whose_request_it_answers() {
        let mut store = Store::default();
        store.register(100, 0, [1; 32]);
        store.register(200, 0, [2; 32]);
        let (a, b) = (addr("192.168.1.1:50000"), addr("192.168.1.2:50000"));

        assert_eq!(store.route(0, b, || Some([2; 32])), Some(200));
        assert_eq!(store.route(0, a, || Some([1; 32])), Some(100));
        assert_eq!(store.route(0, a, || None), Some(100), "later datagrams follow the SYN");
        assert_eq!(store.route(0, b, || None), Some(200));
    }

    /// A worker that exits gives up its request and its clients; a SYN nobody
    /// registered, or one for another listener, reaches no one.
    #[test]
    fn unknown_and_departed_clients_reach_no_one() {
        let mut store = Store::default();
        store.register(100, 0, [1; 32]);
        let a = addr("192.168.1.1:50000");

        assert_eq!(store.route(0, a, || None), None, "not a SYN");
        assert_eq!(store.route(0, a, || Some([9; 32])), None, "nobody's request");
        assert_eq!(store.route(1, a, || Some([1; 32])), None, "another listener's port");

        assert_eq!(store.route(0, a, || Some([1; 32])), Some(100));
        store.remove(100);
        assert_eq!(store.route(0, a, || None), None);
        assert_eq!(store.route(0, a, || Some([1; 32])), None);
    }
}
