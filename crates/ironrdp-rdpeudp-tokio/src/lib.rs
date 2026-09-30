#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![forbid(unsafe_code)]

pub mod error;
pub mod framed;
pub mod multitransport;
pub mod port;
pub mod transport;

pub(crate) mod clock;
pub(crate) mod driver;
pub(crate) mod stream;
pub(crate) mod tls;
pub(crate) mod tunnel;

pub use self::error::{DriverError, DriverErrorKind, UdpTransportError, UdpTransportErrorKind};
pub use self::multitransport::MultitransportBootstrap;
pub use self::port::DatagramPort;
pub use self::transport::{
    UdpAcceptConfig, UdpTlsConfig, UdpTransport, UdpTransportConfig, accept_udp, accept_udp_dispatched, connect_udp,
    cookie_hash, syn_cookie_hash,
};
