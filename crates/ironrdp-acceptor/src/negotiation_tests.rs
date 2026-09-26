//! The acceptor's side of the connection initiation (MS-RDPBCGR 1.3.1.1).

use ironrdp_connector::{DesktopSize, Sequence as _};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::nego::{self, SecurityProtocol};
use ironrdp_pdu::x224::X224;

use crate::Acceptor;

/// The RDP Negotiation Response the acceptor answers a TLS request with.
fn negotiation_response(graphics_pipeline: bool) -> nego::ResponseFlags {
    let mut acceptor = Acceptor::new(
        SecurityProtocol::SSL,
        DesktopSize {
            width: 1024,
            height: 768,
        },
        Vec::new(),
        None,
    );
    acceptor.set_graphics_pipeline_announce(graphics_pipeline);

    let request = encode_vec(&X224(nego::ConnectionRequest {
        nego_data: None,
        flags: nego::RequestFlags::empty(),
        protocol: SecurityProtocol::SSL,
        correlation_info: None,
    }))
    .expect("encode");
    let mut output = WriteBuf::new();
    acceptor.step(&request, None, &mut output).expect("connection request");
    acceptor.step(&[], None, &mut output).expect("connection confirm");

    match decode::<X224<nego::ConnectionConfirm>>(output.filled())
        .expect("decode")
        .0
    {
        nego::ConnectionConfirm::Response { flags, .. } => flags,
        other => panic!("expected an RDP Negotiation Response, got {other:?}"),
    }
}

/// MS-RDPBCGR 2.2.1.2.1: DYNVC_GFX_PROTOCOL_SUPPORTED says "The server
/// supports the Graphics Pipeline Extension Protocol".
///
/// Regression: never set, although the server offers the pipeline.
#[test]
fn the_negotiation_response_announces_the_graphics_pipeline_when_offered() {
    assert!(negotiation_response(true).contains(nego::ResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED));
    assert!(!negotiation_response(false).contains(nego::ResponseFlags::DYNVC_GFX_PROTOCOL_SUPPORTED));
    assert!(negotiation_response(false).contains(nego::ResponseFlags::EXTENDED_CLIENT_DATA_SUPPORTED));
}
