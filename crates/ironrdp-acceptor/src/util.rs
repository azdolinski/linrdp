use std::borrow::Cow;

use ironrdp_connector::{ConnectorError, ConnectorErrorExt as _, ConnectorResult};
use ironrdp_core::{Encode, WriteBuf, encode_vec};
use ironrdp_pdu::rdp;
use ironrdp_pdu::x224::X224;

pub(crate) fn encode_send_data_indication<T>(
    initiator_id: u16,
    channel_id: u16,
    user_msg: &T,
    buf: &mut WriteBuf,
) -> ConnectorResult<usize>
where
    T: Encode,
{
    let user_data = encode_vec(user_msg).map_err(ConnectorError::encode)?;

    let pdu = ironrdp_pdu::mcs::SendDataIndication {
        initiator_id,
        channel_id,
        user_data: Cow::Owned(user_data),
    };

    let written = ironrdp_core::encode_buf(&X224(pdu), buf).map_err(ConnectorError::encode)?;

    Ok(written)
}

/// Wrap a Share Data PDU in its Share Control header.
///
/// `pdu_source` is the Share Control header's `pduSource`. Most callers pass
/// the I/O channel ID; a Set Error Info PDU MUST carry 0 (MS-RDPBCGR 2.2.5.1.1).
pub(crate) fn wrap_share_data(pdu: rdp::headers::ShareDataPdu, pdu_source: u16) -> rdp::headers::ShareControlHeader {
    rdp::headers::ShareControlHeader {
        share_id: 0,
        pdu_source,
        share_control_pdu: rdp::headers::ShareControlPdu::Data(rdp::headers::ShareDataHeader {
            share_data_pdu: pdu,
            stream_priority: rdp::headers::StreamPriority::Undefined,
            compression_flags: rdp::headers::CompressionFlags::empty(),
            compression_type: rdp::client_info::CompressionType::K8,
        }),
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{decode, encode_vec};
    use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu, ShareDataPdu};
    use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};

    use super::wrap_share_data;

    /// MS-RDPBCGR 2.2.5.1.1: TS_SET_ERROR_INFO_PDU is a Share Data PDU whose
    /// `pduSource` MUST be 0. The credential check used to send the bare
    /// four-byte error value, which no client can parse as a PDU.
    #[test]
    fn a_set_error_info_pdu_is_a_share_data_pdu_from_source_zero() {
        let info = ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(ErrorInfo::ProtocolIndependentCode(
            ProtocolIndependentCode::ServerDeniedConnection,
        )));
        let bytes = encode_vec(&wrap_share_data(info, 0)).expect("encode");

        let control: ShareControlHeader = decode(&bytes).expect("decode Share Control header");
        assert_eq!(control.pdu_source, 0);
        let ShareControlPdu::Data(header) = control.share_control_pdu else {
            panic!("expected a Share Data PDU");
        };
        assert!(matches!(
            header.share_data_pdu,
            ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(ErrorInfo::ProtocolIndependentCode(
                ProtocolIndependentCode::ServerDeniedConnection
            )))
        ));
    }
}
