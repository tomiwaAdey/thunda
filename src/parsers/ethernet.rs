// src/parsers/ethernet.rs
use bytes::BytesMut;
use crate::parsers::ParsingError;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHER_MIN_LENGTH: usize = 14;



#[derive(Debug)]
pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
    pub payload: BytesMut,
}

pub fn parse(data: &BytesMut) -> Result<EthernetFrame, ParsingError> {
    if data.len() < ETHER_MIN_LENGTH { // Minimum length for an Ethernet header
        return Err(ParsingError::BufferUnderflow);
    }

    let mut buf = data.clone();
    let destination = get_mac(&mut buf);
    let source = get_mac(&mut buf);
    let ethertype_bytes = get_ethertype(&mut buf);
    let ethertype = to_u16(&ethertype_bytes);
    let payload = buf;

    Ok(
        EthernetFrame {
            destination,
            source,
            ethertype,
            payload
        }
    )
}

/// Return ethertype 2 bytes array as a single u16.
fn to_u16(bytes: &[u8; 2]) -> u16 {
    u16::from_be_bytes(*bytes)
}

fn get_ethertype(buf: &mut BytesMut) -> [u8; 2] {
    let mut array = [0u8; 2];
    array.copy_from_slice(&buf.split_to(2));
    array
}

fn get_mac(buf: &mut BytesMut) -> [u8; 6] {
    let mut array = [0u8; 6];
    array.copy_from_slice(&buf.split_to(6));
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_parse_success() {
        let data = BytesMut::from(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC
                                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source MAC
                                    0x08, 0x00, // Ethertype (IPv4)
                                    // Payload
                                    0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7][..]);
        let frame = parse(&data).unwrap();
        assert_eq!(frame.destination, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(frame.source, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(frame.ethertype, ETHERTYPE_IPV4);
    }

    #[test]
    fn test_parse_failure() {
        let data = BytesMut::from(&[0x00; 10][..]); // Insufficient data
        assert!(parse(&data).is_err());
    }
}
