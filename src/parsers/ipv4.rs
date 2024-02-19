// src/parsers/ipv4.rs
use bytes::{BytesMut, Buf};
use crate::parsers::ParsingError;

pub const IPV4_PACKET_MIN_LENGTH: usize = 14;


/// Internet protocol version 4 packet
///
/// [RFC 791]: https://datatracker.ietf.org/doc/html/rfc791#section-3.1
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub struct IPv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub options: Vec<u8>,
    pub payload: BytesMut,
}

pub fn parse(data: &BytesMut) -> Result<IPv4Packet, ParsingError> {
    if data.len() < IPV4_PACKET_MIN_LENGTH {
        return Err(ParsingError::BufferUnderflow);
    }

    let mut buf = data.clone();

    let version_ihl = buf.get_u8();
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0F;
    let total_length = buf.get_u16();
    let identification = buf.get_u16();
    let flags_fragment_offset = buf.get_u16();
    let ttl = buf.get_u8();
    let protocol = buf.get_u8();
    let header_checksum = buf.get_u16();
    let source_ip = [buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8()];
    let destination_ip = [buf.get_u8(), buf.get_u8(), buf.get_u8(), buf.get_u8()];

    let header_length = ihl as usize * 4;
    if data.len() < header_length || data.len() < total_length as usize {
        return Err(ParsingError::InvalidPacketLength);
    }

    let options_length = header_length - 20; // Options length if any
    let mut options = vec![0u8; options_length];
    if options_length > 0 {
        buf.copy_to_slice(&mut options);
    }

    let payload = buf.split_to(total_length as usize - header_length);

    Ok(IPv4Packet {
        version,
        ihl,
        total_length,
        identification,
        flags: (flags_fragment_offset >> 13) as u8,
        fragment_offset: flags_fragment_offset & 0x1FFF,
        ttl,
        protocol,
        header_checksum,
        source_ip,
        destination_ip,
        options,
        payload,
    })
}
