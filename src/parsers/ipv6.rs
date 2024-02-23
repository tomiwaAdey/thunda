use crate::address::{self, ipv6::IPv6};

// src/parsers/ipv6.rs
use super::{ParsingError, ValidationError};



/// Internet protocol version 6 packet
///
/// [RFC 2460]: https://datatracker.ietf.org/doc/html/rfc2460

// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone)]
pub struct IPv6Packet<'a> {
    buffer: &'a [u8],
}

impl<'a> IPv6Packet<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    pub fn new_with_validation(buffer: &'a [u8]) -> Result<Self, ParsingError> {
        let packet = Self::new(buffer);
        packet.check_length()?;
        Ok(packet)
    }

    pub fn check_length(&self) -> Result<(), ParsingError> {
        let len = self.buffer.len();
        if len < 40 || len < self.total_length()? {
            Err(ValidationError::InvalidPacketLength.into())
        } else {
            Ok(())
        }
    }

    pub fn header_length(&self) -> usize {
        40 // Fixed for IPv6
    }

    /// Reads a 2-byte field from the packet and returns it as u16.
    fn read_u16(&self, start: usize) -> Result<u16, ParsingError> {
        if self.buffer.len() < start + 2 {
            return Err(ParsingError::BufferUnderflow);
        }

        self.buffer.get(start..start + 2)
            .and_then(|slice| slice.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or(ParsingError::InvalidPacketLength)
    }

    /// Return the Version
    pub fn version(&self) -> u8 {
        self.buffer[0] >> 4
    }

    /// Return the Traffic Class
    pub fn traffic_class(&self) -> u8 {
        ((self.buffer[0] & 0x0f) << 4) | (self.buffer[1] >> 4)
    }

    /// Return the Flow Label
    pub fn flow_label(&self) -> u32 {
        // Last 4 bits of the first byte
        // all of the second and third bytes
        ((self.buffer[1] as u32 & 0x0f) << 16) | (self.buffer[2] as u32) << 8 | self.buffer[3] as u32
    }

    /// Return the Payload Length
    pub fn payload_length(&self) -> Result<u16, ParsingError> {
        self.read_u16(4)
    }

    /// Return the Total Length
    pub fn total_length(&self) -> Result<usize, ParsingError> {
        Ok(self.header_length() + self.payload_length()? as usize)
    }

    /// Return the Next Header
    pub fn next_header(&self) -> u8 {
        self.buffer[6]
    }
    /// Return the Hop Limit
    pub fn hop_limit(&self) -> u8 {
        self.buffer[7]
    }

    /// Return the (16 bytes) Source address
    pub fn source(&self) -> Result<IPv6, ParsingError> {
        address::ipv6::from_bytes(&self.buffer[8..24])
        .map_err(ParsingError::from)
    }
    /// Return the (16 bytes) Destination address
    pub fn destination(&self) -> Result<IPv6, ParsingError> {
        address::ipv6::from_bytes(&self.buffer[24..40])
        .map_err(ParsingError::from)
    }

    /// Return a reference to the payload of the IPv6 packet.
    pub fn payload(&self) -> Result<&[u8], ParsingError> {
        if self.buffer.len() < self.total_length()?{
            return Err(ValidationError::InvalidPacketLength.into());
        }
        Ok(&self.buffer[40..])
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // Generate a valid IPv6 buffer
    fn generate_valid_ipv6_buffer() -> Vec<u8> {
        let mut buffer = vec![0u8; 40]; // Minimum IPv6 header size
        buffer[0] = 0x60; // Version 6
        buffer[4] = 0; // Payload length high-byte
        buffer[5] = 0; // Payload length low-byte
        // Set the next header and hop limit to arbitrary but valid values
        buffer[6] = 59; // No Next Header
        buffer[7] = 255; // Max hop limit
        // Fill in source and destination addresses with valid dummy data
        buffer[8..24].fill(0xff); // Source IPv6 address
        buffer[24..40].fill(0xee); // Destination IPv6 address
        buffer
    }

    #[test]
    fn test_new_with_valid_buffer() {
        let buffer = generate_valid_ipv6_buffer();
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.buffer.len(), 40);
    }

    #[test]
    fn test_new_with_validation_success() {
        let buffer = generate_valid_ipv6_buffer();
        assert!(IPv6Packet::new_with_validation(&buffer).is_ok());
    }

    #[test]
    fn test_new_with_too_small_buffer() {
        let small_buffer = vec![0u8; 10]; // Smaller than an IPv6 header
        assert!(IPv6Packet::new(&small_buffer).check_length().is_err());
    }

    #[test]
    fn test_new_with_validation_failure() {
        let small_buffer = vec![0u8; 10]; // Smaller than an IPv6 header
        assert!(IPv6Packet::new_with_validation(&small_buffer).is_err());
    }

    #[test]
    fn test_check_length_exact_size() {
        let buffer = generate_valid_ipv6_buffer(); // No payload, just the header
        let packet = IPv6Packet::new(&buffer);
        assert!(packet.check_length().is_ok());
    }

    #[test]
    fn test_check_length_smaller_than_header() {
        let small_buffer = vec![0u8; 39]; // 1 byte smaller than an IPv6 header
        let packet = IPv6Packet::new(&small_buffer);
        assert!(packet.check_length().is_err());
    }

    #[test]
    fn test_header_length() {
        let buffer = generate_valid_ipv6_buffer();
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.header_length(), 40);
    }

    // Field Getter Tests
    #[test]
    fn test_version() {
        let buffer = generate_valid_ipv6_buffer();
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.version(), 6);
    }

    // #[test]
    // fn test_traffic_class() {
    //     let buffer = generate_valid_ipv6_buffer();
    //     let packet = IPv6Packet::new(&buffer);
    //     assert_eq!(packet.traffic_class(), 0);
    // }

    #[test]
    fn test_flow_label() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Set flow label to a known value
        buffer[1] |= 0x0f; // Flow Label = 0x000fffff
        buffer[2] = 0xff;
        buffer[3] = 0xff;
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.flow_label(), 0x000fffff);
    }

    #[test]
    fn test_payload_length() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Set payload length to a known value
        buffer[4] = 0x01; // Payload length = 256
        buffer[5] = 0x00;
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.payload_length().unwrap(), 256);
    }

    #[test]
    fn test_total_length() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Set payload length to a known value
        buffer[4] = 0x01; // Payload length = 256
        buffer[5] = 0x00;
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.total_length().unwrap(), 40 + 256); // Header + Payload
    }

    #[test]
    fn test_next_header() {
        let buffer = generate_valid_ipv6_buffer();
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.next_header(), 59); // No Next Header
    }

    #[test]
    fn test_hop_limit() {
        let buffer = generate_valid_ipv6_buffer();
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.hop_limit(), 255);
    }

    #[test]
    fn test_source_and_destination() {
        let buffer = generate_valid_ipv6_buffer();
        let packet = IPv6Packet::new(&buffer);
        let src = packet.source().unwrap();
        let dst = packet.destination().unwrap();
        assert_eq!(src, address::ipv6::from_bytes(&[0xff; 16]).unwrap());
        assert_eq!(dst, address::ipv6::from_bytes(&[0xee; 16]).unwrap());
    }

    // Payload Test
    #[test]
    fn test_payload() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Extend buffer with dummy payload
        let payload = vec![0xab; 10]; // Dummy payload
        buffer.extend_from_slice(&payload);
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.payload().unwrap(), &payload[..]);
    }

    #[test]
    fn test_insufficient_buffer_length() {
        let buffer = vec![0u8; 20]; // Less than the minimum IPv6 header size
        assert!(matches!(IPv6Packet::new_with_validation(&buffer), Err(_)));
    }

    // #[test]
    // fn test_invalid_version() {
    //     let mut buffer = generate_valid_ipv6_buffer();
    //     buffer[0] = 0x50; // Version set to 5 instead of 6
    //     assert!(matches!(IPv6Packet::new_with_validation(&buffer), Err(ParsingError::InvalidVersion)));
    // }

    #[test]
    fn test_invalid_payload_length() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Set an invalid payload length that exceeds the actual buffer size
        buffer[4] = 0xFF;
        buffer[5] = 0xFF; // Payload length set to 65535
        assert!(matches!(IPv6Packet::new_with_validation(&buffer), Err(_)));
    }

    #[test]
    fn test_maximum_payload_length() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Set maximum payload length
        buffer[4] = 0xFF;
        buffer[5] = 0xFF; // Maximum payload length 65535
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.payload_length().unwrap(), 65535);
    }

    #[test]
    fn test_traffic_class_and_flow_label_maximum_values() {
        let mut buffer = generate_valid_ipv6_buffer();
        // Set maximum traffic class
        buffer[0] = 0x6F; // Version 6, Traffic Class = 1111 (binary)
        buffer[1] = 0xFF; // Traffic Class (last 4 bits) + Flow Label (first 4 bits)
        // Set maximum flow label
        buffer[2] = 0xFF;
        buffer[3] = 0xFF; // Flow Label continues
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.traffic_class(), 0xFF);
        assert_eq!(packet.flow_label(), 0x0FFFFF);
    }

    #[test]
    fn test_unrecognized_next_header() {
        let mut buffer = generate_valid_ipv6_buffer();
        buffer[6] = 0xFF; // Unrecognized Next Header value
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.next_header(), 0xFF);
    }

    #[test]
    fn test_payload_length_zero() {
        let buffer = generate_valid_ipv6_buffer();
        // Payload length is already set to 0 in `create_valid_ipv6_packet`
        let packet = IPv6Packet::new(&buffer);
        assert_eq!(packet.payload_length().unwrap(), 0);
        assert!(packet.payload().unwrap().is_empty());
    }
}
