// src/parsers/ipv4.rs
use std::convert::TryInto;
use crate::address::{self, ipv4::IPv4};

use super::{ParsingError, ValidationError};

// pub const IPV4_PACKET_MIN_LENGTH: usize = 14;

/// IPv4 packet Identifier.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Key {
    pub id: u16,
    pub src_addr: IPv4,
    pub dst_addr: IPv4,
    pub protocol: u8,
}


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

/// Provides lazy access to IPv4 packet fields.
pub struct IPv4Packet<'a> {
    buffer: &'a [u8],
}

impl<'a> IPv4Packet<'a> {
    /// Constructs a new `IPv4Packet` from a raw octect buffer
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    pub fn new_with_validation(buffer: &'a [u8]) -> Result<Self, ParsingError> {
        let packet = Self::new(buffer);
        packet.check_length()?;
        Ok(packet)
    }

    fn check_length(&self) -> Result<(), ParsingError> {
        let len = self.buffer.len();

        // The minimum length of an IPv4 header is 20 bytes
        if len < 20 {
            return Err(ValidationError::InvalidHeaderLength.into());
        }

        // Ensure the total length field matches the buffer size.
        let total_length = self.total_length()? as usize;
        if total_length > len {
            return Err(ValidationError::TotalLengthExceedsBufferLength.into());
        }

        // Ensure the header length (IHL) is valid.
        let ihl = self.ihl() as usize;
        if ihl < 20 || ihl > total_length {
            return Err(ValidationError::InvalidHeaderLength.into());
        }

        Ok(())
    }

    /// Reads a 2-byte field from the packet and returns it as u16.
    fn read_u16(&self, start: usize) -> Result<u16, ParsingError> {
        if self.buffer.len() < start + 2 {
            return Err(ParsingError::BufferUnderflow);
        }

        self.buffer.get(start..start + 2)
            .and_then(|slice| slice.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or(ParsingError::InvalidPacketLength) // You might choose a more specific error
    }

    /// Return the Version
    pub fn version(&self) -> u8 {
        self.buffer[0] >> 4
    }

    /// Return the IHL (Internet Header Length) on octets.
    pub fn ihl(&self) -> u8 {
        (self.buffer[0] & 0x0F) * 4
    }

    /// Return the Differentiated Services Code Point
    // (6 bit in TOS)
    pub fn dscp(&self) -> u8 {
        self.buffer[1] >> 2
    }

    /// Return the Explicit Congestion Notification.
    // (2 bit in TOS)
    pub fn ecn(&self) -> u8 {
        self.buffer[1] & 0x03
    }

    /// Return the Total length of the packet.
    pub fn total_length(&self) -> Result<u16, ParsingError> {
        self.read_u16(2)
    }

    /// Return the Identification field
    pub fn identification(&self) -> Result<u16, ParsingError> {
        self.read_u16(4)
    }

    /// 3 bit Flags
    //   0   1   2
    // +---+---+---+
    // |   | D | M |
    // | 0 | F | F |
    // +---+---+---+

    /// Checks if the "Don't Fragment" (DF) flag is set
    pub fn dont_frag(&self) -> Result<bool, ParsingError> {
        let flags_offset = self.read_u16(6)?;
        Ok((flags_offset & 0x4000) > 0)
    }

    /// Checks if the "More Fragments" (MF) flag is set
    pub fn more_frags(&self) -> Result<bool, ParsingError> {
        let flags_offset = self.read_u16(6)?;
        Ok((flags_offset & 0x2000) > 0)
    }

    /// Return the Fragment Offset, in octets
    pub fn fragment_offset(&self) -> Result<u16, ParsingError> {
        Ok(self.read_u16(6)? & 0x1FFF)
    }

    /// Return the Time to Live (hop limit)
    pub fn ttl(&self) -> u8 {
        self.buffer[8]
    }

    /// Return the Protocol in payload
    pub fn protocol(&self) -> u8 {
        self.buffer[9]
    }

    /// Return the Header checksum.
    pub fn checksum(&self) -> Result<u16, ParsingError> {
        Ok(self.read_u16(10)?)
    }

   /// Return the Source address.
    pub fn src_addr(&self) -> Result<IPv4, ParsingError> {
        address::ipv4::from_bytes(&self.buffer[12..16])
            .map_err(ParsingError::from)
    }

    /// Return the Destination address.
    pub fn dst_addr(&self) -> Result<IPv4, ParsingError> {
        address::ipv4::from_bytes(&self.buffer[16..20])
            .map_err(ParsingError::from)
    }

    /// Options and padding (if IHL > 5).
    pub fn options(&self) -> &'a [u8] {
        let ihl = self.ihl();
        if ihl > 20 {
            &self.buffer[20..ihl as usize]
        } else {
            &[]
        }
    }

    /// Return the Payload of the packet.
    pub fn payload(&self) -> Result<&'a [u8], ParsingError> {
        let ihl = self.ihl() as usize;
        let total_length = self.total_length()? as usize;

        if ihl > total_length || ihl < 20 || total_length > self.buffer.len() {
            return Err(ParsingError::InvalidPacketLength);
        }

        Ok(&self.buffer[ihl..total_length])
    }

    /// Returns a Key for identifying the packet
    pub fn key(&self) -> Result<Key, ParsingError> {
        Ok(Key {
            id: self.identification()?,
            src_addr: self.src_addr()?,
            dst_addr: self.dst_addr()?,
            protocol: self.protocol()
        })
    }

     /// Verifies the IPv4 header checksum.
     pub fn verify_checksum(&self) -> Result<bool, ParsingError> {
        let ihl = self.ihl() as usize;
        if ihl < 20 || ihl > self.buffer.len() {
            return Err(ValidationError::InvalidHeaderLength.into());
        }

        let mut sum: u32 = 0;
        // Iterate over each 16-bit word in the header.
        for i in (0..ihl).step_by(2) {
            let word = if i == 10 {
                0 // Treat the checksum field as 0.
            } else {
                self.buffer.get(i..i + 2)
                    .and_then(|slice| slice.try_into().ok())
                    .map(u16::from_be_bytes)
                    .ok_or(ParsingError::InvalidPacketLength)? as u32
            };

            sum += word;
            // Handle overflow.
            if sum > 0xFFFF {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        // The correct checksum should result in a sum of 0xFFFF.
        Ok(sum == 0xFFFF)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    const VALID_IPV4_PACKET: &[u8] = &[0x45, 0x00, 0x00, 0x14, // Version, IHL, Total Length
                                   0x00, 0x00, 0x00, 0x00, // Identification, Flags, Fragment Offset
                                   0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Header Checksum
                                   0x7f, 0x00, 0x00, 0x01, // Source IP
                                   0x7f, 0x00, 0x00, 0x01]; // Destination IP

    const EXPECTED_PAYLOAD_SIZE_WITHOUT_PADDING: usize = 4;

    const INVALID_IPV4_PACKET: &[u8] = &[0x45];

    // A valid packet but with an IHL (Internet Header Length) that's too large
    const INVALID_IHL_PACKET: &[u8] = &[0x4F, 0x00, 0x00, 0x14,
                                    0x00, 0x00, 0x00, 0x00,
                                    0x40, 0x06, 0x00, 0x00,
                                    0x7f, 0x00, 0x00, 0x01,
                                    0x7f, 0x00, 0x00, 0x01];

    // A packet with a total length that's less than the actual buffer size
    const TOTAL_LENGTH_TOO_LARGE_PACKET: &[u8] = &[0x45, 0x00, 0xFF, 0xFF, // Version, IHL, and an exaggerated Total Length
                                                0x00, 0x00, 0x00, 0x00,
                                                0x40, 0x06, 0x00, 0x00,
                                                0x7f, 0x00, 0x00, 0x01,
                                                0x7f, 0x00, 0x00, 0x01];

    // A packet with an invalid header length (less than minimum of 20 bytes)
    const INVALID_HEADER_PACKET: &[u8] = &[0x45];

    const VALID_IPV4_PACKET_WITH_OPTIONS: &[u8] = &[
        0x46, // Version (4) and IHL (6); IHL=6 means 24 bytes header.
        0x00, // Type of Service (default)
        0x00, 0x1C, // Total Length (20 bytes header + 4 bytes of options + payload)
        0x00, 0x00, // Identification
        0x40, 0x00, // Flags (Don't Fragment) and Fragment Offset
        0x40, // Time to Live (64)
        0x06, // Protocol (TCP)
        0x00, 0x00, // Header Checksum (set to 0x0000 for simplicity)
        0x7F, 0x00, 0x00, 0x01, // Source IP Address (127.0.0.1)
        0x7F, 0x00, 0x00, 0x01, // Destination IP Address (127.0.0.1)
        // Options start here
        0x01, // Option: NOP (No Operation)
        0x01, // Option: NOP (No Operation) - Adding two NOPs to make alignment for next 4-byte boundary
        0x01, // Option: NOP (No Operation)
        0x01, // Option: NOP (No Operation)
        // End of Options; No payload in this example for simplicity
    ];

    const VALID_IPV4_PACKET_WITH_PAYLOAD: &[u8] = &[
        0x45, // Version (4) and IHL (5); IHL=5 means 20 bytes header.
        0x00, // Type of Service (default)
        0x00, 0x22, // Total Length (20 bytes header + 8 bytes payload = 34 bytes, 0x0022 in hex)
        0x00, 0x00, // Identification
        0x40, 0x00, // Flags (Don't Fragment) and Fragment Offset
        0x40, // Time to Live (64)
        0x06, // Protocol (TCP)
        0xAB, 0xCD, // Header Checksum (dummy)
        0x7F, 0x00, 0x00, 0x01, // Source IP Address (127.0.0.1)
        0x7F, 0x00, 0x00, 0x01, // Destination IP Address (127.0.0.1)
        // Payload starts here (8 bytes)
        'P' as u8, 'a' as u8, 'y' as u8, 'l' as u8,
        'o' as u8, 'a' as u8, 'd' as u8, '!' as u8,
    ];

    const _VALID_IPV4_PACKET_WITH_CORRECT_CHECKSUM: &[u8] = &[
        0x45, 0x00, // Version & IHL, TOS
        0x00, 0x14, // Total length (20 bytes header, no payload)
        0x00, 0x00, // Identification
        0x40, 0x00, // Flags & Fragment offset
        0x40, 0x11, // TTL & Protocol (UDP for simplicity)
        0x3c, 0x4f, // Correct checksum
        0x7f, 0x00, 0x00, 0x01, // Source IP (127.0.0.1)
        0x7f, 0x00, 0x00, 0x01, // Destination IP (127.0.0.1)
    ];

    const VALID_IPV4_PACKET_WITH_INCORRECT_CHECKSUM: &[u8] = &[
        0x45, 0x00,
        0x00, 0x14,
        0x00, 0x00,
        0x40, 0x00,
        0x40, 0x11,
        0xde, 0xad, // Incorrect checksum
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
    ];

    const VALID_IPV4_PACKET_WITH_PADDING: &[u8] = &[
        // Starting with a simple 20-byte header and a small payload
        0x45, 0x00, 0x00, 0x18, // Version & IHL, TOS, total length (24 bytes)
        0x00, 0x00, 0x40, 0x00, // Identification, Flags & Fragment offset
        0x40, 0x11, 0xb8, 0x55, // TTL, Protocol, Correct checksum
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, // Source and destination IPs
        'a' as u8, 'b' as u8, 'c' as u8, 'd' as u8, // 4-byte payload
    ];

    const MINIMUM_SIZE_IPV4_PACKET: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, // Version & IHL, TOS, total length (20 bytes)
        0x00, 0x00, 0x40, 0x00, // Identification, Flags & Fragment offset
        0x40, 0x11, 0xb8, 0x54, // TTL, Protocol, Checksum placeholder
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, // Source and destination IPs
    ];

    // Constructor and Validation Tests

    #[test]
    fn test_new_with_valid_buffer() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.buffer.len(), VALID_IPV4_PACKET.len());
    }

    #[test]
    fn test_new_with_validation_success() {
        let result = IPv4Packet::new_with_validation(VALID_IPV4_PACKET);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_with_validation_failure() {
        let result = IPv4Packet::new_with_validation(INVALID_IPV4_PACKET);
        assert!(result.is_err());
    }

    // Length Checking Tests

    #[test]
    fn test_check_length_success() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert!(packet.check_length().is_ok());
    }

    #[test]
    fn test_check_length_failure_invalid_header_length() {
        let packet = IPv4Packet::new(INVALID_HEADER_PACKET);
        let result = packet.check_length();
        assert!(matches!(result, Err(ParsingError::ValidationError(ValidationError::InvalidHeaderLength))));
    }


    #[test]
    fn test_check_length_failure_total_length_exceeds_buffer() {
        let packet = IPv4Packet::new(TOTAL_LENGTH_TOO_LARGE_PACKET);
        assert!(matches!(
            packet.check_length(),
            Err(ParsingError::ValidationError(ValidationError::TotalLengthExceedsBufferLength))
        ));
    }

    #[test]
    fn test_check_length_failure_ihl_too_large() {
        let packet = IPv4Packet::new(INVALID_IHL_PACKET);
        assert!(matches!(
            packet.check_length(),
            Err(ParsingError::ValidationError(ValidationError::InvalidHeaderLength))
        ));
    }


    // Field Extraction Tests

    #[test]
    fn test_version_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.version(), 4); // Assuming IPv4
    }

    #[test]
    fn test_ihl_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.ihl(), 20);
    }


    #[test]
    fn test_dscp_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.dscp(), 0x0);
    }

    #[test]
    fn test_ecn_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.ecn(), 0x0);
    }

    #[test]
    fn test_total_length_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.total_length().unwrap(), VALID_IPV4_PACKET.len() as u16);
    }

    #[test]
    fn test_identification_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.identification().unwrap(), 0x0000);
    }

    #[test]
    fn test_flags_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        let dont_frag = packet.dont_frag().unwrap();
        let more_frags = packet.more_frags().unwrap();
        assert!(!dont_frag, "Don't Fragment flag should not be set");
        assert!(!more_frags, "More Fragments flag should not be set");
    }

    #[test]
    fn test_fragment_offset_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.fragment_offset().unwrap(), 0);
    }

    #[test]
    fn test_ttl_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.ttl(), 64);
    }

    #[test]
    fn test_protocol_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.protocol(), 6);
    }

    #[test]
    fn test_checksum_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.checksum().unwrap(), 0x0000);
    }

    #[test]
    fn test_src_addr_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.src_addr().unwrap(), IPv4::new(127, 0, 0, 1));
    }

    #[test]
    fn test_dst_addr_extraction() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET);
        assert_eq!(packet.dst_addr().unwrap(), IPv4::new(127, 0, 0, 1));
    }

    #[test]
    fn test_options_extraction() {
        let packet_with_options = IPv4Packet::new(VALID_IPV4_PACKET_WITH_OPTIONS);
        assert!(!packet_with_options.options().is_empty(), "Options should be extracted");
    }


    // #[test]
    // fn test_payload_extraction() {
    //     let packet = IPv4Packet::new(VALID_IPV4_PACKET_WITH_PAYLOAD);
    //     let payload = packet.payload();
    //     let expected_payload = b"Payload!"; // The expected payload as bytes
    //     assert_eq!(payload.unwrap(), expected_payload, "Payload content does not match expected value");
    // }

    // Special Cases and Error Handling Tests
    #[test]
    fn test_read_u16_error_handling() {
        let packet = IPv4Packet::new(&[0x45, 0x00]);
        assert!(packet.read_u16(1).is_err(), "Expected buffer underflow error");
    }

    #[test]
    fn test_key_creation_success() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET_WITH_PAYLOAD);
        let key_result = packet.key();
        assert!(key_result.is_ok(), "Expected successful Key creation");
    }

    #[test]
    fn test_key_creation_failure() {
        let packet = IPv4Packet::new(INVALID_IPV4_PACKET);
        let key_result = packet.key();
        assert!(key_result.is_err(), "Expected failure in Key creation");
    }

    // #[test]
    // fn test_verify_checksum_success() {
    //     let packet = IPv4Packet::new(VALID_IPV4_PACKET_WITH_CORRECT_CHECKSUM);
    //     assert!(packet.verify_checksum().unwrap(), "Checksum verification should succeed");

    // }

    #[test]
    fn test_verify_checksum_failure() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET_WITH_INCORRECT_CHECKSUM);
        assert!(!packet.verify_checksum().unwrap(), "Checksum verification should fail");
    }

    // Behavioral Tests
    // #[test]
    // fn test_packet_with_options_handling() {
    //     let packet = IPv4Packet::new(VALID_IPV4_PACKET_WITH_OPTIONS);
    //     assert_eq!(packet.ihl(), 6, "IHL should reflect options presence");
    //     assert!(!packet.options().is_empty(), "Options should be present and correctly parsed");
    // }

    #[test]
    fn test_packet_with_padding_handling() {
        let packet = IPv4Packet::new(VALID_IPV4_PACKET_WITH_PADDING);
        // Ensure padding does not affect payload extraction
        assert_eq!(packet.payload().unwrap().len(), EXPECTED_PAYLOAD_SIZE_WITHOUT_PADDING, "Payload size should exclude padding");
    }

    #[test]
    fn test_minimum_packet_size() {
        let packet = IPv4Packet::new(MINIMUM_SIZE_IPV4_PACKET);
        assert!(packet.check_length().is_ok(), "Minimum size packet should be considered valid");
    }

    #[test]
    fn test_maximum_packet_size() {
        // Dynamically generate the maximum size IPv4 packet
        let header_size = 20; // Minimum IPv4 header size
        let _payload_size = 65535 - header_size; // Max total length - header size
        let mut packet_data = Vec::with_capacity(65535);
        // Construct the header
        packet_data.extend_from_slice(&[
            0x45, 0x00, // Version & IHL, Type of Service (assuming IHL = 5, no options)
            0xFF, 0xFF, // Total Length (65535)
            0x00, 0x00, // Identification
            0x40, 0x00, // Flags & Fragment Offset
            0x40, 0x06, // TTL & Protocol (assuming TCP for simplicity)
            0x00, 0x00, // Header Checksum placeholder (would need calculation for a real packet)
            0x7F, 0x00, 0x00, 0x01, // Source IP (127.0.0.1)
            0x7F, 0x00, 0x00, 0x01, // Destination IP (127.0.0.1)
        ]);
        // Fill the payload to reach the maximum size
        packet_data.resize(65535, 0x00); // Filling with zeroes

        let packet = IPv4Packet::new(&packet_data);
        // The total length field should correctly reflect the maximum size
        assert_eq!(packet.total_length().unwrap() as usize, 65535, "Maximum size packet should be correctly parsed");
    }

}

