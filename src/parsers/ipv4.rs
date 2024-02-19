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
                                   const INVALID_IPV4_PACKET: &[u8] = &[0x45]; // Incomplete packet
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



}
