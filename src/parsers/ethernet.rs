// src/parsers/ethernet.rs
use crate::parsers::ParsingError;

/// EtherType
///
/// https://en.wikipedia.org/wiki/EtherType
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;


pub const ETHER_MIN_LENGTH: usize = 14;


pub struct EthernetFrame<'a> {
    buffer: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    // Constant representing the minimum Ethernet frame size
    const MIN_FRAME_SIZE: usize = 14; // 6 (Dest) + 6 (Source) + 2 (Ethertype)

    /// Constructs a new `EthernetFrame` from a raw octect buffer
    pub fn new(buffer: &'a [u8]) -> EthernetFrame {
        EthernetFrame { buffer }
    }


    // Constructor with validation
    pub fn new_with_validation(buffer: &'a [u8]) -> Result<EthernetFrame<'a>, ParsingError> {
        if buffer.len() < Self::MIN_FRAME_SIZE {
            Err(ParsingError::BufferUnderflow)
        } else {
            Ok(EthernetFrame { buffer })
        }
    }

    // Return the destination MAC address
    pub fn destination(&self) -> &[u8] {
        &self.buffer[0..6]
    }

    // Return the source MAC address
    pub fn source(&self) -> &[u8] {
        &self.buffer[6..12]
    }

    // Return the Ethertype
    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.buffer[12], self.buffer[13]])
    }

    // Return a reference to the frame's payload.
    pub fn payload(&self) -> &'a [u8] {
        &self.buffer[Self::header_length()..]
    }

    // Return the header length
    pub fn header_length() -> usize {
        Self::MIN_FRAME_SIZE
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    static FRAME_BYTES: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Destination MAC
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // Source MAC
        0x08, 0x00, // Ethertype (IPv4)
        // Start of payload
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, // End of payload
        // Padding to reach 64 bytes
        0x00
    ];


    #[test]
    fn test_deconstruct() {
        let frame = EthernetFrame::new_with_validation(&FRAME_BYTES).expect("Valid frame");
        assert_eq!(frame.destination(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(frame.source(), &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        assert_eq!(frame.ethertype(), 0x0800); // IPv4 in hex
        assert_eq!(frame.payload(), &FRAME_BYTES[14..64]); // Payload comparison
    }

}
