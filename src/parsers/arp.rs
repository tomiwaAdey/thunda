// src/parsers/arp.rs
use crate::parsers::ParsingError;

#[derive(Debug, PartialEq, Eq)]
pub enum Hardware {
    Ethernet = 1,
}

impl From<u16> for Hardware {
    fn from(value: u16) -> Hardware {
        match value {
            1 => Hardware::Ethernet,
            _ => panic!("Unsupported hardware type")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    Request = 1,
    Reply = 2,
}

impl From<u16> for Operation {
    fn from(value: u16) -> Self {
        match value {
            1 => Operation::Request,
            2 => Operation::Reply,
            _ => panic!("Unsupported operation type"),
        }
    }
}

/// Represents an ARP packet
pub struct ArpPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> ArpPacket<'a> {

    /// Constructs a new `ArpPacket` from a byte slice without validation
    pub fn new(buffer: &'a [u8]) -> Self {
        ArpPacket {
            buffer
        }
    }
    /// Constructs a new `ArpPacket` from a byte slice with validation
    pub fn new_with_validation(buffer: &'a [u8]) -> Result<Self, ParsingError> {
        if buffer.len() < 28 {
            return Err(ParsingError::BufferUnderflow);
        }
        Ok(Self { buffer })
    }

    /// Return the hardware type
    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    /// Return the protocol type
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    /// Returns the hardware address length.
    pub fn hardware_address_length(&self) -> u8 {
        self.buffer[4]
    }

    /// Returns the protocol address length.
    pub fn protocol_address_length(&self) -> u8 {
        self.buffer[5]
    }

    /// Returns the operation (1 for request, 2 for reply).
    pub fn operation(&self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    /// Returns the sender hardware address (MAC address).
    pub fn sender_hardware_address(&self) -> &[u8] {
        &self.buffer[8..14]
    }

    /// Returns the sender protocol address (IP address).
    pub fn sender_protocol_address(&self) -> &[u8] {
        &self.buffer[14..18]
    }

    /// Returns the target hardware address (MAC address).
    pub fn target_hardware_address(&self) -> &[u8] {
        &self.buffer[18..24]
    }

    /// Returns the target protocol address (IP address).
    pub fn target_protocol_address(&self) -> &[u8] {
        &self.buffer[24..28]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_packet_parsing() {
        // Example ARP request packet data (truncated for simplicity)
        let data: [u8; 28] = [
            0x00, 0x01, // Hardware type (Ethernet)
            0x08, 0x00, // Protocol type (IPv4)
            0x06,       // Hardware address length
            0x04,       // Protocol address length
            0x00, 0x01, // Operation (request)
            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, // Sender hardware address
            0xc0, 0xa8, 0x01, 0x01,             // Sender protocol address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target hardware address (unknown for request)
            0xc0, 0xa8, 0x01, 0x02,             // Target protocol address
        ];

        let packet = ArpPacket::new_with_validation(&data).unwrap();

        assert_eq!(packet.hardware_type(), 0x0001);
        assert_eq!(packet.protocol_type(), 0x0800);
        assert_eq!(packet.hardware_address_length(), 6);
        assert_eq!(packet.protocol_address_length(), 4);
        assert_eq!(packet.operation(), 0x0001);
        assert_eq!(packet.sender_hardware_address(), &[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad]);
        assert_eq!(packet.sender_protocol_address(), &[0xc0, 0xa8, 0x01, 0x01]);
        assert_eq!(packet.target_hardware_address(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(packet.target_protocol_address(), &[0xc0, 0xa8, 0x01, 0x02]);
    }
}
