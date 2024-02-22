// src/assemblers/ethernet
use crate::address::mac::Mac;

/// Represents the Ethernet frame Ethertype.
#[derive(Debug, Clone, Copy)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
}


pub struct EthernetFrame<'a> {
    buffer: &'a mut [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Creates a new `EthernetFrame` with a mutable reference to a buffer.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        EthernetFrame { buffer }
    }

    /// Set the destination MAC address.
    pub fn set_destination(&mut self, value: Mac) {
        self.buffer[0..6].copy_from_slice(&value.to_bytes());
    }

    /// Set the source MAC address.
    pub fn set_source(&mut self, value: Mac) {
        self.buffer[6..12].copy_from_slice(&value.to_bytes());
    }

    pub fn set_ethertype(&mut self, value: EtherType) {
        let ethertype_bytes = (value as u16).to_be_bytes(); // Convert EtherType to big endian bytes
        self.buffer[12..14].copy_from_slice(&ethertype_bytes); // Copy the bytes into the buffer
    }

    /// Get a mutable reference to the payload.
    pub fn mut_payload_ref(&mut self) -> &mut [u8] {
        &mut self.buffer[14..]
    }
}

#[cfg(test)]
mod tests {
    use crate::address::mac;

    use super::*;

    const FRAME_BYTES: [u8; 64] = [
        // Destination MAC: 01:02:03:04:05:06
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        // Source MAC: 11:12:13:14:15:16
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        // Ethertype (e.g., IPv4): 0x0800
        0x08, 0x00,
        // start of payload
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0xff,
    ];

    #[test]
    fn construct_ethernet_frame() {
        let mut buffer = [0u8; 64];
        let mut frame = EthernetFrame::new(&mut buffer);
        frame.set_destination(mac::from_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]).unwrap());
        frame.set_source(mac::from_bytes(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]).unwrap());
        frame.set_ethertype(EtherType::Ipv4);
        let payload = frame.mut_payload_ref();
        payload.copy_from_slice(&[0xaa,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0xff,]);

        assert_eq!(&buffer[..], &FRAME_BYTES[..]);
    }
}
