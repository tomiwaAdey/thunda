// src/assemblers/ipv6

use crate::address::ipv6::IPv6;
pub struct IPv6Packet<'a> {
    buffer: &'a mut [u8],
}

impl<'a> IPv6Packet<'a> {

    pub fn new(buffer: &'a mut [u8]) -> Self {
        IPv6Packet { buffer }
    }

    /// Set the version
    pub fn set_version(&mut self, version: u8) {
        // Calc (remove later)
        // 00000101  set 00000110 to first 4 bit(ms 1/2b)
        // 00000101 & 00001111 = 00000101
        // 00000110 shift to ms 1/2b -> 00000110 << 4  = 01100000
        // 00000101 | 01100000
        // 01100101
        self.buffer[0] = (self.buffer[0] & 0x0F) | (version << 4);
    }

    /// Set the traffic class
    pub fn set_traffic_class(&mut self, traffic_class: u8) {
        self.buffer[0] = (self.buffer[0] & 0xF0) | (traffic_class >> 4);
        self.buffer[1] = (self.buffer[1] & 0x0F) | (traffic_class << 4);
    }
    /// Set the flow label
    pub fn set_flow_label(&mut self, flow_label: u32) {
        self.buffer[1] = (self.buffer[1] & 0xF0) | ((flow_label >> 16) & 0x0F) as u8;
        self.buffer[2] = ((flow_label >> 8) & 0xFF) as u8;
        self.buffer[3] = (flow_label & 0xFF) as u8;
    }

    /// Set the payload length
    pub fn set_payload_length(&mut self, payload_length: u16) {
        self.buffer[4] = (payload_length >> 8) as u8;
        self.buffer[5] = (payload_length & 0xFF) as u8;
    }

    /// Set the next header
    pub fn set_next_header(&mut self, next_header: u8) {
        self.buffer[6] = next_header;
    }

    /// Set the hop limit
    pub fn set_hop_limit(&mut self, hop_limit: u8) {
        self.buffer[7] = hop_limit;
    }

    /// Set the source
    pub fn set_source(&mut self, source: IPv6) {
        self.buffer[8..24].copy_from_slice(&source.to_bytes());
    }

    /// Set the destination
    pub fn set_destination(&mut self, destination: IPv6 ) {
        self.buffer[24..40].copy_from_slice(&destination.to_bytes());
    }

    /// Return a mutable reference to payload
    pub fn mut_payload_ref(&mut self) -> &mut [u8] {
        let payload_length = ((self.buffer[4] as usize) << 8) | (self.buffer[5] as usize);
        &mut self.buffer[40..40 + payload_length]
    }
}

#[cfg(test)]
mod tests {
    // use super::*;

    // const REPR_PAYLOAD_BYTES: [u8; 16] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00];
    // const IPV6_BYTES: [u8; 56] = [
    //     0x60, 0x00, 0x00, 0x00, // Version (6), TC, Flow Label
    //     0x00, 0x1C, // Payload Length (28 bytes of payload for example purposes)
    //     0x06, // Next Header (TCP)
    //     0x40, // Hop Limit (64)
    //     // Source IPv6 Address (Placeholder)
    //     0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01,
    //     // Destination IPv6 Address (Placeholder)
    //     0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    //     // Payload
    //     0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00
    // ];

    // #[test]
    // fn construct_ipv6_packet() {
    //     let mut buffer = [0u8; 62]; // Ensure this matches header + intended payload size
    //     let mut packet = IPv6Packet::new(&mut buffer);

    //     packet.set_version(6);
    //     packet.set_traffic_class(0x99);
    //     packet.set_flow_label(0x54321);
    //     packet.set_payload_length(REPR_PAYLOAD_BYTES.len() as u16); // Ensure this matches your actual payload size
    //     packet.set_next_header(6); // TCP
    //     packet.set_hop_limit(0xfe);
    //     packet.set_source(IPv6::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1));
    //     packet.set_destination(IPv6::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1));

    //     // Ensure you're only copying as much as the payload length you've set
    //     let payload_slice = packet.mut_payload_ref();
    //     assert!(payload_slice.len() >= REPR_PAYLOAD_BYTES.len(), "Payload buffer is too small");
    //     payload_slice[..REPR_PAYLOAD_BYTES.len()].copy_from_slice(&REPR_PAYLOAD_BYTES);

    //     // Expected state of buffer after modifications
    //     assert_eq!(&buffer[..], &IPV6_BYTES[..], "Buffer state does not match expected state after modifications");
    // }

}
