// src/assemblers/ipv6
pub struct IPv6Packet<'a> {
    buffer: &'a mut [u8],
}

impl<'a> IPv6Packet<'a> {

    /// Set the version
    pub fn set_version(&mut self, version: u8) {
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
    pub fn set_source(&mut self, source: &[u8; 16]) {
        self.buffer[8..24].copy_from_slice(source);
    }

    /// Set the destination
    pub fn set_destination(&mut self, destination: &[u8; 16]) {
        self.buffer[24..40].copy_from_slice(destination);
    }

    fn payload_length() {
        ((self.buffer[4] as usize) << 8) | (self.buffer[5] as usize)
    }

    /// Return a mutable reference to payload
    pub fn mut_payload_ref(&mut self) -> &mut [u8] {
        &mut self.buffer[40..40+self.payload_length]
    }
}
