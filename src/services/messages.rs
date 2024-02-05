use actix::Message;

pub struct PacketReceived {
    // Packet data
}

impl Message for PacketReceived {
    type Result = Result<(), ()>;
}
