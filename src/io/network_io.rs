use actix::prelude::*;
use crate::config::Config;

#[cfg(feature = "tap")]
use crate::iface::tap;

#[cfg(feature = "af_xdp")]
use crate::iface::af_xdp;

#[derive(Message)]
#[rtype(result = "()")]
pub struct RawPacket(pub Vec<u8>);

pub struct NetworkIO;

impl NetworkIO {
    pub fn new(config: &Config) -> Self {
        #[cfg(feature = "tap")]
        {
            if let Err(e) = tap::initialize(config) { // Assuming `initialize` expects a reference
                panic!("Failed to initialize TAP interface: {:?}", e);
            }
        }

        #[cfg(feature = "af_xdp")]
        {
            if let Err(e) = af_xdp::initialize(config) { // Assuming `initialize` expects a reference
                panic!("Failed to initialize AF_XDP interface: {:?}", e);
            }
        }

        NetworkIO
    }
}

impl Actor for NetworkIO {
    type Context = Context<Self>;
    // Further implementation
}

impl Handler<RawPacket> for NetworkIO {
    type Result = ();

    fn handle(&mut self, msg: RawPacket, _: &mut Context<Self>) {
        // Handle raw packet I/O here
        println!("Received raw packet: {:?}", msg.0);
    }
}
