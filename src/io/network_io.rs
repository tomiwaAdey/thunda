// src/io/network_io.rs

// use actix::prelude::*;
use actix::{Actor, Addr, AsyncContext, Context, Handler, Message};
use std::io::Result as IoResult; // Same as Result<T, std::io::Error>
use crate::io::nic_interface::NicInterface;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{self, Duration};
use log::{error, debug};

pub struct NetworkIO {
    nic: Arc<Mutex<dyn NicInterface + Send>>,
}

impl NetworkIO {
    /// Creates a new `NetworkIO` actor with the specified network interface controller (NIC).
    pub fn new(nic: Arc<Mutex<dyn NicInterface + Send>> ) -> Self {
        Self { nic }
    }

    /// Sends a packet through the NIC.
    async fn send_packet(nic: Arc<Mutex<dyn NicInterface + Send>>, data: Vec<u8>) -> IoResult<()> {
        let nic_lock = nic.lock().await;
        nic_lock.write_packet(data).await.map_err(|e| {
            error!("Error sending packet: {}", e);
            e
        })
    }

    /// Initiates packet listening.
    async fn start_listening(nic: Arc<Mutex<dyn NicInterface + Send>>, _addr: Addr<NetworkIO>) {
        debug!("Start listening for incoming packets.");

        // Interval timer to introduce delay in each iteration.
        // Helps in preventing the loop from consuming 100% CPU in a tight loop
        // when there are no packets to process.
        let mut interval = time::interval(Duration::from_millis(100));
        loop {
            // Await next tick of the interval.
            // This pauses the loop, yielding control back to the Tokio runtime until the interval elapses.
            // Simple way to prevent constant polling for packets
            // and allows the CPU to do other tasks or enter a low-power state.
            interval.tick().await;
            let result = {
                let lock = nic.lock().await;
                lock.read_packet().await
            };

            match result {
                Ok(packet) => {
                    // Forward the packet for further processing
                    debug!("Packet received: {:?}", packet);
                    // addr.do_send(ProcessPacket(packet));

                },
                Err(e) => {
                    error!("Error reading packet: {}", e);
                    break; // To Do: Use backoff
                }
            }
        }
        debug!("Stopped listening for incoming packets.");
    }

}






impl Actor for NetworkIO {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        debug!("NetworkIO Actor started, initiating packet listening.");
        let nic = self.nic.clone();
        tokio::spawn(Self::start_listening(nic, ctx.address()));
    }
}

/// Message to request sending a packet through the network interface.
pub struct SendPacket(pub Vec<u8>);

impl Message for SendPacket {
    type Result = IoResult<()>;
}

impl Handler<SendPacket> for NetworkIO {
    type Result = IoResult<()>;

    fn handle(&mut self, msg: SendPacket, _ctx: &mut Context<Self>) -> Self::Result {
        let nic = self.nic.clone();
        let send_fut = Self::send_packet(nic, msg.0);

        tokio::spawn(async move {
            let _ = send_fut.await;
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_rt;
    use actix::Actor;
    use core::pin::Pin;
    use std::io::Result as IoResult;
    use tokio::sync::Mutex;
    use std::sync::Arc;
    use futures::Future;
    use futures::future::{self};

    struct MockNicInterface;
    impl NicInterface for MockNicInterface {
        fn write_packet(&self, _data: Vec<u8>) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send>> {
            Box::pin(future::ready(Ok(())))
        }

        fn read_packet(&self) -> Pin<Box<dyn Future<Output = IoResult<Vec<u8>>> + Send>> {
            let packet = vec![0xde, 0xad, 0xbe, 0xef]; // Mock packet data
            Box::pin(future::ready(Ok(packet)))
        }
    }

    #[actix_rt::test]
    async fn test_send_packet() {
        let nic = Arc::new(Mutex::new(MockNicInterface));
        let network_io = NetworkIO::new(nic).start();

        // Simulate sending a packet
        let packet = vec![0xde, 0xad, 0xbe, 0xef];
        let result = network_io.send(SendPacket(packet)).await;
        assert!(result.is_ok(), "SendPacket should succeed with mock NIC");
    }
}
