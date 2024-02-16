// src/io/nic_interface.rs
use std::future::Future;
use std::pin::Pin;
use std::io::Result as IoResult;

/// Trait defining common operations for network interfaces.
pub trait NicInterface {
    fn read_packet(&self) -> Pin<Box<dyn Future<Output = IoResult<Vec<u8>>> + Send>>;
    fn write_packet(&self, data: Vec<u8>) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send>>;
}
