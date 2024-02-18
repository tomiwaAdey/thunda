// src/parsers/mod.rs
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod arp;
pub mod packet;

#[derive(Debug, PartialEq)]
pub enum ParsingError {
    BufferUnderflow,
    UnsupportedEthertype,
}
