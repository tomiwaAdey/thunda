// src/parsers/mod.rs
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod arp;
pub mod packet;

use crate::address::ipv4::IPv4AddressError;


#[derive(Debug, PartialEq)]
pub enum ParsingError {
    BufferUnderflow,
    UnsupportedEthertype,
    InvalidPacketLength,
    IPv4AddressError(IPv4AddressError),
    ValidationError(ValidationError),
    Default
}

impl std::fmt::Display for ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParsingError::BufferUnderflow => write!(f, "The data buffer is too short to contain a valid packet"),
            ParsingError::UnsupportedEthertype => write!(f, "The ethertype is not supported"),
            ParsingError::InvalidPacketLength => write!(f, "The packet length is invalid"),
            ParsingError::IPv4AddressError(e) => write!(f, "{}", e), // Delegate to IPv4AddressError's Display impl
            ParsingError::ValidationError(e) => write!(f, "{}", e),
            ParsingError::Default => write!(f, "An unspecified parsing error occurred")
        }
    }
}

impl std::error::Error for ParsingError {}


#[derive(Debug, PartialEq)]
pub enum ValidationError {
    BufferTooShort,
    InvalidHeaderLength,
    HeaderLengthExceedsTotalLength,
    TotalLengthExceedsBufferLength,
    InvalidPacketLength,
    Default
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ValidationError::BufferTooShort => write!(f, "Buffer too short"),
            ValidationError::InvalidHeaderLength => write!(f, "Invalid header length"),
            ValidationError::HeaderLengthExceedsTotalLength => write!(f, "Header length exceeds total length"),
            ValidationError::TotalLengthExceedsBufferLength => write!(f, "Total length exceeds buffer length"),
            ValidationError::InvalidPacketLength => write!(f, "The packet length is invalid"),
            ValidationError::Default => write!(f, "Validation error!"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<IPv4AddressError> for ParsingError {
    fn from(error: IPv4AddressError) -> Self {
        ParsingError::IPv4AddressError(error)
    }
}

impl From<ValidationError> for ParsingError {
    fn from(error: ValidationError) -> Self {
        ParsingError::ValidationError(error)
    }
}

