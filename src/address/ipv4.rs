// src/address/ipv4.rs

/// IPv4 Address support library
///
/// Provides abstraction over the IPv4 Address and various utility
/// functions that operate on IPv4 Addresses. It allows parsing, formatting,
/// and manipulation of IPv4 addresses with robust error handling for common
/// issues encountered
///
/// # Example
/// ```
/// ```


/// Size of IPv4 address in octets
pub const ADDR_SIZE: usize = 4;

/// The unspecified address.
pub const UNSPECIFIED: IPv4 = IPv4([0x00; ADDR_SIZE]);

/// The broadcast address.
pub const BROADCAST: IPv4 = IPv4([0xff; ADDR_SIZE]);

#[derive(Debug, PartialEq)]
pub enum IPv4AddressError {
    InvalidLength,
    InvalidFormat,
    InvalidCharacter,
    InvalidSegment,
}

impl std::fmt::Display for IPv4AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            IPv4AddressError::InvalidLength => write!(f, "IPv4 address must have exactly 4 octets"),
            IPv4AddressError::InvalidFormat => write!(f, "Invalid IPv4 address format"),
            IPv4AddressError::InvalidCharacter => write!(f, "IPv4 address contains invalid characters"),
            IPv4AddressError::InvalidSegment => write!(f, "IPv4 address segment out of range (0-255)"),
        }
    }
}

impl std::error::Error for IPv4AddressError {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IPv4(pub [u8; ADDR_SIZE]);

impl IPv4 {
    /// Construct an IPv4 address from octet segments.
    pub fn new(seg0: u8, seg1: u8, seg2: u8, seg3: u8) -> Self {
        IPv4([seg0, seg1, seg2, seg3])
    }

    pub fn to_string(&self) -> String {
        return format!("{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3]);
    }

    /// Return an IPv4 address as a single u32.
    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Return an IPv4 address as a sequence of octets, in big-endian.
    pub fn to_bytes(&self) -> [u8; ADDR_SIZE] {
        self.0
    }

    /// Query if the address is a unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast() && !self.is_multicast() && !self.is_unspecified()
    }

    /// Query if the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self.0 == [255, 255, 255, 255]
    }

    /// Query if the address is a multicast address.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    /// Query if the address is unspecified.
    pub fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    /// Query if the address is link-local.
    pub fn is_link_local(&self) -> bool {
        self.0[0] == 169 && self.0[1] == 254
    }

    /// Query if the address is loopback.
    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// Query if the ddress is a private address.
    pub fn is_private(&self) -> bool {
        // 10.0.0.0 to 10.255.255.255
        (self.0[0] == 10) ||
        // 172.16.0.0 to 172.31.255.255
        (self.0[0] == 172 && (self.0[1] >= 16 && self.0[1] <= 31)) ||
        // 192.168.0.0 to 192.168.255.255
        (self.0[0] == 192 && self.0[1] == 168)
    }

}

pub fn from_string(addr_str: &str) -> Result<IPv4, IPv4AddressError> {
    let parts: Vec<&str> = addr_str.split('.').collect();
    if parts.len() != 4 {
        return Err(IPv4AddressError::InvalidLength);
    }

    let mut addr_bytes = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u8>() {
            Ok(num) => addr_bytes[i] = num,
            Err(_) => return Err(IPv4AddressError::InvalidCharacter),
        }
    }

    Ok(IPv4(addr_bytes))
}

/// Construct an IPv4 address from a sequence of octets, in big-endian.
pub fn from_bytes(data: &[u8]) -> Result<IPv4, IPv4AddressError> {
    if data.len() != ADDR_SIZE {
        return Err(IPv4AddressError::InvalidLength);
    }
    let mut bytes = [0; ADDR_SIZE];
    bytes.copy_from_slice(data);
    Ok(IPv4(bytes))
}

/// Constructs an IPv4 address from a u32.
pub fn from_u32(addr: u32) -> IPv4 {
    IPv4(addr.to_be_bytes())
}

/// Display IPv4 address as text representation
impl std::fmt::Display for IPv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Debug display IPv4 address
impl std::fmt::Debug for IPv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::str::FromStr for IPv4 {
    type Err = IPv4AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return from_string(s);
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for IPv4 {
    fn from(addr: ::std::net::Ipv4Addr) -> IPv4 {
        IPv4(addr.octets())
    }
}

#[cfg(feature = "std")]
impl From<IPv4> for ::std::net::Ipv4Addr {
    fn from(IPv4(addr): IPv4) -> ::std::net::Ipv4Addr {
        addr.into()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for IPv4 {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "{=u8}.{=u8}.{=u8}.{=u8}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let ipv4 = IPv4::new(192, 168, 1, 1);
        assert_eq!(ipv4.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_from_str() {
        let ipv4: IPv4 = "192.168.1.1".parse().unwrap();
        assert_eq!(ipv4, IPv4::new(192, 168, 1, 1));
    }

    #[test]
    fn test_to_bytes() {
        let ipv4 = IPv4::new(192, 168, 1, 1);
        assert_eq!(ipv4.to_bytes(), [192, 168, 1, 1]);
    }
    #[test]
    fn test_is_unicast() {
        let ipv4 = IPv4::new(192, 168, 1, 1);
        assert!(ipv4.is_unicast());
    }

    #[test]
    fn test_is_broadcast() {
        let ipv4 = IPv4::new(255, 255, 255, 255);
        assert!(ipv4.is_broadcast());
        let ipv4_normal = IPv4::new(192, 168, 1, 1);
        assert!(!ipv4_normal.is_broadcast());
    }

    #[test]
    fn test_is_multicast() {
        let ipv4_multicast = IPv4::new(224, 0, 0, 1);
        assert!(ipv4_multicast.is_multicast());
        let ipv4_normal = IPv4::new(192, 168, 1, 1);
        assert!(!ipv4_normal.is_multicast());
    }

    #[test]
    fn test_is_unspecified() {
        let ipv4 = IPv4::new(0, 0, 0, 0);
        assert!(ipv4.is_unspecified());
        let ipv4_normal = IPv4::new(192, 168, 1, 1);
        assert!(!ipv4_normal.is_unspecified());
    }

    #[test]
    fn test_is_link_local() {
        let ipv4_link_local = IPv4::new(169, 254, 0, 1);
        assert!(ipv4_link_local.is_link_local());
        let ipv4_normal = IPv4::new(192, 168, 1, 1);
        assert!(!ipv4_normal.is_link_local());
    }

    #[test]
    fn test_is_loopback() {
        let ipv4_loopback = IPv4::new(127, 0, 0, 1);
        assert!(ipv4_loopback.is_loopback());
        let ipv4_normal = IPv4::new(192, 168, 1, 1);
        assert!(!ipv4_normal.is_loopback());
    }

    #[test]
    fn test_from_bytes_valid() {
        let ipv4 = from_bytes(&[192, 168, 1, 1]).unwrap();
        assert_eq!(ipv4, IPv4::new(192, 168, 1, 1));
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let ipv4_result = from_bytes(&[192, 168, 1]); // Too short
        assert!(ipv4_result.is_err());
    }

    #[test]
    fn test_display_format() {
        let ipv4 = IPv4::new(192, 168, 1, 1);
        assert_eq!(format!("{}", ipv4), "192.168.1.1");
    }

    #[test]
    fn test_to_u32() {
        let addr = IPv4::new(192, 168, 1, 1);
        let addr_u32 = addr.to_u32();
        assert_eq!(addr_u32, 0xC0A80101); // 192.168.1.1 in hexadecimal
    }

    #[test]
    fn test_from_u32() {
        let addr_u32 = 0xC0A80101; // 192.168.1.1 in hexadecimal
        let addr = from_u32(addr_u32);
        assert_eq!(addr, IPv4::new(192, 168, 1, 1));
    }

    #[test]
    fn test_is_private() {
        // Test for a private address in the 10.0.0.0/8 range
        let private_addr_10 = IPv4::new(10, 0, 0, 1);
        assert!(private_addr_10.is_private());

        // Test for a private address in the 172.16.0.0/12 range
        let private_addr_172 = IPv4::new(172, 16, 0, 1);
        assert!(private_addr_172.is_private());

        // Test for a private address in the 192.168.0.0/16 range
        let private_addr_192 = IPv4::new(192, 168, 0, 1);
        assert!(private_addr_192.is_private());

        // Test for a public address (not private)
        let public_addr = IPv4::new(8, 8, 8, 8); // Google DNS for example
        assert!(!public_addr.is_private());
    }
}
