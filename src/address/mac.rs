// src/address/mac.rs

/// MAC Address support library
///
/// Provides abstraction over the MAC Address and various utility
/// functions that operate on MAC Addresses.
///
/// # Example
/// ```
/// use thunda::address::mac::{parse, to_bytes, to_string};
///
/// let mac_str = "11:22:33:44:55:66";
/// let mac = parse(mac_str).expect("Failed to parse MAC address");
/// let mac_bytes = to_bytes(mac);
/// let mac_string = to_string(mac);
///
/// println!("MAC Address: {:?}", mac_bytes);
/// println!("MAC Address (String): {}", mac_string);
/// ```
///
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub u64);

#[derive(Debug, PartialEq)]
pub enum MacAddressParseError {
    InvalidLength,
    InvalidFormat,
    InvalidCharacter,
}

impl std::fmt::Display for MacAddressParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            MacAddressParseError::InvalidLength => write!(f, "MAC address must have exactly 6 octets"),
            MacAddressParseError::InvalidFormat => write!(f, "Each octet in a MAC address must be two hexadecimal digits"),
            MacAddressParseError::InvalidCharacter => write!(f, "MAC address contains invalid hexadecimal characters"),
        }
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", to_string(*self))
    }
}

impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "MacAddress({})", to_string(*self))
    }
}

/// Creates a new MAC address from a u64 value.
pub fn new(address: u64) -> MacAddress {
    MacAddress(address)
}

/// Parses a hexadecimal MAC address string into a MacAddress struct.
pub fn parse(s: &str) -> Result<MacAddress, MacAddressParseError> {
    let parts: Vec<&str> = s.split(':').collect();

    if parts.len() != 6 {
        return Err(MacAddressParseError::InvalidLength);
    }

    parts.iter()
        .try_fold(0u64, |acc, &part| {
            if part.len() != 2 {
                Err(MacAddressParseError::InvalidFormat)
            } else {
                u8::from_str_radix(part, 16)
                    .map_err(|_| MacAddressParseError::InvalidCharacter)
                    .map(|num| (acc << 8) | num as u64)
            }
        })
        .map(MacAddress)
}

 /// Convert MacAddress into array of bytes
pub fn to_bytes(mac: MacAddress) -> [u8; 6] {
    [
        ((mac.0 >> 40) & 0xFF) as u8,
        ((mac.0 >> 32) & 0xFF) as u8,
        ((mac.0 >> 24) & 0xFF) as u8,
        ((mac.0 >> 16) & 0xFF) as u8,
        ((mac.0 >> 8) & 0xFF) as u8,
        (mac.0 & 0xFF) as u8,
    ]
}

pub fn to_string(mac: MacAddress) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        ((mac.0 >> 40) & 0xFF),
        ((mac.0 >> 32) & 0xFF),
        ((mac.0 >> 24) & 0xFF),
        ((mac.0 >> 16) & 0xFF),
        ((mac.0 >> 8) & 0xFF),
        (mac.0 & 0xFF))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let address = 0x112233445566;
        let mac = new(address);
        assert_eq!(mac.0, address);
    }

    #[test]
    fn test_parse_valid() {
        let mac_str = "11:22:33:44:55:66";
        let mac = parse(mac_str).expect("Failed to parse MAC address");
        assert_eq!(mac, MacAddress(0x112233445566));
    }

    #[test]
    fn test_parse_invalid_length() {
        let mac_str = "11:22:33:44:55";
        assert_eq!(parse(mac_str), Err(MacAddressParseError::InvalidLength));
    }

    #[test]
    fn test_parse_invalid_format() {
        let mac_str = "11:22:33:GG:55:66";
        assert_eq!(parse(mac_str), Err(MacAddressParseError::InvalidCharacter));
    }

    #[test]
    fn test_to_bytes() {
        let mac = MacAddress(0x112233445566);
        let expected_bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert_eq!(to_bytes(mac), expected_bytes);
    }

    #[test]
    fn test_to_string() {
        let mac = MacAddress(0x112233445566);
        let expected_str = "11:22:33:44:55:66";
        assert_eq!(to_string(mac), expected_str);
    }

    #[test]
    fn display_mac_address_invalid_length() {
        let error: MacAddressParseError = MacAddressParseError::InvalidLength;
        assert_eq!(format!("{}", error), "MAC address must have exactly 6 octets");
    }

    #[test]
    fn display_mac_address_invalid_format() {
        let error: MacAddressParseError = MacAddressParseError::InvalidFormat;
        assert_eq!(format!("{}", error), "Each octet in a MAC address must be two hexadecimal digits");
    }
    #[test]
    fn display_mac_address_invalid_character() {
        let error: MacAddressParseError = MacAddressParseError::InvalidCharacter;
        assert_eq!(format!("{}", error), "MAC address contains invalid hexadecimal characters");
    }
}
