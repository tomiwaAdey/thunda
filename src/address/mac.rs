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
///
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(pub u64);


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

// Allows using .parse() directly on string slices to create MacAddress instances.
// MacAddress::from_str("...")
impl std::str::FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

/// Creates a new MAC address from a u64 value.
pub fn new(address: u64) -> MacAddress {
    MacAddress(address)
}

/// Parses a hexadecimal MAC address string into a MacAddress struct.
pub fn parse(s: &str) -> Result<MacAddress, MacAddressParseError> {
    let normalized_str = s.replace(&[':', '-', '.'][..], "");
    if normalized_str.len() != 12 {
        return Err(MacAddressParseError::InvalidLength);
    }

    u64::from_str_radix(&normalized_str, 16)
        .map(MacAddress)
        .map_err(|_| MacAddressParseError::InvalidCharacter)
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

// Checks if the MAC address is multicast
pub fn is_multicast(mac: MacAddress) -> bool {
    (to_bytes(mac)[0] & 0x01) != 0
}

// Checks if the MAC address is locally administered
pub fn is_local(mac: MacAddress) -> bool {
    (to_bytes(mac)[0] & 0x02) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONVERSION_TEST_CASES: [(&str, u64); 3] = [
        ("00:00:00:00:00:00", 0x000000000000),
        ("01:23:45:67:89:ab", 0x0123456789ab),
        ("ff:ff:ff:ff:ff:ff", 0xffffffffffff),
    ];

    const INVALID_CONVERSION_TEST_CASES: [&str; 3] = [
        "00-00-00-00-00",
        "g1:22:33:44:55:66",
        "01:23:45:67:89:gh",
    ];

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
    fn batch_test_parse_valid() {
        for &(mac_str, expected) in VALID_CONVERSION_TEST_CASES.iter() {
            assert_eq!(parse(mac_str).unwrap(), MacAddress(expected));
        }
    }

    #[test]
    fn batch_test_parse_invalid() {
        for &mac_str in INVALID_CONVERSION_TEST_CASES.iter() {
            assert!(parse(mac_str).is_err());
        }
    }

    #[test]
    fn test_parsing_variations() {
        let variants = ["00-00-00-00-00-00", "00:00:00:00:00:00", "0000.0000.0000"];
        for &variant in variants.iter() {
            assert_eq!(parse(variant).unwrap(), MacAddress(0));
        }
    }


    #[test]
    fn test_parse_invalid_length() {
        let mac_str = "11:22:33:44:55";
        assert_eq!(parse(mac_str), Err(MacAddressParseError::InvalidLength));
    }


    #[test]
    fn test_invalid_characters() {
        assert!(parse("gg:gg:gg:gg:gg:gg").is_err());
    }

    #[test]
    fn test_unicast_multicast() {
        let unicast_mac = parse("02:00:00:00:00:00").unwrap();
        let multicast_mac = parse("01:00:00:00:00:00").unwrap();
        assert!(!is_multicast(unicast_mac));
        assert!(is_multicast(multicast_mac));
    }

    #[test]
    fn test_local_universal() {
        let local_mac = parse("02:00:00:00:00:00").unwrap();
        let universal_mac = parse("00:00:00:00:00:00").unwrap();
        assert!(is_local(local_mac));
        assert!(!is_local(universal_mac));
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
