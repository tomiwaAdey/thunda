// src/address/mac.rs

/// MAC Address support library
///
/// Provides abstraction over the MAC Address and various utility
/// functions that operate on MAC Addresses. It allows parsing, formatting,
/// and manipulation of MAC addresses with robust error handling for common
/// issues encountered
///
/// # Example
/// ```
/// ```

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
pub struct Mac(pub [u8; 6]);


impl std::fmt::Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Mac Address({})", self.to_string())
    }
}

// Allows using .parse() directly on string slices to create MacAddress instances.
// Mac::from_str("...")
impl std::str::FromStr for Mac {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        from_string(s)
    }
}

impl Mac {
    /// Construct a Mac address from bytes segments.
    pub fn new(
        seg0: u8,
        seg1: u8,
        seg2: u8,
        seg3: u8,
        seg4: u8,
        seg5: u8,
    ) -> Self {
        Mac([seg0, seg1, seg2, seg3, seg4, seg5])
    }

    /// Convert Mac ddress into a string.
    pub fn to_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    /// Convert Mac address into array of bytes
    pub fn to_bytes(&self) -> [u8; 6] {
        self.0
    }

    // Checks if the MAC address is multicast
    pub fn is_multicast(&self) -> bool {
        (self.0[0] & 0x01) != 0
    }

    // Checks if the MAC address is locally administered
    pub fn is_local(&self) -> bool {
        (self.0[0] & 0x02) != 0
    }

}


/// Construct a Mac address from a string
pub fn from_string(s: &str) -> Result<Mac, MacAddressParseError> {
    // Remove common MAC address delimiters to simplify parsing
    let clean_s = s.replace(&[':', '-', '.'][..], "");

    if clean_s.len() != 12 {
        return Err(MacAddressParseError::InvalidLength);
    }
    let mut mac_bytes = [0u8; 6];
    for (i, byte_str) in clean_s.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(byte_str).unwrap(), 16)
            .map_err(|_| MacAddressParseError::InvalidCharacter)?;
        mac_bytes[i] = byte;
    }

    Ok(Mac(mac_bytes))
}

/// Construct an Mac address from an array of bytes.
pub fn from_bytes(data: &[u8]) -> Result<Mac, MacAddressParseError> {
    if data.len() != 6 {
        return Err(MacAddressParseError::InvalidLength);
    }
    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(data);
    Ok(Mac(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONVERSION_TEST_CASES: [(&str, [u8; 6]); 3] = [
        ("00:00:00:00:00:00", [0, 0, 0, 0, 0, 0]),
        ("01:23:45:67:89:ab", [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
        ("ff:ff:ff:ff:ff:ff", [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    ];

    const INVALID_CONVERSION_TEST_CASES: [&str; 3] = [
        "00-00-00-00-00",
        "g1:22:33:44:55:66",
        "01:23:45:67:89:gh",
    ];


    #[test]
    fn test_new() {
        let mac = Mac::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        assert_eq!(mac, Mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
    }

    #[test]
    fn test_parse_valid() {
        for &(mac_str, expected) in &VALID_CONVERSION_TEST_CASES {
            let mac = from_string(mac_str).expect("Failed to parse MAC address");
            assert_eq!(mac, Mac(expected));
        }
    }

    #[test]
    fn test_to_bytes() {
        let mac = Mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let expected_bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert_eq!(mac.to_bytes(), expected_bytes);
    }

    #[test]
    fn test_to_string() {
        let mac = Mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let expected_str = "11:22:33:44:55:66";
        assert_eq!(mac.to_string(), expected_str);
    }

    #[test]
    fn batch_test_parse_invalid() {
        for &mac_str in INVALID_CONVERSION_TEST_CASES.iter() {
            assert!(from_string(mac_str).is_err());
        }
    }

    #[test]
    fn test_edge_cases() {
        let all_zeroes = "00:00:00:00:00:00";
        assert_eq!(from_string(all_zeroes).unwrap(), Mac([0, 0, 0, 0, 0, 0]));

        let all_ones = "ff:ff:ff:ff:ff:ff";
        assert_eq!(from_string(all_ones).unwrap(), Mac([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));

        let local_universal_boundary = "02:00:00:00:00:00";
        let mac = from_string(local_universal_boundary).unwrap();
        assert!(mac.is_local());
    }

    #[test]
    fn test_display_traits() {
        let mac = Mac::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01);
        assert_eq!(mac.to_string(), "de:ad:be:ef:00:01");

        let error = MacAddressParseError::InvalidCharacter;
        assert_eq!(format!("{}", error), "MAC address contains invalid hexadecimal characters");
    }



    #[test]
    fn test_parse_invalid_length() {
        let mac_str = "11:22:33:44:55";
        assert_eq!(from_string(mac_str), Err(MacAddressParseError::InvalidLength));
    }


    #[test]
    fn test_invalid_characters() {
        assert!(from_string("gg:gg:gg:gg:gg:gg").is_err());
    }

    #[test]
    fn test_unicast_multicast() {
        let unicast_mac = from_string("02:00:00:00:00:00").unwrap();
        let multicast_mac = from_string("01:00:00:00:00:00").unwrap();
        assert!(!unicast_mac.is_multicast());
        assert!(multicast_mac.is_multicast());
    }

    #[test]
    fn test_local_universal() {
        let local_mac = from_string("02:00:00:00:00:00").unwrap();
        let universal_mac = from_string("00:00:00:00:00:00").unwrap();
        assert!(local_mac.is_local());
        assert!(!universal_mac.is_local());
    }

    #[test]
    fn test_parse_invalid_format() {
        let mac_str = "11:22:33:GG:55:66";
        assert_eq!(from_string(mac_str), Err(MacAddressParseError::InvalidCharacter));
    }
}
