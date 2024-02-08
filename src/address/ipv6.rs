// src/address/ipv6.rs

/// IPv6 Address support library
///
/// Provides abstraction over the IPv6 Address and various utility
/// functions that operate on IPv6 Addresses. It allows parsing, formatting,
/// and manipulation of IPv6 addresses with robust error handling for common
/// issues encountered
///
/// # Example
/// ```
/// ```


/// Size of IPv6 adderess in octets.
///
/// [RFC 8200]: https://www.rfc-editor.org/rfc/rfc4291#section-2
pub const ADDR_SIZE: usize = 16;

/// The [unspecified address].
///
/// [unspecified address]: https://tools.ietf.org/html/rfc4291#section-2.5.2
pub const UNSPECIFIED: IPv6 = IPv6([0x00; ADDR_SIZE]);

/// The [loopback address].
///
/// [loopback address]: https://tools.ietf.org/html/rfc4291#section-2.5.3
pub const LOOPBACK: IPv6 = IPv6([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01,
]);

/// The prefix used in [IPv4-mapped addresses].
///
/// [IPv4-mapped addresses]: https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2
pub const IPV4_MAPPED_PREFIX: [u8; 12] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

#[derive(Debug, PartialEq)]
pub enum Ipv6AddressError {
    InvalidLength,
    InvalidFormat,
    InvalidCharacter,
    UnsupportedOperation,
}

impl std::fmt::Display for Ipv6AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Ipv6AddressError::InvalidLength => write!(f, "IPv6 address must have exactly 16 octets"),
            Ipv6AddressError::InvalidFormat => write!(f, "Invalid IPv6 address format"),
            Ipv6AddressError::InvalidCharacter => write!(f, "IPv6 address contains invalid characters"),
            Ipv6AddressError::UnsupportedOperation => write!(f, "Unsupported operation for IPv6 address"),
        }
    }
}

impl std::error::Error for Ipv6AddressError {}


/// A sixteen-octet (128 bits) IPv6 address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IPv6([u8; 16]);

/// Display IPv6 address as text representation
///
/// [Text Representation of Addresses]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.2
impl std::fmt::Display for IPv6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", to_string(self))
    }
}

/// Debug display IPv6 address
impl std::fmt::Debug for IPv6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", to_string(self))
    }
}


impl IPv6 {

    /// Construct an IPv6 address from word segments.
    // TODO
    // - Benchmark direct casting vs manual bitwise masking with 0xFF
    pub fn new(
        seg0: u16,
        seg1: u16,
        seg2: u16,
        seg3: u16,
        seg4: u16,
        seg5: u16,
        seg6: u16,
        seg7: u16,
    ) -> Self {
        IPv6([
            (seg0 >> 8) as u8,
            (seg0 & 0xFF) as u8, // explict as opposed to direct casting 'seg0 as u8'
            (seg1 >> 8) as u8,
            (seg1 & 0xFF) as u8,
            (seg2 >> 8) as u8,
            (seg2 & 0xFF) as u8,
            (seg3 >> 8) as u8,
            (seg3 & 0xFF) as u8,
            (seg4 >> 8) as u8,
            (seg4 & 0xFF) as u8,
            (seg5 >> 8) as u8,
            (seg5 & 0xFF) as u8,
            (seg6 >> 8) as u8,
            (seg6 & 0xFF) as u8,
            (seg7 >> 8) as u8,
            (seg7 & 0xFF) as u8,
        ])
    }
}

/// Construct an IPv6 address from a string
pub fn from_string(addr_str: &str) -> Result<IPv6, Ipv6AddressError> {
    addr_str.parse::<std::net::Ipv6Addr>()
        .map(|addr| IPv6(addr.octets()))
        .map_err(|_| Ipv6AddressError::InvalidFormat)
}

/// Construct an IPv6 address from an array of octets in big-endian
pub fn from_bytes(data: &[u8]) -> Result<IPv6, Ipv6AddressError> {
    if data.len() != 16 {
        return Err(Ipv6AddressError::InvalidLength);
    }

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(data);
    Ok(IPv6(bytes))
}

/// Return an IPv6 address as an array of octets in big-endian
pub fn to_bytes(addr: &IPv6) -> &[u8] {
    &addr.0
}

/// Construct an IPv6 address from an array of word segments in big-endian
pub fn from_segments(data: &[u16]) -> Result<IPv6, Ipv6AddressError> {
    if data.len() != 8 {
        return Err(Ipv6AddressError::InvalidLength);
    }
    let mut bytes = [0u8; 16];
    for (i, segment) in data.iter().enumerate() {
        let upper_byte = (segment >> 8) as u8;
        let lower_byte = (segment & 0xFF) as u8;
        bytes[i * 2] = upper_byte;
        bytes[i * 2 + 1] = lower_byte;
    }
    Ok(IPv6(bytes))
}
/// Return an IPv6 address as an array of word segments
pub fn to_segments(addr: &IPv6) -> [u16; 8]{
    let mut segments = [0u16; 8];
    for (i, chunk) in addr.0.chunks(2).enumerate() {
        let upper_word = (chunk[0] as u16) << 8;
        segments[i] = upper_word | (chunk[1] as u16) as u16;
    }
    segments
}

/// Return an IPv6 address as a zero compressed string
///
/// [Zero compressed notation]: https://tools.ietf.org/html/rfc4291#section-2.2
pub fn to_string(addr: &IPv6) -> String {

    if is_ipv4_mapped(addr) {
        return format!(
            "::ffff:{}.{}.{}.{}",
            addr.0[12],
            addr.0[13],
            addr.0[14],
            addr.0[15]
        );
    }

    enum State {
        Head,
        HeadBody,
        Tail,
        TailBody,
    }
    let segments = to_segments(addr);
    let mut state = State::Head;
    let mut result = String::new();
    for segment in segments.iter() {
        match (*segment, &state) {
            (0, State::Head) | (0, State::HeadBody) => {
                result.push_str("::");
                state = State::Tail
            }
            (0, State::Tail) => {}, // continue
            (_, State::Head) => {
                result.push_str(&format!("{:x}", segment));
                state = State::HeadBody
            }
            (_, State::Tail) => {
                result.push_str(&format!("{:x}", segment));
                state = State::TailBody
            }
            (_, State::HeadBody) | (_, State::TailBody) => {
                result.push_str(&format!(":{:x}", segment));
            }
        };
    }

    result
}

// Cpnvert an IPv4 mapped IPv6 address to an IPv4 mapped
pub fn to_ipv4(_addr: IPv6) {
    todo!()
}

/// Query if the IPv6 address is a unicast address.
pub fn is_unicast(addr: &IPv6) -> bool {
    !is_multicast(addr) && !is_unspecified(addr)
}

/// Query if the IPv6 address is a [global unicast address].
///
/// [global unicast address]: https://datatracker.ietf.org/doc/html/rfc3587
pub fn is_global_unicast(addr: &IPv6) -> bool {
    (addr.0[0] >> 5) == 0b001
}

/// Query if the IPv6 address is a multicast address.
pub fn is_multicast(addr: &IPv6) -> bool {
    addr.0[0] == 0xFF
}

/// Query if the IPv6 address is the [unspecified address].
pub fn is_unspecified(addr: &IPv6) -> bool {
    addr.0 == UNSPECIFIED.0
}

/// Query if the IPv6 address is a link local address.
pub fn is_link_local(addr: &IPv6) -> bool {
    addr.0[0] == 0b1111_1110 && (addr.0[1] & 0b1100_0000) == 0b1000_0000
}

/// Query if the IPv6 address is a [Unique Local Address] (ULA).
///
/// [Unique Local Address]: https://tools.ietf.org/html/rfc4193
pub fn is_private(addr: &IPv6) -> bool {
    (addr.0[0] & 0b1111_1110) == 0b1111_1100
}

/// Query whether the IPv6 address is the [loopback address].
pub fn is_loopback(addr: &IPv6) -> bool {
    addr.0 == LOOPBACK.0
}

/// Query whether the IPv6 address is IPv4 mapped.
pub fn is_ipv4_mapped(addr: &IPv6) -> bool {
    addr.0[..12] == IPV4_MAPPED_PREFIX
}

/// Checks if an IPv6 address is a solicited-node multicast address.
pub fn is_solicited_node_multicast(addr: &IPv6) -> bool {
    addr.0[0] == 0xff && addr.0[1] == 0x02 && addr.0[11] == 0x01 &&
    addr.0[12] == 0xff && (addr.0[13] & addr.0[14] & addr.0[15]) != 0x00
}

/// Checks if an IPv6 address is a Teredo tunneling address.
pub fn is_teredo_tunneling(addr: &IPv6) -> bool {
    addr.0[0] == 0x20 && addr.0[1] == 0x01 && addr.0[2] == 0x00 && addr.0[3] == 0x00
}

/// Checks if an IPv6 address is a 6to4 tunneling address.
pub fn is_6to4_tunneling(addr: &IPv6) -> bool {
    addr.0[0] == 0x20 && addr.0[1] == 0x02
}

// Helper function to mask an IPv6 address
pub fn mask(_addr: &IPv6, _mask: u8) -> [u8; ADDR_SIZE]{
    todo!()
}

#[cfg(feature = "std")]
impl From<std::net::Ipv6Addr> for IPv6 {
    fn from(addr: std::net::Ipv6Addr) -> IPv6 {
        IPv6(addr.octets())
    }
}

#[cfg(feature = "std")]
impl From<IPv6> for std::net::Ipv6Addr {
    fn from(IPv6(addr): IPv6) -> std::net::Ipv6Addr {
        addr.into()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checks() {
        let lla: IPv6 = IPv6::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let ula: IPv6 = IPv6::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
        let gua: IPv6 = IPv6::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 1);

        // Multicast
        // Link Local Address
        assert!(is_link_local(&lla));
        assert!(!is_unspecified(&lla));
        assert!(!is_loopback(&lla));
        assert!(!is_multicast(&lla));
        assert!(!is_global_unicast(&lla));
        assert!(!is_private(&lla));

        // Loopback
        assert!(is_loopback(&LOOPBACK));
        assert!(!is_link_local(&LOOPBACK));
        assert!(!is_unspecified(&LOOPBACK));
        assert!(!is_multicast(&LOOPBACK));
        assert!(!is_global_unicast(&LOOPBACK));
        assert!(!is_private(&LOOPBACK));

        // Unique local
        assert!(is_private(&ula));
        assert!(!is_link_local(&ula));
        assert!(!is_unspecified(&ula));
        assert!(!is_loopback(&ula));
        assert!(!is_multicast(&ula));
        assert!(!is_global_unicast(&ula));

        // Global unicast
        assert!(is_global_unicast(&gua));
        assert!(!is_private(&gua));
        assert!(!is_link_local(&gua));
        assert!(!is_unspecified(&gua));
        assert!(!is_loopback(&gua));
        assert!(!is_multicast(&gua));


        // Unspecified
        assert!(is_unspecified(&UNSPECIFIED));
        assert!(!is_loopback(&UNSPECIFIED));
        assert!(!is_link_local(&UNSPECIFIED));
        assert!(!is_multicast(&UNSPECIFIED));
        assert!(!is_global_unicast(&UNSPECIFIED));
        assert!(!is_private(&UNSPECIFIED));

    }

    // Text representation
    #[test]
    fn display_standard_ipv6() {
        let addr = IPv6::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0x8a2e, 0x0370, 0x7334);
        assert_eq!(to_string(&addr), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn display_zero_compressed_ipv6() {
        let addr = IPv6::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        assert_eq!(to_string(&addr), "fe80::1");
    }

    #[test]
    fn display_loopback_address() {
        assert_eq!(LOOPBACK.to_string(), "::1");
    }

    #[test]
    fn display_unspecified_address() {
        assert_eq!(UNSPECIFIED.to_string(), "::");
    }

    #[test]
    fn display_ipv4_mapped_ipv6() {
        let addr = IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]);
        assert_eq!(to_string(&addr), "::ffff:192.168.1.1");
    }

    #[test]
    fn display_unique_local_address() {
        let addr = IPv6::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x1);
        assert_eq!(to_string(&addr), "fd00::1");
    }

    #[test]
    fn display_link_local_address() {
        let addr = IPv6::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        assert_eq!(to_string(&addr), "fe80::1");
    }

    #[test]
    fn display_full_ipv6() {
        let addr = IPv6::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);
        assert_eq!(to_string(&addr), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    }

    #[test]
    fn test_parse_valid_ipv6() {
        let valid_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        assert_eq!(
            from_string(valid_ipv6).unwrap(),
            IPv6([0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34])
        );
    }

    // Formatting
    #[test]
    fn test_address_format() {
        let link_local_all_nodes = IPv6::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            "ff02::1",
            format!("{}", link_local_all_nodes)
        );

        let link_local_addr = IPv6::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            "fe80::1",
            format!("{}", link_local_addr)
        );

        // Complex custom IPv6 address
        assert_eq!(
            "fe80::7f00:0:1",
            format!(
                "{}",
                IPv6::new(0xfe80, 0, 0, 0, 0, 0x7f00, 0, 1)
            )
        );

        // unspecified
        assert_eq!(
            "::",
            format!("{}", IPv6([0; 16]))
        );

        //  loopback
        assert_eq!(
            "::1",
            format!("{}", IPv6::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    // init

    #[test]
    fn test_new_ipv6() {
        // Define the segments of an IPv6 address
        let seg0: u16 = 0x2001;
        let seg1: u16 = 0x0db8;
        let seg2: u16 = 0x85a3;
        let seg3: u16 = 0x0000;
        let seg4: u16 = 0x0000;
        let seg5: u16 = 0x8a2e;
        let seg6: u16 = 0x0370;
        let seg7: u16 = 0x7334;

        let ipv6_addr = IPv6::new(seg0, seg1, seg2, seg3, seg4, seg5, seg6, seg7);

        let expected_addr = IPv6([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]);
        assert_eq!(ipv6_addr, expected_addr);
    }

    #[test]
    fn test_parse_invalid_ipv6() {
        let invalid_ipv6 = "2001:0db8::85a3::7334";
        assert!(from_string(invalid_ipv6).is_err());
    }

    #[test]
    fn test_ipv6_to_string() {
        let ipv6 = IPv6([0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34]);
        assert_eq!(to_string(&ipv6), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn test_from_bytes_valid() {
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34];
        assert_eq!(from_bytes(&bytes).unwrap(), IPv6(bytes));
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let bytes = [0x20, 0x01]; // Invalid length
        assert_eq!(from_bytes(&bytes), Err(Ipv6AddressError::InvalidLength));
    }

    #[test]
    fn test_from_segments_invalid_length() {
        let segments_short = [0x2001, 0x0db8]; // Invalid length: only 2 segments
        assert_eq!(
            from_segments(&segments_short),
            Err(Ipv6AddressError::InvalidLength)
        );

        let segments_long = [
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334, 0x1234
        ];
        assert_eq!(
            from_segments(&segments_long),
            Err(Ipv6AddressError::InvalidLength)
        );
    }

    #[test]
    fn test_to_bytes() {
        let ipv6_addr = IPv6([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]);
        let bytes = to_bytes(&ipv6_addr);
        let expected_bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ];
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_from_segments() {
        let segments: [u16; 8] = [0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334];

        let ipv6_addr = from_segments(&segments).unwrap();

        let expected_addr = IPv6([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]);

        assert_eq!(ipv6_addr, expected_addr);
    }

    #[test]
    fn test_to_segments() {
        let ipv6_addr = IPv6([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]);

        let segments = to_segments(&ipv6_addr);

        let expected_segments: [u16; 8] = [0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334];

        assert_eq!(segments, expected_segments);
    }

    #[test]
    fn test_from_string() {
        let ipv6_str = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let expected_ipv6 = IPv6([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ]);
        let result = from_string(ipv6_str).unwrap();
        assert_eq!(result, expected_ipv6);
    }
}
