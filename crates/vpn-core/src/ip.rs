//! Minimal IP header inspection. Enough to route: we need the destination
//! address of an outbound packet and to recognise which family it is.

use std::net::{Ipv4Addr, Ipv6Addr};

/// True for an IPv4 packet (first nibble is 4).
#[must_use]
pub fn is_ipv4(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|b| b >> 4 == 4)
}

/// True for an IPv6 packet (first nibble is 6).
#[must_use]
pub fn is_ipv6(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|b| b >> 4 == 6)
}

/// Destination IPv4 address, or `None` if the packet is not a well-formed IPv4
/// header large enough to contain the field.
#[must_use]
pub fn dst_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if !is_ipv4(pkt) || pkt.len() < 20 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

/// Source IPv4 address, or `None`.
#[must_use]
pub fn src_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if !is_ipv4(pkt) || pkt.len() < 20 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Destination IPv6 address, or `None`.
#[must_use]
pub fn dst_ipv6(pkt: &[u8]) -> Option<Ipv6Addr> {
    if !is_ipv6(pkt) || pkt.len() < 40 {
        return None;
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Addr::from(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn parses_ipv4_addresses() {
        let p = v4([10, 0, 0, 1], [10, 66, 0, 7]);
        assert!(is_ipv4(&p));
        assert!(!is_ipv6(&p));
        assert_eq!(src_ipv4(&p), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(dst_ipv4(&p), Some(Ipv4Addr::new(10, 66, 0, 7)));
    }

    #[test]
    fn rejects_truncated_and_other_families() {
        assert_eq!(dst_ipv4(&[0x45, 0, 0]), None);
        assert_eq!(dst_ipv4(&[0x60; 40]), None);
        assert!(!is_ipv4(&[]));
    }

    #[test]
    fn parses_ipv6_destination() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(is_ipv6(&p));
        assert_eq!(
            dst_ipv6(&p),
            Some(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
    }
}
