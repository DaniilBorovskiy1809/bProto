//! Tunnel address pool.
//!
//! The server hands each client one IPv4 address from the tunnel subnet. The
//! network address, the server's own address (host offset 1) and the broadcast
//! address are never leased.

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// A lease allocator over one IPv4 prefix.
#[derive(Debug, Clone)]
pub struct IpPool {
    network: u32,
    /// Bits that address the host inside the prefix.
    host_bits: u32,
    /// `0..=u32::MAX` with every host bit set.
    host_mask: u32,
    used: HashSet<u32>,
}

impl IpPool {
    /// Build a pool from a network address and a prefix length.
    ///
    /// `network` should be the network address (`10.66.0.0` for `10.66.0.0/24`);
    /// any host bits present in it are masked off.
    #[must_use]
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        let host_bits = 32u32.saturating_sub(u32::from(prefix_len).min(32));
        let host_mask = if host_bits == 32 {
            u32::MAX
        } else if host_bits == 0 {
            0
        } else {
            (1u32 << host_bits) - 1
        };
        Self {
            network: u32::from(network) & !host_mask,
            host_bits,
            host_mask,
            used: HashSet::new(),
        }
    }

    /// The prefix as `a.b.c.d/len`.
    #[must_use]
    pub fn cidr(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), 32 - self.host_bits)
    }

    /// The server's own address (`host == 1`).
    #[must_use]
    pub fn server_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | 1)
    }

    fn host_of(&self, ip: Ipv4Addr) -> u32 {
        u32::from(ip) & self.host_mask
    }

    fn to_addr(&self, host: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.network | (host & self.host_mask))
    }

    /// Is `ip` inside this pool?
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & !self.host_mask) == self.network
    }

    /// Lease the next free address.
    ///
    /// Host offsets `0` (network), `1` (server) and the all-ones broadcast
    /// address are skipped. Returns `None` when the pool is exhausted.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Highest usable host offset: broadcast (host_mask) and the server (1)
        // are excluded, so the last usable host is host_mask - 1.
        let last = self.host_mask.saturating_sub(1);
        let mut host = 2;
        while host <= last {
            if !self.used.contains(&host) {
                self.used.insert(host);
                return Some(self.to_addr(host));
            }
            host += 1;
        }
        None
    }

    /// Return an address to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        if self.contains(ip) {
            self.used.remove(&self.host_of(ip));
        }
    }

    /// Reserve a specific address. Returns `false` if it is outside the pool or
    /// already leased.
    pub fn reserve(&mut self, ip: Ipv4Addr) -> bool {
        if !self.contains(ip) {
            return false;
        }
        self.used.insert(self.host_of(ip))
    }

    /// Number of live leases.
    #[must_use]
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// True when nothing is leased.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequentially_from_host_two() {
        let mut p = IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24);
        assert_eq!(p.allocate(), Some(Ipv4Addr::new(10, 66, 0, 2)));
        assert_eq!(p.allocate(), Some(Ipv4Addr::new(10, 66, 0, 3)));
        assert_eq!(p.len(), 2);
        assert_eq!(p.cidr(), "10.66.0.0/24");
        assert_eq!(p.server_addr(), Ipv4Addr::new(10, 66, 0, 1));
    }

    #[test]
    fn a_thirty_bit_prefix_yields_one_client_host() {
        // /30: .0 network, .1 server, .2 client, .3 broadcast
        let mut p = IpPool::new(Ipv4Addr::new(10, 0, 0, 0), 30);
        assert_eq!(p.allocate(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(p.allocate().is_none());
    }

    #[test]
    fn released_addresses_are_reusable() {
        let mut p = IpPool::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let a = p.allocate().unwrap();
        assert_eq!(a, Ipv4Addr::new(10, 0, 0, 2));
        p.release(a);
        assert_eq!(p.allocate(), Some(a));
    }

    #[test]
    fn contains_respects_the_prefix() {
        let p = IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24);
        assert!(p.contains(Ipv4Addr::new(10, 66, 0, 55)));
        assert!(!p.contains(Ipv4Addr::new(10, 67, 0, 1)));
    }

    #[test]
    fn reserve_rejects_out_of_pool_and_duplicates() {
        let mut p = IpPool::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert!(p.reserve(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(!p.reserve(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(!p.reserve(Ipv4Addr::new(192, 168, 9, 9)));
    }

    #[test]
    fn slash_zero_does_not_panic() {
        let mut p = IpPool::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        assert!(p.contains(Ipv4Addr::new(203, 0, 113, 9)));
        assert!(p.allocate().is_some());
    }
}
