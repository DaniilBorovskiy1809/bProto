//! The routing tag table: `tag -> (user, psk)`.
//!
//! The panel is the source of truth; servers hold this table in memory and
//! refresh it over the loopback admin API. Revocation is a `remove`, which takes
//! effect on the next packet.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::auth::{TAG_LEN, compute_tag};
use crate::config::from_hex;
use crate::crypto::KEY_LEN;

/// One user's authentication material.
#[derive(Debug, Clone)]
struct Entry {
    psk: [u8; KEY_LEN],
    user_id: u64,
    /// Address currently leased to this user, if any.
    ip: Option<Ipv4Addr>,
}

/// In-memory tag table.
#[derive(Debug, Default)]
pub struct TagTable {
    by_tag: HashMap<[u8; TAG_LEN], Entry>,
    by_ip: HashMap<Ipv4Addr, [u8; TAG_LEN]>,
}

impl TagTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a user list and the shared routing tag key.
    pub fn build(tag_key: &[u8; KEY_LEN], users: &[(u64, String)]) -> Result<Self, String> {
        let mut t = Self::new();
        for (id, psk_hex) in users {
            let psk = parse_psk(psk_hex)?;
            t.insert(tag_key, *id, psk);
        }
        Ok(t)
    }

    /// Insert or replace one user.
    pub fn insert(&mut self, tag_key: &[u8; KEY_LEN], user_id: u64, psk: [u8; KEY_LEN]) {
        let tag = compute_tag(tag_key, user_id);
        self.by_tag.insert(
            tag,
            Entry {
                psk,
                user_id,
                ip: None,
            },
        );
    }

    /// Remove a user (immediate revocation).
    pub fn remove(&mut self, tag_key: &[u8; KEY_LEN], user_id: u64) {
        let tag = compute_tag(tag_key, user_id);
        if let Some(e) = self.by_tag.remove(&tag)
            && let Some(ip) = e.ip
        {
            self.by_ip.remove(&ip);
        }
    }

    /// Look up the PSK and user id for a routing tag.
    #[must_use]
    pub fn lookup(&self, tag: &[u8; TAG_LEN]) -> Option<([u8; KEY_LEN], u64)> {
        self.by_tag.get(tag).map(|e| (e.psk, e.user_id))
    }

    /// Bind a tunnel address to a tag. Replaces any previous lease for that tag.
    pub fn bind_ip(&mut self, tag: &[u8; TAG_LEN], ip: Ipv4Addr) {
        if let Some(e) = self.by_tag.get_mut(tag) {
            if let Some(old) = e.ip.replace(ip) {
                self.by_ip.remove(&old);
            }
            self.by_ip.insert(ip, *tag);
        }
    }

    /// Release the address leased to a tag.
    pub fn release_ip(&mut self, tag: &[u8; TAG_LEN]) {
        if let Some(e) = self.by_tag.get_mut(tag)
            && let Some(ip) = e.ip.take()
        {
            self.by_ip.remove(&ip);
        }
    }

    /// Reverse map: which tag owns this tunnel address.
    #[must_use]
    pub fn tag_for_ip(&self, ip: Ipv4Addr) -> Option<[u8; TAG_LEN]> {
        self.by_ip.get(&ip).copied()
    }

    /// All currently leased addresses.
    #[must_use]
    pub fn leased_ips(&self) -> Vec<Ipv4Addr> {
        self.by_ip.keys().copied().collect()
    }

    /// Number of known users.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

/// Parse a 32-byte hex PSK.
pub fn parse_psk(hex: &str) -> Result<[u8; KEY_LEN], String> {
    from_hex(hex)?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_and_revoke() {
        let key = [0x01u8; KEY_LEN];
        let mut t = TagTable::new();
        t.insert(&key, 1, [0x11; KEY_LEN]);
        let tag = compute_tag(&key, 1);
        assert_eq!(t.lookup(&tag), Some(([0x11; KEY_LEN], 1)));

        t.remove(&key, 1);
        assert_eq!(t.lookup(&tag), None);
        assert!(t.is_empty());
    }

    #[test]
    fn ip_lease_is_bidirectional_and_releasable() {
        let key = [0x02u8; KEY_LEN];
        let mut t = TagTable::new();
        t.insert(&key, 5, [0x22; KEY_LEN]);
        let tag = compute_tag(&key, 5);

        t.bind_ip(&tag, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 2)), Some(tag));
        assert_eq!(t.leased_ips(), vec![Ipv4Addr::new(10, 66, 0, 2)]);

        // rebinding releases the old address
        t.bind_ip(&tag, Ipv4Addr::new(10, 66, 0, 3));
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 2)), None);
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 3)), Some(tag));

        // revocation releases both
        t.remove(&key, 5);
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 3)), None);
    }

    #[test]
    fn build_from_user_list() {
        let key = [0x03u8; KEY_LEN];
        let users = vec![(1u64, "11".repeat(32)), (2u64, "22".repeat(32))];
        let t = TagTable::build(&key, &users).unwrap();
        assert_eq!(t.len(), 2);
        assert!(TagTable::build(&key, &[(3, "zz".into())]).is_err());
    }
}
