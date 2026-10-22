//! Server configuration (`server.toml`).

use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vpn_core::config::from_hex;
use vpn_core::crypto::KEY_LEN;

/// Top-level server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP address the QUIC/bProto listener binds to. Use `:443` to look like QUIC.
    pub listen_addr: SocketAddr,
    /// Donor site whose identity we borrow.
    pub donor: DonorConfig,
    /// Routing tag key `K_tag` (hex, 32 bytes). Must match the clients and panel.
    pub tag_key: String,
    /// Static user table for MVP (the panel syncs this over the admin API).
    #[serde(default)]
    pub users: Vec<UserEntry>,
    /// TUN device settings.
    #[serde(default)]
    pub tun: TunConfig,
    /// Loopback admin API.
    #[serde(default)]
    pub admin: AdminConfig,
}

/// Donor site definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonorConfig {
    /// Donor hostname (SNI).
    pub sni: String,
    /// ALPN to offer; `h3` for a QUIC donor, `h2`/`http/1.1` for the TCP fallback.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Optional pinned address, to survive DNS poisoning.
    #[serde(default)]
    pub addr_override: Option<SocketAddr>,
    /// Health-check interval in seconds.
    #[serde(default = "default_health_secs")]
    pub health_interval_secs: u64,
}

fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

fn default_health_secs() -> u64 {
    30
}

/// One static user (MVP; the panel becomes the source of truth at stage 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntry {
    /// Numeric user id, matches the panel.
    pub id: u64,
    /// PSK in hex (32 bytes).
    pub psk: String,
}

/// TUN device settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Interface name.
    #[serde(default = "default_tun_name")]
    pub name: String,
    /// Server-side tunnel address.
    #[serde(default = "default_tun_addr")]
    pub address: String,
    /// Netmask/prefix.
    #[serde(default = "default_tun_netmask")]
    pub netmask: String,
    /// MTU; must match the client and stay <= 1280.
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    /// Outbound interface for NAT masquerade. When empty, NAT is skipped and
    /// clients can reach the server but not the internet.
    #[serde(default)]
    pub nat_interface: Option<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            address: default_tun_addr(),
            netmask: default_tun_netmask(),
            mtu: default_tun_mtu(),
            nat_interface: None,
        }
    }
}

fn default_tun_name() -> String {
    "bproto0".to_string()
}
fn default_tun_addr() -> String {
    "10.66.0.1".to_string()
}
fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}
fn default_tun_mtu() -> u16 {
    1280
}

/// Admin API settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Loopback listen address. Never expose this publicly.
    #[serde(default = "default_admin_addr")]
    pub listen_addr: SocketAddr,
    /// Static bearer token the panel presents.
    #[serde(default)]
    pub token: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_admin_addr(),
            token: String::new(),
        }
    }
}

fn default_admin_addr() -> SocketAddr {
    "127.0.0.1:9100".parse().expect("valid literal")
}

/// In-memory tag table. Owned by `vpn-core` because the server and the protocol
/// node both need it; re-exported here so the config module stays the one place
/// the binary imports from.
pub use vpn_core::tags::TagTable;

impl TunConfig {
    /// The configured tunnel address and prefix length.
    pub fn ipv4(&self) -> anyhow::Result<(std::net::Ipv4Addr, u8)> {
        let addr: std::net::Ipv4Addr = self.address.parse().map_err(|_| {
            anyhow::anyhow!("tun.address {:?} is not an IPv4 address", self.address)
        })?;
        Ok((addr, vpn_tun::dev::netmask_to_prefix(&self.netmask)))
    }

    /// The tunnel network address and prefix length (used to size the pool).
    pub fn network(&self) -> anyhow::Result<(std::net::Ipv4Addr, u8)> {
        let (addr, prefix) = self.ipv4()?;
        let host_mask = if prefix == 0 {
            0u32
        } else if prefix >= 32 {
            u32::MAX
        } else {
            (1u32 << (32 - u32::from(prefix))) - 1
        };
        let net = std::net::Ipv4Addr::from(u32::from(addr) & !host_mask);
        Ok((net, prefix))
    }
}

impl ServerConfig {
    /// Load and validate from a TOML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate invariants that would otherwise fail at runtime.
    pub fn validate(&self) -> anyhow::Result<()> {
        let key = from_hex(&self.tag_key).map_err(|e| anyhow::anyhow!("tag_key: {e}"))?;
        if key.len() != KEY_LEN {
            anyhow::bail!("tag_key must be 32 bytes (64 hex chars)");
        }
        if self.donor.sni.is_empty() {
            anyhow::bail!("donor.sni must not be empty");
        }
        if self.tun.mtu > vpn_core::packet::MAX_DATAGRAM as u16 {
            anyhow::bail!("tun.mtu must be <= {}", vpn_core::packet::MAX_DATAGRAM);
        }
        Ok(())
    }

    /// The tag key as raw bytes (validated in [`Self::validate`]).
    pub fn tag_key_bytes(&self) -> anyhow::Result<[u8; KEY_LEN]> {
        let v = from_hex(&self.tag_key).map_err(|e| anyhow::anyhow!("tag_key: {e}"))?;
        v.try_into()
            .map_err(|_| anyhow::anyhow!("tag_key must be 32 bytes"))
    }

    /// Build the in-memory tag table from the configured users.
    pub fn tag_table(&self) -> anyhow::Result<TagTable> {
        let key = self.tag_key_bytes()?;
        let users: Vec<(u64, String)> = self.users.iter().map(|u| (u.id, u.psk.clone())).collect();
        let table = TagTable::build(&key, &users).map_err(|e| anyhow::anyhow!("users: {e}"))?;
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_table_roundtrip_and_revocable() {
        let tag_key = [0x01u8; KEY_LEN];
        let cfg = ServerConfig {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            donor: DonorConfig {
                sni: "example.org".into(),
                alpn: default_alpn(),
                addr_override: None,
                health_interval_secs: 30,
            },
            tag_key: "01".repeat(32),
            users: vec![
                UserEntry {
                    id: 1,
                    psk: "11".repeat(32),
                },
                UserEntry {
                    id: 2,
                    psk: "22".repeat(32),
                },
            ],
            tun: TunConfig::default(),
            admin: AdminConfig::default(),
        };
        let mut t = cfg.tag_table().unwrap();
        assert_eq!(t.len(), 2);

        let tag = vpn_core::auth::compute_tag(&tag_key, 1);
        let (psk, user) = t.lookup(&tag).unwrap();
        assert_eq!(user, 1);
        assert_eq!(psk, [0x11u8; KEY_LEN]);

        t.remove(&tag_key, 1);
        assert!(t.lookup(&tag).is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn rejects_short_tag_key() {
        let cfg = ServerConfig {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            donor: DonorConfig {
                sni: "example.org".into(),
                alpn: default_alpn(),
                addr_override: None,
                health_interval_secs: 30,
            },
            tag_key: "abcd".into(),
            users: vec![],
            tun: TunConfig::default(),
            admin: AdminConfig::default(),
        };
        assert!(cfg.validate().is_err());
    }
}
