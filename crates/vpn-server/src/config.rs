//! Server configuration (`server.toml`).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use serde::{Deserialize, Serialize};
use vpn_core::config::from_hex;
use vpn_core::crypto::KEY_LEN;

/// Top-level server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP address the bProto datapath binds to.
    pub listen_addr: SocketAddr,
    /// Donor site whose identity we borrow on the masquerade port.
    pub donor: DonorConfig,
    /// Routing tag key `K_tag` (hex, 32 bytes). Must match the clients and panel.
    pub tag_key: String,
    /// Static user table, used when no panel is configured and as the bootstrap
    /// table before the first successful pull.
    #[serde(default)]
    pub users: Vec<UserEntry>,
    /// TUN device settings.
    #[serde(default)]
    pub tun: TunConfig,
    /// Control panel to pull keys from and push traffic to.
    #[serde(default)]
    pub panel: PanelConfig,
    /// The masquerade listener: browser-shaped handshakes, unknown ones relayed
    /// to the donor.
    #[serde(default)]
    pub masquerade: MasqueradeConfig,
}

/// Donor site definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonorConfig {
    /// Donor hostname (SNI).
    pub sni: String,
    /// ALPN to offer; `h3` for a QUIC donor.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
    /// Pinned address of the donor, to survive DNS poisoning.
    ///
    /// Required by the masquerade layer: deciding where to relay is the whole
    /// job, and a poisoned answer would send probes to the wrong place.
    #[serde(default)]
    pub addr: Option<SocketAddr>,
}

fn default_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

/// One static user.
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

/// The control panel this server reports to and pulls keys from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConfig {
    /// Base URL of the panel, e.g. `https://panel.example.com`.
    /// Empty disables the control plane; the server then uses `users` only.
    #[serde(default)]
    pub url: String,
    /// Bearer token matching the panel's `BPROTO_INTERNAL_TOKEN`.
    #[serde(default)]
    pub token: String,
    /// Name this server reports under. Defaults to the hostname.
    #[serde(default = "default_server_id")]
    pub server_id: String,
    /// How often to pull keys and push traffic, in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}

fn default_server_id() -> String {
    // Deliberately not a new dependency: the hostname is cosmetic, it only names
    // this server in the panel's traffic view.
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "bproto".to_string())
}

fn default_interval() -> u64 {
    30
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            server_id: default_server_id(),
            interval_secs: default_interval(),
        }
    }
}

/// The masquerade listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeConfig {
    /// Run the listener. Off by default: it needs a reachable donor.
    #[serde(default)]
    pub enabled: bool,
    /// UDP address to listen on; `0.0.0.0:443` to look like QUIC.
    #[serde(default = "default_masq_addr")]
    pub listen_addr: SocketAddr,
    /// Cap on concurrent relay flows, so one scanner cannot exhaust the server.
    #[serde(default = "default_max_relays")]
    pub max_relays: usize,
    /// Drop a relay flow after this much silence, in seconds.
    #[serde(default = "default_relay_idle")]
    pub relay_idle_secs: u64,
}

fn default_masq_addr() -> SocketAddr {
    "0.0.0.0:443".parse().expect("valid literal")
}
fn default_max_relays() -> usize {
    4096
}
fn default_relay_idle() -> u64 {
    60
}

impl Default for MasqueradeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_masq_addr(),
            max_relays: default_max_relays(),
            relay_idle_secs: default_relay_idle(),
        }
    }
}

impl TunConfig {
    /// The configured tunnel address and prefix length.
    pub fn ipv4(&self) -> anyhow::Result<(Ipv4Addr, u8)> {
        let addr: Ipv4Addr = self.address.parse().map_err(|_| {
            anyhow::anyhow!("tun.address {:?} is not an IPv4 address", self.address)
        })?;
        Ok((addr, vpn_tun::dev::netmask_to_prefix(&self.netmask)))
    }

    /// The tunnel network address and prefix length (used to size the pool).
    pub fn network(&self) -> anyhow::Result<(Ipv4Addr, u8)> {
        let (addr, prefix) = self.ipv4()?;
        let host_mask = if prefix == 0 {
            0u32
        } else if prefix >= 32 {
            u32::MAX
        } else {
            (1u32 << (32 - u32::from(prefix))) - 1
        };
        let net = Ipv4Addr::from(u32::from(addr) & !host_mask);
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

    /// Validate everything that would otherwise fail at runtime.
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
        if self.masquerade.enabled && self.donor.addr.is_none() {
            anyhow::bail!(
                "masquerade.enabled requires donor.addr: relaying to a name that DNS \
                 can poison would send probes to the wrong place"
            );
        }
        if !self.panel.url.is_empty() && self.panel.token.is_empty() {
            anyhow::bail!("panel.url is set but panel.token is empty");
        }
        Ok(())
    }

    /// The tag key as raw bytes (validated in [`Self::validate`]).
    pub fn tag_key_bytes(&self) -> anyhow::Result<[u8; KEY_LEN]> {
        let v = from_hex(&self.tag_key).map_err(|e| anyhow::anyhow!("tag_key: {e}"))?;
        v.try_into()
            .map_err(|_| anyhow::anyhow!("tag_key must be 32 bytes"))
    }

    /// Build the in-memory tag table from the static user list.
    pub fn tag_table(&self) -> anyhow::Result<vpn_core::TagTable> {
        let key = self.tag_key_bytes()?;
        let users: Vec<(u64, String)> = self.users.iter().map(|u| (u.id, u.psk.clone())).collect();
        let table =
            vpn_core::TagTable::build(&key, &users).map_err(|e| anyhow::anyhow!("users: {e}"))?;
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn donor() -> DonorConfig {
        DonorConfig {
            sni: "example.org".into(),
            alpn: default_alpn(),
            addr: None,
        }
    }

    fn base() -> ServerConfig {
        ServerConfig {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            donor: donor(),
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
            panel: PanelConfig::default(),
            masquerade: MasqueradeConfig::default(),
        }
    }

    #[test]
    fn tag_table_roundtrip_and_revocable() {
        let tag_key = [0x01u8; KEY_LEN];
        let mut t = base().tag_table().unwrap();
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
        let mut c = base();
        c.tag_key = "abcd".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn masquerade_requires_a_pinned_donor() {
        let mut c = base();
        c.masquerade.enabled = true;
        assert!(
            c.validate().is_err(),
            "an unpinned donor is a relay footgun"
        );

        c.donor.addr = Some("1.2.3.4:443".parse().unwrap());
        c.validate().unwrap();
    }

    #[test]
    fn a_panel_url_requires_a_token() {
        let mut c = base();
        c.panel.url = "https://panel.example.com".into();
        assert!(c.validate().is_err());
        c.panel.token = "secret".into();
        c.validate().unwrap();
    }

    #[test]
    fn defaults_leave_the_control_plane_and_masquerade_off() {
        let c = base();
        assert!(c.panel.url.is_empty());
        assert!(!c.masquerade.enabled);
        assert_eq!(c.panel.interval_secs, 30);
        assert!(!c.panel.server_id.is_empty());
    }

    #[test]
    fn the_pool_subnet_is_derived_from_the_tun_address() {
        let c = base();
        let (net, prefix) = c.tun.network().unwrap();
        assert_eq!(net, Ipv4Addr::new(10, 66, 0, 0));
        assert_eq!(prefix, 24);
    }
}
