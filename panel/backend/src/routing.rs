//! Subscription routing policy, intentionally limited to capabilities Android applies.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoutingPolicy {
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub bypass_apps: Vec<String>,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self { routes: vec!["0.0.0.0/0".into()], dns: vec!["1.1.1.1".into()], bypass_apps: vec![] }
    }
}

impl RoutingPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.routes.is_empty() || self.routes.len() > 128 || self.dns.is_empty() || self.dns.len() > 128 || self.bypass_apps.len() > 128 {
            return Err("routes and dns require 1..128 entries; bypass_apps allows at most 128");
        }
        for route in &self.routes {
            let (ip, prefix) = route.split_once('/').ok_or("route must be IPv4 CIDR")?;
            let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| "invalid IPv4 route")?;
            let prefix: u32 = prefix.parse().map_err(|_| "invalid route prefix")?;
            if prefix > 32 { return Err("route prefix must be 0..32"); }
            let mask = if prefix == 32 { 0 } else { u32::MAX >> prefix };
            if u32::from(ip) & mask != 0 { return Err("route must use a network address"); }
        }
        for dns in &self.dns {
            dns.parse::<std::net::Ipv4Addr>().map_err(|_| "DNS must be an IPv4 literal")?;
        }
        for package in &self.bypass_apps {
            let parts: Vec<_> = package.split('.').collect();
            if parts.len() < 2 || parts.iter().any(|part| {
                part.is_empty() || !part.as_bytes()[0].is_ascii_alphabetic() || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }) { return Err("invalid application package"); }
        }
        Ok(())
    }
}
