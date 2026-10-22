//! The control plane: how this server talks to the panel.
//!
//! The panel (bUI) is the single source of truth. Two things flow over this
//! channel and no others:
//!
//! * **keys in** — the server pulls the active `user -> psk` list and rebuilds
//!   its in-memory [`TagTable`] from it. Revoking a key in the panel takes
//!   effect here within one poll interval. A server restart re-pulls; nothing is
//!   persisted here on purpose.
//! * **traffic out** — the server pushes per-session byte deltas so the panel's
//!   dashboard, "online" indicator and per-user traffic limits are driven by
//!   real traffic.
//!
//! The direction matters: the server **pulls** keys rather than having the panel
//! push them, because servers are typically behind NAT or a firewall with no
//! inbound route, while the panel is a normal HTTPS site. The panel never needs
//! to know a server's address.
//!
//! Every request is bearer-authenticated with `panel.token` and must go to the
//! panel's `/internal/*` namespace, which is only ever bound behind Caddy.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vpn_core::tags::TagTable;

use crate::config::PanelConfig;

/// One active key as the panel reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    /// Panel user id.
    pub user_id: u64,
    /// PSK, hex encoded, 32 bytes.
    pub psk: String,
}

/// Response of `GET /internal/v1/keys`.
#[derive(Debug, Clone, Deserialize)]
pub struct KeySnapshot {
    /// Every active key.
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
}

/// One session's traffic delta, in exactly the shape the panel's
/// `/internal/v1/sessions/report` accepts.
#[derive(Debug, Clone, Serialize)]
pub struct SessionDelta {
    /// Routing tag as hex (8 bytes). This is what the server actually holds, so
    /// it is the most robust identifier to send.
    pub tag: String,
    /// Unix seconds when the session was established.
    pub started_at: i64,
    /// Unix seconds when it ended; `None` for a live session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    /// Bytes received from this client since the last report.
    pub bytes_rx: i64,
    /// Bytes sent to this client since the last report.
    pub bytes_tx: i64,
    /// Public address the client is connecting from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
}

/// Body of `POST /internal/v1/sessions/report`.
#[derive(Debug, Clone, Serialize)]
pub struct SessionReport {
    /// Identifier for this server, so the panel can attribute traffic.
    pub server_id: String,
    /// Deltas for live and just-ended sessions.
    pub sessions: Vec<SessionDelta>,
}

/// A client for the panel's internal API.
#[derive(Debug, Clone)]
pub struct PanelClient {
    http: reqwest::Client,
    base: String,
    token: String,
    server_id: String,
}

impl PanelClient {
    /// Build a client from configuration. Returns `None` when no panel is
    /// configured, which leaves the server running on static keys.
    #[must_use]
    pub fn new(cfg: &PanelConfig) -> Option<Self> {
        if cfg.url.is_empty() {
            return None;
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?;
        Some(Self {
            http,
            base: cfg.url.trim_end_matches('/').to_string(),
            token: cfg.token.clone(),
            server_id: cfg.server_id.clone(),
        })
    }

    /// Identifier this server reports under.
    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Pull the active key list.
    ///
    /// A failure here is never fatal: the server keeps serving with whatever
    /// table it already has, and retries on the next interval. Losing contact
    /// with the panel must not disconnect everyone.
    pub async fn pull_keys(&self) -> anyhow::Result<Vec<KeyEntry>> {
        let resp = self
            .http
            .get(format!("{}/internal/v1/keys", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        let snapshot: KeySnapshot = resp.json().await?;
        Ok(snapshot.keys)
    }

    /// Push one batch of session deltas.
    pub async fn report(&self, batch: &SessionReport) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/internal/v1/sessions/report", self.base))
            .bearer_auth(&self.token)
            .json(batch)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

/// Rebuild a tag table from a freshly pulled key list.
///
/// Swapped in one shot behind the write lock, so a concurrent handshake either
/// sees the old table or the new one, never a half-built one.
pub fn apply_keys(
    target: &Arc<RwLock<TagTable>>,
    tag_key: &[u8; 32],
    keys: &[KeyEntry],
) -> anyhow::Result<usize> {
    let users: Vec<(u64, String)> = keys.iter().map(|k| (k.user_id, k.psk.clone())).collect();
    let table = TagTable::build(tag_key, &users).map_err(|e| anyhow::anyhow!("keys: {e}"))?;
    let n = table.len();
    match target.write() {
        Ok(mut t) => *t = table,
        Err(e) => *e.into_inner() = table,
    }
    Ok(n)
}

/// Format an IP for the panel, dropping the port and any IPv6 scope id.
#[must_use]
pub fn peer_ip_string(addr: IpAddr) -> String {
    match addr {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
            v6.to_ipv4_mapped().expect("checked").to_string()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_delta_omits_ended_at() {
        let d = SessionDelta {
            tag: "0011223344556677".into(),
            started_at: 1_700_000_000,
            ended_at: None,
            bytes_rx: 4096,
            bytes_tx: 2048,
            peer_ip: Some("198.51.100.7".into()),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert!(json.get("ended_at").is_none());
        assert_eq!(json["tag"], "0011223344556677");
        assert_eq!(json["bytes_rx"], 4096);
    }

    #[test]
    fn a_closed_delta_carries_ended_at() {
        let d = SessionDelta {
            tag: "00".repeat(8),
            started_at: 1,
            ended_at: Some(2),
            bytes_rx: 0,
            bytes_tx: 0,
            peer_ip: None,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["ended_at"], 2);
        assert!(json.get("peer_ip").is_none());
    }

    #[test]
    fn peer_ips_are_normalised() {
        assert_eq!(
            peer_ip_string("203.0.113.4".parse().unwrap()),
            "203.0.113.4"
        );
        // An IPv4-mapped IPv6 socket address must report as IPv4.
        let mapped: IpAddr = "::ffff:203.0.113.4".parse().unwrap();
        assert_eq!(peer_ip_string(mapped), "203.0.113.4");
    }
}
