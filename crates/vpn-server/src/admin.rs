//! Loopback admin API used by the control panel.
//!
//! Contract (see `proto/bproto.proto` and docs/PLAN.md section 6.3):
//!   * the panel owns the SQLite database and is the single source of truth;
//!   * on every key change it pushes an incremental snapshot `tag -> (user, psk)`
//!     to each server;
//!   * the server keeps that snapshot in memory only — a restart re-syncs;
//!   * the endpoint binds to loopback and requires a static bearer token, and is
//!     never exposed publicly.
//!
//! Stage 1 ships the shape of this module; the gRPC server is wired when the
//! panel lands. Keeping it a separate module means the token check and binding
//! policy live in one auditable place.

use std::sync::{Arc, RwLock};

use crate::config::{AdminConfig, TagTable};

/// Shared, hot-swappable tag table.
pub type SharedTags = Arc<RwLock<TagTable>>;

/// Handle the admin API until the future is cancelled.
pub async fn serve(cfg: AdminConfig, tags: SharedTags) -> anyhow::Result<()> {
    if cfg.token.is_empty() {
        anyhow::bail!("admin.token is empty; refusing to start the admin API");
    }
    if !cfg.listen_addr.ip().is_loopback() {
        anyhow::bail!(
            "admin.listen_addr {} is not loopback; refusing (never expose the admin API)",
            cfg.listen_addr
        );
    }

    tracing::info!(
        addr = %cfg.listen_addr,
        users = tags.read().map(|t| t.len()).unwrap_or(0),
        "admin API: stage 1 stub, gRPC server lands with the panel"
    );
    // TODO(stage 2): tonic server implementing:
    //   KeysSync(KeySnapshot)  -> replace the in-memory TagTable atomically
    //   ReportSessions(batch)  -> panel pulls stats
    //   Health()               -> liveness
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_empty_token() {
        let cfg = AdminConfig {
            listen_addr: "127.0.0.1:9100".parse().unwrap(),
            token: String::new(),
        };
        let tags: SharedTags = Arc::new(RwLock::new(TagTable::default()));
        assert!(serve(cfg, tags).await.is_err());
    }

    #[tokio::test]
    async fn refuses_non_loopback_bind() {
        let cfg = AdminConfig {
            listen_addr: "0.0.0.0:9100".parse().unwrap(),
            token: "secret".into(),
        };
        let tags: SharedTags = Arc::new(RwLock::new(TagTable::default()));
        assert!(serve(cfg, tags).await.is_err());
    }

    #[tokio::test]
    async fn loopback_with_token_is_accepted() {
        let cfg = AdminConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            token: "secret".into(),
        };
        let tags: SharedTags = Arc::new(RwLock::new(TagTable::default()));
        assert!(serve(cfg, tags).await.is_ok());
    }
}
