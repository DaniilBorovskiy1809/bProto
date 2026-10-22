//! Dashboard aggregation and the internal reporting endpoint.
//!
//! Servers push **deltas** to `/internal/v1/sessions/report`:
//!
//! ```json
//! { "server_id": "de1",
//!   "sessions": [ { "tag": "0011223344556677", "started_at": 1700000000,
//!                   "ended_at": null, "bytes_rx": 4096, "bytes_tx": 2048,
//!                   "peer_ip": "198.51.100.7" } ] }
//! ```
//!
//! * `ended_at: null` — a live session; the panel upserts one open row per
//!   (key, server) and adds the deltas to it;
//! * `ended_at: <ts>` — the session is over; the open row is closed, and if
//!   there was none (the panel missed the start) a closed row is inserted;
//! * every byte also lands in `users.traffic_used_bytes`, which is what
//!   limits and the "reset traffic" button work on.
//!
//! Rows that a server stops reporting are closed after
//! [`STALE_SESSION_SECS`], so "online" cannot get stuck.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use subtle::ConstantTimeEq;

use crate::auth::Admin;
use crate::inbounds::inbound_rows;
use crate::{ApiError, App, PANEL_NAME, audit, now};

/// A key counts as online if its session was refreshed this recently.
pub(crate) const ONLINE_WINDOW_SECS: i64 = 120;
/// Open sessions not refreshed for this long are closed by the panel.
const STALE_SESSION_SECS: i64 = 300;
/// Demo traffic uses this `server_id` so it can be yanked in one statement.
const DEMO_SERVER: &str = "demo";

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

pub(crate) async fn overview(State(state): State<App>) -> Result<Json<Value>, ApiError> {
    let clients: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 0")
        .fetch_one(&state.db)
        .await?;
    let active_clients: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 0 AND status = 'active'")
            .fetch_one(&state.db)
            .await?;
    let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(&state.db)
        .await?;
    let inbounds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM inbounds")
        .fetch_one(&state.db)
        .await?;
    let active_inbounds: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM inbounds WHERE status = 'active'")
            .fetch_one(&state.db)
            .await?;
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys WHERE status = 'active'")
        .fetch_one(&state.db)
        .await?;
    let online: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT s.key_id) FROM sessions s \
         WHERE s.ended_at IS NULL AND s.updated_at > ?",
    )
    .bind(now() - ONLINE_WINDOW_SECS)
    .fetch_one(&state.db)
    .await?;
    let (rx, tx): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT SUM(bytes_rx), SUM(bytes_tx) FROM sessions")
            .fetch_one(&state.db)
            .await?;
    let traffic_used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(traffic_used_bytes), 0) FROM users WHERE is_admin = 0",
    )
    .fetch_one(&state.db)
    .await?;
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&state.db)
        .await?;
    let (rx24, tx24): (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT SUM(bytes_rx), SUM(bytes_tx) FROM sessions WHERE started_at >= ?")
            .bind(now() - 86_400)
            .fetch_one(&state.db)
            .await?;
    let remote_subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM remote_subs")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(json!({
        "panel": PANEL_NAME,
        "clients": clients,
        "active_clients": active_clients,
        "admins": admins,
        "inbounds": inbounds,
        "active_inbounds": active_inbounds,
        "active_keys": keys,
        "online": online,
        "sessions": sessions,
        "remote_subs": remote_subs,
        "traffic_used_bytes": traffic_used,
        "bytes_rx": rx.unwrap_or(0),
        "bytes_tx": tx.unwrap_or(0),
        "bytes_rx_24h": rx24.unwrap_or(0),
        "bytes_tx_24h": tx24.unwrap_or(0),
        "series_24h": series_24h(&state.db).await?,
    })))
}

/// Hourly rx/tx buckets for the last 24 hours, oldest first.
async fn series_24h(db: &SqlitePool) -> Result<Vec<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT (started_at / 3600) * 3600 AS bucket, SUM(bytes_rx) AS rx, SUM(bytes_tx) AS tx \
         FROM sessions WHERE started_at >= ? GROUP BY bucket ORDER BY bucket",
    )
    .bind(now() - 86_400)
    .fetch_all(db)
    .await?;

    let current_hour = (now() / 3600) * 3600;
    let mut series = Vec::with_capacity(24);
    for i in (0..24).rev() {
        let ts = current_hour - i * 3600;
        let (rx, tx) = rows
            .iter()
            .find(|r| r.get::<i64, _>("bucket") == ts)
            .map(|r| {
                (
                    r.get::<Option<i64>, _>("rx").unwrap_or(0),
                    r.get::<Option<i64>, _>("tx").unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));
        series.push(json!({ "ts": ts, "rx": rx, "tx": tx }));
    }
    Ok(series)
}

pub(crate) async fn by_inbound(State(state): State<App>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "inbounds": inbound_rows(&state.db).await? })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct LimitQuery {
    #[serde(default)]
    limit: Option<i64>,
}

pub(crate) async fn top_clients(
    State(state): State<App>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let rows = sqlx::query(
        "SELECT u.id, u.username, u.status, u.traffic_used_bytes, u.traffic_limit_bytes, \
                i.remark AS inbound_remark, u.expires_at, \
                (SELECT COUNT(*) FROM sessions s JOIN keys k ON k.id = s.key_id \
                  WHERE k.user_id = u.id AND s.ended_at IS NULL AND s.updated_at > ?) AS online \
         FROM users u LEFT JOIN inbounds i ON i.id = u.inbound_id \
         WHERE u.is_admin = 0 ORDER BY u.traffic_used_bytes DESC, u.id LIMIT ?",
    )
    .bind(now() - ONLINE_WINDOW_SECS)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let clients: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "username": r.get::<String, _>("username"),
                "status": r.get::<String, _>("status"),
                "inbound_remark": r.get::<Option<String>, _>("inbound_remark"),
                "traffic_used_bytes": r.get::<i64, _>("traffic_used_bytes"),
                "traffic_limit_bytes": r.get::<Option<i64>, _>("traffic_limit_bytes"),
                "expires_at": r.get::<Option<i64>, _>("expires_at"),
                "online": r.get::<i64, _>("online") > 0,
            })
        })
        .collect();
    Ok(Json(json!({ "clients": clients })))
}

pub(crate) async fn recent_sessions(
    State(state): State<App>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let rows = sqlx::query(
        "SELECT s.id, s.key_id, k.label AS key_label, u.username, s.server_id, s.started_at, \
                s.ended_at, s.bytes_rx, s.bytes_tx, s.peer_ip, s.updated_at \
         FROM sessions s JOIN keys k ON k.id = s.key_id JOIN users u ON u.id = k.user_id \
         ORDER BY s.updated_at DESC, s.id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "key_id": r.get::<i64, _>("key_id"),
                "key_label": r.get::<String, _>("key_label"),
                "username": r.get::<String, _>("username"),
                "server_id": r.get::<Option<String>, _>("server_id"),
                "started_at": r.get::<i64, _>("started_at"),
                "ended_at": r.get::<Option<i64>, _>("ended_at"),
                "bytes_rx": r.get::<i64, _>("bytes_rx"),
                "bytes_tx": r.get::<i64, _>("bytes_tx"),
                "peer_ip": r.get::<Option<String>, _>("peer_ip"),
                "updated_at": r.get::<Option<i64>, _>("updated_at"),
                "online": r.get::<Option<i64>, _>("ended_at").is_none()
                    && r.get::<Option<i64>, _>("updated_at").is_some_and(|t| t > now() - ONLINE_WINDOW_SECS),
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": entries })))
}

/// Cheap host facts for the dashboard. Linux-only; every read is best effort.
pub(crate) async fn system_info(State(state): State<App>) -> Result<Json<Value>, ApiError> {
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .map(|s| s as i64);
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| {
            s.split_whitespace()
                .take(3)
                .filter_map(|v| v.parse::<f64>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_value = |key: &str| -> Option<i64> {
        meminfo
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<i64>().ok())
            .map(|kb| kb * 1024)
    };
    let db_bytes = std::fs::metadata(state.db_path_hint())
        .ok()
        .map(|m| m.len());
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    Ok(Json(json!({
        "panel": PANEL_NAME,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": uptime,
        "load": load,
        "cpus": cpus,
        "mem_total": mem_value("MemTotal:"),
        "mem_available": mem_value("MemAvailable:"),
        "db_bytes": db_bytes,
        "clients_online": sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT key_id) FROM sessions WHERE ended_at IS NULL AND updated_at > ?",
        )
        .bind(now() - ONLINE_WINDOW_SECS)
        .fetch_one(&state.db)
        .await?,
    })))
}

pub(crate) async fn audit_log(
    State(state): State<App>,
    Query(q): Query<LimitQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = sqlx::query(
        "SELECT a.id, a.admin_id, u.username, a.action, a.target, a.at, a.ip FROM admin_audit a \
         LEFT JOIN users u ON u.id = a.admin_id ORDER BY a.id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "admin_id": r.get::<Option<i64>, _>("admin_id"),
                "admin": r.get::<Option<String>, _>("username"),
                "action": r.get::<String, _>("action"),
                "target": r.get::<Option<String>, _>("target"),
                "at": r.get::<i64, _>("at"),
                "ip": r.get::<Option<String>, _>("ip"),
            })
        })
        .collect();
    Ok(Json(json!({ "entries": entries })))
}

// ---------------------------------------------------------------------------
// Internal reporting (servers -> panel)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct SessionReport {
    #[serde(default)]
    server_id: Option<String>,
    sessions: Vec<ReportedSession>,
}

#[derive(Debug, Deserialize)]
struct ReportedSession {
    /// Routing tag as hex (8 bytes) — what the server actually holds.
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    key_id: Option<i64>,
    #[serde(default)]
    started_at: Option<i64>,
    #[serde(default)]
    ended_at: Option<i64>,
    #[serde(default)]
    bytes_rx: i64,
    #[serde(default)]
    bytes_tx: i64,
    #[serde(default)]
    peer_ip: Option<String>,
}

fn internal_token_ok(state: &App, headers: &HeaderMap) -> bool {
    let Some(expected) = state.internal_token.as_deref() else {
        return false;
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .unwrap_or("")
        .trim();
    !presented.is_empty()
        && expected.len() == presented.len()
        && bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
}

pub(crate) async fn report_sessions(
    State(state): State<App>,
    headers: HeaderMap,
    Json(body): Json<SessionReport>,
) -> Result<Json<Value>, ApiError> {
    if state.internal_token.is_none() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session reporting is disabled; set BPROTO_INTERNAL_TOKEN on the panel",
        ));
    }
    if !internal_token_ok(&state, &headers) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "bad internal token",
        ));
    }

    let server_id = body.server_id.unwrap_or_else(|| "unknown".into());
    let mut accepted = 0i64;
    let mut unknown: Vec<String> = Vec::new();
    let mut warned: std::collections::HashSet<String> = std::collections::HashSet::new();

    // A server that died mid-report leaves rows open; close the abandoned ones.
    sqlx::query(
        "UPDATE sessions SET ended_at = ?, updated_at = ? \
         WHERE ended_at IS NULL AND updated_at IS NOT NULL AND updated_at < ?",
    )
    .bind(now())
    .bind(now())
    .bind(now() - STALE_SESSION_SECS)
    .execute(&state.db)
    .await?;

    for s in &body.sessions {
        let Some((key_id, user_id)) = resolve_key(&state.db, s).await? else {
            let tag = s
                .tag
                .clone()
                .or_else(|| s.key_id.map(|k| k.to_string()))
                .unwrap_or_else(|| "?".into());
            if warned.insert(tag.clone()) {
                unknown.push(tag);
            }
            continue;
        };

        let start = s.started_at.unwrap_or_else(now);
        let open = sqlx::query(
            "SELECT id FROM sessions WHERE key_id = ? AND server_id = ? AND ended_at IS NULL",
        )
        .bind(key_id)
        .bind(&server_id)
        .fetch_optional(&state.db)
        .await?
        .map(|r| r.get::<i64, _>("id"));

        match (open, s.ended_at) {
            (Some(id), None) => {
                sqlx::query(
                    "UPDATE sessions SET bytes_rx = bytes_rx + ?, bytes_tx = bytes_tx + ?, \
                     peer_ip = COALESCE(?, peer_ip), updated_at = ? WHERE id = ?",
                )
                .bind(s.bytes_rx)
                .bind(s.bytes_tx)
                .bind(&s.peer_ip)
                .bind(now())
                .bind(id)
                .execute(&state.db)
                .await?;
            }
            (Some(id), Some(end)) => {
                sqlx::query(
                    "UPDATE sessions SET bytes_rx = bytes_rx + ?, bytes_tx = bytes_tx + ?, \
                     peer_ip = COALESCE(?, peer_ip), ended_at = ?, updated_at = ? WHERE id = ?",
                )
                .bind(s.bytes_rx)
                .bind(s.bytes_tx)
                .bind(&s.peer_ip)
                .bind(end)
                .bind(now())
                .bind(id)
                .execute(&state.db)
                .await?;
            }
            (None, ended) => {
                sqlx::query(
                    "INSERT INTO sessions (key_id, server_id, started_at, ended_at, bytes_rx, bytes_tx, peer_ip, updated_at) \
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(key_id)
                .bind(&server_id)
                .bind(start)
                .bind(ended)
                .bind(s.bytes_rx)
                .bind(s.bytes_tx)
                .bind(&s.peer_ip)
                .bind(now())
                .execute(&state.db)
                .await?;
            }
        }

        sqlx::query("UPDATE users SET traffic_used_bytes = traffic_used_bytes + ? WHERE id = ?")
            .bind(s.bytes_rx + s.bytes_tx)
            .bind(user_id)
            .execute(&state.db)
            .await?;
        if let Some(ip) = &s.peer_ip {
            sqlx::query("UPDATE keys SET last_seen_ip = ? WHERE id = ?")
                .bind(ip)
                .bind(key_id)
                .execute(&state.db)
                .await?;
        }
        accepted += 1;
    }

    Ok(Json(json!({ "accepted": accepted, "unknown": unknown })))
}

/// Map a reported session to a key. The server knows routing tags, not user ids.
async fn resolve_key(db: &SqlitePool, s: &ReportedSession) -> Result<Option<(i64, i64)>, ApiError> {
    if let Some(tag) = &s.tag {
        let bytes = hex::decode(tag.trim()).unwrap_or_default();
        if bytes.len() == 8 {
            let row = sqlx::query("SELECT id, user_id FROM keys WHERE tag = ?")
                .bind(&bytes[..])
                .fetch_optional(db)
                .await?;
            if let Some(row) = row {
                return Ok(Some((row.get("id"), row.get("user_id"))));
            }
        }
        return Ok(None);
    }
    if let Some(key_id) = s.key_id {
        let row = sqlx::query("SELECT id, user_id FROM keys WHERE id = ?")
            .bind(key_id)
            .fetch_optional(db)
            .await?;
        if let Some(row) = row {
            return Ok(Some((row.get("id"), row.get("user_id"))));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Demo data
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct DemoQuery {
    #[serde(default)]
    count: Option<i64>,
}

/// Fill the dashboard with plausible sessions. Everything written here carries
/// `server_id = 'demo'`, so `DELETE /api/stats/demo` removes exactly this data.
pub(crate) async fn seed_demo(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Query(q): Query<DemoQuery>,
) -> Result<Json<Value>, ApiError> {
    let count = q.count.unwrap_or(48).clamp(1, 500);
    let keys = sqlx::query(
        "SELECT k.id, k.user_id FROM keys k JOIN users u ON u.id = k.user_id \
         WHERE u.is_admin = 0 AND k.status = 'active' ORDER BY k.id",
    )
    .fetch_all(&state.db)
    .await?;
    if keys.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "no active keys to attach demo traffic to; create an inbound and a client first",
        ));
    }

    let mut inserted = 0i64;
    for i in 0..count {
        let k = &keys[(rand::random::<u32>() as usize) % keys.len()];
        let key_id: i64 = k.get("id");
        let user_id: i64 = k.get("user_id");
        let started = now() - (rand::random::<u32>() % 86_400) as i64;
        let duration = 60 + (rand::random::<u32>() % 3_600) as i64;
        let rx = (rand::random::<u32>() % 40_000_000) as i64;
        let tx = (rand::random::<u32>() % 90_000_000) as i64;
        let peer = format!("198.51.100.{}", 1 + (rand::random::<u8>() % 250));
        // Every fourth row stays open, so the dashboard shows live sessions.
        let ended = (i % 4 != 0).then_some(started + duration);

        sqlx::query(
            "INSERT INTO sessions (key_id, server_id, started_at, ended_at, bytes_rx, bytes_tx, peer_ip, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(key_id)
        .bind(DEMO_SERVER)
        .bind(started)
        .bind(ended)
        .bind(rx)
        .bind(tx)
        .bind(&peer)
        .bind(now())
        .execute(&state.db)
        .await?;

        sqlx::query("UPDATE users SET traffic_used_bytes = traffic_used_bytes + ? WHERE id = ?")
            .bind(rx + tx)
            .bind(user_id)
            .execute(&state.db)
            .await?;
        inserted += 1;
    }

    audit(
        &state.db,
        admin.user_id,
        "seed_demo",
        &inserted.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "inserted": inserted })))
}

pub(crate) async fn clear_demo(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
) -> Result<Json<Value>, ApiError> {
    // Take the demo bytes back out of the client counters before dropping rows.
    let rows = sqlx::query(
        "SELECT k.user_id AS user_id, SUM(s.bytes_rx + s.bytes_tx) AS bytes FROM sessions s \
         JOIN keys k ON k.id = s.key_id WHERE s.server_id = ? GROUP BY k.user_id",
    )
    .bind(DEMO_SERVER)
    .fetch_all(&state.db)
    .await?;
    for r in &rows {
        let bytes: i64 = r.get::<Option<i64>, _>("bytes").unwrap_or(0);
        sqlx::query(
            "UPDATE users SET traffic_used_bytes = MAX(0, traffic_used_bytes - ?) WHERE id = ?",
        )
        .bind(bytes)
        .bind(r.get::<i64, _>("user_id"))
        .execute(&state.db)
        .await?;
    }
    let deleted = sqlx::query("DELETE FROM sessions WHERE server_id = ?")
        .bind(DEMO_SERVER)
        .execute(&state.db)
        .await?
        .rows_affected();

    audit(
        &state.db,
        admin.user_id,
        "clear_demo",
        &deleted.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "deleted": deleted })))
}

/// Where the SQLite file lives, for the dashboard size readout. Best effort:
/// `BPROTO_DB` is a URL, and only the file-backed form has a size.
impl App {
    fn db_path_hint(&self) -> String {
        std::env::var("BPROTO_DB")
            .unwrap_or_else(|_| "sqlite://panel.db?mode=rwc".into())
            .trim_start_matches("sqlite://")
            .split('?')
            .next()
            .unwrap_or("panel.db")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_window_is_sane() {
        // Compile-time invariants: the window must be minutes, and stale rows
        // must be closed only after a key stopped counting as online.
        const _: () = assert!(ONLINE_WINDOW_SECS >= 60 && ONLINE_WINDOW_SECS <= 600);
        const _: () = assert!(STALE_SESSION_SECS > ONLINE_WINDOW_SECS);
    }

    #[tokio::test]
    async fn internal_token_must_match_exactly() {
        let state = App {
            db: sqlx::SqlitePool::connect_lazy("sqlite::memory:").unwrap(),
            tag_key: [0u8; 32],
            limiter: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            http: reqwest::Client::new(),
            internal_token: Some("secret".into()),
            allow_private_subs: false,
        };
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(internal_token_ok(&state, &h));
        h.insert(header::AUTHORIZATION, "Bearer secret2".parse().unwrap());
        assert!(!internal_token_ok(&state, &h));
        h.remove(header::AUTHORIZATION);
        assert!(!internal_token_ok(&state, &h));

        let disabled = App {
            internal_token: None,
            ..state
        };
        assert!(!internal_token_ok(&disabled, &HeaderMap::new()));
    }

    #[test]
    fn db_path_hint_strips_the_url() {
        // Only the shape matters here; the env var belongs to the process.
        let path = "sqlite:///data/panel.db?mode=rwc"
            .trim_start_matches("sqlite://")
            .split('?')
            .next()
            .unwrap();
        assert_eq!(path, "/data/panel.db");
    }

    #[test]
    fn demo_server_id_is_stable() {
        assert_eq!(DEMO_SERVER, "demo");
        assert_eq!(crate::random_token().len(), 64);
    }
}
