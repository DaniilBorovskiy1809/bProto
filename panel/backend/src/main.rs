//! bUI — the bProto control panel backend.
//!
//! The panel is the single source of truth: inbounds, clients, keys and
//! subscriptions live in SQLite here, the servers only hold an in-memory
//! snapshot and report traffic back (docs/PLAN.md section 6.3).
//!
//! Modules:
//!   * [`auth`]     — admin login, opaque sessions, admin accounts, rate limits;
//!   * [`inbounds`] — inbounds and the clients/keys inside them;
//!   * [`subs`]     — client subscriptions and remote subscription sources;
//!   * [`stats`]    — dashboard aggregation and the internal report endpoint;
//!   * [`keys`]     — key material: PSK, routing tag, config URI, QR.
//!
//! Security posture (panel/README.md): argon2id, opaque server-side sessions,
//! bearer-authenticated mutating routes, rate-limited login and subscription
//! endpoints, and HTTPS terminated by Caddy in front — the panel itself must
//! never be exposed on a public port without it.

#![forbid(unsafe_code)]

mod auth;
mod inbounds;
mod keys;
mod stats;
mod subs;

#[cfg(test)]
mod api_tests;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

/// Panel name, shown in the UI and in subscription profiles.
pub(crate) const PANEL_NAME: &str = "bUI";

/// Setting that remembers which `K_tag` the stored routing tags belong to.
const TAG_FINGERPRINT_SETTING: &str = "tag_key_fingerprint";

/// Shared application state.
#[derive(Clone)]
pub(crate) struct App {
    pub(crate) db: SqlitePool,
    /// Routing tag key `K_tag` (32 bytes). Shared with the servers.
    pub(crate) tag_key: [u8; 32],
    /// Login/subscription token buckets, keyed by `ip:…`/`user:…`.
    pub(crate) limiter: auth::Limiter,
    /// HTTP client used to pull remote subscriptions.
    pub(crate) http: reqwest::Client,
    /// Bearer token the servers present on `/internal/*`; `None` disables it.
    pub(crate) internal_token: Option<String>,
    /// Lab escape hatch: allow remote subscriptions on private addresses.
    pub(crate) allow_private_subs: bool,
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// 32 random bytes, hex encoded. Sessions and subscription ids.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    hex::encode(bytes)
}

pub(crate) fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

pub(crate) fn verify_password(pw: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Append an admin action to the audit log. Never fails the request.
pub(crate) async fn audit(db: &SqlitePool, admin_id: i64, action: &str, target: &str, ip: &str) {
    let _ = sqlx::query(
        "INSERT INTO admin_audit (admin_id, action, target, at, ip) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(admin_id)
    .bind(action)
    .bind(target)
    .bind(now())
    .bind(ip)
    .execute(db)
    .await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let db_url = std::env::var("BPROTO_DB").unwrap_or_else(|_| "sqlite://panel.db?mode=rwc".into());
    let listen: SocketAddr = std::env::var("BPROTO_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let tag_key_hex = std::env::var("BPROTO_TAG_KEY")
        .map_err(|_| anyhow::anyhow!("BPROTO_TAG_KEY must be set (32 bytes hex)"))?;
    let tag_key: [u8; 32] = hex::decode(tag_key_hex.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("BPROTO_TAG_KEY must be 32 bytes"))?;
    let internal_token = std::env::var("BPROTO_INTERNAL_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty());
    let allow_private_subs = std::env::var("BPROTO_ALLOW_PRIVATE_SUBS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // WAL and foreign keys are per-connection settings, so they belong on every
    // pooled connection: a PRAGMA inside a migration would only configure the
    // one connection that ran it (and SQLite refuses `journal_mode = WAL` from
    // inside sqlx's migration transaction).
    let db_options: SqliteConnectOptions = db_url
        .parse::<SqliteConnectOptions>()?
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(db_options)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;
    bootstrap_admin(&db).await?;
    backfill_sub_ids(&db).await?;
    sync_tags(&db, &tag_key).await?;

    let http = reqwest::Client::builder()
        .user_agent(concat!("bUI/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;

    let app = App {
        db,
        tag_key,
        limiter: Arc::new(Mutex::new(std::collections::HashMap::new())),
        http,
        internal_token,
        allow_private_subs,
    };

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, panel = PANEL_NAME, "listening (put Caddy/HTTPS in front)");
    axum::serve(listener, router(app)).await?;
    Ok(())
}

/// Build the full router. Separate from `main` so tests can mount it.
fn router(app: App) -> Router {
    let public = Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(auth::login))
        .route("/sub/{sub_id}", get(subs::serve_sub))
        .route("/internal/v1/sessions/report", post(stats::report_sessions));

    let protected = Router::new()
        // --- account ---
        .route("/api/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/password", post(auth::change_password))
        .route(
            "/api/admins",
            get(auth::list_admins).post(auth::create_admin),
        )
        .route("/api/admins/{id}", delete(auth::delete_admin))
        .route(
            "/api/admins/{id}/password",
            post(auth::reset_admin_password),
        )
        // --- inbounds ---
        .route(
            "/api/inbounds",
            get(inbounds::list_inbounds).post(inbounds::create_inbound),
        )
        .route(
            "/api/inbounds/{id}",
            patch(inbounds::update_inbound).delete(inbounds::delete_inbound),
        )
        .route(
            "/api/inbounds/{id}/reset-traffic",
            post(inbounds::reset_inbound_traffic),
        )
        .route(
            "/api/inbounds/{id}/clients",
            get(inbounds::list_clients_of_inbound).post(inbounds::create_client_of_inbound),
        )
        // --- clients ---
        .route(
            "/api/users",
            get(inbounds::list_clients).post(inbounds::create_client),
        )
        .route(
            "/api/users/{id}",
            get(inbounds::get_client)
                .patch(inbounds::update_client)
                .delete(inbounds::delete_client),
        )
        .route(
            "/api/users/{id}/reset-traffic",
            post(inbounds::reset_client_traffic),
        )
        .route(
            "/api/users/{id}/keys",
            get(inbounds::list_keys).post(inbounds::create_key),
        )
        .route(
            "/api/users/{id}/remote-subs",
            get(subs::list_client_remote_subs).post(subs::attach_remote_sub),
        )
        .route(
            "/api/users/{id}/remote-subs/{remote_sub_id}",
            delete(subs::detach_remote_sub),
        )
        .route("/api/keys/{id}", delete(inbounds::delete_key))
        .route("/api/keys/{id}/config", get(inbounds::key_config))
        .route("/api/keys/{id}/revoke", post(inbounds::revoke_key))
        // --- subscriptions ---
        .route("/api/subscriptions", get(subs::list_subscriptions))
        .route(
            "/api/subscriptions/settings",
            get(subs::get_sub_settings).patch(subs::update_sub_settings),
        )
        .route(
            "/api/remote-subs",
            get(subs::list_remote_subs).post(subs::create_remote_sub),
        )
        .route(
            "/api/remote-subs/{id}",
            patch(subs::update_remote_sub).delete(subs::delete_remote_sub),
        )
        .route(
            "/api/remote-subs/{id}/refresh",
            post(subs::refresh_remote_sub),
        )
        .route(
            "/api/remote-subs/{id}/entries",
            get(subs::remote_sub_entries),
        )
        // --- stats / audit ---
        .route("/api/stats/overview", get(stats::overview))
        .route("/api/stats/inbounds", get(stats::by_inbound))
        .route("/api/stats/top", get(stats::top_clients))
        .route("/api/stats/sessions", get(stats::recent_sessions))
        .route("/api/stats/system", get(stats::system_info))
        .route(
            "/api/stats/demo",
            post(stats::seed_demo).delete(stats::clear_demo),
        )
        .route("/api/audit", get(stats::audit_log))
        .route_layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::require_admin,
        ));

    public
        .merge(protected)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(256 * 1024))
        .with_state(app)
}

async fn health() -> &'static str {
    "ok"
}

/// Create a default admin if the table is empty, so a fresh install is usable.
async fn bootstrap_admin(db: &SqlitePool) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(db)
        .await?;
    if count > 0 {
        return Ok(());
    }
    let pw = std::env::var("BPROTO_ADMIN_PASSWORD").unwrap_or_else(|_| random_token());
    let hash = hash_password(&pw)?;
    sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, status, created_at) \
         VALUES ('admin', ?, 1, 'active', ?)",
    )
    .bind(&hash)
    .bind(now())
    .execute(db)
    .await?;
    tracing::warn!("created default admin 'admin' with password: {pw}");
    tracing::warn!("change it immediately; this line is written once");
    Ok(())
}

/// Every client needs a subscription id; rows created before the migration get
/// one here, and the bootstrap admin is a client of nothing (inbound is NULL).
async fn backfill_sub_ids(db: &SqlitePool) -> anyhow::Result<()> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM users WHERE sub_id IS NULL")
        .fetch_all(db)
        .await?;
    for id in ids {
        sqlx::query("UPDATE users SET sub_id = ? WHERE id = ?")
            .bind(&random_token()[..32])
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// `keys.tag` is derived from `K_tag`, so it rots the moment an operator changes
/// `K_tag` — an easy thing to do, since the dev recipe generates a fresh one per
/// start. Recompute the whole tag column whenever that happens, and say so.
async fn sync_tags(db: &SqlitePool, tag_key: &[u8; 32]) -> anyhow::Result<()> {
    let fingerprint = hex::encode(&Sha256::digest(tag_key)[..8]);
    if subs::get_setting(db, TAG_FINGERPRINT_SETTING)
        .await
        .as_deref()
        == Some(&fingerprint)
    {
        return Ok(());
    }

    let rows = sqlx::query("SELECT id, user_id FROM keys")
        .fetch_all(db)
        .await?;
    let keys_count = rows.len();
    for row in &rows {
        let id: i64 = row.get("id");
        let user_id: i64 = row.get("user_id");
        sqlx::query("UPDATE keys SET tag = ? WHERE id = ?")
            .bind(&keys::compute_tag(tag_key, user_id as u64)[..])
            .bind(id)
            .execute(db)
            .await?;
    }
    subs::set_setting(db, TAG_FINGERPRINT_SETTING, &fingerprint)
        .await
        .map_err(|e| anyhow::anyhow!("cannot store tag fingerprint: {}", e.status))?;

    if keys_count > 0 {
        tracing::warn!(
            keys = keys_count,
            "K_tag changed since the last start: recomputed every routing tag"
        );
    }
    Ok(())
}

/// RFC 7807-ish JSON error.
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub(crate) fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "internal error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn sub_ids_fit_the_column() {
        // `backfill_sub_ids` truncates to 32 hex chars on purpose.
        assert_eq!(random_token()[..32].len(), 32);
    }

    #[test]
    fn panel_name_is_set() {
        assert_eq!(PANEL_NAME, "bUI");
    }
}
