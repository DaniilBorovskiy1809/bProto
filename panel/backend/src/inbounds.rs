//! Inbounds and the clients inside them.
//!
//! An inbound is one bProto endpoint: `server` (IP:port clients dial), the donor
//! SNI whose TLS identity the handshake borrows, and the ClientHello
//! fingerprint. Everything a client config needs comes from its inbound, so
//! editing an inbound re-issues configs with the new values.
//!
//! A client is a `users` row with `inbound_id` set and `is_admin = 0`. It has no
//! panel password — it authenticates to the server with its PSK — and its
//! credential to the panel is the subscription URL. A client owns `keys`, one
//! per device the config was imported on.

use std::net::SocketAddr;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};

use crate::auth::Admin;
use crate::stats::ONLINE_WINDOW_SECS;
use crate::{ApiError, App, audit, hash_password, keys, now, random_token, subs};

/// Fingerprint offered when the inbound does not name one.
const DEFAULT_FINGERPRINT: &str = "chrome112";

/// Fingerprints a `bproto` client can decode. `vpn_core::config` refuses any
/// other `fp` value, so an unknown name here would silently produce configs
/// every client rejects on import.
const KNOWN_FINGERPRINTS: [&str; 4] = ["chrome108", "chrome112", "firefox105", "safari171"];

fn validate_fingerprint(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    if KNOWN_FINGERPRINTS.contains(&name) {
        Ok(name)
    } else {
        Err(ApiError::bad_request(format!(
            "fingerprint must be one of: {}",
            KNOWN_FINGERPRINTS.join(", ")
        )))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Inbound {
    pub(crate) id: i64,
    pub(crate) server: String,
    pub(crate) donor_sni: String,
    pub(crate) fingerprint: String,
}

/// Load one inbound or 404.
pub(crate) async fn load_inbound(db: &SqlitePool, id: i64) -> Result<Inbound, ApiError> {
    let row = sqlx::query("SELECT id, server, donor_sni, fingerprint FROM inbounds WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::not_found("inbound not found"))?;
    Ok(Inbound {
        id: row.get("id"),
        server: row.get("server"),
        donor_sni: row.get("donor_sni"),
        fingerprint: row.get("fingerprint"),
    })
}

/// Validate `host:port` for a client config. Configs carry an address the client
/// dials directly, so an IP literal is required (the panel does no DNS).
fn validate_server(server: &str) -> Result<(), ApiError> {
    server
        .trim()
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| ApiError::bad_request("server must be an IP:port, e.g. 203.0.113.10:443"))
}

fn validate_sni(sni: &str) -> Result<(), ApiError> {
    let ok = !sni.trim().is_empty()
        && sni.len() <= 253
        && sni
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "donor_sni must be a hostname, e.g. www.cloudflare.com",
        ))
    }
}

fn validate_username(username: &str) -> Result<&str, ApiError> {
    let name = username.trim();
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@');
    if ok {
        Ok(name)
    } else {
        Err(ApiError::bad_request(
            "username must be 1-64 chars of [A-Za-z0-9-_.@]",
        ))
    }
}

/// Build a client config URI plus its QR code.
fn config_for(
    state: &App,
    user_id: i64,
    inbound: &Inbound,
    psk: [u8; 32],
    label: &str,
) -> Result<String, ApiError> {
    let server: SocketAddr = inbound
        .server
        .parse()
        .map_err(|_| ApiError::internal(format!("inbound {} has a bad server", inbound.id)))?;
    Ok(keys::config_uri(&keys::ConfigParts {
        server,
        donor_sni: inbound.donor_sni.clone(),
        user_id: user_id as u64,
        psk,
        tag_key: state.tag_key,
        fingerprint: inbound.fingerprint.clone(),
        label: label.to_string(),
    }))
}

fn config_response(uri: &str) -> Result<Value, ApiError> {
    let qr_svg = keys::qr_svg(uri).map_err(ApiError::internal)?;
    Ok(json!({ "config_uri": uri, "qr_svg": qr_svg }))
}

// ---------------------------------------------------------------------------
// Inbounds
// ---------------------------------------------------------------------------

/// Inbounds with their client/key/traffic rollup. Shared by `/api/inbounds`
/// and the dashboard's per-inbound panel.
pub(crate) async fn inbound_rows(db: &SqlitePool) -> Result<Vec<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT i.id, i.remark, i.server, i.donor_sni, i.fingerprint, i.protocol, i.transport, \
                i.listen_port, i.status, i.note, i.created_at, \
                (SELECT COUNT(*) FROM users u WHERE u.inbound_id = i.id) AS clients, \
                (SELECT COUNT(*) FROM users u WHERE u.inbound_id = i.id AND u.status = 'active') AS active_clients, \
                (SELECT COUNT(*) FROM keys k JOIN users u ON u.id = k.user_id \
                  WHERE u.inbound_id = i.id AND k.status = 'active') AS active_keys, \
                (SELECT COALESCE(SUM(u.traffic_used_bytes), 0) FROM users u WHERE u.inbound_id = i.id) AS traffic_used, \
                (SELECT COUNT(DISTINCT s.key_id) FROM sessions s \
                  JOIN keys k ON k.id = s.key_id JOIN users u ON u.id = k.user_id \
                  WHERE u.inbound_id = i.id AND s.ended_at IS NULL AND s.updated_at > ?) AS online \
         FROM inbounds i ORDER BY i.id",
    )
    .bind(now() - ONLINE_WINDOW_SECS)
    .fetch_all(db)
    .await?;

    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "remark": r.get::<String, _>("remark"),
                "server": r.get::<String, _>("server"),
                "donor_sni": r.get::<String, _>("donor_sni"),
                "fingerprint": r.get::<String, _>("fingerprint"),
                "protocol": r.get::<String, _>("protocol"),
                "transport": r.get::<String, _>("transport"),
                "listen_port": r.get::<Option<i64>, _>("listen_port"),
                "status": r.get::<String, _>("status"),
                "note": r.get::<Option<String>, _>("note"),
                "created_at": r.get::<i64, _>("created_at"),
                "clients": r.get::<i64, _>("clients"),
                "active_clients": r.get::<i64, _>("active_clients"),
                "active_keys": r.get::<i64, _>("active_keys"),
                "traffic_used_bytes": r.get::<i64, _>("traffic_used"),
                "online": r.get::<i64, _>("online"),
            })
        })
        .collect())
}

pub(crate) async fn list_inbounds(State(state): State<App>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "inbounds": inbound_rows(&state.db).await? })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct InboundReq {
    remark: String,
    server: String,
    donor_sni: String,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    listen_port: Option<i64>,
    #[serde(default)]
    note: Option<String>,
}

pub(crate) async fn create_inbound(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Json(body): Json<InboundReq>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if body.remark.trim().is_empty() {
        return Err(ApiError::bad_request("remark required"));
    }
    validate_server(&body.server)?;
    validate_sni(&body.donor_sni)?;
    let requested = body
        .fingerprint
        .filter(|f| !f.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_FINGERPRINT.to_string());
    // Validated *before* the INSERT: an unknown name would land in every
    // subsequent client config and break the import on the device.
    let fingerprint = validate_fingerprint(&requested)?.to_string();

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO inbounds (remark, server, donor_sni, fingerprint, protocol, transport, \
         listen_port, status, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?) RETURNING id",
    )
    .bind(body.remark.trim())
    .bind(body.server.trim())
    .bind(body.donor_sni.trim())
    .bind(&fingerprint)
    .bind(body.protocol.as_deref().unwrap_or("bproto"))
    .bind(body.transport.as_deref().unwrap_or("udp"))
    .bind(body.listen_port)
    .bind(body.note.as_deref())
    .bind(now())
    .fetch_one(&state.db)
    .await?;

    audit(
        &state.db,
        admin.user_id,
        "create_inbound",
        &id.to_string(),
        &crate::auth::client_ip(&headers),
    )
    .await;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateInboundReq {
    #[serde(default)]
    remark: Option<String>,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    donor_sni: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    listen_port: Option<i64>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

pub(crate) async fn update_inbound(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateInboundReq>,
) -> Result<Json<Value>, ApiError> {
    load_inbound(&state.db, id).await?;
    if let Some(server) = &body.server {
        validate_server(server)?;
    }
    if let Some(sni) = &body.donor_sni {
        validate_sni(sni)?;
    }
    if let Some(fp) = &body.fingerprint {
        validate_fingerprint(fp)?;
    }
    if let Some(status) = &body.status
        && !["active", "disabled"].contains(&status.as_str())
    {
        return Err(ApiError::bad_request("status must be active or disabled"));
    }

    // One UPDATE per provided field keeps the statement readable and avoids
    // COALESCE tricks that cannot express "leave unchanged" vs "set NULL".
    let mut sets: Vec<&str> = Vec::new();
    if body.remark.is_some() {
        sets.push("remark = ?");
    }
    if body.server.is_some() {
        sets.push("server = ?");
    }
    if body.donor_sni.is_some() {
        sets.push("donor_sni = ?");
    }
    if body.fingerprint.is_some() {
        sets.push("fingerprint = ?");
    }
    if body.listen_port.is_some() {
        sets.push("listen_port = ?");
    }
    if body.status.is_some() {
        sets.push("status = ?");
    }
    if body.note.is_some() {
        sets.push("note = ?");
    }
    if sets.is_empty() {
        return Err(ApiError::bad_request("nothing to update"));
    }

    let sql = format!("UPDATE inbounds SET {} WHERE id = ?", sets.join(", "));
    let mut q = sqlx::query(&sql);
    if let Some(v) = &body.remark {
        q = q.bind(v.trim());
    }
    if let Some(v) = &body.server {
        q = q.bind(v.trim());
    }
    if let Some(v) = &body.donor_sni {
        q = q.bind(v.trim());
    }
    if let Some(v) = &body.fingerprint {
        q = q.bind(v.trim());
    }
    if let Some(v) = body.listen_port {
        q = q.bind(v);
    }
    if let Some(v) = &body.status {
        q = q.bind(v);
    }
    if let Some(v) = &body.note {
        q = q.bind(v);
    }
    q.bind(id).execute(&state.db).await?;

    audit(
        &state.db,
        admin.user_id,
        "update_inbound",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "id": id, "updated": true })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteQuery {
    #[serde(default)]
    with_clients: Option<String>,
}

/// Delete an inbound. Clients are only removed when `?with_clients=1` is passed,
/// so a mis-click cannot silently drop everyone.
pub(crate) async fn delete_inbound(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
    Query(q): Query<DeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    load_inbound(&state.db, id).await?;
    let clients: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE inbound_id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    let with_clients = matches!(q.with_clients.as_deref(), Some("1" | "true"));
    if clients > 0 && !with_clients {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("inbound has {clients} clients; pass with_clients=1 to delete them too"),
        ));
    }
    if with_clients {
        sqlx::query("DELETE FROM users WHERE inbound_id = ?")
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    sqlx::query("DELETE FROM inbounds WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    audit(
        &state.db,
        admin.user_id,
        "delete_inbound",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(
        json!({ "id": id, "deleted": true, "clients_deleted": clients }),
    ))
}

/// Zero the traffic counters of every client of an inbound (3x-ui's
/// "reset traffic"): the session history stays, the clients' counters restart.
pub(crate) async fn reset_inbound_traffic(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    load_inbound(&state.db, id).await?;
    let n = sqlx::query("UPDATE users SET traffic_used_bytes = 0 WHERE inbound_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    audit(
        &state.db,
        admin.user_id,
        "reset_inbound_traffic",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "id": id, "clients_reset": n })))
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ListClientsQuery {
    #[serde(default)]
    inbound_id: Option<i64>,
}

pub(crate) async fn list_clients(
    State(state): State<App>,
    headers: HeaderMap,
    Query(q): Query<ListClientsQuery>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({
        "clients": client_rows(&state, &headers, q.inbound_id).await?
    })))
}

pub(crate) async fn list_clients_of_inbound(
    State(state): State<App>,
    headers: HeaderMap,
    Path(inbound_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    load_inbound(&state.db, inbound_id).await?;
    Ok(Json(json!({
        "clients": client_rows(&state, &headers, Some(inbound_id)).await?
    })))
}

/// Clients (tunnel users) with their key counts, live state and subscription
/// URL. `inbound_id` filters to one inbound.
async fn client_rows(
    state: &App,
    headers: &HeaderMap,
    inbound_id: Option<i64>,
) -> Result<Vec<Value>, ApiError> {
    let mut sql = String::from(
        "SELECT u.id, u.username, u.status, u.inbound_id, i.remark AS inbound_remark, \
                u.traffic_limit_bytes, u.traffic_used_bytes, u.expires_at, u.note, u.sub_id, \
                u.created_at, \
                (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id) AS keys_total, \
                (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id AND k.status = 'active') AS keys_active, \
                (SELECT COUNT(*) FROM sessions s JOIN keys k ON k.id = s.key_id \
                  WHERE k.user_id = u.id AND s.ended_at IS NULL AND s.updated_at > ?) AS online, \
                (SELECT MAX(s.updated_at) FROM sessions s JOIN keys k ON k.id = s.key_id \
                  WHERE k.user_id = u.id) AS last_seen, \
                (SELECT COUNT(*) FROM user_remote_subs r WHERE r.user_id = u.id) AS remote_subs \
         FROM users u LEFT JOIN inbounds i ON i.id = u.inbound_id WHERE u.is_admin = 0",
    );
    if inbound_id.is_some() {
        sql.push_str(" AND u.inbound_id = ?");
    }
    sql.push_str(" ORDER BY u.id");

    let mut q = sqlx::query(&sql).bind(now() - ONLINE_WINDOW_SECS);
    if let Some(id) = inbound_id {
        q = q.bind(id);
    }
    let rows = q.fetch_all(&state.db).await?;
    let base = subs::sub_base_url(state, headers).await;

    Ok(rows.iter().map(|r| client_json(r, &base, None)).collect())
}

/// One client row as JSON. `keys` is the per-key detail list, when the caller
/// loaded it (the single-client view does).
pub(crate) fn client_json(
    row: &sqlx::sqlite::SqliteRow,
    base: &str,
    keys: Option<Vec<Value>>,
) -> Value {
    let sub_id: String = row.get("sub_id");
    let mut out = json!({
        "id": row.get::<i64, _>("id"),
        "username": row.get::<String, _>("username"),
        "status": row.get::<String, _>("status"),
        "inbound_id": row.get::<Option<i64>, _>("inbound_id"),
        "inbound_remark": row.get::<Option<String>, _>("inbound_remark"),
        "traffic_limit_bytes": row.get::<Option<i64>, _>("traffic_limit_bytes"),
        "traffic_used_bytes": row.get::<i64, _>("traffic_used_bytes"),
        "expires_at": row.get::<Option<i64>, _>("expires_at"),
        "note": row.get::<Option<String>, _>("note"),
        "created_at": row.get::<i64, _>("created_at"),
        "sub_id": sub_id,
        "sub_url": subs::sub_url(base, &sub_id),
        "keys": row.get::<i64, _>("keys_total"),
        "active_keys": row.get::<i64, _>("keys_active"),
        "online": row.get::<i64, _>("online"),
        "last_seen_at": row.get::<Option<i64>, _>("last_seen"),
        "remote_subs": row.get::<i64, _>("remote_subs"),
    });
    if let Some(keys) = keys {
        out["key_list"] = json!(keys);
    }
    out
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateClientReq {
    username: String,
    #[serde(default)]
    inbound_id: Option<i64>,
    #[serde(default)]
    traffic_limit_bytes: Option<i64>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

pub(crate) async fn create_client(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Json(body): Json<CreateClientReq>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let inbound_id = body.inbound_id;
    create_client_impl(&state, &admin, &headers, body, inbound_id).await
}

pub(crate) async fn create_client_of_inbound(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Path(inbound_id): Path<i64>,
    Json(body): Json<CreateClientReq>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    create_client_impl(&state, &admin, &headers, body, Some(inbound_id)).await
}

/// Create a client (user) in an inbound and issue its first key.
async fn create_client_impl(
    state: &App,
    admin: &Admin,
    headers: &HeaderMap,
    body: CreateClientReq,
    inbound_id: Option<i64>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let inbound_id = inbound_id.ok_or_else(|| ApiError::bad_request("inbound_id required"))?;
    let inbound = load_inbound(&state.db, inbound_id).await?;
    let username = validate_username(&body.username)?.to_string();
    if body.traffic_limit_bytes.is_some_and(|v| v < 0) {
        return Err(ApiError::bad_request("traffic_limit_bytes must be >= 0"));
    }

    // A client has no panel password: it never signs in here. The column is NOT
    // NULL, so store the hash of a random throwaway secret.
    let throwaway = hash_password(&random_token()).map_err(ApiError::internal)?;
    let sub_id = random_token()[..32].to_string();
    let psk = keys::generate_psk();

    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, is_admin, traffic_limit_bytes, \
         traffic_used_bytes, expires_at, status, created_at, inbound_id, sub_id, note) \
         VALUES (?, ?, 0, ?, 0, ?, 'active', ?, ?, ?, ?) RETURNING id",
    )
    .bind(&username)
    .bind(&throwaway)
    // 0 means "unlimited" on the wire; the database uses NULL.
    .bind(body.traffic_limit_bytes.filter(|v| *v > 0))
    .bind(body.expires_at.filter(|v| *v > 0))
    .bind(now())
    .bind(inbound_id)
    .bind(&sub_id)
    .bind(body.note.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::new(StatusCode::CONFLICT, format!("cannot create client: {e}")))?;

    let label = body.label.unwrap_or_else(|| "device".into());
    let tag = keys::compute_tag(&state.tag_key, user_id as u64);
    let key_id: i64 = sqlx::query_scalar(
        "INSERT INTO keys (user_id, label, psk, tag, status, created_at) \
         VALUES (?, ?, ?, ?, 'active', ?) RETURNING id",
    )
    .bind(user_id)
    .bind(&label)
    .bind(&psk[..])
    .bind(&tag[..])
    .bind(now())
    .fetch_one(&state.db)
    .await?;

    let uri = config_for(state, user_id, &inbound, psk, &label)?;
    let mut resp = config_response(&uri)?;
    let base = subs::sub_base_url(state, headers).await;
    resp["user_id"] = json!(user_id);
    resp["sub_id"] = json!(sub_id);
    resp["sub_url"] = json!(subs::sub_url(&base, &sub_id));
    resp["key_id"] = json!(key_id);

    audit(
        &state.db,
        admin.user_id,
        "create_client",
        &user_id.to_string(),
        "",
    )
    .await;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub(crate) async fn get_client(
    State(state): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query(
        "SELECT u.id, u.username, u.status, u.inbound_id, i.remark AS inbound_remark, \
                u.traffic_limit_bytes, u.traffic_used_bytes, u.expires_at, u.note, u.sub_id, \
                u.created_at, \
                (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id) AS keys_total, \
                (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id AND k.status = 'active') AS keys_active, \
                (SELECT COUNT(*) FROM sessions s JOIN keys k ON k.id = s.key_id \
                  WHERE k.user_id = u.id AND s.ended_at IS NULL AND s.updated_at > ?) AS online, \
                (SELECT MAX(s.updated_at) FROM sessions s JOIN keys k ON k.id = s.key_id \
                  WHERE k.user_id = u.id) AS last_seen, \
                (SELECT COUNT(*) FROM user_remote_subs r WHERE r.user_id = u.id) AS remote_subs \
         FROM users u LEFT JOIN inbounds i ON i.id = u.inbound_id \
         WHERE u.id = ? AND u.is_admin = 0",
    )
    .bind(now() - ONLINE_WINDOW_SECS)
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("client not found"))?;

    let base = subs::sub_base_url(&state, &headers).await;
    let keys = key_rows(&state.db, id).await?;
    Ok(Json(
        json!({ "client": client_json(&row, &base, Some(keys)) }),
    ))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateClientReq {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    inbound_id: Option<i64>,
    /// 0 (or null) = unlimited.
    #[serde(default)]
    traffic_limit_bytes: Option<i64>,
    /// 0 = never expires.
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

pub(crate) async fn update_client(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateClientReq>,
) -> Result<Json<Value>, ApiError> {
    let exists: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = ? AND is_admin = 0")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    if exists == 0 {
        return Err(ApiError::not_found("client not found"));
    }

    if let Some(username) = &body.username {
        let name = validate_username(username)?;
        sqlx::query("UPDATE users SET username = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(&state.db)
            .await
            .map_err(|e| ApiError::new(StatusCode::CONFLICT, format!("cannot rename: {e}")))?;
    }
    if let Some(inbound_id) = body.inbound_id {
        load_inbound(&state.db, inbound_id).await?;
        sqlx::query("UPDATE users SET inbound_id = ? WHERE id = ?")
            .bind(inbound_id)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(limit) = body.traffic_limit_bytes {
        if limit < 0 {
            return Err(ApiError::bad_request("traffic_limit_bytes cannot be negative"));
        }
        sqlx::query("UPDATE users SET traffic_limit_bytes = ? WHERE id = ?")
            .bind((limit > 0).then_some(limit))
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(expires) = body.expires_at {
        if expires < 0 {
            return Err(ApiError::bad_request("expires_at cannot be negative"));
        }
        sqlx::query("UPDATE users SET expires_at = ? WHERE id = ?")
            .bind((expires > 0).then_some(expires))
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(note) = &body.note {
        sqlx::query("UPDATE users SET note = ? WHERE id = ?")
            .bind(note)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(status) = &body.status {
        if !["active", "disabled", "revoked"].contains(&status.as_str()) {
            return Err(ApiError::bad_request("bad status"));
        }
        sqlx::query("UPDATE users SET status = ? WHERE id = ?")
            .bind(status)
            .bind(id)
            .execute(&state.db)
            .await?;
        if status == "revoked" {
            sqlx::query("UPDATE keys SET status = 'revoked', revoked_at = ? WHERE user_id = ? AND status = 'active'")
                .bind(now())
                .bind(id)
                .execute(&state.db)
                .await?;
        }
    }
    audit(
        &state.db,
        admin.user_id,
        "update_client",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "id": id, "updated": true })))
}

/// Delete a client, its keys and its session history.
pub(crate) async fn delete_client(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let n = sqlx::query("DELETE FROM users WHERE id = ? AND is_admin = 0")
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("client not found"));
    }
    audit(
        &state.db,
        admin.user_id,
        "delete_client",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "id": id, "deleted": true })))
}

pub(crate) async fn reset_client_traffic(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let n = sqlx::query("UPDATE users SET traffic_used_bytes = 0 WHERE id = ? AND is_admin = 0")
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("client not found"));
    }
    audit(
        &state.db,
        admin.user_id,
        "reset_client_traffic",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "id": id, "reset": true })))
}

// ---------------------------------------------------------------------------
// Keys (devices of a client)
// ---------------------------------------------------------------------------

async fn key_rows(db: &SqlitePool, user_id: i64) -> Result<Vec<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, label, status, created_at, revoked_at, last_seen_ip FROM keys \
         WHERE user_id = ? ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "label": r.get::<String, _>("label"),
                "status": r.get::<String, _>("status"),
                "created_at": r.get::<i64, _>("created_at"),
                "revoked_at": r.get::<Option<i64>, _>("revoked_at"),
                "last_seen_ip": r.get::<Option<String>, _>("last_seen_ip"),
            })
        })
        .collect())
}

pub(crate) async fn list_keys(
    State(state): State<App>,
    Path(user_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "keys": key_rows(&state.db, user_id).await? })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateKeyReq {
    #[serde(default)]
    label: Option<String>,
}

pub(crate) async fn create_key(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(user_id): Path<i64>,
    Json(body): Json<CreateKeyReq>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let row =
        sqlx::query("SELECT u.id, u.inbound_id FROM users u WHERE u.id = ? AND u.is_admin = 0")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::not_found("client not found"))?;
    let inbound_id: Option<i64> = row.get("inbound_id");
    let inbound_id = inbound_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "client has no inbound; assign one before issuing a config",
        )
    })?;
    let inbound = load_inbound(&state.db, inbound_id).await?;

    let label = body.label.unwrap_or_else(|| "device".into());
    // The label goes into the config URI, which becomes a QR code; a QR code
    // has a hard payload limit, so keep the label from pushing the URI past
    // it. Failing here keeps the 400 *before* the key row exists.
    if label.trim().is_empty() || label.len() > 64 {
        return Err(ApiError::bad_request("label must be 1-64 characters"));
    }
    let psk = keys::generate_psk();
    let tag = keys::compute_tag(&state.tag_key, user_id as u64);
    let key_id: i64 = sqlx::query_scalar(
        "INSERT INTO keys (user_id, label, psk, tag, status, created_at) \
         VALUES (?, ?, ?, ?, 'active', ?) RETURNING id",
    )
    .bind(user_id)
    .bind(&label)
    .bind(&psk[..])
    .bind(&tag[..])
    .bind(now())
    .fetch_one(&state.db)
    .await?;

    let uri = config_for(&state, user_id, &inbound, psk, &label)?;
    let mut resp = config_response(&uri)?;
    resp["key_id"] = json!(key_id);

    audit(
        &state.db,
        admin.user_id,
        "create_key",
        &key_id.to_string(),
        "",
    )
    .await;
    Ok((StatusCode::CREATED, Json(resp)))
}

/// Re-issue a config for an existing key. Admin-only. Note the PSK also leaves
/// the database through the subscription URL (`/sub/<id>`), by design: the
/// subscription URL *is* the client credential.
pub(crate) async fn key_config(
    State(state): State<App>,
    Path(key_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query(
        "SELECT k.id, k.label, k.psk, k.status, u.id AS user_id, u.inbound_id, u.status AS user_status \
         FROM keys k JOIN users u ON u.id = k.user_id WHERE k.id = ?",
    )
    .bind(key_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("key not found"))?;

    let inbound_id: Option<i64> = row.get("inbound_id");
    let inbound_id = inbound_id.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "client has no inbound; assign one before showing a config",
        )
    })?;
    let inbound = load_inbound(&state.db, inbound_id).await?;

    let psk_bytes: Vec<u8> = row.get("psk");
    let psk: [u8; 32] = psk_bytes
        .try_into()
        .map_err(|_| ApiError::internal("stored psk is not 32 bytes"))?;
    let uri = config_for(
        &state,
        row.get::<i64, _>("user_id"),
        &inbound,
        psk,
        &row.get::<String, _>("label"),
    )?;
    let mut resp = config_response(&uri)?;
    resp["key_id"] = json!(key_id);
    resp["key_status"] = json!(row.get::<String, _>("status"));
    resp["client_status"] = json!(row.get::<String, _>("user_status"));
    Ok(Json(resp))
}

pub(crate) async fn revoke_key(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(key_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let n = sqlx::query(
        "UPDATE keys SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'",
    )
    .bind(now())
    .bind(key_id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "key not found or already revoked",
        ));
    }
    audit(
        &state.db,
        admin.user_id,
        "revoke_key",
        &key_id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "key_id": key_id, "revoked": true })))
}

pub(crate) async fn delete_key(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(key_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let n = sqlx::query("DELETE FROM keys WHERE id = ?")
        .bind(key_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("key not found"));
    }
    audit(
        &state.db,
        admin.user_id,
        "delete_key",
        &key_id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "key_id": key_id, "deleted": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_must_be_ip_port() {
        assert!(validate_server("203.0.113.10:443").is_ok());
        assert!(validate_server("[2001:db8::1]:443").is_ok());
        assert!(validate_server("vpn.example.com:443").is_err());
        assert!(validate_server("203.0.113.10").is_err());
    }

    #[test]
    fn sni_must_look_like_a_hostname() {
        assert!(validate_sni("www.cloudflare.com").is_ok());
        assert!(validate_sni("").is_err());
        assert!(validate_sni("http://x/").is_err());
        assert!(validate_sni("bad sni").is_err());
    }

    #[test]
    fn usernames_are_restricted() {
        assert_eq!(validate_username("  alice ").unwrap(), "alice");
        assert!(validate_username("").is_err());
        assert!(validate_username("a b").is_err());
        assert!(validate_username(&"x".repeat(65)).is_err());
    }
}
