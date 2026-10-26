//! Client subscriptions and remote subscription sources.
//!
//! `/sub/<sub_id>` is the only public, unauthenticated route that hands out
//! credentials, so it is rate limited and returns nothing for a client that is
//! disabled, revoked, expired or over its limit.
//!
//! Formats, for maximum importer compatibility:
//!   * default (and `?format=base64`) — standard base64 of the newline-joined
//!     `bproto://import/…` URIs, plus the usual `Subscription-Userinfo` header;
//!   * `?format=list` — the same URIs as plain text, one per line;
//!   * `?format=json` — structured, what bUI's own clients read.
//!
//! A client's subscription contains its own active configs **and** the configs of
//! every remote source attached to it (see `attach_remote_sub`), so one URL can
//! aggregate several bProto deployments.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use url::Url;

use crate::auth::{Admin, SUB_BURST, SUB_PER_SEC, allow_with, client_ip};
use crate::inbounds::{Inbound, load_inbound};
use crate::{ApiError, App, PANEL_NAME, audit, keys, now};

/// Remote subscription bodies are capped: a config list is a few KiB.
const MAX_SUB_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

const SETTING_SUB_BASE_URL: &str = "sub_base_url";
const SETTING_SUB_TITLE: &str = "sub_title";

pub(crate) async fn get_setting(db: &SqlitePool, key: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
}

pub(crate) async fn set_setting(db: &SqlitePool, key: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

/// Public base URL of the panel: the configured one, else the request's
/// (Caddy sets `X-Forwarded-*`). A database error falls back to the request
/// headers too, but is logged instead of being silently treated as "unset".
pub(crate) async fn sub_base_url(state: &App, headers: &HeaderMap) -> String {
    let configured = get_setting(&state.db, SETTING_SUB_BASE_URL).await;
    if let Ok(Some(url)) = &configured {
        let url = url.trim().trim_end_matches('/').to_string();
        if !url.is_empty() {
            return url;
        }
    }
    if let Err(e) = configured {
        tracing::warn!(error = %e, "cannot read sub_base_url; using request host");
    }
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

pub(crate) fn sub_url(base: &str, sub_id: &str) -> String {
    format!("{}/sub/{sub_id}", base.trim_end_matches('/'))
}

// ---------------------------------------------------------------------------
// Serving a subscription
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct SubQuery {
    #[serde(default)]
    format: Option<String>,
}

/// One config in a subscription.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SubEntry {
    pub(crate) uri: String,
    pub(crate) server: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) uid: Option<i64>,
    pub(crate) label: Option<String>,
    /// ClientHello fingerprint carried by the URI payload (`fp`).
    pub(crate) fingerprint: Option<String>,
}

/// Decode a `bproto://import/<base64url(json)>` payload.
pub(crate) fn decode_uri(uri: &str) -> Option<Value> {
    let payload = uri.strip_prefix("bproto://import/")?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}

fn entry_from_uri(uri: &str) -> SubEntry {
    let parsed = decode_uri(uri);
    SubEntry {
        uri: uri.to_string(),
        server: parsed.as_ref().and_then(|v| v.get("server").and_then(Value::as_str).map(str::to_owned)),
        sni: parsed.as_ref().and_then(|v| v.get("sni").and_then(Value::as_str).map(str::to_owned)),
        uid: parsed.as_ref().and_then(|v| v.get("uid")).and_then(Value::as_i64),
        label: parsed.as_ref().and_then(|v| v.get("label")).and_then(Value::as_str).map(str::to_owned),
        fingerprint: parsed.as_ref().and_then(|v| opt_str(v, "fp")),
    }
}

/// Every `bproto://import/…` link in a blob of text.
fn extract_uris(text: &str) -> Vec<String> {
    const PREFIX: &str = "bproto://import/";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(c, '"' | '\'' | '\\' | ',' | '}' | ']' | ')' | '<' | '>')
            })
            .unwrap_or(tail.len());
        if end > PREFIX.len() {
            out.push(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    out
}

/// Decode a subscription body: JSON (our `?format=json`, or a `{"uris":…}`
/// envelope), base64 of a URI list, or plain text.
pub(crate) fn parse_subscription(body: &str) -> Vec<SubEntry> {
    let trimmed = body.trim();

    // JSON first: a structured body may legitimately contain base64-looking text.
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        let mut uris = Vec::new();
        for key in ["uris", "links", "configs"] {
            if let Some(arr) = value.get(key).and_then(|v| v.as_array()) {
                uris.extend(arr.iter().filter_map(|v| v.as_str()).map(str::to_string));
            }
        }
        if let Some(arr) = value.get("clients").and_then(|v| v.as_array()) {
            uris.extend(arr.iter().filter_map(|c| {
                c.as_str()
                    .map(str::to_string)
                    .or_else(|| c.get("uri").and_then(|u| u.as_str()).map(str::to_string))
            }));
        }
        if let Some(uri) = value.get("uri").and_then(|v| v.as_str()) {
            uris.push(uri.to_string());
        }
        if !uris.is_empty() {
            return uris.iter().map(|u| entry_from_uri(u)).collect();
        }
    }

    let direct = extract_uris(trimmed);
    if !direct.is_empty() {
        return direct.iter().map(|u| entry_from_uri(u)).collect();
    }

    // Base64 in either alphabet, with or without padding.
    let stripped: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let decoded = STANDARD
        .decode(&stripped)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(&stripped).ok())
        .or_else(|| URL_SAFE.decode(&stripped).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(&stripped).ok());
    if let Some(bytes) = decoded
        && let Ok(text) = String::from_utf8(bytes)
    {
        return extract_uris(&text)
            .iter()
            .map(|u| entry_from_uri(u))
            .collect();
    }
    Vec::new()
}

/// Local configs of a client: one per active key.
async fn local_entries(state: &App, user_id: i64) -> Result<Vec<SubEntry>, ApiError> {
    let row = sqlx::query("SELECT inbound_id FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("client not found"))?;
    let inbound_id: Option<i64> = row.get("inbound_id");
    let Some(inbound_id) = inbound_id else {
        return Ok(Vec::new());
    };
    let inbound: Inbound = load_inbound(&state.db, inbound_id).await?;

    let rows = sqlx::query(
        "SELECT id, label, psk FROM keys WHERE user_id = ? AND status = 'active' ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    let mut out = Vec::new();
    for r in rows {
        let psk_bytes: Vec<u8> = r.get("psk");
        let Ok(psk) = <[u8; 32]>::try_from(psk_bytes) else {
            continue;
        };
        let label: String = r.get("label");
        let server: std::net::SocketAddr = match inbound.server.parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let uri = keys::config_uri(&keys::ConfigParts {
            server,
            donor_sni: inbound.donor_sni.clone(),
            user_id: user_id as u64,
            psk,
            tag_key: state.tag_key,
            fingerprint: inbound.fingerprint.clone(),
            label: label.clone(),
        });
        out.push(SubEntry {
            uri,
            server: Some(inbound.server.clone()),
            sni: Some(inbound.donor_sni.clone()),
            uid: Some(user_id),
            label: Some(label),
            fingerprint: Some(inbound.fingerprint.clone()),
        });
    }
    Ok(out)
}

/// Configs of the remote sources attached to a client.
async fn remote_entries(state: &App, user_id: i64) -> Result<Vec<SubEntry>, ApiError> {
    let rows = sqlx::query(
        "SELECT e.uri, e.server, e.sni, e.uid, e.label FROM remote_sub_entries e \
         JOIN user_remote_subs u ON u.remote_sub_id = e.sub_id \
         JOIN remote_subs r ON r.id = e.sub_id \
         WHERE u.user_id = ? AND r.enabled = 1 ORDER BY e.sub_id, e.id",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .iter()
        .map(|r| SubEntry {
            uri: r.get("uri"),
            server: r.get("server"),
            sni: r.get("sni"),
            uid: r.get("uid"),
            label: r.get("label"),
            fingerprint: r.get("fingerprint"),
        })
        .collect())
}

pub(crate) async fn serve_sub(
    State(state): State<App>,
    Path(sub_id): Path<String>,
    Query(q): Query<SubQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !allow_with(
        &state.limiter,
        &format!("sub:{}", client_ip(&headers)),
        SUB_BURST,
        SUB_PER_SEC,
    ) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }

    let row = sqlx::query(
        "SELECT id, username, status, traffic_limit_bytes, traffic_used_bytes, expires_at \
         FROM users WHERE sub_id = ? AND is_admin = 0",
    )
    .bind(&sub_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("subscription not found"))?;

    let user_id: i64 = row.get("id");
    let username: String = row.get("username");
    let status: String = row.get("status");
    let limit: Option<i64> = row.get("traffic_limit_bytes");
    let used: i64 = row.get("traffic_used_bytes");
    let expires_at: Option<i64> = row.get("expires_at");

    if status != "active" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "subscription disabled",
        ));
    }
    if expires_at.is_some_and(|ts| ts < now()) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "subscription expired"));
    }
    if limit.is_some_and(|l| used >= l) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "traffic limit reached",
        ));
    }

    let mut entries = local_entries(&state, user_id).await?;
    entries.extend(remote_entries(&state, user_id).await?);

    let (rx, tx): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT SUM(s.bytes_rx), SUM(s.bytes_tx) FROM sessions s \
         JOIN keys k ON k.id = s.key_id WHERE k.user_id = ?",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let (rx, tx) = (rx.unwrap_or(0), tx.unwrap_or(0));

    let title = get_setting(&state.db, SETTING_SUB_TITLE)
        .await
        .map_err(ApiError::internal)?
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| format!("{PANEL_NAME} · {username}"));

    let format = q.format.as_deref().unwrap_or("base64");
    let (content_type, body) = match format {
        "json" => (
            "application/json; charset=utf-8",
            json!({
                "title": title,
                "sub_id": sub_id,
                "username": username,
                "userinfo": {
                    "upload": rx,
                    "download": tx,
                    "total": limit.unwrap_or(0),
                    "expire": expires_at.unwrap_or(0),
                },
                "count": entries.len(),
                "clients": entries.iter().map(|e| json!({
                    "uri": e.uri,
                    "server": e.server,
                    "sni": e.sni,
                    "uid": e.uid,
                    "label": e.label,
                    "fingerprint": e.fingerprint,
                })).collect::<Vec<_>>(),
            })
            .to_string(),
        ),
        "list" | "text" => (
            "text/plain; charset=utf-8",
            entries
                .iter()
                .map(|e| e.uri.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        _ => {
            let joined = entries
                .iter()
                .map(|e| e.uri.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            (
                "text/plain; charset=utf-8",
                STANDARD.encode(joined.as_bytes()),
            )
        }
    };

    let userinfo = format!(
        "upload={rx}; download={tx}; total={}; expire={}",
        limit.unwrap_or(0),
        expires_at.unwrap_or(0)
    );
    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(ApiError::internal)?,
    );
    for (name, value) in [
        ("subscription-userinfo", userinfo.as_str()),
        ("profile-update-interval", "12"),
        ("cache-control", "no-store"),
    ] {
        out_headers.insert(
            name,
            HeaderValue::from_str(value).map_err(ApiError::internal)?,
        );
    }
    // Importers that read profile-title expect the `base64:` marker followed by
    // the encoded value, because a title may contain non-ASCII text.
    out_headers.insert(
        "profile-title",
        HeaderValue::from_str(&format!("base64:{}", STANDARD.encode(title.as_bytes())))
            .map_err(ApiError::internal)?,
    );

    Ok((StatusCode::OK, out_headers, body).into_response())
}

// ---------------------------------------------------------------------------
// Subscription list + settings
// ---------------------------------------------------------------------------

pub(crate) async fn list_subscriptions(
    State(state): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT u.id, u.username, u.status, u.sub_id, u.traffic_limit_bytes, u.traffic_used_bytes, \
                u.expires_at, i.remark AS inbound_remark, \
                (SELECT COUNT(*) FROM keys k WHERE k.user_id = u.id AND k.status = 'active') AS active_keys, \
                (SELECT COUNT(*) FROM user_remote_subs r WHERE r.user_id = u.id) AS remote_subs \
         FROM users u LEFT JOIN inbounds i ON i.id = u.inbound_id \
         WHERE u.is_admin = 0 ORDER BY u.id",
    )
    .fetch_all(&state.db)
    .await?;
    let base = sub_base_url(&state, &headers).await;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            let sub_id: String = r.get("sub_id");
            json!({
                "user_id": r.get::<i64, _>("id"),
                "username": r.get::<String, _>("username"),
                "status": r.get::<String, _>("status"),
                "inbound_remark": r.get::<Option<String>, _>("inbound_remark"),
                "sub_id": sub_id,
                "sub_url": sub_url(&base, &sub_id),
                "traffic_limit_bytes": r.get::<Option<i64>, _>("traffic_limit_bytes"),
                "traffic_used_bytes": r.get::<i64, _>("traffic_used_bytes"),
                "expires_at": r.get::<Option<i64>, _>("expires_at"),
                "active_keys": r.get::<i64, _>("active_keys"),
                "remote_subs": r.get::<i64, _>("remote_subs"),
            })
        })
        .collect();
    Ok(Json(json!({ "sub_base_url": base, "items": items })))
}

pub(crate) async fn get_sub_settings(State(state): State<App>) -> Result<Json<Value>, ApiError> {
    // A failing settings read is reported, not shown as blank defaults.
    let base = get_setting(&state.db, SETTING_SUB_BASE_URL)
        .await
        .map_err(ApiError::internal)?
        .unwrap_or_default();
    let title = get_setting(&state.db, SETTING_SUB_TITLE)
        .await
        .map_err(ApiError::internal)?
        .unwrap_or_default();
    Ok(Json(json!({
        "sub_base_url": base,
        "sub_title": title,
        "panel": PANEL_NAME,
    })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct SubSettingsReq {
    #[serde(default)]
    sub_base_url: Option<String>,
    #[serde(default)]
    sub_title: Option<String>,
}

pub(crate) async fn update_sub_settings(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Json(body): Json<SubSettingsReq>,
) -> Result<Json<Value>, ApiError> {
    if let Some(url) = &body.sub_base_url {
        let url = url.trim().trim_end_matches('/');
        if !url.is_empty() {
            let parsed = Url::parse(url)
                .map_err(|_| ApiError::bad_request("sub_base_url must be a full URL"))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(ApiError::bad_request("sub_base_url must be http(s)"));
            }
        }
        set_setting(&state.db, SETTING_SUB_BASE_URL, url).await?;
    }
    if let Some(title) = &body.sub_title {
        set_setting(&state.db, SETTING_SUB_TITLE, title.trim()).await?;
    }
    audit(&state.db, admin.user_id, "update_sub_settings", "", "").await;
    get_sub_settings(State(state)).await
}

// ---------------------------------------------------------------------------
// Remote subscription sources
// ---------------------------------------------------------------------------

/// Reject a URL that points into our own network. DNS is resolved here, so a
/// hostname that resolves to a private address is refused too. Redirects are
/// not followed (the fetch client is built with `Policy::none()`), so the
/// check cannot be bypassed by a hop — a remote host that answers 3xx is
/// simply reported as an error. A rebinding race
/// remains possible; the lab flag `BPROTO_ALLOW_PRIVATE_SUBS=1` disables this.
pub(crate) async fn guard_url(state: &App, raw: &str) -> Result<Url, ApiError> {
    let url = Url::parse(raw.trim()).map_err(|_| {
        ApiError::bad_request("url must be absolute, e.g. https://panel.example.com/sub/abc")
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ApiError::bad_request("url must be http(s)"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::bad_request("url has no host"))?
        .to_string();
    if state.allow_private_subs {
        return Ok(url);
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| ApiError::bad_request(format!("cannot resolve {host}: {e}")))?;
    let mut seen = 0;
    for addr in addrs {
        seen += 1;
        if is_disallowed_ip(&addr.ip()) {
            return Err(ApiError::bad_request(format!(
                "{host} resolves to a private or reserved address; refusing to fetch"
            )));
        }
    }
    if seen == 0 {
        return Err(ApiError::bad_request(format!("{host} did not resolve")));
    }
    Ok(url)
}

fn is_disallowed_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                // "this host" /24 (0.0.0.0/8) -- on Linux connecting to an
                // address like 0.1.2.3 is treated as the local host
                || v4.octets()[0] == 0
                // 100.64.0.0/10 (CGNAT) and 198.18.0.0/15 (benchmarking)
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240.0.0.0/4 reserved
                || (v4.octets()[0] & 0xf0) == 0xf0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // 64:ff9b::/96 NAT64: the embedded IPv4 address may be private
                // (segments 6 and 7 hold the v4 octets)
                || (v6.segments()[0] == 0x0064
                    && v6.segments()[1] == 0xff9b
                    && v6.segments()[2..6].iter().all(|&s| s == 0))
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_disallowed_ip(&IpAddr::V4(v4)))
        }
    }
}

/// Fetch a remote subscription and replace its stored entries.
async fn fetch_remote(state: &App, sub_id: i64) -> Result<usize, ApiError> {
    let row = sqlx::query("SELECT url FROM remote_subs WHERE id = ?")
        .bind(sub_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::not_found("remote subscription not found"))?;
    let url: String = row.get("url");
    let parsed_url = guard_url(state, &url).await?;

    let outcome: Result<usize, String> = async {
        let resp = state
            .http
            .get(parsed_url.clone())
            .header("accept", "text/plain, application/json;q=0.9, */*;q=0.5")
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("upstream returned HTTP {}", status.as_u16()));
        }
        if resp
            .content_length()
            .is_some_and(|l| l > MAX_SUB_BYTES as u64)
        {
            return Err("upstream body too large".into());
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("cannot read body: {e}"))?;
        if bytes.len() > MAX_SUB_BYTES {
            return Err("upstream body too large".into());
        }
        let text = String::from_utf8_lossy(&bytes).to_string();
        let entries = parse_subscription(&text);
        if entries.is_empty() {
            return Err("no bproto:// configs found in that response".into());
        }

        let mut tx = state.db.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("DELETE FROM remote_sub_entries WHERE sub_id = ?")
            .bind(sub_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        for e in &entries {
            sqlx::query(
                "INSERT INTO remote_sub_entries (sub_id, uri, server, sni, uid, label, fingerprint, fetched_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(sub_id)
            .bind(&e.uri)
            .bind(&e.server)
            .bind(&e.sni)
            .bind(e.uid)
            .bind(&e.label)
            .bind(&e.fingerprint)
            .bind(now())
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        }
        sqlx::query(
            "UPDATE remote_subs SET last_fetch_at = ?, last_status = 'ok', last_error = NULL, \
             entry_count = ? WHERE id = ?",
        )
        .bind(now())
        .bind(entries.len() as i64)
        .bind(sub_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(entries.len())
    }
    .await;

    match outcome {
        Ok(n) => Ok(n),
        Err(err) => {
            sqlx::query(
                "UPDATE remote_subs SET last_fetch_at = ?, last_status = 'error', last_error = ? WHERE id = ?",
            )
            .bind(now())
            .bind(&err)
            .bind(sub_id)
            .execute(&state.db)
            .await?;
            Err(ApiError::new(StatusCode::BAD_GATEWAY, err))
        }
    }
}

fn remote_sub_json(row: &sqlx::sqlite::SqliteRow) -> Value {
    json!({
        "id": row.get::<i64, _>("id"),
        "name": row.get::<String, _>("name"),
        "url": row.get::<String, _>("url"),
        "enabled": row.get::<i64, _>("enabled") == 1,
        "last_fetch_at": row.get::<Option<i64>, _>("last_fetch_at"),
        "last_status": row.get::<Option<String>, _>("last_status"),
        "last_error": row.get::<Option<String>, _>("last_error"),
        "entry_count": row.get::<i64, _>("entry_count"),
        "created_at": row.get::<i64, _>("created_at"),
    })
}

async fn load_remote_sub(db: &SqlitePool, id: i64) -> Result<Value, ApiError> {
    let row = sqlx::query("SELECT * FROM remote_subs WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::not_found("remote subscription not found"))?;
    Ok(remote_sub_json(&row))
}

pub(crate) async fn list_remote_subs(State(state): State<App>) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query("SELECT * FROM remote_subs ORDER BY id")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(json!({
        "items": rows.iter().map(remote_sub_json).collect::<Vec<_>>()
    })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateRemoteSubReq {
    #[serde(default)]
    name: Option<String>,
    url: String,
}

/// Add a subscription from another bProto server and pull it once, so a
/// misconfigured URL is visible immediately.
pub(crate) async fn create_remote_sub(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Json(body): Json<CreateRemoteSubReq>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let url = guard_url(&state, &body.url).await?;
    let name = body
        .name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| url.host_str().unwrap_or("remote").to_string());

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO remote_subs (name, url, enabled, entry_count, created_at) \
         VALUES (?, ?, 1, 0, ?) RETURNING id",
    )
    .bind(name.trim())
    .bind(url.as_str())
    .bind(now())
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::new(StatusCode::CONFLICT, format!("cannot add source: {e}")))?;

    audit(
        &state.db,
        admin.user_id,
        "create_remote_sub",
        &id.to_string(),
        "",
    )
    .await;

    // A source that is down right now is still worth keeping in the list.
    let _ = fetch_remote(&state, id).await;
    Ok((
        StatusCode::CREATED,
        Json(load_remote_sub(&state.db, id).await?),
    ))
}

pub(crate) async fn refresh_remote_sub(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    fetch_remote(&state, id).await?;
    audit(
        &state.db,
        admin.user_id,
        "refresh_remote_sub",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(load_remote_sub(&state.db, id).await?))
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateRemoteSubReq {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

pub(crate) async fn update_remote_sub(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateRemoteSubReq>,
) -> Result<Json<Value>, ApiError> {
    load_remote_sub(&state.db, id).await?;
    if let Some(name) = &body.name {
        sqlx::query("UPDATE remote_subs SET name = ? WHERE id = ?")
            .bind(name.trim())
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(url) = &body.url {
        let parsed = guard_url(&state, url).await?;
        sqlx::query("UPDATE remote_subs SET url = ? WHERE id = ?")
            .bind(parsed.as_str())
            .bind(id)
            .execute(&state.db)
            .await?;
        let _ = fetch_remote(&state, id).await;
    }
    if let Some(enabled) = body.enabled {
        sqlx::query("UPDATE remote_subs SET enabled = ? WHERE id = ?")
            .bind(i64::from(enabled))
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    audit(
        &state.db,
        admin.user_id,
        "update_remote_sub",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(load_remote_sub(&state.db, id).await?))
}

pub(crate) async fn delete_remote_sub(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let n = sqlx::query("DELETE FROM remote_subs WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("remote subscription not found"));
    }
    audit(
        &state.db,
        admin.user_id,
        "delete_remote_sub",
        &id.to_string(),
        "",
    )
    .await;
    Ok(Json(json!({ "id": id, "deleted": true })))
}

pub(crate) async fn remote_sub_entries(
    State(state): State<App>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    load_remote_sub(&state.db, id).await?;
    let rows = sqlx::query(
        "SELECT id, uri, server, sni, uid, label, fingerprint, fetched_at FROM remote_sub_entries \
         WHERE sub_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "uri": r.get::<String, _>("uri"),
                "server": r.get::<Option<String>, _>("server"),
                "sni": r.get::<Option<String>, _>("sni"),
                "uid": r.get::<Option<i64>, _>("uid"),
                "label": r.get::<Option<String>, _>("label"),
                "fingerprint": r.get::<Option<String>, _>("fingerprint"),
                "fetched_at": r.get::<i64, _>("fetched_at"),
            })
        })
        .collect();
    Ok(Json(json!({ "entries": entries })))
}

// ---------------------------------------------------------------------------
// Attaching remote sources to a client
// ---------------------------------------------------------------------------

pub(crate) async fn list_client_remote_subs(
    State(state): State<App>,
    Path(user_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT r.* FROM remote_subs r JOIN user_remote_subs u ON u.remote_sub_id = r.id \
         WHERE u.user_id = ? ORDER BY r.id",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "items": rows.iter().map(remote_sub_json).collect::<Vec<_>>()
    })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct AttachReq {
    remote_sub_id: i64,
}

pub(crate) async fn attach_remote_sub(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path(user_id): Path<i64>,
    Json(body): Json<AttachReq>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let is_client: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = ? AND is_admin = 0")
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
    if is_client == 0 {
        return Err(ApiError::not_found("client not found"));
    }
    load_remote_sub(&state.db, body.remote_sub_id).await?;

    sqlx::query("INSERT OR IGNORE INTO user_remote_subs (user_id, remote_sub_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(body.remote_sub_id)
        .execute(&state.db)
        .await?;
    audit(
        &state.db,
        admin.user_id,
        "attach_remote_sub",
        &format!("{user_id}:{}", body.remote_sub_id),
        "",
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "user_id": user_id, "remote_sub_id": body.remote_sub_id })),
    ))
}

pub(crate) async fn detach_remote_sub(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    Path((user_id, remote_sub_id)): Path<(i64, i64)>,
) -> Result<Json<Value>, ApiError> {
    let n = sqlx::query("DELETE FROM user_remote_subs WHERE user_id = ? AND remote_sub_id = ?")
        .bind(user_id)
        .bind(remote_sub_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found(
            "that source is not attached to this client",
        ));
    }
    audit(
        &state.db,
        admin.user_id,
        "detach_remote_sub",
        &format!("{user_id}:{remote_sub_id}"),
        "",
    )
    .await;
    Ok(Json(
        json!({ "user_id": user_id, "remote_sub_id": remote_sub_id, "detached": true }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri_for(uid: i64, label: &str) -> String {
        keys::config_uri(&keys::ConfigParts {
            server: "203.0.113.10:443".parse().unwrap(),
            donor_sni: "www.cloudflare.com".into(),
            user_id: uid as u64,
            psk: [0x11; 32],
            tag_key: [0x22; 32],
            fingerprint: "chrome112".into(),
            label: label.into(),
        })
    }

    #[test]
    fn plain_text_payload_is_parsed() {
        let body = format!("{}\n{}\n", uri_for(1, "a"), uri_for(2, "b"));
        let entries = parse_subscription(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].uid, Some(1));
        assert_eq!(entries[1].label.as_deref(), Some("b"));
        assert_eq!(entries[1].sni.as_deref(), Some("www.cloudflare.com"));
    }

    #[test]
    fn base64_payload_is_parsed() {
        let body = STANDARD.encode(format!("{}\n{}", uri_for(3, "c"), uri_for(4, "d")));
        let entries = parse_subscription(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].uid, Some(3));
    }

    #[test]
    fn base64_payload_with_newlines_is_parsed() {
        let raw = format!("{}\n{}", uri_for(5, "e"), uri_for(6, "f"));
        let mut encoded = STANDARD.encode(raw);
        encoded.insert(10, '\n');
        assert_eq!(parse_subscription(&encoded).len(), 2);
    }

    #[test]
    fn json_payload_is_parsed() {
        let body = json!({ "clients": [ { "uri": uri_for(7, "g") } ] }).to_string();
        let entries = parse_subscription(&body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, Some(7));

        let body = json!({ "uris": [ uri_for(8, "h") ] }).to_string();
        assert_eq!(parse_subscription(&body).len(), 1);
    }

    #[test]
    fn garbage_payload_yields_nothing() {
        assert!(parse_subscription("hello, world").is_empty());
        assert!(parse_subscription("").is_empty());
    }

    #[test]
    fn decode_uri_rejects_foreign_links() {
        assert!(decode_uri("vless://x").is_none());
        assert!(decode_uri(&uri_for(9, "i")).is_some());
    }

    #[test]
    fn private_addresses_are_disallowed() {
        use std::net::IpAddr;
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "0.0.0.0",
            "203.0.113.10",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(is_disallowed_ip(&ip), "{ip} should be refused");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700::1111"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(!is_disallowed_ip(&ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn sub_url_has_no_double_slash() {
        assert_eq!(
            sub_url("https://p.example/", "abc"),
            "https://p.example/sub/abc"
        );
    }
}
