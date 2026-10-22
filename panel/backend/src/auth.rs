//! Admin authentication: argon2id login, opaque server-side sessions, rate
//! limiting and admin account management.
//!
//! Sessions are rows in `admin_sessions`, not JWTs: revocation is a `DELETE`.
//! The TTL is short and slides forward on activity, so an idle tab logs itself
//! out while a working one stays signed in.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::{ApiError, App, audit, hash_password, now, random_token, verify_password};

/// Login attempts: burst then one every 20s.
pub(crate) const LOGIN_BURST: f64 = 5.0;
pub(crate) const LOGIN_PER_SEC: f64 = 0.05;
/// Subscription fetches are cheap and polling clients hammer them.
pub(crate) const SUB_BURST: f64 = 90.0;
pub(crate) const SUB_PER_SEC: f64 = 1.0;
/// Session lifetime; extended on use. Short by design: an idle tab signs out.
pub(crate) const SESSION_TTL: i64 = 30 * 60;
const _: () = assert!(SESSION_TTL > 0 && SESSION_TTL <= 3600);
/// Minimum admin password length.
pub(crate) const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug)]
pub(crate) struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// Token buckets keyed by `ip:…`, `user:…` or `sub:…`.
pub(crate) type Limiter = Arc<Mutex<HashMap<String, Bucket>>>;

/// Take one token from `key`'s bucket, refilling at `per_sec` up to `burst`.
pub(crate) fn allow_with(
    limiter: &Mutex<HashMap<String, Bucket>>,
    key: &str,
    burst: f64,
    per_sec: f64,
) -> bool {
    let mut map = limiter.lock().expect("limiter lock");
    let b = map.entry(key.to_string()).or_insert(Bucket {
        tokens: burst,
        updated: Instant::now(),
    });
    let elapsed = b.updated.elapsed().as_secs_f64();
    b.updated = Instant::now();
    b.tokens = (b.tokens + elapsed * per_sec).min(burst);
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// Best-effort client address. The panel runs behind Caddy, so the forwarded
/// headers are the only truth available.
pub(crate) fn client_ip(headers: &HeaderMap) -> String {
    for name in ["x-forwarded-for", "x-real-ip"] {
        let candidate = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|first| !first.is_empty());
        if let Some(first) = candidate {
            return first.to_string();
        }
    }
    "unknown".into()
}

/// Bearer token from the request, if any.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Authenticated admin, injected as a request extension.
#[derive(Debug, Clone)]
pub(crate) struct Admin {
    pub(crate) user_id: i64,
    pub(crate) username: String,
    /// The session token this request presented (for logout/password change).
    pub(crate) token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginReq {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LoginResp {
    token: String,
    expires_at: i64,
}

pub(crate) async fn login(
    State(state): State<App>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Result<Json<LoginResp>, ApiError> {
    let ip = client_ip(&headers);
    if !allow_with(
        &state.limiter,
        &format!("ip:{ip}"),
        LOGIN_BURST,
        LOGIN_PER_SEC,
    ) || !allow_with(
        &state.limiter,
        &format!("user:{}", req.username),
        LOGIN_BURST,
        LOGIN_PER_SEC,
    ) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }

    let row =
        sqlx::query("SELECT id, password_hash, status, is_admin FROM users WHERE username = ?")
            .bind(&req.username)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials"))?;

    let hash: String = row.get("password_hash");
    let status: String = row.get("status");
    let is_admin: i64 = row.get("is_admin");
    // Tunnel clients have no panel password; never let one in even if a hash
    // exists. Same error as a wrong password, so this is not an admin oracle.
    if status != "active" || is_admin != 1 || !verify_password(&req.password, &hash) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ));
    }

    let user_id: i64 = row.get("id");
    let token = random_token();
    let expires_at = now() + SESSION_TTL;
    sqlx::query(
        "INSERT INTO admin_sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(now())
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    audit(&state.db, user_id, "login", "", &ip).await;

    Ok(Json(LoginResp { token, expires_at }))
}

pub(crate) async fn require_admin(
    State(state): State<App>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer(req.headers())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing bearer token"))?;

    let row = sqlx::query(
        "SELECT s.token, s.expires_at, u.id AS uid, u.username, u.is_admin \
         FROM admin_sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid token"))?;

    let expires_at: i64 = row.get("expires_at");
    let stored: String = row.get("token");
    if expires_at < now() || !bool::from(stored.as_bytes().ct_eq(token.as_bytes())) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "expired token"));
    }
    let is_admin: i64 = row.get("is_admin");
    if is_admin != 1 {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "not an admin"));
    }

    // Slide the window, but only when it is worth the write.
    let fresh_expiry = now() + SESSION_TTL;
    if fresh_expiry - expires_at > 60 {
        let _ = sqlx::query("UPDATE admin_sessions SET expires_at = ? WHERE token = ?")
            .bind(fresh_expiry)
            .bind(&token)
            .execute(&state.db)
            .await;
    }

    req.extensions_mut().insert(Admin {
        user_id: row.get("uid"),
        username: row.get("username"),
        token,
    });
    Ok(next.run(req).await)
}

pub(crate) async fn me(Extension(admin): Extension<Admin>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": admin.user_id,
        "username": admin.username,
        "panel": crate::PANEL_NAME,
    }))
}

pub(crate) async fn logout(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
) -> Result<Json<serde_json::Value>, ApiError> {
    sqlx::query("DELETE FROM admin_sessions WHERE token = ?")
        .bind(&admin.token)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "logged_out": true })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChangePasswordReq {
    current_password: String,
    new_password: String,
}

/// Change the caller's own password. Requires the current one, and drops every
/// other session of that account.
pub(crate) async fn change_password(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
        .bind(admin.user_id)
        .fetch_one(&state.db)
        .await?;
    if !verify_password(&body.current_password, &hash) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "current password is wrong",
        ));
    }
    let new_hash = hash_password(&body.new_password).map_err(ApiError::internal)?;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&new_hash)
        .bind(admin.user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM admin_sessions WHERE user_id = ? AND token <> ?")
        .bind(admin.user_id)
        .bind(&admin.token)
        .execute(&state.db)
        .await?;
    audit(
        &state.db,
        admin.user_id,
        "change_password",
        "",
        &client_ip(&headers),
    )
    .await;
    Ok(Json(serde_json::json!({ "changed": true })))
}

pub(crate) async fn list_admins(
    State(state): State<App>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT u.id, u.username, u.status, u.created_at, \
                (SELECT COUNT(*) FROM admin_sessions s WHERE s.user_id = u.id AND s.expires_at > ?) AS sessions, \
                (SELECT MAX(at) FROM admin_audit a WHERE a.admin_id = u.id AND a.action = 'login') AS last_login \
         FROM users u WHERE u.is_admin = 1 ORDER BY u.id",
    )
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    let admins: Vec<_> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<i64, _>("id"),
                "username": r.get::<String, _>("username"),
                "status": r.get::<String, _>("status"),
                "created_at": r.get::<i64, _>("created_at"),
                "sessions": r.get::<i64, _>("sessions"),
                "last_login": r.get::<Option<i64>, _>("last_login"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "admins": admins })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateAdminReq {
    username: String,
    password: String,
}

pub(crate) async fn create_admin(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Json(body): Json<CreateAdminReq>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.username.trim().is_empty() {
        return Err(ApiError::bad_request("username required"));
    }
    if body.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    let hash = hash_password(&body.password).map_err(ApiError::internal)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, is_admin, status, created_at, sub_id) \
         VALUES (?, ?, 1, 'active', ?, ?) RETURNING id",
    )
    .bind(body.username.trim())
    .bind(&hash)
    .bind(now())
    .bind(&random_token()[..32])
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::new(StatusCode::CONFLICT, format!("cannot create admin: {e}")))?;

    audit(
        &state.db,
        admin.user_id,
        "create_admin",
        &id.to_string(),
        &client_ip(&headers),
    )
    .await;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

pub(crate) async fn delete_admin(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if id == admin.user_id {
        return Err(ApiError::bad_request("refusing to delete your own account"));
    }
    let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(&state.db)
        .await?;
    if admins <= 1 {
        return Err(ApiError::bad_request("refusing to delete the last admin"));
    }
    let n = sqlx::query("DELETE FROM users WHERE id = ? AND is_admin = 1")
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("admin not found"));
    }
    audit(
        &state.db,
        admin.user_id,
        "delete_admin",
        &id.to_string(),
        &client_ip(&headers),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "deleted": true })))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResetPasswordReq {
    password: String,
}

/// Reset another admin's password (the "I forgot mine" path for a second
/// operator). Drops that account's sessions.
pub(crate) async fn reset_admin_password(
    State(state): State<App>,
    Extension(admin): Extension<Admin>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ResetPasswordReq>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    let hash = hash_password(&body.password).map_err(ApiError::internal)?;
    let n = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ? AND is_admin = 1")
        .bind(&hash)
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::not_found("admin not found"));
    }
    sqlx::query("DELETE FROM admin_sessions WHERE user_id = ?")
        .bind(id)
        .execute(&state.db)
        .await?;
    audit(
        &state.db,
        admin.user_id,
        "reset_admin_password",
        &id.to_string(),
        &client_ip(&headers),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "reset": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_drains() {
        let limiter = Mutex::new(HashMap::new());
        let mut allowed = 0;
        for _ in 0..10 {
            if allow_with(&limiter, "ip:1.2.3.4", LOGIN_BURST, LOGIN_PER_SEC) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, LOGIN_BURST as i32);
    }

    #[test]
    fn rate_limiter_keys_are_independent() {
        let limiter = Mutex::new(HashMap::new());
        for _ in 0..LOGIN_BURST as i32 {
            assert!(allow_with(&limiter, "ip:a", LOGIN_BURST, LOGIN_PER_SEC));
        }
        assert!(!allow_with(&limiter, "ip:a", LOGIN_BURST, LOGIN_PER_SEC));
        assert!(allow_with(&limiter, "ip:b", LOGIN_BURST, LOGIN_PER_SEC));
    }

    #[test]
    fn client_ip_prefers_forwarded_for() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.7");
        assert_eq!(client_ip(&HeaderMap::new()), "unknown");
    }

    #[test]
    fn bearer_parsing() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer(&h).as_deref(), Some("abc"));
        h.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(bearer(&h).is_none());
    }
}
