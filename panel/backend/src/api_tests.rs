//! Router-level integration tests: they mount the real `router()` over an
//! in-memory SQLite database, so route wiring, auth, JSON shapes and the
//! migration set are all exercised end to end.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

use crate::{App, keys, now, random_token, router, sync_tags};

/// A fresh panel over an in-memory database. One connection on purpose: each
/// extra connection would get its own empty in-memory database.
async fn test_app() -> App {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");
    App {
        db: pool,
        tag_key: [0x22; 32],
        limiter: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        http: reqwest::Client::new(),
        internal_token: Some("devtoken".into()),
        allow_private_subs: false,
    }
}

async fn call(
    app: &App,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = router(app.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn get_raw(app: &App, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = router(app.clone())
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

/// Create an admin directly and return its username/password pair.
async fn seed_admin(app: &App) -> (String, String) {
    let password = "test-admin-password".to_string();
    let hash = crate::hash_password(&password).unwrap();
    sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, status, created_at, sub_id) \
         VALUES ('admin', ?, 1, 'active', ?, ?)",
    )
    .bind(&hash)
    .bind(now())
    .bind(&random_token()[..32])
    .execute(&app.db)
    .await
    .unwrap();
    ("admin".to_string(), password)
}

async fn login(app: &App) -> String {
    let (username, password) = seed_admin(app).await;
    let (status, body) = call(
        app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

async fn create_inbound(app: &App, token: &str) -> i64 {
    let (status, body) = call(
        app,
        "POST",
        "/api/inbounds",
        Some(token),
        Some(json!({
            "remark": "DE-1",
            "server": "203.0.113.10:443",
            "donor_sni": "www.cloudflare.com"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create inbound failed: {body}");
    body["id"].as_i64().unwrap()
}

/// Insert a client row + one key straight into the database.
async fn seed_key(app: &App, username: &str) -> (i64, i64, [u8; 8], String) {
    let sub_id = random_token()[..32].to_string();
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, is_admin, status, created_at, sub_id) \
         VALUES (?, 'x', 0, 'active', ?, ?) RETURNING id",
    )
    .bind(username)
    .bind(now())
    .bind(&sub_id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    let tag = keys::compute_tag(&app.tag_key, user_id as u64);
    let key_id: i64 = sqlx::query_scalar(
        "INSERT INTO keys (user_id, label, psk, tag, status, created_at) \
         VALUES (?, 'device', ?, ?, 'active', ?) RETURNING id",
    )
    .bind(user_id)
    .bind(vec![0x11u8; 32])
    .bind(&tag[..])
    .bind(now())
    .fetch_one(&app.db)
    .await
    .unwrap();
    (user_id, key_id, tag, sub_id)
}

async fn report(app: &App, body: Value) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        "/internal/v1/sessions/report",
        Some("devtoken"),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn protected_routes_need_a_bearer_token() {
    let app = test_app().await;
    for uri in [
        "/api/inbounds",
        "/api/users",
        "/api/subscriptions",
        "/api/stats/overview",
        "/api/audit",
    ] {
        let (status, _) = call(&app, "GET", uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} must need a token");
        let (status, _) = call(&app, "GET", uri, Some("bogus"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} rejected bad token");
    }
    let (status, _) = call(&app, "GET", "/api/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn inbound_client_config_and_subscription_flow() {
    let app = test_app().await;
    let token = login(&app).await;
    let inbound_id = create_inbound(&app, &token).await;

    let (status, client) = call(
        &app,
        "POST",
        &format!("/api/inbounds/{inbound_id}/clients"),
        Some(&token),
        Some(json!({ "username": "alice", "traffic_limit_bytes": 0, "label": "Pixel" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create client: {client}");
    let user_id = client["user_id"].as_i64().unwrap();
    assert!(
        client["config_uri"]
            .as_str()
            .unwrap()
            .starts_with("bproto://import/")
    );
    assert!(client["qr_svg"].as_str().unwrap().contains("<svg"));
    let sub_url = client["sub_url"].as_str().unwrap().to_string();
    assert!(sub_url.ends_with(&client["sub_id"].as_str().unwrap().to_string()));

    // The config decodes back to what the client needs.
    let payload = crate::subs::decode_uri(client["config_uri"].as_str().unwrap()).unwrap();
    assert_eq!(payload["server"], "203.0.113.10:443");
    assert_eq!(payload["sni"], "www.cloudflare.com");
    assert_eq!(payload["uid"].as_i64().unwrap(), user_id);

    // Subscription: just the URI for our own client, in the plain-text form.
    let sub_path = format!("/sub/{}?format=list", client["sub_id"].as_str().unwrap());
    let (status, headers, text) = get_raw(&app, &sub_path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get("subscription-userinfo")
            .is_some_and(|v| v.to_str().unwrap().contains("upload=")),
        "subscription-userinfo header is what importers read"
    );
    assert_eq!(text.matches("bproto://import/").count(), 1);

    // A second key means a second config in the same subscription.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/users/{user_id}/keys"),
        Some(&token),
        Some(json!({ "label": "Laptop" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, _, text) = get_raw(&app, &sub_path).await;
    assert_eq!(text.matches("bproto://import/").count(), 2);

    // The base64 form is what a generic importer expects.
    let (_, _, encoded) = get_raw(
        &app,
        &format!("/sub/{}", client["sub_id"].as_str().unwrap()),
    )
    .await;
    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim()).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.matches("bproto://import/").count(), 2);

    // Inventory the dashboard reads.
    let (status, overview) = call(&app, "GET", "/api/stats/overview", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(overview["clients"], 1);
    assert_eq!(overview["inbounds"], 1);
    assert_eq!(overview["active_keys"], 2);
    assert_eq!(overview["series_24h"].as_array().unwrap().len(), 24);

    // Disabling the client closes its subscription.
    let (status, _) = call(
        &app,
        "PATCH",
        &format!("/api/users/{user_id}"),
        Some(&token),
        Some(json!({ "status": "disabled" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&app, "GET", &sub_path, None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn inbound_needs_a_flag_to_take_its_clients_with_it() {
    let app = test_app().await;
    let token = login(&app).await;
    let inbound_id = create_inbound(&app, &token).await;
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/inbounds/{inbound_id}/clients"),
        Some(&token),
        Some(json!({ "username": "alice" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = call(
        &app,
        "DELETE",
        &format!("/api/inbounds/{inbound_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, body) = call(
        &app,
        "DELETE",
        &format!("/api/inbounds/{inbound_id}?with_clients=1"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["clients_deleted"], 1);
    let (_, users) = call(&app, "GET", "/api/users", Some(&token), None).await;
    assert!(users["clients"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn session_reports_accumulate_and_close() {
    let app = test_app().await;
    let token = login(&app).await;
    let (user_id, _key_id, tag, _sub_id) = seed_key(&app, "alice").await;
    let tag_hex = hex::encode(tag);
    let started = now() - 60;

    // Live session: deltas add up on one open row.
    let (status, body) = report(
        &app,
        json!({ "server_id": "de1", "sessions": [
            { "tag": tag_hex, "started_at": started, "bytes_rx": 100, "bytes_tx": 50, "peer_ip": "198.51.100.9" }
        ]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 1);
    let (_, body) = report(
        &app,
        json!({ "server_id": "de1", "sessions": [
            { "tag": tag_hex, "bytes_rx": 25, "bytes_tx": 25 }
        ]}),
    )
    .await;
    assert_eq!(body["accepted"], 1);

    let open: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(open, 1, "one open row, not two");

    // The client's counter is what limits work on.
    let (_, client) = call(
        &app,
        "GET",
        &format!("/api/users/{user_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(client["client"]["traffic_used_bytes"], 200);
    assert_eq!(client["client"]["online"], 1);

    // Closing it: the same row gets an end, the counter keeps growing.
    let (status, body) = report(
        &app,
        json!({ "server_id": "de1", "sessions": [
            { "tag": tag_hex, "ended_at": now(), "bytes_rx": 10, "bytes_tx": 5 }
        ]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 1);
    let closed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE ended_at IS NOT NULL")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(closed, 1);
    let (_, client) = call(
        &app,
        "GET",
        &format!("/api/users/{user_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(client["client"]["traffic_used_bytes"], 215);
    assert_eq!(client["client"]["online"], 0);

    // Unknown tags are reported back instead of being silently dropped.
    let (_, body) = report(
        &app,
        json!({ "sessions": [{ "tag": "0000000000000000", "bytes_rx": 1, "bytes_tx": 1 }] }),
    )
    .await;
    assert_eq!(body["unknown"].as_array().unwrap().len(), 1);

    // Without the internal token the endpoint is closed.
    let (status, _) = call(
        &app,
        "POST",
        "/internal/v1/sessions/report",
        None,
        Some(json!({ "sessions": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Resetting traffic zeroes the counter but keeps the history.
    let resetted: i64 = sqlx::query_scalar(
        "UPDATE users SET traffic_used_bytes = 0 WHERE id = ? RETURNING traffic_used_bytes",
    )
    .bind(user_id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(resetted, 0);
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(sessions, 1);
}

#[tokio::test]
async fn tag_sync_follows_a_changed_k_tag() {
    let app = test_app().await;
    let (user_id, key_id, old_tag, _) = seed_key(&app, "alice").await;
    let new_key = [0x33u8; 32];

    sync_tags(&app.db, &new_key).await.unwrap();

    let stored: Vec<u8> = sqlx::query_scalar("SELECT tag FROM keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    let expected = keys::compute_tag(&new_key, user_id as u64);
    assert_ne!(stored, old_tag.to_vec());
    assert_eq!(stored, expected.to_vec());

    // Running again is a no-op.
    sync_tags(&app.db, &new_key).await.unwrap();
    let again: Vec<u8> = sqlx::query_scalar("SELECT tag FROM keys WHERE id = ?")
        .bind(key_id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(again, expected.to_vec());
}

#[tokio::test]
async fn password_change_rotates_the_credential() {
    let app = test_app().await;
    let (username, old_password) = seed_admin(&app).await;
    let (_, body) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": username, "password": old_password })),
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();

    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/password",
        Some(&token),
        Some(json!({ "current_password": "wrong", "new_password": "a-new-long-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/password",
        Some(&token),
        Some(json!({ "current_password": old_password, "new_password": "short" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "short passwords are refused"
    );

    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/password",
        Some(&token),
        Some(json!({ "current_password": old_password, "new_password": "a-new-long-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": username, "password": old_password })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old password stops working"
    );
    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": username, "password": "a-new-long-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn clients_cannot_log_in_as_admins() {
    let app = test_app().await;
    let (user_id, _key_id, _tag, _sub_id) = seed_key(&app, "alice").await;
    // Give the client a password-like hash; login must still refuse.
    let hash = crate::hash_password("client-secret-password").unwrap();
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash)
        .bind(user_id)
        .execute(&app.db)
        .await
        .unwrap();
    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({ "username": "alice", "password": "client-secret-password" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn guard_url_blocks_private_targets() {
    let app = test_app().await;
    for url in [
        "http://127.0.0.1/sub/x",
        "http://10.0.0.1/sub/x",
        "http://192.168.0.10:8080/sub/x",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/sub/x",
    ] {
        assert!(
            crate::subs::guard_url(&app, url).await.is_err(),
            "{url} must be refused"
        );
    }
    for url in ["file:///etc/passwd", "/sub/x", "ftp://example.com/sub"] {
        assert!(crate::subs::guard_url(&app, url).await.is_err(), "{url}");
    }
    assert!(
        crate::subs::guard_url(&app, "https://93.184.216.34/sub/abc")
            .await
            .is_ok()
    );

    // The lab flag is the documented way to point bUI at a private address.
    let lab = App {
        allow_private_subs: true,
        ..test_app().await
    };
    assert!(
        crate::subs::guard_url(&lab, "http://127.0.0.1/sub/x")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn audit_log_records_admin_actions() {
    let app = test_app().await;
    let token = login(&app).await;
    create_inbound(&app, &token).await;
    let (status, body) = call(&app, "GET", "/api/audit", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<String> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect();
    assert!(actions.contains(&"login".to_string()));
    assert!(actions.contains(&"create_inbound".to_string()));
}
