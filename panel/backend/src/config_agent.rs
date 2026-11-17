//! Fixed operator-configured mTLS agent; requests cannot select a destination.
use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use crate::{ApiError, App, audit, auth::Admin};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    action: String,
    #[serde(default)]
    config: Value,
}

pub(crate) async fn apply(
    State(app): State<App>,
    Extension(admin): Extension<Admin>,
    Json(request): Json<Request>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(request.action.as_str(), "apply" | "health" | "rollback") {
        return Err(ApiError::bad_request("Unknown agent action"));
    }
    let setting = |name| std::env::var(name)
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "Config agent is not configured"));
    let endpoint = setting("BPROTO_CONFIG_AGENT_URL")?;
    let url = url::Url::parse(&endpoint).map_err(ApiError::internal)?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some() {
        return Err(ApiError::bad_request("Agent requires a fixed HTTPS URL"));
    }
    let identity = std::fs::read(setting("BPROTO_CONFIG_AGENT_IDENTITY")?).map_err(ApiError::internal)?;
    let ca = std::fs::read(setting("BPROTO_CONFIG_AGENT_CA")?).map_err(ApiError::internal)?;
    let client = reqwest::Client::builder()
        .identity(reqwest::Identity::from_pem(&identity).map_err(ApiError::internal)?)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(ApiError::internal)?)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(85))
        .build().map_err(ApiError::internal)?;
    let body = if request.action == "apply" {
        json!({"version": 1, "config": request.config})
    } else { json!({}) };
    let response = client.post(format!("{}/{}", endpoint.trim_end_matches('/'), request.action))
        .header("Content-Type", "application/json").body(body.to_string())
        .send().await.map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Config agent connection failed"))?;
    let status = response.status();
    audit(&app.db, admin.user_id, "config_agent", &format!("{}:{}", request.action, status.as_u16()), "").await;
    let data = response.bytes().await.map_err(ApiError::internal)?;
    let value: Value = serde_json::from_slice(&data).map_err(ApiError::internal)?;
    if !status.is_success() {
        let message = match value.get("status").and_then(Value::as_str) {
            Some("rolled_back") => "Apply failed; previous configuration restored and healthy",
            Some("rollback_failed") => "Apply failed; previous file restored but service is unhealthy",
            _ => "Agent rejected operation; inspect service health",
        };
        return Err(ApiError::new(StatusCode::BAD_GATEWAY, message));
    }
    Ok(Json(value))
}
