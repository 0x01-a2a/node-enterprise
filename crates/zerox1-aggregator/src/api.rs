//! REST API handlers.

use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;

use crate::store::{
    ActivityEvent, AgentProfile, AgentRegistryEntry, CapabilityMatch, HostingNode, IngestEvent,
    NetworkStats, ReputationStore,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};

// ============================================================================
// App state
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub store: ReputationStore,
    /// Shared secret for POST /ingest/envelope.
    /// None = unauthenticated (dev/local only).
    pub ingest_secret: Option<String>,
    /// Shared secret for POST /hosting/register.
    /// None = unauthenticated (dev/local only); set in production.
    pub hosting_secret: Option<String>,
    /// Broadcast channel for real-time activity events (GET /ws/activity).
    pub activity_tx: broadcast::Sender<ActivityEvent>,
    /// Path to store media blobs.
    pub blob_dir: Option<PathBuf>,
    /// Maximum blob upload size in bytes (configurable via --max-blob-size).
    pub max_blob_size: usize,
    /// API keys for gating read endpoints.
    /// Empty = public access (dev mode). When non-empty, all read endpoints
    /// require `Authorization: Bearer <key>` matching one of these values.
    pub api_keys: Vec<String>,
}

/// Check if the request carries a valid API key.
/// Returns None (pass) if api_keys is empty (dev mode) or the token matches.
/// Returns Some(401) if api_keys is configured but the token is missing/invalid.
pub fn require_api_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if state.api_keys.is_empty() {
        return None; // No keys configured — public access (dev mode)
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    for key in &state.api_keys {
        if ct_eq(provided, key.as_str()) {
            return None; // Valid key
        }
    }

    Some((
        StatusCode::UNAUTHORIZED,
        Json(
            json!({ "error": "unauthorized — provide a valid API key via Authorization: Bearer <key>" }),
        ),
    ))
}

/// Axum middleware that gates requests behind `AGGREGATOR_API_KEYS`.
/// Applied via `route_layer(middleware::from_fn_with_state(...))` on the
/// gated route group.
pub async fn api_key_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some((status, body)) = require_api_key(&state, &headers) {
        return (status, body).into_response();
    }
    next.run(request).await
}

// ============================================================================
// Agent ID validation — 64-char hex Ed25519 verifying key
// ============================================================================

fn is_valid_agent_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

// ============================================================================
// Constant-time string comparison (prevents timing attacks on the secret).
// ============================================================================

fn ct_eq(a: &str, b: &str) -> bool {
    // Compare in constant time — no early return on length mismatch to prevent
    // timing side-channels that would reveal secret length.
    let a = a.as_bytes();
    let b = b.as_bytes();
    let len = a.len().max(b.len());
    let mut diff: u8 = (a.len() ^ b.len()) as u8;
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Health
// ============================================================================

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// GET /version
///
/// Returns the current expected SDK and node version.
/// Agents check this on startup and warn if their installed version is behind.
pub async fn get_version() -> impl IntoResponse {
    // SDK_VERSION is the npm package version that ships the current binary.
    // Update this string on every release — it drives the SDK update warning.
    const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
    Json(json!({
        "sdk":  SDK_VERSION,
        "node": SDK_VERSION,
    }))
}

// ============================================================================
// Network stats
// ============================================================================

/// GET /stats/network
///
/// Returns a quick summary of network-wide activity:
/// - agent_count: distinct agents seen by the aggregator
/// - interaction_count: total feedback events recorded (all-time)
/// - started_at: unix timestamp when this aggregator process started
pub async fn get_network_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats: NetworkStats = state.store.network_stats();
    Json(stats)
}

// ============================================================================
// Ingest
// ============================================================================

pub async fn ingest_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<IngestEvent>,
) -> impl IntoResponse {
    // Authenticate ingest requests when a secret is configured.
    if let Some(ref secret) = state.ingest_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, secret.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
    }
    tracing::debug!("Ingest: received event: {:?}", event);
    if let Some(activity) = state.store.ingest(event) {
        if let Err(e) = state.activity_tx.send(activity) {
            tracing::warn!(
                "Activity broadcast dropped (no active subscribers or channel full): {e}"
            );
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

// ============================================================================
// Reputation
// ============================================================================

pub async fn get_reputation(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match state.store.get(&agent_id) {
        Some(rep) => Json(rep).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "agent not found" })),
        )
            .into_response(),
    }
}

// ============================================================================
// Leaderboard
// ============================================================================

#[derive(Deserialize)]
pub struct LeaderboardParams {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    50
}

pub async fn get_leaderboard(
    State(state): State<AppState>,
    Query(params): Query<LeaderboardParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let board = state.store.leaderboard(limit);
    Json(board)
}

#[derive(Deserialize)]
pub struct AgentsParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default = "default_offset")]
    offset: usize,
    #[serde(default = "default_sort")]
    sort: String,
    /// Optional ISO 3166-1 alpha-2 country filter (e.g. ?country=NG).
    country: Option<String>,
}

fn default_offset() -> usize {
    0
}
fn default_sort() -> String {
    "reputation".to_string()
}

pub async fn get_agents(
    State(state): State<AppState>,
    Query(params): Query<AgentsParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let agents = state.store.list_agents(
        limit,
        params.offset,
        &params.sort,
        params.country.as_deref(),
    );
    Json(agents)
}

// ============================================================================
// Agent Registry (BEACON tracking)
// ============================================================================

pub async fn get_registry(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.get_registry())
}

// ============================================================================
// Interactions — raw feedback graph edges for visualisation
// ============================================================================

#[derive(Deserialize)]
pub struct InteractionsParams {
    /// Filter by sender agent_id (hex).
    from: Option<String>,
    /// Filter by target agent_id (hex).
    to: Option<String>,
    #[serde(default = "default_interactions_limit")]
    limit: usize,
}

fn default_interactions_limit() -> usize {
    100
}

/// GET /interactions[?from=<agent_id>&to=<agent_id>&limit=N]
///
/// Returns raw FEEDBACK events, newest first. Use `from`/`to` to filter
/// edges originating from or arriving at a specific agent. Maximum 1 000
/// per request.
pub async fn get_interactions(
    State(state): State<AppState>,
    Query(params): Query<InteractionsParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(1_000);
    let result = state
        .store
        .interactions(params.from.as_deref(), params.to.as_deref(), limit);
    Json(result)
}

// ============================================================================
// Timeseries — hourly feedback volume for charts
// ============================================================================

#[derive(Deserialize)]
pub struct TimeseriesParams {
    /// Look-back window. Accepted values: "1h", "24h", "7d", "30d".
    /// Default: "24h".
    #[serde(default = "default_window")]
    window: String,
}

fn default_window() -> String {
    "24h".to_string()
}

fn parse_window(s: &str) -> u64 {
    match s {
        "1h" => 3_600,
        "7d" => 604_800,
        "30d" => 2_592_000,
        _ => 86_400, // "24h" and anything unrecognised
    }
}

/// GET /stats/timeseries[?window=24h]
///
/// Returns hourly feedback buckets (bucket = unix timestamp of window start).
/// Each bucket contains feedback_count, positive_count, negative_count,
/// dispute_count. Useful for activity charts.
pub async fn get_timeseries(
    State(state): State<AppState>,
    Query(params): Query<TimeseriesParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(&params.window);
    Json(state.store.timeseries(window_secs))
}

// ============================================================================
// Capability discovery (ADVERTISE indexing)
// ============================================================================

#[derive(Deserialize)]
pub struct SearchParams {
    /// Capability name to search for (e.g. "translation", "price-feed").
    capability: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// GET /agents/search?capability=<name>[&limit=50]
///
/// Returns agents that have advertised the given capability, newest first.
/// Agents must have broadcast an ADVERTISE message with a matching
/// capabilities JSON array to appear here.
pub async fn search_agents(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let limit: usize = params.limit.min(200);
    // Sanitise capability string: alphanumeric + dash/underscore, max 64 chars.
    let cap = params.capability.trim().to_lowercase();
    if cap.is_empty()
        || cap.len() > 64
        || !cap
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid capability name" })),
        )
            .into_response();
    }
    let results: Vec<CapabilityMatch> = state.store.search_by_capability(&cap, limit);
    Json(results).into_response()
}

// ============================================================================
// Agent full profile
// ============================================================================

/// GET /agents/{agent_id}/profile
///
/// Returns reputation + entropy + capabilities + recent disputes + name in one call.
/// Avoids 4 separate round trips for dashboard use.
pub async fn get_agent_profile(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    if !is_valid_agent_id(&agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid agent_id" })),
        )
            .into_response();
    }
    let profile: AgentProfile = state.store.agent_profile(&agent_id);
    Json(profile).into_response()
}

// ============================================================================
// Agent search by name
// ============================================================================

#[derive(Deserialize)]
pub struct NameSearchParams {
    name: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// GET /agents/search/name?name=X[&limit=50]
///
/// Case-insensitive substring search against names broadcast in BEACON messages.
pub async fn search_agents_by_name(
    State(state): State<AppState>,
    Query(params): Query<NameSearchParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let name = params.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid name" })),
        )
            .into_response();
    }
    let results: Vec<AgentRegistryEntry> = state.store.search_by_name(&name, limit);
    Json(results).into_response()
}

// ============================================================================
// Sender-side interactions
// ============================================================================

/// GET /interactions/by/{agent_id}[?limit=100]
///
/// All interactions where the given agent was the *sender* (outbound history).
/// Complements GET /interactions?to=X which shows inbound.
pub async fn get_interactions_by(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<InteractionsParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(1_000);
    let result = state.store.interactions(Some(&agent_id), None, limit);
    Json(result)
}

// ============================================================================
// Activity feed
// ============================================================================

#[derive(Deserialize)]
pub struct ActivityParams {
    #[serde(default = "default_activity_limit")]
    limit: usize,
    before: Option<i64>,
}

fn default_activity_limit() -> usize {
    50
}

/// GET /activity[?limit=50&before=<id>]
///
/// Returns recent activity events (JOIN, FEEDBACK, DISPUTE, VERDICT), newest first.
/// Use `before=<id>` for cursor-based pagination.
pub async fn get_activity(
    State(state): State<AppState>,
    Query(params): Query<ActivityParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    Json(state.store.list_activity(limit, params.before))
}

/// GET /ws/activity
///
/// WebSocket endpoint that streams activity events in real-time.
/// Requires `Authorization: Bearer <secret>` or `token=<secret>` query param (HIGH-10).
pub async fn ws_activity(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    // Authenticate.
    if let Some(ref secret) = state.ingest_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| params.get("token").map(|s: &String| s.as_str()))
            .unwrap_or("");

        if !ct_eq(provided, secret) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Ok(ws.on_upgrade(move |mut socket| async move {
        use axum::extract::ws::Message;
        let mut rx = state.activity_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if let Ok(text) = serde_json::to_string(&ev) {
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Skip missed events and continue.
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }))
}

// ============================================================================
// Hosting node registry
// ============================================================================

#[derive(Deserialize)]
pub struct HostingRegisterBody {
    node_id: String,
    name: String,
    fee_bps: u32,
    api_url: String,
}

/// Validate that a host `api_url` is safe to store and surface to mobile clients.
///
/// Requirements:
///   - Parseable as an absolute URL
///   - Scheme is `http` or `https`
///   - No loopback / link-local / unspecified addresses (prevents SSRF when
///     mobile probes the URL)
///   - Length ≤ 256 bytes (prevents database bloat)
fn validate_host_api_url(url: &str) -> Result<(), &'static str> {
    if url.len() > 256 {
        return Err("api_url exceeds 256 characters");
    }

    // Must be a parseable absolute URL with http or https scheme.
    let parsed: reqwest::Url = url.parse().map_err(|_| "api_url is not a valid URL")?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("api_url scheme must be http or https"),
    }

    // Reject private / loopback / link-local hosts to prevent SSRF from
    // mobile clients that blindly fetch the advertised URL.
    if let Some(host) = parsed.host() {
        let host_str = host.to_string();

        // Loopback and unspecified.
        if host_str == "localhost"
            || host_str == "::1"
            || host_str.starts_with("127.")
            || host_str == "0.0.0.0"
        {
            return Err("api_url must not be a loopback address");
        }

        // Private RFC-1918 ranges (simple prefix checks).
        if host_str.starts_with("10.")
            || host_str.starts_with("192.168.")
            || is_rfc1918_172(&host_str)
        {
            return Err("api_url must not be a private IP address");
        }

        // Link-local.
        if host_str.starts_with("169.254.") || host_str.starts_with("fe80:") {
            return Err("api_url must not be a link-local address");
        }
    } else {
        return Err("api_url has no host");
    }

    Ok(())
}

fn is_rfc1918_172(host: &str) -> bool {
    // 172.16.0.0/12 = 172.16.x.x – 172.31.x.x
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 || parts[0] != "172" {
        return false;
    }
    if let Ok(second) = parts[1].parse::<u8>() {
        return (16..=31).contains(&second);
    }
    false
}

fn decode_pubkey_bytes(pubkey: &str) -> Result<[u8; 32], StatusCode> {
    hex::decode(pubkey)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn verify_request_signature(pubkey: &str, signature: &str, body: &[u8]) -> Result<(), StatusCode> {
    let pubkey_arr = decode_pubkey_bytes(pubkey)?;
    let pubkey = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig_bytes = hex::decode(signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    pubkey
        .verify(body, &sig)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

/// POST /hosting/register — called by host nodes on startup and every 60s.
///
/// Requires `Authorization: Bearer <hosting_secret>` when `--hosting-secret`
/// is configured on the aggregator. Validates `api_url` format to prevent
/// SSRF vectors from reaching mobile clients.
/// POST /hosting/register — called by host nodes on startup and every 60s.
///
/// Requirement: Must be signed by the node (HIGH-6).
pub async fn post_hosting_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // When --hosting-secret is configured, require Bearer token as a first gate.
    // This prevents nodes that don't know the secret from registering at all,
    // even if they hold a valid signing key.
    if let Some(ref secret) = state.hosting_secret {
        let expected = format!("Bearer {secret}");
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct_eq(provided, &expected) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body: HostingRegisterBody =
        serde_json::from_str(body_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(s) = sig {
        // HIGH-6: Signature MUST match the node_id
        verify_request_signature(&body.node_id, s, &body_bytes)?;
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate api_url before persisting.
    if let Err(_e) = validate_host_api_url(&body.api_url) {
        return Err(StatusCode::BAD_REQUEST);
    }

    state
        .store
        .register_hosting_node(&body.node_id, &body.name, body.fee_bps, &body.api_url);
    Ok(StatusCode::OK)
}

/// GET /hosting/nodes — returns hosting nodes seen within the last 120 seconds.
pub async fn get_hosting_nodes(State(state): State<AppState>) -> impl IntoResponse {
    let nodes: Vec<HostingNode> = state.store.list_hosting_nodes();
    Json(nodes)
}

// ============================================================================
// Blob Relay (Tiered Media Storage)
// ============================================================================

/// POST /blobs
///
/// Uploads a media blob.
/// Required Headers:
///   X-0x01-Agent-Id:  Hex-encoded 32-byte Ed25519 verifying key (agent identity).
///                     Used for reputation / tier lookup.
///   X-0x01-Signer:   Hex-encoded 32-byte Ed25519 verifying key that produced
///                     X-0x01-Signature.  Optional: falls back to X-0x01-Agent-Id.
///   X-0x01-Timestamp: Unix seconds.
///   X-0x01-Signature: Ed25519 signature of body bytes || timestamp LE-u64.
pub async fn post_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let blob_dir = match state.blob_dir {
        Some(ref d) => d,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "blob storage disabled" })),
            )
                .into_response()
        }
    };

    // 1. Extract and validate headers
    let agent_id_hex = headers
        .get("X-0x01-Agent-Id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let timestamp_str = headers
        .get("X-0x01-Timestamp")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let signature_hex = headers
        .get("X-0x01-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Optional metadata — stored alongside the blob.
    let filename = headers
        .get("X-0x01-Filename")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    let content_type = headers
        .get("Content-Type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    // In enterprise mode agent_id = Ed25519 verifying key (hex), so signer == agent_id.
    // X-0x01-Signer is accepted as an alias for forward-compatibility.
    let signer_hex = headers
        .get("X-0x01-Signer")
        .and_then(|h| h.to_str().ok())
        .unwrap_or(agent_id_hex);

    if !is_valid_agent_id(agent_id_hex) || timestamp_str.is_empty() || signature_hex.len() != 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing or invalid X-0x01 headers" })),
        )
            .into_response();
    }

    let timestamp = match timestamp_str.parse::<u64>() {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid timestamp" })),
            )
                .into_response()
        }
    };

    // Clock skew check (+/- 30s)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if timestamp < now.saturating_sub(60) || timestamp > now + 60 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "timestamp out of sync" })),
        )
            .into_response();
    }

    // 2. Verify Signature
    // Use X-0x01-Signer for the crypto check; it equals X-0x01-Agent-Id in
    // enterprise mode: the node's Ed25519 verifying key.
    let signer_bytes = match hex::decode(signer_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signer (expected 64-char hex Ed25519 key)" })),
            )
                .into_response()
        }
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signature hex" })),
            )
                .into_response()
        }
    };

    let pubkey_bytes: [u8; 32] = match signer_bytes.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signer key length" })),
            )
                .into_response()
        }
    };
    let pubkey = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signer key" })),
            )
                .into_response()
        }
    };

    let sig_bytes: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signature length" })),
            )
                .into_response()
        }
    };
    let sig = Signature::from_bytes(&sig_bytes);

    // Data to verify: body + timestamp (as LE bytes)
    let mut data = body.to_vec();
    data.extend_from_slice(&timestamp.to_le_bytes());
    if pubkey.verify(&data, &sig).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "signature verification failed" })),
        )
            .into_response();
    }

    // 3. Size check against the operator-configured limit.
    let max_size = state.max_blob_size;
    if body.len() > max_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": format!("blob too large (max {} bytes)", max_size) })),
        )
            .into_response();
    }

    // 4. Store Blob
    let mut hasher = Keccak::v256();
    hasher.update(&body);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let cid = hex::encode(hash);

    let file_path = blob_dir.join(&cid);
    if let Err(e) = std::fs::write(&file_path, &body) {
        tracing::error!("Failed to write blob {}: {}", cid, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "failed to store blob" })),
        )
            .into_response();
    }

    // Write sidecar metadata file (.meta.json) for filename and content-type.
    let meta = json!({
        "filename":     filename,
        "content_type": content_type,
        "uploader":     agent_id_hex,
        "size":         body.len(),
    });
    let meta_path = blob_dir.join(format!("{}.meta.json", &cid));
    if let Err(e) = std::fs::write(&meta_path, meta.to_string()) {
        tracing::warn!("Failed to write blob metadata {}: {}", cid, e);
    }

    tracing::info!(
        "Blob uploaded: cid={} from={} size={} filename={:?}",
        &cid[..8],
        &agent_id_hex[..8],
        body.len(),
        filename,
    );
    (StatusCode::CREATED, Json(json!({
        "cid":          cid,
        "filename":     filename,
        "content_type": content_type,
        "size":         body.len(),
    }))).into_response()
}

/// GET /blobs/:cid
pub async fn get_blob(State(state): State<AppState>, Path(cid): Path<String>) -> impl IntoResponse {
    let blob_dir = match state.blob_dir {
        Some(ref d) => d,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "blob storage disabled" })),
            )
                .into_response()
        }
    };

    // Sanitize CID (prevent path traversal)
    if cid.len() != 64 || !cid.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid cid" })),
        )
            .into_response();
    }

    let file_path = blob_dir.join(&cid);
    if !file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "blob not found" })),
        )
            .into_response();
    }

    // Load optional sidecar metadata.
    let meta_path = blob_dir.join(format!("{}.meta.json", &cid));
    let (content_type, filename) = if let Ok(raw) = std::fs::read_to_string(&meta_path) {
        if let Ok(m) = serde_json::from_str::<serde_json::Value>(&raw) {
            let ct = m["content_type"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string();
            let fn_ = m["filename"].as_str().unwrap_or("").to_string();
            (ct, fn_)
        } else {
            ("application/octet-stream".to_string(), String::new())
        }
    } else {
        ("application/octet-stream".to_string(), String::new())
    };

    match std::fs::read(file_path) {
        Ok(data) => {
            let mut headers = axum::http::HeaderMap::new();
            if let Ok(v) = content_type.parse() {
                headers.insert(axum::http::header::CONTENT_TYPE, v);
            }
            if !filename.is_empty() {
                let disposition = format!("inline; filename=\"{}\"", filename.replace('"', ""));
                if let Ok(v) = disposition.parse() {
                    headers.insert(axum::http::header::CONTENT_DISPOSITION, v);
                }
            }
            (StatusCode::OK, headers, data).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "failed to read blob" })),
        )
            .into_response(),
    }
}

/// GET /blobs/:cid/meta
///
/// Returns the metadata sidecar for a blob (filename, content_type, size, uploader)
/// without downloading the blob body itself.
pub async fn get_blob_meta(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> impl IntoResponse {
    let blob_dir = match state.blob_dir {
        Some(ref d) => d,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "blob storage disabled" })),
            )
                .into_response()
        }
    };

    if cid.len() != 64 || !cid.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid cid" })),
        )
            .into_response();
    }

    let meta_path = blob_dir.join(format!("{}.meta.json", &cid));
    match std::fs::read_to_string(&meta_path) {
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(mut m) => {
                m["cid"] = serde_json::Value::String(cid);
                Json(m).into_response()
            }
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "corrupt metadata" })),
            )
                .into_response(),
        },
        Err(_) => {
            // No meta sidecar — blob may predate metadata support.
            let blob_path = blob_dir.join(&cid);
            if blob_path.exists() {
                Json(json!({ "cid": cid, "content_type": "application/octet-stream", "filename": "" }))
                    .into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(json!({ "error": "blob not found" }))).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_request_signature_accepts_hex_pubkeys() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let body = br#"{"ok":true}"#;
        let sig = signing_key.sign(body);

        assert!(verify_request_signature(
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &hex::encode(sig.to_bytes()),
            body
        )
        .is_ok());
    }

    #[test]
    fn verify_request_signature_accepts_hex_pubkeys_hosting() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let body = br#"{"node_id":"test"}"#;
        let sig = signing_key.sign(body);

        assert!(verify_request_signature(
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &hex::encode(sig.to_bytes()),
            body
        )
        .is_ok());
    }
}
