//! Visualization API + Agent Integration API.
//!
//! Visualization (read-only):
//!   GET  /ws/events              — WebSocket stream of node events
//!   GET  /peers                  — All known peers with SATI/lease status
//!   GET  /reputation/{agent_id}  — Reputation vector for an agent
//!   GET  /batch/{agent_id}/{epoch} — Batch summary (own node only)
//!
//! Agent integration:
//!   POST /envelopes/send         — Send an envelope (node signs + routes)
//!   GET  /ws/inbox               — WebSocket stream of inbound envelopes
//!
//! High-level negotiation (encode + send in one call):
//!   POST /negotiate/propose      — Send PROPOSE with structured payload
//!   POST /negotiate/counter      — Send COUNTER with structured payload
//!   POST /negotiate/accept       — Send ACCEPT with agreed amount encoded
//!   POST /hosted/negotiate/propose  — Same, for hosted agents (Bearer token)
//!   POST /hosted/negotiate/counter  — Same, for hosted agents
//!   POST /hosted/negotiate/accept   — Same, for hosted agents
//!
//! Escrow (explicit on-chain locking):
//!   POST /escrow/lock            — Lock USDC in escrow (requester → provider)
//!   POST /escrow/approve         — Approve and release locked payment
//!
//! 8004 Solana Agent Registry:
//!   GET  /registry/8004/info              — Program IDs, collection, step-by-step guide
//!   POST /registry/8004/register-prepare  — Build partially-signed tx (agent signs message_b64)
//!   POST /registry/8004/register-submit   — Inject owner sig + broadcast to Solana

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use zerox1_protocol::{
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::FeedbackPayload,
};

// ============================================================================
// Snapshot types — serialisable views of node state (visualization)
// ============================================================================

#[derive(Clone, Serialize)]
pub struct PeerSnapshot {
    pub agent_id: String,
    pub peer_id: Option<String>,
    pub last_active_epoch: u64,
}

#[derive(Clone, Serialize)]
pub struct ReputationSnapshot {
    pub agent_id: String,
    pub reliability: i64,
    pub cooperation: i64,
    pub notary_accuracy: i64,
    pub total_tasks: u32,
    pub total_disputes: u32,
    pub last_active_epoch: u64,
}

#[derive(Clone, Serialize)]
pub struct BatchSnapshot {
    pub agent_id: String,
    pub epoch: u64,
    pub message_count: u32,
    pub log_merkle_root: String,
    pub batch_hash: String,
}

// ============================================================================
// Visualization events — broadcast to /ws/events subscribers
// ============================================================================

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiEvent {
    Envelope {
        sender: String,
        msg_type: String,
        slot: u64,
    },
    PeerRegistered {
        agent_id: String,
        peer_id: String,
    },
    ReputationUpdate {
        agent_id: String,
        reliability: i64,
        cooperation: i64,
    },
    BatchSubmitted {
        epoch: u64,
        message_count: u32,
        batch_hash: String,
    },
}

// ============================================================================
// Portfolio types
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortfolioEvent {
    Swap {
        input_mint: String,
        output_mint: String,
        input_amount: f64,
        output_amount: f64,
        txid: String,
        timestamp: u64,
    },
    Bounty {
        amount_usdc: f64,
        from_agent: String,
        conversation_id: String,
        timestamp: u64,
    },
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PortfolioHistory {
    pub events: Vec<PortfolioEvent>,
}

// ============================================================================
// Agent integration types
// ============================================================================

/// Request body for POST /envelopes/send.
#[derive(Deserialize)]
pub struct SendEnvelopeRequest {
    /// Message type string, e.g. "PROPOSE", "ACCEPT", "DELIVER".
    pub msg_type: String,
    /// Recipient agent ID as hex (32 bytes). Omit or null for broadcast types.
    pub recipient: Option<String>,
    /// Conversation ID as hex (16 bytes).
    pub conversation_id: String,
    /// Payload bytes as base64.
    pub payload_b64: String,
}

/// Response body for POST /envelopes/send.
#[derive(Serialize)]
pub struct SentConfirmation {
    pub nonce: u64,
    pub payload_hash: String, // hex keccak256
}

// ── Negotiate endpoint types ──────────────────────────────────────────────

/// Build the standard negotiate payload wire format:
/// `[16-byte LE i128 amount_usdc_micro][JSON extra]`
fn build_negotiate_payload(amount_usdc_micro: u64, extra: serde_json::Value) -> Vec<u8> {
    let mut payload = (amount_usdc_micro as i128).to_le_bytes().to_vec();
    payload.extend_from_slice(extra.to_string().as_bytes());
    payload
}

/// Request body for POST /negotiate/propose (and /hosted/negotiate/propose).
#[derive(Deserialize)]
pub struct NegotiateProposeRequest {
    pub recipient: String,
    /// 16-byte hex conversation ID. Auto-generated if omitted.
    pub conversation_id: Option<String>,
    /// Bid amount in USDC microunits. Default: 0 (unspecified).
    pub amount_usdc_micro: Option<u64>,
    /// Max counter rounds (default: 2).
    pub max_rounds: Option<u8>,
    pub message: String,
}

/// Request body for POST /negotiate/counter (and /hosted/negotiate/counter).
#[derive(Deserialize)]
pub struct NegotiateCounterRequest {
    pub recipient: String,
    pub conversation_id: String,
    pub amount_usdc_micro: u64,
    pub round: u8,
    pub max_rounds: Option<u8>,
    pub message: Option<String>,
}

/// Request body for POST /negotiate/accept (and /hosted/negotiate/accept).
#[derive(Deserialize)]
pub struct NegotiateAcceptRequest {
    pub recipient: String,
    pub conversation_id: String,
    pub amount_usdc_micro: u64,
    pub message: Option<String>,
}

// (Removed duplicate PortfolioBalances)

/// Outbound request queued by POST /envelopes/send, consumed by the node loop.
pub struct OutboundRequest {
    pub msg_type: MsgType,
    pub recipient: [u8; 32],
    pub conversation_id: [u8; 16],
    pub payload: Vec<u8>,
    pub reply: tokio::sync::oneshot::Sender<Result<SentConfirmation, String>>,
}

/// Inbound envelope pushed from the node loop to /ws/inbox subscribers.
#[derive(Clone, Serialize)]
pub struct InboundEnvelope {
    pub msg_type: String,
    pub sender: String,          // hex
    pub recipient: String,       // hex
    pub conversation_id: String, // hex
    pub slot: u64,
    pub nonce: u64,
    pub payload_b64: String,
    /// Decoded FEEDBACK payload fields (only present for FEEDBACK messages).
    pub feedback: Option<serde_json::Value>,
}

// ============================================================================
// Hosted-agent session state
// ============================================================================

/// Hard cap on concurrent hosted sessions to prevent memory DoS.
const MAX_HOSTED_SESSIONS: usize = 10_000;
/// Sessions older than this are evicted and their tokens rejected.
const SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
/// Maximum outbound sends per 60-second window per session.
const MAX_SENDS_PER_MINUTE: u32 = 60;
/// Maximum API `/envelopes/send` requests per 60-second window.
const MAX_API_SENDS_PER_MINUTE: u32 = 120;
/// Maximum `/hosted/send` requests per 60-second window.
const MAX_HOSTED_SENDS_PER_MINUTE: u32 = 120;

struct RateLimitWindow {
    window_start: u64,
    count: u32,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Active hosted-agent session — one per registered hosted agent.
///
/// On registration the host generates a fresh ed25519 sub-keypair.
/// `agent_id = verifying_key.to_bytes()`. All outbound envelopes for this
/// agent are signed with `signing_key` by the host.
pub struct HostedSession {
    /// 32-byte verifying key — used as the agent_id on the mesh.
    pub agent_id: [u8; 32],
    pub signing_key: SigningKey,
    pub created_at: u64,
    pub nonce: u64,
    /// Start of the current 60-second rate-limit window (unix seconds).
    pub rate_window_start: u64,
    /// Number of sends in the current rate-limit window.
    pub sends_in_window: u32,
}

/// Request body for POST /hosted/send.
#[derive(Deserialize)]
pub struct HostedSendRequest {
    pub msg_type: String,
    pub recipient: Option<String>,
    pub conversation_id: String,
    pub payload_hex: String,
}

/// Query parameters for GET /ws/hosted/inbox (token fallback only).
#[derive(Deserialize)]
pub struct HostedInboxQuery {
    pub token: Option<String>,
}

// ============================================================================
// Shared API state
// ============================================================================

pub struct ApiInner {
    // Visualization state
    peers: RwLock<HashMap<[u8; 32], PeerSnapshot>>,
    reputation: RwLock<HashMap<[u8; 32], ReputationSnapshot>>,
    batches: RwLock<Vec<BatchSnapshot>>,
    event_tx: broadcast::Sender<ApiEvent>,
    self_agent: [u8; 32],
    self_name: String,

    // Agent integration channels
    /// Outbound requests from HTTP handlers to the node loop.
    outbound_tx: mpsc::Sender<OutboundRequest>,
    /// Inbound envelopes from node loop to /ws/inbox subscribers.
    inbox_tx: broadcast::Sender<InboundEnvelope>,
    /// Optional bearer token to authenticate mutating API endpoints.
    api_secret: Option<String>,
    /// Read-only bearer tokens — grants access to GET/WS visualization endpoints
    /// but NOT to mutating endpoints like /envelopes/send.
    api_read_keys: Vec<String>,

    // Hosted-agent state
    /// token (hex-32) → HostedSession
    pub hosted_sessions: Arc<RwLock<HashMap<String, HostedSession>>>,
    #[allow(dead_code)]
    hosting_fee_bps: u32,
    /// Pre-signed envelopes from hosted-agent send handler → node loop.
    hosted_outbound_tx: mpsc::Sender<Envelope>,
    /// Global rate limit window for `/envelopes/send`.
    send_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/hosted/register`.
    hosted_register_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/hosted/send`.
    hosted_send_rate_limit: Mutex<RateLimitWindow>,

    /// Shared HTTP client for outbound requests.
    pub(crate) http_client: reqwest::Client,
    /// The current slot (for informational purposes), updated periodically.
    current_slot: core::sync::atomic::AtomicU64,

    // Portfolio state
    pub portfolio_history: RwLock<PortfolioHistory>,
    portfolio_persist_path: RwLock<PathBuf>,

    // Agent (zeroclaw) process management
    /// PID of the running zeroclaw agent process. Set by POST /agent/register-pid.
    /// Used by POST /agent/reload to restart the agent so new skills are loaded.
    pub agent_pid: Mutex<Option<u32>>,
    /// Rate limit for POST /agent/reload — max 3 reloads per minute.
    agent_reload_rate_limit: Mutex<RateLimitWindow>,

    // Skill manager
    /// Zeroclaw workspace directory. When set, skill management endpoints are active.
    pub skill_workspace: Option<std::path::PathBuf>,
}

/// Cheaply cloneable shared state passed to all axum handlers.
#[derive(Clone)]
pub struct ApiState(Arc<ApiInner>);

impl ApiState {
    /// Create a new ApiState.
    ///
    /// Returns `(state, outbound_rx, hosted_outbound_rx)`. The caller (node)
    /// must hold onto both receivers and drive them in the main event loop.
    pub fn new(
        self_agent: [u8; 32],
        self_name: String,
        api_secret: Option<String>,
        api_read_keys: Vec<String>,
        hosting_fee_bps: u32,
        http_client: reqwest::Client,
        skill_workspace: Option<std::path::PathBuf>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundRequest>,
        mpsc::Receiver<Envelope>,
    ) {
        let (event_tx, _) = broadcast::channel(512);
        let (inbox_tx, _) = broadcast::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (hosted_outbound_tx, hosted_outbound_rx) = mpsc::channel(64);

        let state = Self(Arc::new(ApiInner {
            peers: RwLock::new(HashMap::new()),
            reputation: RwLock::new(HashMap::new()),
            batches: RwLock::new(Vec::new()),
            event_tx,
            self_agent,
            self_name,
            outbound_tx,
            inbox_tx,
            api_secret,
            api_read_keys,
            hosted_sessions: Arc::new(RwLock::new(HashMap::new())),
            hosting_fee_bps,
            hosted_outbound_tx,
            send_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            hosted_register_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            hosted_send_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            http_client,
            current_slot: core::sync::atomic::AtomicU64::new(0),
            portfolio_history: RwLock::new(PortfolioHistory::default()),
            portfolio_persist_path: RwLock::new(PathBuf::new()), // set during init
            agent_pid: Mutex::new(None),
            agent_reload_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            skill_workspace,
        }));

        (state, outbound_rx, hosted_outbound_rx)
    }

    pub async fn load_portfolio_history(&self, path: PathBuf) -> anyhow::Result<()> {
        *self.0.portfolio_persist_path.write().await = path.clone();

        if path.exists() {
            let data = tokio::fs::read_to_string(&path).await?;
            let history: PortfolioHistory = serde_json::from_str(&data)?;
            *self.0.portfolio_history.write().await = history;
        }
        Ok(())
    }

    pub async fn record_portfolio_event(&self, event: PortfolioEvent) {
        let mut history = self.0.portfolio_history.write().await;
        history.events.insert(0, event);
        if history.events.len() > 1000 {
            history.events.truncate(1000);
        }

        // Persist asynchronously — drop the write lock first so other tasks
        // can access portfolio_history while we do the (potentially slow) write.
        let path = self.0.portfolio_persist_path.read().await.clone();
        if !path.as_os_str().is_empty() {
            if let Ok(json) = serde_json::to_string_pretty(&*history) {
                drop(history);
                let _ = tokio::fs::write(&path, json).await;
            }
        }
    }

    // ── Visualization update helpers ─────────────────────────────────────────

    pub async fn upsert_peer(&self, agent_id: [u8; 32], snap: PeerSnapshot) {
        self.0.peers.write().await.insert(agent_id, snap);
    }

    pub async fn upsert_reputation(&self, agent_id: [u8; 32], snap: ReputationSnapshot) {
        self.0.reputation.write().await.insert(agent_id, snap);
    }

    pub async fn push_batch(&self, snap: BatchSnapshot) {
        let mut batches = self.0.batches.write().await;
        batches.push(snap);
        if batches.len() > 200 {
            batches.remove(0);
        }
    }

    /// Broadcast a visualization event to all /ws/events subscribers.
    pub fn send_event(&self, event: ApiEvent) {
        let _ = self.0.event_tx.send(event);
    }

    pub fn get_current_slot(&self) -> u64 {
        self.0
            .current_slot
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    // ── Agent integration helpers ─────────────────────────────────────────────

    /// Push a validated inbound envelope to all /ws/inbox subscribers.
    ///
    /// Called by the node loop after every successfully validated envelope.
    pub fn push_inbound(&self, env: &zerox1_protocol::envelope::Envelope, slot: u64) {
        // Decode protocol-defined payloads for convenience.
        let feedback = if env.msg_type == zerox1_protocol::message::MsgType::Feedback {
            FeedbackPayload::decode(&env.payload).ok().map(|p| {
                serde_json::json!({
                    "conversation_id": hex::encode(p.conversation_id),
                    "target_agent":    hex::encode(p.target_agent),
                    "score":           p.score,
                    "outcome":         p.outcome,
                    "is_dispute":      p.is_dispute,
                    "role":            p.role,
                })
            })
        } else {
            None
        };

        let inbound = InboundEnvelope {
            msg_type: format!("{}", env.msg_type),
            sender: hex::encode(env.sender),
            recipient: hex::encode(env.recipient),
            conversation_id: hex::encode(env.conversation_id),
            slot,
            nonce: env.nonce,
            payload_b64: B64.encode(&env.payload),
            feedback,
        };

        let _ = self.0.inbox_tx.send(inbound);
    }

    /// Queue an outbound envelope request to the node loop.
    ///
    /// Called by the POST /envelopes/send handler.
    pub async fn send_outbound(&self, req: OutboundRequest) -> Result<(), String> {
        self.0
            .outbound_tx
            .send(req)
            .await
            .map_err(|_| "node loop unavailable".to_string())
    }

    /// Queue a pre-signed hosted-agent envelope to the node loop for gossipsub broadcast.
    pub async fn send_hosted_outbound(&self, env: Envelope) -> Result<(), String> {
        self.0
            .hosted_outbound_tx
            .send(env)
            .await
            .map_err(|_| "node loop unavailable".to_string())
    }
}

// ============================================================================
// Server
// ============================================================================

pub async fn serve(state: ApiState, addr: SocketAddr, cors_origins: Vec<String>) {
    let router = Router::new()
        // Visualization
        .route("/ws/events", get(ws_events_handler))
        .route("/identity", get(get_identity))
        .route("/peers", get(get_peers))
        .route("/reputation/{agent_id}", get(get_reputation))
        .route("/batch/{agent_id}/{epoch}", get(get_batch))
        // Agent integration
        .route("/envelopes/send", post(send_envelope))
        .route("/ws/inbox", get(ws_inbox_handler))
        // High-level negotiate endpoints (encode + send)
        .route("/negotiate/propose", post(negotiate_propose))
        .route("/negotiate/counter", post(negotiate_counter))
        .route("/negotiate/accept", post(negotiate_accept))
        // Hosted-agent API
        .route("/hosted/ping", get(hosted_ping))
        .route("/hosted/register", post(hosted_register))
        .route("/hosted/send", post(hosted_send))
        .route("/hosted/negotiate/propose", post(hosted_negotiate_propose))
        .route("/hosted/negotiate/counter", post(hosted_negotiate_counter))
        .route("/hosted/negotiate/accept", post(hosted_negotiate_accept))
        .route("/ws/hosted/inbox", get(ws_hosted_inbox_handler))
        // Agent process management (skill hot-reload)
        .route("/agent/register-pid", post(agent_register_pid))
        .route("/agent/reload", post(agent_reload))
        // Skill manager — safe Rust-side file operations (no shell injection)
        .route("/skill/list", get(skill_list_handler))
        .route("/skill/write", post(skill_write_handler))
        .route("/skill/install-url", post(skill_install_url_handler))
        .route("/skill/remove", post(skill_remove_handler));

    let app = router
        .layer({
            let origins: Vec<axum::http::HeaderValue> = if cors_origins.is_empty() {
                // Default: loopback only (zeroclaw, React Native WebView).
                vec![
                    "http://127.0.0.1".parse().expect("valid CORS origin"),
                    "http://localhost".parse().expect("valid CORS origin"),
                ]
            } else {
                cors_origins.iter().filter_map(|o| o.parse().ok()).collect()
            };
            tower_http::cors::CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers(tower_http::cors::Any)
        })
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("API listener bind failed on {addr}: {e}");
            return;
        }
    };

    tracing::info!("API listening on http://{addr}");

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("API server error on {addr}: {e}");
    }
}

// ============================================================================
// Visualization route handlers
// ============================================================================

async fn ws_events_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(resp) = require_read_or_master_ws(&state, &headers, &params) {
        return resp;
    }
    ws.on_upgrade(|socket| ws_events_task(socket, state))
}

async fn ws_events_task(mut socket: WebSocket, state: ApiState) {
    let mut rx = state.0.event_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => match serde_json::to_string(&event) {
                Ok(json) => {
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("WS events serialize error: {e}"),
            },
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

async fn get_identity(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    Json(serde_json::json!({
        "agent_id": hex::encode(state.0.self_agent),
        "name":     state.0.self_name,
    }))
    .into_response()
}

async fn get_peers(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let peers = state.0.peers.read().await;
    let list: Vec<_> = peers.values().cloned().collect();
    Json(serde_json::to_value(list).unwrap_or_default()).into_response()
}

async fn get_reputation(
    Path(agent_id_hex): Path<String>,
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let Ok(bytes) = hex::decode(&agent_id_hex) else {
        return Json(serde_json::json!({ "error": "invalid agent_id hex" })).into_response();
    };
    let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> else {
        return Json(serde_json::json!({ "error": "agent_id must be 32 bytes" })).into_response();
    };
    let rep = state.0.reputation.read().await;
    match rep.get(&arr) {
        Some(snap) => Json(serde_json::to_value(snap).unwrap_or_default()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no reputation data" })),
        )
            .into_response(),
    }
}

async fn get_batch(
    Path((agent_id_hex, epoch)): Path<(String, u64)>,
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let self_hex = hex::encode(state.0.self_agent);
    if agent_id_hex != self_hex {
        return Json(serde_json::json!({
            "error": "batch history is only available for this node's own agent_id"
        }))
        .into_response();
    }
    let batches = state.0.batches.read().await;
    match batches.iter().find(|b| b.epoch == epoch) {
        Some(snap) => Json(serde_json::to_value(snap).unwrap_or_default()).into_response(),
        None => Json(serde_json::json!({ "error": "epoch not found" })).into_response(),
    }
}

// ============================================================================
// Agent integration route handlers
// ============================================================================

async fn send_envelope(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<SendEnvelopeRequest>,
) -> impl IntoResponse {
    // Authenticate: only the master secret (not read-only keys) can send envelopes.
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }

    // Shared API-level rate limit to reduce flooding impact if credentials leak.
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }

    // Parse msg_type.
    let msg_type = match parse_msg_type(&req.msg_type) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("unknown msg_type: {}", req.msg_type) })),
            )
        }
    };

    // Parse recipient.
    let recipient: [u8; 32] = if msg_type.is_broadcast()
        || msg_type.is_reputation_pubsub()
    {
        BROADCAST_RECIPIENT
    } else {
        match &req.recipient {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "recipient required for bilateral messages" }),
                    ),
                )
            }
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(b) => match b.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": "recipient must be 32 bytes" })),
                        )
                    }
                },
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "recipient: invalid hex" })),
                    )
                }
            },
        }
    };

    // Parse conversation_id.
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id) {
        Ok(b) => match b.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "conversation_id must be 16 bytes" })),
                )
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "conversation_id: invalid hex" })),
            )
        }
    };

    // Guard against oversized payloads before decoding — base64 of 64 KB ≈ 88 KB.
    const MAX_PAYLOAD_B64_LEN: usize = (zerox1_protocol::constants::MAX_MESSAGE_SIZE / 3 + 1) * 4;
    if req.payload_b64.len() > MAX_PAYLOAD_B64_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "payload_b64: exceeds maximum envelope size" })),
        );
    }

    // Decode payload.
    let payload = match B64.decode(&req.payload_b64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payload_b64: invalid base64" })),
            )
        }
    };

    // Send to node loop via oneshot.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };

    if state.send_outbound(outbound).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }

    match reply_rx.await {
        Ok(Ok(conf)) => (
            StatusCode::OK,
            Json(serde_json::to_value(conf).unwrap_or_default()),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "node loop dropped reply" })),
        ),
    }
}

async fn ws_inbox_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(resp) = require_read_or_master_ws(&state, &headers, &params) {
        return resp;
    }
    ws.on_upgrade(|socket| ws_inbox_task(socket, state))
}

async fn ws_inbox_task(mut socket: WebSocket, state: ApiState) {
    let mut rx = state.0.inbox_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(env) => match serde_json::to_string(&env) {
                Ok(json) => {
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("WS inbox serialize error: {e}"),
            },
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

// ============================================================================
// Negotiate route handlers (local)
// ============================================================================

/// POST /negotiate/propose
///
/// Encodes amount + message into the standard negotiate wire format and sends
/// a PROPOSE envelope. Conversation ID is auto-generated if not supplied.
async fn negotiate_propose(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateProposeRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let (conv_id_hex, conversation_id) = match req.conversation_id {
        Some(ref s) => match hex::decode(s).ok().and_then(|b| b.try_into().ok()) {
            Some(a) => (s.clone(), a),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                    ),
                )
            }
        },
        None => {
            let b = rand::random::<[u8; 16]>();
            (hex::encode(b), b)
        }
    };
    let amount = req.amount_usdc_micro.unwrap_or(0);
    let max_rounds = req.max_rounds.unwrap_or(2);
    let payload = build_negotiate_payload(
        amount,
        serde_json::json!({
            "max_rounds": max_rounds,
            "message": req.message,
        }),
    );
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: MsgType::Propose,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };
    if state.send_outbound(outbound).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    match reply_rx.await {
        Ok(Ok(conf)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "conversation_id": conv_id_hex,
                "nonce": conf.nonce,
                "payload_hash": conf.payload_hash,
            })),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "node loop dropped reply" })),
        ),
    }
}

/// POST /negotiate/counter
async fn negotiate_counter(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateCounterRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }
    let max_rounds = req.max_rounds.unwrap_or(2);
    if req.round == 0 || req.round > max_rounds {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("round {} is out of range [1, {}]", req.round, max_rounds)
            })),
        );
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let payload = build_negotiate_payload(
        req.amount_usdc_micro,
        serde_json::json!({
            "round": req.round,
            "max_rounds": max_rounds,
            "message": req.message.unwrap_or_default(),
        }),
    );
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: MsgType::Counter,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };
    if state.send_outbound(outbound).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    match reply_rx.await {
        Ok(Ok(conf)) => (
            StatusCode::OK,
            Json(serde_json::to_value(conf).unwrap_or_default()),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "node loop dropped reply" })),
        ),
    }
}

/// POST /negotiate/accept
async fn negotiate_accept(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateAcceptRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let payload = build_negotiate_payload(
        req.amount_usdc_micro,
        serde_json::json!({
            "message": req.message.unwrap_or_default(),
        }),
    );
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: MsgType::Accept,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };
    if state.send_outbound(outbound).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    match reply_rx.await {
        Ok(Ok(conf)) => (
            StatusCode::OK,
            Json(serde_json::to_value(conf).unwrap_or_default()),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "node loop dropped reply" })),
        ),
    }
}

// ============================================================================
// Hosted-agent route handlers
// ============================================================================

/// GET /hosted/ping — no auth. Returns immediately; used by mobile for RTT probing.
async fn hosted_ping() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

/// POST /hosted/register — open (no auth).
///
/// Generates a fresh ed25519 sub-keypair for the hosted agent.
/// Returns `{ "agent_id": "<hex64>", "token": "<hex64>" }`.
async fn hosted_register(State(state): State<ApiState>) -> impl IntoResponse {
    if state.0.api_secret.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "hosting requires api_secret" })),
        );
    }
    let now = now_secs();

    // Global rate limit for unauthenticated registration to prevent memory/RPC DoS
    {
        let mut rl = state.0.hosted_register_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        // Allow up to 60 registrations per minute globally (1 per second average).
        // This accommodates normal web/mobile app usage while preventing massive DoS bursts.
        if rl.count >= 60 {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "registration rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }

    let mut sessions = state.0.hosted_sessions.write().await;

    // Evict expired sessions before checking capacity.
    sessions.retain(|_, s| now.saturating_sub(s.created_at) < SESSION_TTL_SECS);

    if sessions.len() >= MAX_HOSTED_SESSIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "host at capacity" })),
        );
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let agent_id = signing_key.verifying_key().to_bytes();
    let token = hex::encode(rand::random::<[u8; 32]>());

    let session = HostedSession {
        agent_id,
        signing_key,
        created_at: now,
        nonce: 0,
        rate_window_start: now,
        sends_in_window: 0,
    };
    sessions.insert(token.clone(), session);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "agent_id": hex::encode(agent_id),
            "token":    token,
        })),
    )
}

/// POST /hosted/send — `Authorization: Bearer <token>`.
///
/// Signs an envelope using the session sub-keypair and forwards it to the
/// node loop for gossipsub broadcast.
async fn hosted_send(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<HostedSendRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };

    // Rate limit: cap hosted sends to prevent mesh spam if a token is compromised.
    {
        let now = now_secs();
        let mut rl = state.0.hosted_send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_HOSTED_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            );
        }
        rl.count += 1;
    }

    // Parse msg_type.
    let msg_type = match parse_msg_type(&req.msg_type) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("unknown msg_type: {}", req.msg_type) })),
            )
        }
    };

    // Parse recipient.
    let recipient: [u8; 32] = if msg_type.is_broadcast()
        || msg_type.is_reputation_pubsub()
    {
        BROADCAST_RECIPIENT
    } else {
        match &req.recipient {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "recipient required for bilateral messages" }),
                    ),
                )
            }
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(b) => match b.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": "recipient must be 32 bytes" })),
                        )
                    }
                },
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "recipient: invalid hex" })),
                    )
                }
            },
        }
    };

    // Parse conversation_id.
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id) {
        Ok(b) => match b.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "conversation_id must be 16 bytes" })),
                )
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "conversation_id: invalid hex" })),
            )
        }
    };

    // Guard against oversized payloads before decoding — hex of 64 KB = 128 KB.
    const MAX_PAYLOAD_HEX_LEN: usize = zerox1_protocol::constants::MAX_MESSAGE_SIZE * 2;
    if req.payload_hex.len() > MAX_PAYLOAD_HEX_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "payload_hex: exceeds maximum envelope size" })),
        );
    }

    // Decode payload.
    let payload = match hex::decode(&req.payload_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payload_hex: invalid hex" })),
            )
        }
    };

    // Build pre-signed envelope using the session sub-keypair.
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };

        // Session TTL check.
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }

        // Rate limiting: sliding 60-second window.
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        session.sends_in_window += 1;
        if session.sends_in_window > MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }

        session.nonce += 1;
        Envelope::build(
            msg_type,
            session.agent_id,
            recipient,
            state.get_current_slot(),
            session.nonce,
            conversation_id,
            payload,
            &session.signing_key,
        )
    };

    if state.send_hosted_outbound(env).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }

    (StatusCode::NO_CONTENT, Json(serde_json::json!(null)))
}

/// POST /hosted/negotiate/propose — `Authorization: Bearer <token>`.
async fn hosted_negotiate_propose(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateProposeRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };
    {
        let now = now_secs();
        let mut rl = state.0.hosted_send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_HOSTED_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            );
        }
        rl.count += 1;
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let (conv_id_hex, conversation_id) = match req.conversation_id {
        Some(ref s) => match hex::decode(s).ok().and_then(|b| b.try_into().ok()) {
            Some(a) => (s.clone(), a),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                    ),
                )
            }
        },
        None => {
            let b = rand::random::<[u8; 16]>();
            (hex::encode(b), b)
        }
    };
    let amount = req.amount_usdc_micro.unwrap_or(0);
    let max_rounds = req.max_rounds.unwrap_or(2);
    let payload = build_negotiate_payload(
        amount,
        serde_json::json!({
            "max_rounds": max_rounds,
            "message": req.message,
        }),
    );
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        session.sends_in_window += 1;
        if session.sends_in_window > MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        session.nonce += 1;
        Envelope::build(
            MsgType::Propose,
            session.agent_id,
            recipient,
            state.get_current_slot(),
            session.nonce,
            conversation_id,
            payload,
            &session.signing_key,
        )
    };
    if state.send_hosted_outbound(env).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "conversation_id": conv_id_hex })),
    )
}

/// POST /hosted/negotiate/counter — `Authorization: Bearer <token>`.
async fn hosted_negotiate_counter(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateCounterRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };
    {
        let now = now_secs();
        let mut rl = state.0.hosted_send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_HOSTED_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            );
        }
        rl.count += 1;
    }
    let max_rounds = req.max_rounds.unwrap_or(2);
    if req.round == 0 || req.round > max_rounds {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("round {} is out of range [1, {}]", req.round, max_rounds)
            })),
        );
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let payload = build_negotiate_payload(
        req.amount_usdc_micro,
        serde_json::json!({
            "round": req.round,
            "max_rounds": max_rounds,
            "message": req.message.unwrap_or_default(),
        }),
    );
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        session.sends_in_window += 1;
        if session.sends_in_window > MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        session.nonce += 1;
        Envelope::build(
            MsgType::Counter,
            session.agent_id,
            recipient,
            state.get_current_slot(),
            session.nonce,
            conversation_id,
            payload,
            &session.signing_key,
        )
    };
    if state.send_hosted_outbound(env).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    (StatusCode::NO_CONTENT, Json(serde_json::json!(null)))
}

/// POST /hosted/negotiate/accept — `Authorization: Bearer <token>`.
async fn hosted_negotiate_accept(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateAcceptRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };
    {
        let now = now_secs();
        let mut rl = state.0.hosted_send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_HOSTED_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            );
        }
        rl.count += 1;
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let payload = build_negotiate_payload(
        req.amount_usdc_micro,
        serde_json::json!({
            "message": req.message.unwrap_or_default(),
        }),
    );
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        session.sends_in_window += 1;
        if session.sends_in_window > MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        session.nonce += 1;
        Envelope::build(
            MsgType::Accept,
            session.agent_id,
            recipient,
            state.get_current_slot(),
            session.nonce,
            conversation_id,
            payload,
            &session.signing_key,
        )
    };
    if state.send_hosted_outbound(env).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    (StatusCode::NO_CONTENT, Json(serde_json::json!(null)))
}

/// GET /ws/hosted/inbox
///
/// Opens a WebSocket and streams inbound envelopes addressed to the hosted
/// agent's agent_id.
///
/// Token is resolved with the following priority:
///   1. `Authorization: Bearer <token>` header (preferred — never logged)
///   2. `?token=<hex>` query param (deprecated — visible in server logs)
async fn ws_hosted_inbox_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(q): Query<HostedInboxQuery>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    let token = resolve_hosted_token(&headers).or_else(|| {
        if q.token.is_some() {
            tracing::warn!(
                "WS /ws/hosted/inbox: token passed via query param (deprecated). \
                     Use Authorization: Bearer header instead."
            );
        }
        q.token
    });

    match token {
        Some(t) => ws
            .on_upgrade(|socket| ws_hosted_inbox_task(socket, state, t))
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing Bearer token" })),
        )
            .into_response(),
    }
}

async fn ws_hosted_inbox_task(mut socket: WebSocket, state: ApiState, token: String) {
    // Resolve session to get agent_id for filtering; reject expired tokens.
    let agent_id_hex = {
        let sessions = state.0.hosted_sessions.read().await;
        match sessions.get(&token) {
            Some(s) => {
                if now_secs().saturating_sub(s.created_at) >= SESSION_TTL_SECS {
                    let _ = socket
                        .send(Message::Text(r#"{"error":"session expired"}"#.into()))
                        .await;
                    return;
                }
                hex::encode(s.agent_id)
            }
            None => {
                let _ = socket
                    .send(Message::Text(r#"{"error":"invalid token"}"#.into()))
                    .await;
                return;
            }
        }
    };

    let mut rx = state.0.inbox_tx.subscribe();
    loop {
        // Re-check TTL on each loop to avoid long-lived sockets after expiry.
        {
            let sessions = state.0.hosted_sessions.read().await;
            match sessions.get(&token) {
                Some(s) if now_secs().saturating_sub(s.created_at) < SESSION_TTL_SECS => {}
                _ => {
                    let _ = socket
                        .send(Message::Text(r#"{"error":"session expired"}"#.into()))
                        .await;
                    break;
                }
            }
        }
        match rx.recv().await {
            Ok(env) => {
                // Only forward envelopes addressed to this hosted agent.
                if env.recipient != agent_id_hex {
                    continue;
                }
                match serde_json::to_string(&env) {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::warn!("WS hosted inbox serialize error: {e}"),
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_msg_type(s: &str) -> Option<MsgType> {
    match s.to_uppercase().as_str() {
        // Infrastructure
        "ADVERTISE"   => Some(MsgType::Advertise),
        "DISCOVER"    => Some(MsgType::Discover),
        "BEACON"      => Some(MsgType::Beacon),
        "FEEDBACK"    => Some(MsgType::Feedback),
        // Collaboration
        "ASSIGN"      => Some(MsgType::Assign),
        "ACK"         => Some(MsgType::Ack),
        "CLARIFY"     => Some(MsgType::Clarify),
        "REPORT"      => Some(MsgType::Report),
        "APPROVE"     => Some(MsgType::Approve),
        "TASK_CANCEL" => Some(MsgType::TaskCancel),
        "ESCALATE"    => Some(MsgType::Escalate),
        "SYNC"        => Some(MsgType::Sync),
        // Negotiation
        "PROPOSE"     => Some(MsgType::Propose),
        "COUNTER"     => Some(MsgType::Counter),
        "ACCEPT"      => Some(MsgType::Accept),
        "DELIVER"     => Some(MsgType::Deliver),
        "DISPUTE"     => Some(MsgType::Dispute),
        "REJECT"      => Some(MsgType::Reject),
        "DEAL_CANCEL" => Some(MsgType::DealCancel),
        _ => None,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let len = a.len().max(b.len());
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

pub(crate) fn require_api_secret_or_unauthorized(
    state: &ApiState,
    headers: &HeaderMap,
) -> Option<Response> {
    let has_read_keys = !state.0.api_read_keys.is_empty();
    if let Some(ref secret) = state.0.api_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, secret.as_str()) {
            return Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "unauthorized" })),
                )
                    .into_response(),
            );
        }
        return None;
    }

    if has_read_keys {
        // Operator intended to secure the node but forgot the master secret.
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": "unauthorized: mutating endpoints require api_secret" }),
                ),
            )
                .into_response(),
        );
    }
    None
}

/// Like `require_api_secret_or_unauthorized` but ALSO accepts any read-only key
/// from `--api-read-keys`. Used for GET/WS visualization endpoints that the
/// explorer team needs without granting write access.
fn require_read_or_master_access(state: &ApiState, headers: &HeaderMap) -> Option<Response> {
    // If no master secret is configured, all endpoints are open (dev mode).
    let has_master = state.0.api_secret.is_some();
    let has_read_keys = !state.0.api_read_keys.is_empty();
    if !has_master && !has_read_keys {
        return None;
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    // Check master key first.
    if let Some(ref secret) = state.0.api_secret {
        if ct_eq(provided, secret.as_str()) {
            return None; // master key — full access
        }
    }

    // Check read-only keys.
    for key in &state.0.api_read_keys {
        if ct_eq(provided, key.as_str()) {
            return None; // valid read key
        }
    }

    Some(
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response(),
    )
}

/// WS variant: extract token from `Authorization` header OR `?token=` query param,
/// then check read-only OR master key.
fn require_read_or_master_ws(
    state: &ApiState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Option<Response> {
    let has_master = state.0.api_secret.is_some();
    let has_read_keys = !state.0.api_read_keys.is_empty();
    if !has_master && !has_read_keys {
        return None;
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| params.get("token").map(|s| s.as_str()))
        .unwrap_or("");

    if let Some(ref secret) = state.0.api_secret {
        if ct_eq(provided, secret.as_str()) {
            return None;
        }
    }
    for key in &state.0.api_read_keys {
        if ct_eq(provided, key.as_str()) {
            return None;
        }
    }

    Some(StatusCode::UNAUTHORIZED.into_response())
}

/// Extract the Bearer token from an `Authorization: Bearer <token>` header.
pub(crate) fn resolve_hosted_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}







// ============================================================================
// Agent process management — skill hot-reload
// ============================================================================

const MAX_AGENT_RELOAD_PER_MINUTE: u32 = 3;

#[derive(Deserialize)]
struct RegisterPidRequest {
    pid: u32,
}

/// Return the real UID of `pid` by reading /proc/{pid}/status.
/// Returns `None` if the file cannot be read or parsed.
#[cfg(unix)]
fn proc_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Format: "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// POST /agent/register-pid — called by NodeService after starting zeroclaw.
///
/// Requires auth (same as other mutating endpoints). Validates that the given
/// PID belongs to a user-space process owned by the same UID as the node to
/// prevent an attacker from registering arbitrary system PIDs.
async fn agent_register_pid(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterPidRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Reject system PIDs and kernel threads — user processes start at 1024+.
    if req.pid < 1024 || req.pid > 4_194_304 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "pid out of user-space range"})),
        )
            .into_response();
    }

    // Verify the PID belongs to the same UID as the current process.
    // Prevents an attacker from registering a PID they don't own.
    #[cfg(unix)]
    {
        let our_uid = unsafe { libc::getuid() };
        match proc_uid(req.pid) {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "process not found or not readable"})),
                )
                    .into_response()
            }
            Some(pid_uid) if pid_uid != our_uid => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "pid belongs to a different user"})),
                )
                    .into_response()
            }
            _ => {}
        }
    }

    *state.0.agent_pid.lock().await = Some(req.pid);
    tracing::info!("Agent PID registered: {}", req.pid);
    Json(serde_json::json!({"ok": true})).into_response()
}

/// POST /agent/reload — signal zeroclaw to restart so it picks up new skills.
///
/// Sends SIGTERM to the registered zeroclaw PID. NodeService's restart loop
/// automatically re-launches zeroclaw, which re-reads all SKILL.toml files.
/// Rate-limited to 3 reloads per minute to prevent DoS via reload loop.
async fn agent_reload(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Rate limit: max 3 reloads per minute.
    {
        let mut rl = state.0.agent_reload_rate_limit.lock().await;
        let now = now_secs();
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_AGENT_RELOAD_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "reload rate limit exceeded (max 3/min)"})),
            )
                .into_response();
        }
        rl.count += 1;
    }

    let pid = *state.0.agent_pid.lock().await;
    match pid {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "No agent PID registered — is zeroclaw running?"})),
        )
            .into_response(),
        Some(pid) => {
            // SIGTERM — zeroclaw exits gracefully, NodeService auto-restarts it.
            // kill(2) is Unix-only; on Windows the skill manager cannot be used
            // (zeroclaw only runs on Android/Linux), so return a clear error.
            #[cfg(unix)]
            {
                let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                if result == 0 {
                    tracing::info!("Sent SIGTERM to agent PID {pid} for skill reload");
                    Json(serde_json::json!({"ok": true, "pid": pid})).into_response()
                } else {
                    let err = std::io::Error::last_os_error();
                    tracing::warn!("Failed to send SIGTERM to agent PID {pid}: {err}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("kill({pid}): {err}")})),
                    )
                        .into_response()
                }
            }
            #[cfg(not(unix))]
            {
                let _ = pid;
                (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(serde_json::json!({"error": "agent reload not supported on this platform"})),
                )
                    .into_response()
            }
        }
    }
}

// ============================================================================
// Skill manager REST endpoints — safe Rust-side file operations
// ============================================================================

/// Validate a skill name: lowercase alphanumeric + hyphens + underscores,
/// no path separators, no leading hyphens, 1–64 chars.
fn validate_skill_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 64 {
        return Err("skill name must be 1–64 chars");
    }
    if name.starts_with('-') || name.starts_with('_') {
        return Err("skill name must start with a letter or digit");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("skill name may only contain lowercase letters, digits, hyphens, underscores");
    }
    Ok(())
}

/// Check that `path` is strictly inside `base` (no path traversal).
fn is_inside(path: &std::path::Path, base: &std::path::Path) -> bool {
    // Both paths must be canonicalized by the caller.
    path.starts_with(base)
}

macro_rules! skill_workspace {
    ($state:expr) => {
        match $state.0.skill_workspace.as_ref() {
            Some(w) => w,
            None => return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "skill workspace not configured (--skill-workspace)"})),
            ).into_response(),
        }
    };
}

/// GET /skill/list — list installed skill names.
async fn skill_list_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let workspace = skill_workspace!(state);
    let skills_dir = workspace.join("skills");
    let mut skills: Vec<String> = Vec::new();
    match tokio::fs::read_dir(&skills_dir).await {
        Ok(mut dir) => {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Ok(ft) = entry.file_type().await {
                    if ft.is_dir() {
                        skills.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
            }
        }
        Err(_) => { /* directory doesn't exist yet — empty list */ }
    }
    skills.sort();
    Json(serde_json::json!({"skills": skills})).into_response()
}

#[derive(Deserialize)]
struct SkillWriteRequest {
    name: String,
    /// Base64-encoded SKILL.toml content.
    content_b64: String,
}

/// POST /skill/write — install a new skill by writing its SKILL.toml.
///
/// `content_b64` must be the base64-encoded UTF-8 SKILL.toml. The name is
/// validated before any filesystem operation — no path traversal possible.
async fn skill_write_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SkillWriteRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if let Err(e) = validate_skill_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }
    let workspace = skill_workspace!(state);

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let content_bytes = match B64.decode(&req.content_b64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "content_b64 is not valid base64"})),
            )
                .into_response()
        }
    };
    if content_bytes.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "decoded content is empty"})),
        )
            .into_response();
    }
    let content_str = match String::from_utf8(content_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "content is not valid UTF-8"})),
            )
                .into_response()
        }
    };

    let skill_dir = workspace.join("skills").join(&req.name);
    if let Err(e) = tokio::fs::create_dir_all(&skill_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("mkdir: {e}")})),
        )
            .into_response();
    }
    let toml_path = skill_dir.join("SKILL.toml");
    if let Err(e) = tokio::fs::write(&toml_path, &content_str).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write: {e}")})),
        )
            .into_response();
    }
    tracing::info!("Skill '{}' written ({} bytes)", req.name, content_str.len());
    Json(serde_json::json!({"ok": true, "name": req.name})).into_response()
}

#[derive(Deserialize)]
struct SkillInstallUrlRequest {
    name: String,
    url: String,
}

/// Reject private/loopback IP ranges used in SSRF attacks.
fn is_private_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

/// POST /skill/install-url — fetch a SKILL.toml from an HTTPS URL and install it.
///
/// Only HTTPS is accepted. Private/loopback hosts are rejected to prevent SSRF.
/// The content size is capped at 128 KiB.
async fn skill_install_url_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SkillInstallUrlRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if let Err(e) = validate_skill_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }

    // Parse and validate URL.
    let parsed = match req.url.parse::<url::Url>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid URL"})),
            )
                .into_response()
        }
    };
    if parsed.scheme() != "https" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "only HTTPS URLs are accepted"})),
        )
            .into_response();
    }
    if let Some(host) = parsed.host_str() {
        if is_private_host(host) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "private/loopback hosts are not allowed"})),
            )
                .into_response();
        }
    }

    let workspace = skill_workspace!(state);

    // Fetch content via the shared HTTP client (safe, no shell involved).
    let resp = match state
        .0
        .http_client
        .get(parsed)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("fetch failed: {e}")})),
            )
                .into_response()
        }
    };
    if !resp.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("remote returned {}", resp.status())})),
        )
            .into_response();
    }

    const MAX_SKILL_BYTES: usize = 128 * 1024; // 128 KiB
    let content = match resp.text().await {
        Ok(t) if t.len() <= MAX_SKILL_BYTES => t,
        Ok(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({"error": "SKILL.toml exceeds 128 KiB limit"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("read body: {e}")})),
            )
                .into_response()
        }
    };

    let skill_dir = workspace.join("skills").join(&req.name);
    if let Err(e) = tokio::fs::create_dir_all(&skill_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("mkdir: {e}")})),
        )
            .into_response();
    }
    if let Err(e) = tokio::fs::write(skill_dir.join("SKILL.toml"), &content).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write: {e}")})),
        )
            .into_response();
    }
    tracing::info!(
        "Skill '{}' installed from URL ({} bytes)",
        req.name,
        content.len()
    );
    Json(serde_json::json!({"ok": true, "name": req.name, "bytes": content.len()})).into_response()
}

#[derive(Deserialize)]
struct SkillRemoveRequest {
    name: String,
}

/// POST /skill/remove — remove an installed skill by name.
///
/// The skill name is validated (no path traversal). The resulting path is
/// verified to be inside the skills directory before deletion.
async fn skill_remove_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SkillRemoveRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if let Err(e) = validate_skill_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }
    let workspace = skill_workspace!(state);
    let skills_root = workspace.join("skills");
    let skill_dir = skills_root.join(&req.name);

    // Canonicalize both paths and verify containment — belt-and-suspenders against symlinks.
    let canonical_root = match skills_root.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "skills directory does not exist"})),
            )
                .into_response()
        }
    };
    let canonical_skill = match skill_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("skill '{}' not found", req.name)})),
            )
                .into_response()
        }
    };
    if !is_inside(&canonical_skill, &canonical_root) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "path traversal detected"})),
        )
            .into_response();
    }

    if let Err(e) = tokio::fs::remove_dir_all(&skill_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("remove: {e}")})),
        )
            .into_response();
    }
    tracing::info!("Skill '{}' removed", req.name);
    Json(serde_json::json!({"ok": true, "name": req.name})).into_response()
}

