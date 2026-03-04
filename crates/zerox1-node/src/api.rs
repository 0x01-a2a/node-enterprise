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
//! 8004 Solana Agent Registry:
//!   GET  /registry/8004/info              — Program IDs, collection, step-by-step guide
//!   POST /registry/8004/register-prepare  — Build partially-signed tx (agent signs message_b64)
//!   POST /registry/8004/register-submit   — Inject owner sig + broadcast to Solana

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

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
use solana_sdk::pubkey::Pubkey;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use crate::registry_8004::{
    broadcast_transaction, build_register_tx, fetch_latest_blockhash, COLLECTION_DEVNET,
    PROGRAM_ID_DEVNET, PROGRAM_ID_MAINNET,
};

use zerox1_protocol::{
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::{FeedbackPayload, NotarizeBidPayload},
};

// ============================================================================
// Snapshot types — serialisable views of node state (visualization)
// ============================================================================

#[derive(Clone, Serialize)]
pub struct PeerSnapshot {
    pub agent_id: String,
    pub peer_id: Option<String>,
    pub sati_ok: Option<bool>,
    pub lease_ok: Option<bool>,
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
    LeaseStatus {
        agent_id: String,
        active: bool,
    },
    SatiStatus {
        agent_id: String,
        registered: bool,
    },
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
    /// Decoded NOTARIZE_BID payload fields (only present for NOTARIZE_BID messages).
    pub notarize_bid: Option<serde_json::Value>,
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
/// Maximum `/registry/8004/register-prepare` requests per 60-second window.
/// Each request makes an external Solana RPC call, so cap tightly.
const MAX_REGISTRY_PREPARE_PER_MINUTE: u32 = 10;

// USDC sweep constants
const USDC_MINT_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";
/// Minimum balance (atomic USDC units, 6 decimals) required to attempt a sweep.
const MIN_SWEEP_AMOUNT: u64 = 10_000;

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

struct ApiInner {
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
    hosted_sessions: Arc<RwLock<HashMap<String, HostedSession>>>,
    #[allow(dead_code)]
    hosting_fee_bps: u32,
    /// Pre-signed envelopes from hosted-agent send handler → node loop.
    hosted_outbound_tx: mpsc::Sender<Envelope>,
    /// Global rate limit window for `/envelopes/send`.
    send_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/hosted/register`.
    hosted_register_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/registry/8004/register-prepare`.
    registry_prepare_rate_limit: Mutex<RateLimitWindow>,

    // 8004 registry helpers
    /// Solana RPC URL — used by registry endpoints for blockhash + broadcast.
    rpc_url: String,
    /// Node's own Ed25519 signing key — used for /wallet/sweep.
    node_signing_key: Arc<SigningKey>,
    /// Shared HTTP client for registry RPC calls.
    http_client: reqwest::Client,
    /// Whether this node is pointed at mainnet-beta (affects 8004 program IDs).
    is_mainnet: bool,
    /// Optional override for the 8004 base collection (required on mainnet).
    registry_8004_collection: Option<String>,
    /// The current Solana slot, continuously updated by the node event loop.
    current_slot: core::sync::atomic::AtomicU64,
}

/// Cheaply cloneable shared state passed to all axum handlers.
#[derive(Clone)]
pub struct ApiState(Arc<ApiInner>);

impl ApiState {
    /// Create a new ApiState.
    ///
    /// Returns `(state, outbound_rx, hosted_outbound_rx)`. The caller (node)
    /// must hold onto both receivers and drive them in the main event loop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        self_agent: [u8; 32],
        self_name: String,
        api_secret: Option<String>,
        api_read_keys: Vec<String>,
        hosting_fee_bps: u32,
        rpc_url: String,
        http_client: reqwest::Client,
        registry_8004_collection: Option<String>,
        node_signing_key: Arc<SigningKey>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundRequest>,
        mpsc::Receiver<Envelope>,
    ) {
        let is_mainnet = rpc_url.contains("mainnet-beta");
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
            registry_prepare_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            rpc_url,
            node_signing_key,
            http_client,
            is_mainnet,
            registry_8004_collection,
            current_slot: core::sync::atomic::AtomicU64::new(0),
        }));

        (state, outbound_rx, hosted_outbound_rx)
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

    pub fn set_current_slot(&self, slot: u64) {
        self.0.current_slot.store(slot, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_current_slot(&self) -> u64 {
        self.0.current_slot.load(core::sync::atomic::Ordering::Relaxed)
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

        let notarize_bid = if env.msg_type == zerox1_protocol::message::MsgType::NotarizeBid {
            NotarizeBidPayload::decode(&env.payload).ok().map(|p| {
                serde_json::json!({
                    "bid_type":        p.bid_type,
                    "conversation_id": hex::encode(p.conversation_id),
                    "opaque_b64":      B64.encode(&p.opaque),
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
            notarize_bid,
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

pub async fn serve(state: ApiState, addr: SocketAddr) {
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
        // Hosted-agent API
        .route("/hosted/ping", get(hosted_ping))
        .route("/hosted/register", post(hosted_register))
        .route("/hosted/send", post(hosted_send))
        .route("/ws/hosted/inbox", get(ws_hosted_inbox_handler))
        // 8004 Solana Agent Registry helpers
        .route("/registry/8004/info", get(registry_8004_info))
        .route("/registry/8004/register-prepare", post(registry_8004_register_prepare))
        .route("/registry/8004/register-submit", post(registry_8004_register_submit))
        // Hot wallet sweep
        .route("/wallet/sweep", post(sweep_usdc))
        .layer(
            // INFO-2: Local API — only allow loopback origins (zeroclaw, React Native).
            tower_http::cors::CorsLayer::new()
                .allow_origin([
                    "http://127.0.0.1"
                        .parse::<axum::http::HeaderValue>()
                        .expect("hardcoded CORS origin '127.0.0.1' failed to parse"),
                    "http://localhost"
                        .parse::<axum::http::HeaderValue>()
                        .expect("hardcoded CORS origin 'localhost' failed to parse"),
                ])
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("API listener bind failed");

    tracing::info!("API listening on http://{addr}");

    axum::serve(listener, router)
        .await
        .expect("API server error");
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
        None => {
            Json(serde_json::json!({ "agent_id": agent_id_hex, "score": null })).into_response()
        }
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
        || msg_type.is_notary_pubsub()
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
    const MAX_PAYLOAD_B64_LEN: usize =
        (zerox1_protocol::constants::MAX_MESSAGE_SIZE / 3 + 1) * 4;
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
        || msg_type.is_notary_pubsub()
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
        "ADVERTISE" => Some(MsgType::Advertise),
        "DISCOVER" => Some(MsgType::Discover),
        "PROPOSE" => Some(MsgType::Propose),
        "COUNTER" => Some(MsgType::Counter),
        "ACCEPT" => Some(MsgType::Accept),
        "REJECT" => Some(MsgType::Reject),
        "DELIVER" => Some(MsgType::Deliver),
        "NOTARIZE_BID" => Some(MsgType::NotarizeBid),
        "NOTARIZE_ASSIGN" => Some(MsgType::NotarizeAssign),
        "VERDICT" => Some(MsgType::Verdict),
        "FEEDBACK" => Some(MsgType::Feedback),
        "DISPUTE" => Some(MsgType::Dispute),
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

fn require_api_secret_or_unauthorized(state: &ApiState, headers: &HeaderMap) -> Option<Response> {
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
fn resolve_hosted_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

// ============================================================================
// 8004 Solana Agent Registry — registration helpers
// ============================================================================

/// GET /registry/8004/info
///
/// Returns the program constants, collection address, and step-by-step
/// instructions an agent needs to self-register in the 8004 registry.
/// No authentication required — this is public informational data.
async fn registry_8004_info(State(state): State<ApiState>) -> Response {
    let network = if state.0.is_mainnet { "mainnet-beta" } else { "devnet" };
    let program_id = if state.0.is_mainnet {
        PROGRAM_ID_MAINNET
    } else {
        PROGRAM_ID_DEVNET
    };
    let collection = state
        .0
        .registry_8004_collection
        .as_deref()
        .unwrap_or(if state.0.is_mainnet { "(query RootConfig or set ZX01_REGISTRY_8004_COLLECTION)" } else { COLLECTION_DEVNET });

    Json(serde_json::json!({
        "network":     network,
        "program_id":  program_id,
        "collection":  collection,
        "mpl_core":    "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d",
        "indexer_url": if state.0.is_mainnet {
            "https://8004.qnt.sh/v2/graphql"
        } else {
            "https://8004-indexer-production.up.railway.app/v2/graphql"
        },
        "register_via_node": {
            "prepare": "POST /registry/8004/register-prepare",
            "submit":  "POST /registry/8004/register-submit",
        },
        "steps": [
            "1. POST /registry/8004/register-prepare with { owner_pubkey, agent_uri? }",
            "2. Sign the returned message_b64 with your Ed25519/owner keypair",
            "3. POST /registry/8004/register-submit with { transaction_b64, owner_signature_b64 }",
            "4. Save the asset_pubkey — it is your permanent 8004 identity",
            "5. Within ~30 seconds the indexer will reflect your registration",
        ],
        "note": "Your 0x01 agent_id hex == your Solana owner pubkey (base58). No extra keys needed."
    }))
    .into_response()
}

/// Request body for POST /registry/8004/register-prepare.
#[derive(Deserialize)]
struct RegisterPrepareRequest {
    /// base58 Solana pubkey of the agent registering.
    /// Must equal the caller's Ed25519 agent_id (base58).
    owner_pubkey: String,
    /// Optional metadata URI (IPFS, Arweave, HTTPS, or empty).
    /// Points to a JSON file with name, description, endpoints, etc.
    /// Max 250 bytes.  Defaults to empty string.
    #[serde(default)]
    agent_uri: String,
}

/// POST /registry/8004/register-prepare
///
/// Builds a partially-signed `register` transaction for the 8004 Solana
/// Agent Registry.  The asset keypair is generated by the node and pre-signed;
/// the caller only needs to sign the message with their owner/Ed25519 key.
///
/// Returns:
/// - `asset_pubkey`      — store this; it is your on-chain 8004 identity
/// - `transaction_b64`   — bincode tx, asset already signed, owner slot empty
/// - `message_b64`       — raw message bytes to sign with owner Ed25519 key
/// - `signing_hint`      — instructions for completing the signature
///
/// Requires API secret if one is configured.
async fn registry_8004_register_prepare(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterPrepareRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Rate limit: this endpoint makes an external Solana RPC call per request.
    {
        let now = now_secs();
        let mut rl = state.0.registry_prepare_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_REGISTRY_PREPARE_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            )
                .into_response();
        }
        rl.count += 1;
    }

    // Validate agent_uri: reject control characters and C0/C1 chars that could
    // cause log injection or confuse on-chain metadata parsers.
    if req.agent_uri.chars().any(|c| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_uri: control characters not allowed" })),
        )
            .into_response();
    }

    let owner_pubkey: Pubkey = match req.owner_pubkey.parse() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid owner_pubkey: expected base58 Solana pubkey" })),
            )
                .into_response();
        }
    };

    // Fetch recent blockhash from the configured Solana RPC.
    let blockhash = match fetch_latest_blockhash(&state.0.rpc_url, &state.0.http_client).await {
        Ok(bh) => bh,
        Err(e) => {
            tracing::warn!("registry-prepare: blockhash fetch failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response();
        }
    };

    // Resolve collection override (mainnet requires explicit address).
    let collection_override = state
        .0
        .registry_8004_collection
        .as_deref()
        .and_then(|s| s.parse::<Pubkey>().ok());

    match build_register_tx(
        owner_pubkey,
        &req.agent_uri,
        blockhash,
        state.0.is_mainnet,
        collection_override,
    ) {
        Ok(prepared) => Json(serde_json::json!({
            "asset_pubkey":    prepared.asset_pubkey,
            "transaction_b64": prepared.transaction_b64,
            "message_b64":     prepared.message_b64,
            "signing_hint": concat!(
                "Sign message_b64 with your Ed25519 owner keypair (64-byte signature). ",
                "Then POST { transaction_b64, owner_signature_b64 } to /registry/8004/register-submit. ",
                "Or deserialize transaction_b64, add owner signature at index 0, and broadcast yourself."
            ),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("tx build failed: {e}") })),
        )
            .into_response(),
    }
}

/// Request body for POST /registry/8004/register-submit.
#[derive(Deserialize)]
struct RegisterSubmitRequest {
    /// base64 bincode Solana transaction (from register-prepare, asset already signed).
    transaction_b64: String,
    /// base64 64-byte Ed25519 signature of the transaction message by the owner keypair.
    owner_signature_b64: String,
}

/// POST /registry/8004/register-submit
///
/// Injects the owner's Ed25519 signature into the prepared transaction and
/// broadcasts it to Solana via the configured RPC endpoint.
///
/// Returns `{ signature }` — the Solana transaction signature (base58).
///
/// Requires API secret if one is configured.
async fn registry_8004_register_submit(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterSubmitRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Decode and validate the owner signature.
    let sig_bytes = match B64.decode(&req.owner_signature_b64) {
        Ok(b) if b.len() == 64 => b,
        Ok(b) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("owner_signature_b64 must be 64 bytes, got {}", b.len())
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid owner_signature_b64: {e}") })),
            )
                .into_response();
        }
    };

    // Guard transaction size: Solana max tx is 1232 bytes → ~1644 base64 chars.
    // Allow 2× headroom for padding/overhead before even decoding.
    const MAX_TX_B64_LEN: usize = 3300;
    if req.transaction_b64.len() > MAX_TX_B64_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "transaction_b64: exceeds maximum transaction size" })),
        )
            .into_response();
    }

    // Decode the partially-signed transaction.
    let tx_bytes = match B64.decode(&req.transaction_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid transaction_b64: {e}") })),
            )
                .into_response();
        }
    };

    let mut tx: solana_sdk::transaction::Transaction =
        match bincode::deserialize(&tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("transaction deserialize failed: {e}") })),
                )
                    .into_response();
            }
        };

    // The register tx must have exactly 2 signature slots: owner (index 0) + asset (index 1).
    // Also verify the fee payer is in account_keys[0] to prevent owner impersonation.
    if tx.signatures.len() != 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "expected 2 signature slots (owner + asset), got {}",
                    tx.signatures.len()
                )
            })),
        )
            .into_response();
    }

    // Security check (Prevent Open RPC Relay):
    // 1. Ensure exactly 1 instruction
    // 2. Ensure the instruction calls the expected 8004 registry program ID
    if tx.message.instructions.len() != 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "transaction must contain exactly 1 instruction, got {}",
                    tx.message.instructions.len()
                )
            })),
        )
            .into_response();
    }

    let program_id_str = if state.0.is_mainnet {
        crate::registry_8004::PROGRAM_ID_MAINNET
    } else {
        crate::registry_8004::PROGRAM_ID_DEVNET
    };
    
    let expected_program_id = program_id_str
        .parse::<solana_sdk::pubkey::Pubkey>()
        .expect("static program ID parses");

    let instruction_program_id = tx.message.instructions[0].program_id(&tx.message.account_keys);
    
    if instruction_program_id != &expected_program_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "invalid program ID: expected {}, got {}",
                    expected_program_id, instruction_program_id
                )
            })),
        )
            .into_response();
    }

    // Inject the owner signature at index 0 (owner is fee payer = first signer).
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("checked length above");
    tx.signatures[0] = solana_sdk::signature::Signature::from(sig_arr);

    // Re-serialize with owner signature injected and broadcast.
    let signed_bytes = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("re-serialize failed: {e}") })),
            )
                .into_response();
        }
    };
    let signed_b64 = B64.encode(&signed_bytes);

    match broadcast_transaction(&state.0.rpc_url, &state.0.http_client, &signed_b64).await {
        Ok(signature) => {
            tracing::info!("8004 registration broadcast: tx={signature}");
            Json(serde_json::json!({
                "signature": signature,
                "explorer":  format!(
                    "https://explorer.solana.com/tx/{}?cluster={}",
                    signature,
                    if state.0.is_mainnet { "mainnet-beta" } else { "devnet" }
                ),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("8004 registration broadcast failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Wallet sweep — POST /wallet/sweep
// ============================================================================

#[derive(Deserialize)]
pub(crate) struct SweepRequest {
    destination: String,
}

/// Convert an ed25519_dalek SigningKey to a solana_sdk Keypair.
///
/// solana_sdk::signature::Keypair is a 64-byte keypair: [secret(32) || public(32)].
fn to_solana_keypair(sk: &SigningKey) -> solana_sdk::signature::Keypair {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&sk.to_bytes());
    bytes[32..].copy_from_slice(sk.verifying_key().as_bytes());
    solana_sdk::signature::Keypair::try_from(bytes.as_slice()).expect("valid ed25519 keypair bytes")
}

/// Derive the Associated Token Account address for a given owner and mint.
fn derive_ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let spl_token: Pubkey = SPL_TOKEN_PROGRAM_ID.parse().expect("valid SPL_TOKEN_PROGRAM_ID");
    let ata_program: Pubkey = SPL_ATA_PROGRAM_ID.parse().expect("valid SPL_ATA_PROGRAM_ID");
    Pubkey::find_program_address(
        &[&owner.to_bytes(), &spl_token.to_bytes(), &mint.to_bytes()],
        &ata_program,
    )
    .0
}

/// POST /wallet/sweep
///
/// Transfers all USDC from the node's hot wallet ATA to `destination`.
/// The destination must be a base58-encoded Solana wallet (not an ATA — the
/// handler derives the destination ATA automatically).
///
/// Returns: `{ "signature": "...", "amount_usdc": 1.23, "destination": "..." }`
pub async fn sweep_usdc(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<SweepRequest>,
) -> Response {
    // CRITICAL: sweep moves real money — require master secret.
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    // 1. Validate destination pubkey.
    let destination: Pubkey = match body.destination.parse() {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid destination pubkey" })),
            )
                .into_response();
        }
    };

    // 2. Derive agent's hot wallet pubkey.
    let signing_key = Arc::clone(&state.0.node_signing_key);
    let agent_pubkey: Pubkey = {
        let vk_bytes = signing_key.verifying_key().to_bytes();
        Pubkey::new_from_array(vk_bytes)
    };

    // 3. Select USDC mint based on network.
    let usdc_mint_str = if state.0.is_mainnet {
        USDC_MINT_MAINNET
    } else {
        USDC_MINT_DEVNET
    };
    let usdc_mint: Pubkey = usdc_mint_str.parse().expect("valid USDC mint");

    // 4. Derive source and destination ATAs.
    let source_ata = derive_ata(&agent_pubkey, &usdc_mint);
    let dest_ata = derive_ata(&destination, &usdc_mint);

    // 5. Query source ATA balance via RPC.
    let balance_resp = state
        .0
        .http_client
        .post(&state.0.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountBalance",
            "params": [source_ata.to_string()]
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let amount: u64 = match balance_resp {
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("RPC request failed: {e}") })),
            )
                .into_response();
        }
        Ok(resp) => {
            let data: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({ "error": format!("RPC parse error: {e}") })),
                    )
                        .into_response();
                }
            };
            if data.get("error").is_some() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "token account not found or has no balance" })),
                )
                    .into_response();
            }
            match data["result"]["value"]["amount"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
            {
                Some(v) => v,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({ "error": "token account not found or has no balance" })),
                    )
                        .into_response();
                }
            }
        }
    };

    if amount < MIN_SWEEP_AMOUNT {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "balance too low to sweep",
                "amount_atomic": amount,
                "min_atomic": MIN_SWEEP_AMOUNT,
            })),
        )
            .into_response();
    }

    // 6. Build SPL Token Transfer instruction (discriminant 3).
    let spl_token_program: Pubkey =
        SPL_TOKEN_PROGRAM_ID.parse().expect("valid SPL_TOKEN_PROGRAM_ID");
    let mut ix_data = vec![3u8];
    ix_data.extend_from_slice(&amount.to_le_bytes());
    let transfer_ix = solana_sdk::instruction::Instruction {
        program_id: spl_token_program,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(source_ata, false),
            solana_sdk::instruction::AccountMeta::new(dest_ata, false),
            solana_sdk::instruction::AccountMeta::new(agent_pubkey, true),
        ],
        data: ix_data,
    };

    // 7. Fetch recent blockhash.
    let blockhash = match fetch_latest_blockhash(&state.0.rpc_url, &state.0.http_client).await {
        Ok(bh) => bh,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response();
        }
    };

    // 8. Build, sign, and serialize the transaction.
    let solana_kp = to_solana_keypair(&signing_key);
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&agent_pubkey),
        &[&solana_kp],
        blockhash,
    );

    let serialized = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("tx serialization failed: {e}") })),
            )
                .into_response();
        }
    };
    let signed_b64 = B64.encode(&serialized);

    // 9. Broadcast.
    match broadcast_transaction(&state.0.rpc_url, &state.0.http_client, &signed_b64).await {
        Ok(signature) => {
            let amount_usdc = amount as f64 / 1_000_000.0;
            tracing::info!("Swept {amount_usdc:.6} USDC → {destination}: tx={signature}");
            Json(serde_json::json!({
                "signature": signature,
                "amount_usdc": amount_usdc,
                "destination": destination.to_string(),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("sweep broadcast failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
            )
                .into_response()
        }
    }
}
