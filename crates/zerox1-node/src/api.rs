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
    collections::{HashMap, HashSet},
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
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use crate::{
    kora::KoraClient,
    registry_8004::{
        broadcast_transaction, build_register_tx, fetch_latest_blockhash, COLLECTION_DEVNET,
        PROGRAM_ID_DEVNET, PROGRAM_ID_MAINNET,
    },
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
    #[cfg(feature = "bags")]
    BagsFee {
        amount_usdc: f64,
        txid: String,
        timestamp: u64,
    },
    #[cfg(feature = "bags")]
    BagsLaunch {
        token_mint: String,
        name: String,
        symbol: String,
        txid: String,
        timestamp: u64,
    },
    #[cfg(feature = "bags")]
    BagsClaim {
        token_mint: String,
        claimed_txs: usize,
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

// ── Escrow endpoint types ─────────────────────────────────────────────────

/// Request body for POST /escrow/lock.
#[derive(Deserialize)]
pub struct EscrowLockRequest {
    /// Hex-encoded 32-byte agent_id of the provider (payment recipient).
    pub provider: String,
    /// Hex-encoded 16-byte conversation ID.
    pub conversation_id: String,
    /// Amount to lock in USDC microunits (e.g. 1_000_000 = 1 USDC).
    pub amount_usdc_micro: u64,
    /// Notary fee in USDC microunits. Default: amount / 10.
    pub notary_fee: Option<u64>,
    /// Solana slot timeout before provider can claim without approval. Default: 1000.
    pub timeout_slots: Option<u64>,
    /// Optional hex-encoded 32-byte agent_id of a designated notary.
    pub notary: Option<String>,
}

/// Request body for POST /escrow/approve.
#[derive(Deserialize)]
pub struct EscrowApproveRequest {
    /// Hex-encoded 32-byte agent_id of the requester (payer).
    pub requester: String,
    /// Hex-encoded 32-byte agent_id of the provider (payee).
    pub provider: String,
    /// Hex-encoded 16-byte conversation ID.
    pub conversation_id: String,
    /// Optional hex-encoded 32-byte notary agent_id (defaults to self).
    pub notary: Option<String>,
    /// Settlement amount in USDC microunits — used by Bags fee-sharing to compute
    /// the routing cut. Optional so existing callers without this field still work.
    #[cfg_attr(not(feature = "bags"), allow(dead_code))]
    pub amount_usdc_micro: Option<u64>,
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
/// Maximum `/registry/8004/register-submit` requests per 60-second window.
const MAX_REGISTRY_SUBMIT_PER_MINUTE: u32 = 20;
/// Maximum `/hosted/send` requests per 60-second window.
const MAX_HOSTED_SENDS_PER_MINUTE: u32 = 120;

// USDC sweep constants
pub(crate) const USDC_MINT_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
pub(crate) const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub(crate) const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
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
    /// Global rate limit window for `/registry/8004/register-prepare`.
    registry_prepare_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/registry/8004/register-submit`.
    registry_submit_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/hosted/send`.
    hosted_send_rate_limit: Mutex<RateLimitWindow>,

    // 8004 registry helpers
    /// Solana RPC URL — used by registry endpoints for blockhash + broadcast.
    pub rpc_url: String,
    /// Solana RPC URL for trading (Jupiter swaps, Bags fees, USDC sweep).
    /// Defaults to mainnet so financial ops are on real network even when
    /// mesh rpc_url points at devnet.
    pub trade_rpc_url: String,
    /// Node's own Ed25519 signing key — used for /wallet/sweep.
    pub node_signing_key: Arc<SigningKey>,
    /// Shared HTTP client for registry RPC calls.
    pub(crate) http_client: reqwest::Client,
    /// Whether this node is pointed at mainnet-beta (affects 8004 program IDs).
    pub(crate) is_mainnet: bool,
    /// Whether trade_rpc_url points at mainnet-beta (affects USDC mint selection).
    pub(crate) is_trading_mainnet: bool,
    /// Kora paymaster client — present when --kora-url is configured.
    pub kora: Option<KoraClient>,
    /// Optional override for the 8004 base collection (required on mainnet).
    registry_8004_collection: Option<String>,
    /// The current Solana slot, continuously updated by the node event loop.
    current_slot: core::sync::atomic::AtomicU64,
    /// Agent IDs exempt from stake/lease/registration checks.
    /// Shared with Node so either side can read it; admin API writes via POST/DELETE /admin/exempt.
    exempt_agents: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
    /// Path to persist exempt_agents across restarts (log_dir/exempt_agents.json).
    exempt_persist_path: PathBuf,

    // Portfolio state
    pub portfolio_history: RwLock<PortfolioHistory>,
    portfolio_persist_path: PathBuf,

    // Bags fee-sharing (feature = "bags")
    #[cfg(feature = "bags")]
    pub bags_config: Option<Arc<crate::bags::BagsConfig>>,

    // Bags token launch (feature = "bags")
    #[cfg(feature = "bags")]
    pub bags_launch: Option<Arc<crate::bags::BagsLaunchClient>>,

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
    #[cfg(feature = "trade")]
    pub fn inner(&self) -> &ApiInner {
        &self.0
    }
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
        trade_rpc_url: String,
        http_client: reqwest::Client,
        registry_8004_collection: Option<String>,
        node_signing_key: Arc<SigningKey>,
        kora: Option<KoraClient>,
        exempt_agents: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
        exempt_persist_path: PathBuf,
        #[cfg(feature = "bags")] bags_config: Option<Arc<crate::bags::BagsConfig>>,
        #[cfg(feature = "bags")] bags_launch: Option<Arc<crate::bags::BagsLaunchClient>>,
        skill_workspace: Option<std::path::PathBuf>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundRequest>,
        mpsc::Receiver<Envelope>,
    ) {
        let is_mainnet = !rpc_url.contains("devnet")
            && !rpc_url.contains("testnet")
            && !rpc_url.contains("localhost")
            && !rpc_url.contains("127.0.0.1");
        let is_trading_mainnet = !trade_rpc_url.contains("devnet")
            && !trade_rpc_url.contains("testnet")
            && !trade_rpc_url.contains("localhost")
            && !trade_rpc_url.contains("127.0.0.1");
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
            registry_submit_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            hosted_send_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            rpc_url,
            trade_rpc_url,
            node_signing_key,
            http_client,
            is_mainnet,
            is_trading_mainnet,
            kora,
            registry_8004_collection,
            current_slot: core::sync::atomic::AtomicU64::new(0),
            exempt_agents,
            exempt_persist_path,
            portfolio_history: RwLock::new(PortfolioHistory::default()),
            portfolio_persist_path: PathBuf::new(), // to be set in load_or_init
            #[cfg(feature = "bags")]
            bags_config,
            #[cfg(feature = "bags")]
            bags_launch,
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
        let mut arc = Arc::clone(&self.0);
        let inner = Arc::get_mut(&mut arc).expect("ApiInner unique ref for init");
        inner.portfolio_persist_path = path.clone();

        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let history: PortfolioHistory = serde_json::from_str(&data)?;
            *inner.portfolio_history.get_mut() = history;
        }
        Ok(())
    }

    pub async fn record_portfolio_event(&self, event: PortfolioEvent) {
        let mut history = self.0.portfolio_history.write().await;
        history.events.insert(0, event);
        if history.events.len() > 1000 {
            history.events.truncate(1000);
        }

        // Persist
        let path = &self.0.portfolio_persist_path;
        if !path.as_os_str().is_empty() {
            if let Ok(json) = serde_json::to_string_pretty(&*history) {
                let _ = std::fs::write(path, json);
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

    pub fn set_current_slot(&self, slot: u64) {
        self.0
            .current_slot
            .store(slot, core::sync::atomic::Ordering::Relaxed);
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
        // 8004 Solana Agent Registry helpers
        .route("/registry/8004/info", get(registry_8004_info))
        .route(
            "/registry/8004/register-prepare",
            post(registry_8004_register_prepare),
        )
        .route(
            "/registry/8004/register-submit",
            post(registry_8004_register_submit),
        )
        // Escrow
        .route("/escrow/lock", post(escrow_lock))
        .route("/escrow/approve", post(escrow_approve))
        // Hot wallet sweep
        .route("/wallet/sweep", post(sweep_usdc))
        // Admin — exempt agent management (loopback only; requires api_secret)
        .route(
            "/admin/exempt",
            get(admin_exempt_list).post(admin_exempt_add),
        )
        .route("/admin/exempt/{agent_id}", delete(admin_exempt_remove))
        // Agent process management (skill hot-reload)
        .route("/agent/register-pid", post(agent_register_pid))
        .route("/agent/reload", post(agent_reload))
        // Skill manager — safe Rust-side file operations (no shell injection)
        .route("/skill/list", get(skill_list_handler))
        .route("/skill/write", post(skill_write_handler))
        .route("/skill/install-url", post(skill_install_url_handler))
        .route("/skill/remove", post(skill_remove_handler));

    #[cfg(feature = "trade")]
    let router = router
        .route("/trade/swap", post(crate::trade::trade_swap_handler))
        .route("/trade/quote", get(crate::trade::trade_quote_handler))
        .route("/portfolio/history", get(portfolio_history))
        .route("/portfolio/balances", get(portfolio_balances));

    #[cfg(not(feature = "trade"))]
    let router = router
        .route("/portfolio/history", get(portfolio_history))
        .route("/portfolio/balances", get(portfolio_balances));

    #[cfg(feature = "bags")]
    let router = router
        .route("/bags/config", get(bags_config_handler))
        .route("/bags/launch", post(bags_launch_handler))
        .route("/bags/claim", post(bags_claim_handler))
        .route("/bags/positions", get(bags_positions_handler));

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

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("API listener bind failed");

    tracing::info!("API listening on http://{addr}");

    axum::serve(listener, app).await.expect("API server error");
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

#[cfg(feature = "trade")]
pub(crate) async fn resolve_active_hosted_signing_key(
    state: &ApiState,
    token: &str,
) -> Option<SigningKey> {
    let now = now_secs();
    let mut sessions = state.0.hosted_sessions.write().await;
    match sessions.get(token) {
        Some(session) if now.saturating_sub(session.created_at) < SESSION_TTL_SECS => {
            Some(session.signing_key.clone())
        }
        Some(_) => {
            sessions.remove(token);
            None
        }
        None => None,
    }
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
    let network = if state.0.is_mainnet {
        "mainnet-beta"
    } else {
        "devnet"
    };
    let program_id = if state.0.is_mainnet {
        PROGRAM_ID_MAINNET
    } else {
        PROGRAM_ID_DEVNET
    };
    let collection = state
        .0
        .registry_8004_collection
        .as_deref()
        .unwrap_or(if state.0.is_mainnet {
            "(query RootConfig or set ZX01_REGISTRY_8004_COLLECTION)"
        } else {
            COLLECTION_DEVNET
        });

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

    // Validate agent_uri: must be non-empty, bounded, and free of control chars.
    if req.agent_uri.is_empty() || req.agent_uri.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_uri must be 1–256 characters" })),
        )
            .into_response();
    }
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
        None, // fee_payer_override
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

    // Rate limit: each submit triggers signature validation + RPC broadcast.
    {
        let now = now_secs();
        let mut rl = state.0.registry_submit_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_REGISTRY_SUBMIT_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            )
                .into_response();
        }
        rl.count += 1;
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
            Json(
                serde_json::json!({ "error": "transaction_b64: exceeds maximum transaction size" }),
            ),
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

    let mut tx: solana_sdk::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": format!("transaction deserialize failed: {e}") }),
                ),
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
    amount: Option<u64>,
}

/// Convert an ed25519_dalek SigningKey to a solana_sdk Keypair.
///
/// solana_sdk::signature::Keypair is a 64-byte keypair: [secret(32) || public(32)].
pub(crate) fn to_solana_keypair(sk: &SigningKey) -> solana_sdk::signature::Keypair {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&sk.to_bytes());
    bytes[32..].copy_from_slice(sk.verifying_key().as_bytes());
    solana_sdk::signature::Keypair::try_from(bytes.as_slice()).expect("valid ed25519 keypair bytes")
}

/// Derive the Associated Token Account address for a given owner and mint.
pub(crate) fn derive_ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let spl_token: Pubkey = SPL_TOKEN_PROGRAM_ID
        .parse()
        .expect("valid SPL_TOKEN_PROGRAM_ID");
    let ata_program: Pubkey = SPL_ATA_PROGRAM_ID
        .parse()
        .expect("valid SPL_ATA_PROGRAM_ID");
    Pubkey::find_program_address(
        &[&owner.to_bytes(), &spl_token.to_bytes(), &mint.to_bytes()],
        &ata_program,
    )
    .0
}

// ============================================================================
// Escrow handlers
// ============================================================================

/// POST /escrow/lock
///
/// Locks USDC in the 0x01 escrow program on behalf of this node's agent
/// (requester) to pay a provider for completing a task.
///
/// The node uses its own keypair to sign the Solana transaction.
/// `amount_usdc_micro` must match the agreed amount from the ACCEPT payload.
async fn escrow_lock(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<EscrowLockRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }

    let provider_bytes: [u8; 32] = match hex::decode(&req.provider)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "provider: invalid hex or not 32 bytes" })),
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

    let notary_pubkey: Option<solana_sdk::pubkey::Pubkey> = match req.notary {
        Some(ref hex_str) => match hex::decode(hex_str).ok().and_then(|b| b.try_into().ok()) {
            Some(bytes) => Some(solana_sdk::pubkey::Pubkey::new_from_array(bytes)),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "notary: invalid hex or not 32 bytes" })),
                )
            }
        },
        None => None,
    };

    let amount = req.amount_usdc_micro;
    if amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "amount_usdc_micro must be > 0" })),
        );
    }
    let notary_fee = req.notary_fee.unwrap_or(amount / 10);
    let timeout_slots = req.timeout_slots.unwrap_or(1000);

    let sk_bytes = state.0.node_signing_key.to_bytes();
    let vk_bytes = state.0.node_signing_key.verifying_key().to_bytes();
    let rpc_url = state.0.rpc_url.clone();
    let kora = state.0.kora.clone();

    use solana_rpc_client::nonblocking::rpc_client::RpcClient as SolanaRpc;
    match crate::escrow::lock_payment_onchain(
        &SolanaRpc::new(rpc_url),
        sk_bytes,
        vk_bytes,
        provider_bytes,
        conversation_id,
        amount,
        notary_fee,
        notary_pubkey,
        timeout_slots,
        kora.as_ref(),
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

/// POST /escrow/approve
///
/// Approves and releases a locked escrow payment to the provider.
/// Must be called by the notary or requester after the provider has delivered.
async fn escrow_approve(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<EscrowApproveRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }

    let requester_bytes: [u8; 32] = match hex::decode(&req.requester)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "requester: invalid hex or not 32 bytes" })),
            )
        }
    };

    let provider_bytes: [u8; 32] = match hex::decode(&req.provider)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "provider: invalid hex or not 32 bytes" })),
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

    let sk_bytes = state.0.node_signing_key.to_bytes();
    let vk_bytes = state.0.node_signing_key.verifying_key().to_bytes();

    // Notary defaults to self (this node is acting as approver/notary).
    let notary_bytes: [u8; 32] = match req.notary {
        Some(ref hex_str) => match hex::decode(hex_str).ok().and_then(|b| b.try_into().ok()) {
            Some(a) => a,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "notary: invalid hex or not 32 bytes" })),
                )
            }
        },
        None => vk_bytes,
    };

    let rpc_url = state.0.rpc_url.clone();
    let kora = state.0.kora.clone();

    use solana_rpc_client::nonblocking::rpc_client::RpcClient as SolanaRpc;
    match crate::escrow::approve_payment_onchain(
        &SolanaRpc::new(rpc_url),
        sk_bytes,
        vk_bytes,
        requester_bytes,
        provider_bytes,
        conversation_id,
        notary_bytes,
        kora.as_ref(),
    )
    .await
    {
        Ok(()) => {
            #[cfg(feature = "bags")]
            if let Some(bags) = state.0.bags_config.as_ref() {
                if let Some(amount_micro) = req.amount_usdc_micro {
                    let fee = ((amount_micro as u128 * bags.fee_bps as u128) / 10_000) as u64;
                    if fee >= bags.min_fee_micro {
                        let bags = bags.clone();
                        let sk = state.0.node_signing_key.clone();
                        let rpc = state.0.trade_rpc_url.clone();
                        let client = state.0.http_client.clone();
                        let mainnet = state.0.is_trading_mainnet;
                        let state2 = state.clone();
                        tokio::spawn(async move {
                            match crate::bags::distribute_fee(
                                sk, fee, &bags, &rpc, &client, mainnet,
                            )
                            .await
                            {
                                Ok(txid) => {
                                    tracing::info!(
                                        "Bags escrow fee distributed: {txid} ({fee} micro)"
                                    );
                                    state2
                                        .record_portfolio_event(PortfolioEvent::BagsFee {
                                            amount_usdc: fee as f64 / 1_000_000.0,
                                            txid,
                                            timestamp: now_secs(),
                                        })
                                        .await;
                                }
                                Err(e) => {
                                    tracing::warn!("Bags escrow fee distribution failed: {e}")
                                }
                            }
                        });
                    }
                }
            }
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

/// handler derives the destination ATA automatically).
/// If `amount` is specified in the body, it sweeps that specific atomic amount.
/// Otherwise, it sweeps the entire balance.
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

    // 3. Select USDC mint based on trading network.
    let usdc_mint_str = if state.0.is_trading_mainnet {
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
        .post(&state.0.trade_rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountBalance",
            "params": [source_ata.to_string()]
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let available_balance: u64 = match balance_resp {
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
                    Json(
                        serde_json::json!({ "error": "token account not found or has no balance" }),
                    ),
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

    let amount_to_sweep = body.amount.unwrap_or(available_balance);

    if amount_to_sweep < MIN_SWEEP_AMOUNT {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "requested amount too low to sweep",
                "amount_atomic": amount_to_sweep,
                "min_atomic": MIN_SWEEP_AMOUNT,
            })),
        )
            .into_response();
    }

    if amount_to_sweep > available_balance {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "insufficient balance",
                "requested_atomic": amount_to_sweep,
                "available_atomic": available_balance,
            })),
        )
            .into_response();
    }

    // 6. Build SPL Token Transfer instruction (discriminant 3).
    let spl_token_program: Pubkey = SPL_TOKEN_PROGRAM_ID
        .parse()
        .expect("valid SPL_TOKEN_PROGRAM_ID");
    let mut ix_data = vec![3u8];
    ix_data.extend_from_slice(&amount_to_sweep.to_le_bytes());
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
    let blockhash = match fetch_latest_blockhash(&state.0.trade_rpc_url, &state.0.http_client).await
    {
        Ok(bh) => bh,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response();
        }
    };

    // 8. Build, sign, and broadcast — Kora pays gas if configured, otherwise agent pays SOL.
    let solana_kp = to_solana_keypair(&signing_key);

    if let Some(kora) = state.0.kora.as_ref() {
        // ── Kora path: agent partial-signs, Kora adds fee-payer sig + broadcasts ──
        let fee_payer = match kora.get_fee_payer().await {
            Ok(fp) => fp,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("Kora fee payer failed: {e}") })),
                )
                    .into_response();
            }
        };
        let message = solana_sdk::message::Message::new_with_blockhash(
            &[transfer_ix],
            Some(&fee_payer),
            &blockhash,
        );
        let mut tx = solana_sdk::transaction::Transaction {
            signatures: vec![
                solana_sdk::signature::Signature::default();
                message.header.num_required_signatures as usize
            ],
            message,
        };
        tx.partial_sign(&[&solana_kp], blockhash);
        let tx_b64 = match bincode::serialize(&tx) {
            Ok(b) => B64.encode(&b),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("tx serialization failed: {e}") })),
                )
                    .into_response();
            }
        };
        match kora.sign_and_send(&tx_b64).await {
            Ok(signer) => {
                let amount_usdc = amount_to_sweep as f64 / 1_000_000.0;
                tracing::info!(
                    "Swept {amount_usdc:.6} USDC → {destination} via Kora (gasless, signer={signer})"
                );
                Json(serde_json::json!({
                    "signature": signer,
                    "amount_usdc": amount_usdc,
                    "destination": destination.to_string(),
                    "via": "kora",
                }))
                .into_response()
            }
            Err(e) => {
                tracing::warn!("sweep via Kora failed: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("Kora broadcast failed: {e}") })),
                )
                    .into_response()
            }
        }
    } else {
        // ── Direct path: agent is fee payer (requires SOL) ───────────────────
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
        match broadcast_transaction(&state.0.trade_rpc_url, &state.0.http_client, &signed_b64).await
        {
            Ok(signature) => {
                let amount_usdc = amount_to_sweep as f64 / 1_000_000.0;
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
}

// ============================================================================
// Admin — exempt agent management
//
// All three routes require the master api_secret (Authorization: Bearer <secret>).
// They are registered on the same local API server (127.0.0.1:9090 by default),
// so they are only reachable by someone with SSH access to the host.
//
// Usage (from GCP instance or via ssh -L tunnel):
//   # Add Guardian NPC
//   curl -X POST http://127.0.0.1:9090/admin/exempt \
//        -H 'Authorization: Bearer <api_secret>' \
//        -H 'Content-Type: application/json' \
//        -d '{"agent_id":"<64-hex-char-agent-id>"}'
//
//   # List current exemptions
//   curl -H 'Authorization: Bearer <api_secret>' http://127.0.0.1:9090/admin/exempt
//
//   # Remove an exemption
//   curl -X DELETE -H 'Authorization: Bearer <api_secret>' \
//        http://127.0.0.1:9090/admin/exempt/<64-hex-char-agent-id>
//
// Changes are persisted to log_dir/exempt_agents.json and survive node restarts.
// ============================================================================

fn save_exempt_agents(path: &std::path::Path, set: &HashSet<[u8; 32]>) {
    let ids: Vec<String> = set.iter().map(hex::encode).collect();
    match serde_json::to_string(&ids) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, &json) {
                tracing::warn!("Failed to persist exempt_agents to {:?}: {e}", path);
            }
        }
        Err(e) => tracing::warn!("Failed to serialize exempt_agents: {e}"),
    }
}

/// GET /admin/exempt — list all currently exempt agent IDs.
async fn admin_exempt_list(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let set = state.0.exempt_agents.read().unwrap();
    let ids: Vec<String> = set.iter().map(hex::encode).collect();
    Json(serde_json::json!({ "exempt_agents": ids, "count": ids.len() })).into_response()
}

/// POST /admin/exempt — add an agent ID to the exempt set.
/// Body: `{ "agent_id": "<64-hex-char-id>" }`
async fn admin_exempt_add(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let Some(hex_str) = body.get("agent_id").and_then(|v| v.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_id required" })),
        )
            .into_response();
    };
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid hex" })),
            )
                .into_response()
        }
    };
    let arr: [u8; 32] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "agent_id must be 32 bytes (64 hex chars)" })),
            )
                .into_response()
        }
    };
    {
        let mut set = state.0.exempt_agents.write().unwrap();
        set.insert(arr);
        save_exempt_agents(&state.0.exempt_persist_path, &set);
    }
    tracing::info!("Admin: added exempt agent {hex_str}");
    Json(serde_json::json!({ "ok": true, "agent_id": hex_str })).into_response()
}

/// DELETE /admin/exempt/{agent_id} — remove an agent ID from the exempt set.
async fn admin_exempt_remove(
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let bytes = match hex::decode(&agent_id) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid hex" })),
            )
                .into_response()
        }
    };
    let arr: [u8; 32] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "agent_id must be 32 bytes (64 hex chars)" })),
            )
                .into_response()
        }
    };
    {
        let mut set = state.0.exempt_agents.write().unwrap();
        set.remove(&arr);
        save_exempt_agents(&state.0.exempt_persist_path, &set);
    }
    tracing::info!("Admin: removed exempt agent {agent_id}");
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn portfolio_history(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let history = state.0.portfolio_history.read().await;
    Json(history.clone()).into_response()
}

#[derive(Serialize)]
pub struct TokenBalance {
    pub mint: String,
    pub amount: f64,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct PortfolioBalances {
    pub tokens: Vec<TokenBalance>,
}

pub async fn portfolio_balances(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<PortfolioBalances>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return Err((
            resp.status(),
            Json(serde_json::json!({ "error": "unauthorized" })),
        ));
    }

    let pubkey = Pubkey::new_from_array(state.0.self_agent);
    let mut tokens = Vec::new();

    // Fetch SOL balance
    match state
        .0
        .http_client
        .post(&state.0.trade_rpc_url)
        .timeout(std::time::Duration::from_secs(10))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [pubkey.to_string()]
        }))
        .send()
        .await
    {
        Ok(res) => {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                let lamports = data["result"]["value"].as_f64().unwrap_or(0.0);
                if lamports > 0.0 {
                    tokens.push(TokenBalance {
                        mint: "So11111111111111111111111111111111111111112".to_string(), // SOL wrapped mint representation
                        amount: lamports / 1_000_000_000.0,
                        decimals: 9,
                    });
                }
            }
        }
        Err(e) => tracing::error!("Failed to fetch SOL balance: {}", e),
    }

    // Fetch all SPL token balances
    let spl_res = state
        .0
        .http_client
        .post(&state.0.trade_rpc_url)
        .timeout(std::time::Duration::from_secs(15))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTokenAccountsByOwner",
            "params": [
                pubkey.to_string(),
                { "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
                { "encoding": "jsonParsed" }
            ]
        }))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Token accounts fetch failed: {e}")})),
            )
        })?;

    let spl_data: serde_json::Value = spl_res.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Token accounts JSON parse failed: {e}")})),
        )
    })?;

    if let Some(accounts) = spl_data["result"]["value"].as_array() {
        for acc in accounts {
            let parsed = &acc["account"]["data"]["parsed"]["info"];
            let amount_f64 = parsed["tokenAmount"]["uiAmount"].as_f64().unwrap_or(0.0);
            if amount_f64 > 0.0 {
                let mint = parsed["mint"].as_str().unwrap_or("").to_string();
                let decimals = parsed["tokenAmount"]["decimals"].as_u64().unwrap_or(0) as u8;
                tokens.push(TokenBalance {
                    mint,
                    amount: amount_f64,
                    decimals,
                });
            }
        }
    }

    Ok(Json(PortfolioBalances { tokens }))
}

// ============================================================================
// Bags fee-sharing config endpoint (feature = "bags")
// ============================================================================

#[cfg(feature = "bags")]
async fn bags_config_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    match state.0.bags_config.as_ref() {
        None => Json(serde_json::json!({
            "enabled": false,
            "fee_bps": 0,
            "distribution_wallet": null,
            "min_fee_micro": 0,
        }))
        .into_response(),
        Some(cfg) => Json(serde_json::json!({
            "enabled": true,
            "fee_bps": cfg.fee_bps,
            "distribution_wallet": cfg.distribution_wallet.to_string(),
            "min_fee_micro": cfg.min_fee_micro,
        }))
        .into_response(),
    }
}

// ============================================================================
// Bags token launch handlers (feature = "bags")
// ============================================================================

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsLaunchRequest {
    name: String,
    symbol: String,
    description: String,
    image_url: Option<String>,
    website_url: Option<String>,
    twitter_url: Option<String>,
    telegram_url: Option<String>,
    /// Lamports to use for the initial token buy (0 = no initial buy).
    initial_buy_lamports: Option<u64>,
}

/// POST /bags/launch — launch a new token on Bags.fm with fee-sharing.
///
/// Flow:
///   1. Create token info (IPFS metadata + mint address)
///   2. Create fee-share config (Kora pays gas if available)
///   3. Build + sign launch transaction (agent pays SOL for mint account)
///   4. Broadcast and record portfolio event
#[cfg(feature = "bags")]
async fn bags_launch_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsLaunchRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured — set --bags-api-key"})),
        )
            .into_response(),
    };

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    // ── Input validation ─────────────────────────────────────────────────────
    if req.name.is_empty() || req.name.len() > 100 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "name must be 1–100 chars"})),
        )
            .into_response();
    }
    if req.symbol.is_empty()
        || req.symbol.len() > 10
        || !req.symbol.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "symbol must be 1–10 ASCII alphanumeric chars"})),
        )
            .into_response();
    }
    if req.description.len() > 1000 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "description must be ≤1000 chars"})),
        )
            .into_response();
    }
    for u in [
        req.image_url.as_deref(),
        req.website_url.as_deref(),
        req.twitter_url.as_deref(),
        req.telegram_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if u.len() > 512 || (!u.starts_with("https://") && !u.starts_with("http://")) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "URLs must start with http(s):// and be ≤512 chars"})),
            ).into_response();
        }
    }

    // ── Step 1: Create token info ────────────────────────────────────────────
    let (token_mint, ipfs_uri) = match launch
        .create_token_info(
            &req.name,
            &req.symbol,
            &req.description,
            req.image_url.as_deref(),
            req.website_url.as_deref(),
            req.twitter_url.as_deref(),
            req.telegram_url.as_deref(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("create-token-info: {e}")})),
            )
                .into_response()
        }
    };

    // ── Step 2: Create fee-share config (Kora as fee payer when available) ──
    let fee_payer = if let Some(ref kora) = state.0.kora {
        match kora.get_fee_payer().await {
            Ok(pk) => pk.to_string(),
            Err(e) => {
                tracing::warn!("Kora fee-payer unavailable, using agent wallet: {e}");
                agent_wallet.clone()
            }
        }
    } else {
        agent_wallet.clone()
    };

    let (config_key, fee_share_txs) = match launch
        .create_fee_share_config(
            &fee_payer,
            &token_mint, // fee-share config is for the launched token, not USDC
            &[agent_wallet.as_str()],
            &[10_000u32], // agent receives 100% of pool trading fees
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("fee-share config: {e}")})),
            )
                .into_response()
        }
    };

    // Submit fee-share config txs: via Kora (gasless) or direct (agent pays SOL).
    let use_kora = state.0.kora.is_some() && fee_payer != agent_wallet;
    let mut fee_share_errors = 0usize;
    for tx_b64 in &fee_share_txs {
        let mut submitted = false;
        if use_kora {
            if let Some(ref kora) = state.0.kora {
                match kora.sign_and_send(tx_b64).await {
                    Ok(_) => submitted = true,
                    Err(e) => tracing::warn!("Kora fee-share tx failed: {e}"),
                }
            }
        } else {
            // Agent pays gas: deserialize, sign, broadcast.
            if let Ok(tx_bytes) = B64.decode(tx_b64) {
                if let Ok(mut tx) =
                    bincode::deserialize::<solana_sdk::transaction::Transaction>(&tx_bytes)
                {
                    if tx.message.recent_blockhash == solana_sdk::hash::Hash::default() {
                        tracing::warn!("Fee-share tx has zero blockhash — skipping");
                    } else {
                        let kp = to_solana_keypair(&state.0.node_signing_key);
                        tx.partial_sign(&[&kp], tx.message.recent_blockhash);
                        if let Ok(serialized) = bincode::serialize(&tx) {
                            let signed = B64.encode(&serialized);
                            match broadcast_transaction(
                                &state.0.trade_rpc_url,
                                &state.0.http_client,
                                &signed,
                            )
                            .await
                            {
                                Ok(_) => submitted = true,
                                Err(e) => tracing::warn!("Fee-share tx broadcast failed: {e}"),
                            }
                        }
                    }
                }
            }
        }
        if !submitted {
            fee_share_errors += 1;
        }
    }
    if !fee_share_txs.is_empty() && fee_share_errors == fee_share_txs.len() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "All fee-share config transactions failed"})),
        )
            .into_response();
    }

    // Allow fee-share config txs to confirm on-chain before creating launch tx.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // ── Step 3: Build launch transaction (Bags pre-signs with mint keypair) ──
    let launch_tx_bytes = match launch
        .create_launch_transaction(
            &ipfs_uri,
            &token_mint,
            &agent_wallet,
            req.initial_buy_lamports,
            &config_key,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("create-launch-tx: {e}")})),
            )
                .into_response()
        }
    };

    // ── Step 4: Agent signs + broadcasts ────────────────────────────────────
    let mut tx =
        match bincode::deserialize::<solana_sdk::transaction::Transaction>(&launch_tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("launch-tx deserialize: {e}")})),
                )
                    .into_response()
            }
        };
    let kp = to_solana_keypair(&state.0.node_signing_key);
    tx.partial_sign(&[&kp], tx.message.recent_blockhash);
    let serialized = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("launch-tx serialize: {e}")})),
            )
                .into_response()
        }
    };
    let txid = match broadcast_transaction(
        &state.0.trade_rpc_url,
        &state.0.http_client,
        &B64.encode(&serialized),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("launch-tx broadcast: {e}")})),
            )
                .into_response()
        }
    };

    // ── Step 5: Record portfolio event ──────────────────────────────────────
    state
        .record_portfolio_event(PortfolioEvent::BagsLaunch {
            token_mint: token_mint.clone(),
            name: req.name.clone(),
            symbol: req.symbol.clone(),
            txid: txid.clone(),
            timestamp: now_secs(),
        })
        .await;

    tracing::info!(
        "Bags token launched: {} ({}) mint={} txid={}",
        req.name,
        req.symbol,
        token_mint,
        txid
    );

    Json(serde_json::json!({
        "token_mint": token_mint,
        "txid": txid,
        "config_key": config_key,
        "ipfs_uri": ipfs_uri,
    }))
    .into_response()
}

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsClaimRequest {
    token_mint: String,
}

/// POST /bags/claim — claim accumulated pool-fee revenue for a launched token.
#[cfg(feature = "bags")]
async fn bags_claim_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsClaimRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Bags API key not configured"})),
            )
                .into_response()
        }
    };

    // Validate token_mint is a well-formed base58 pubkey before calling Bags API.
    if req.token_mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "token_mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    let claim_txs = match launch
        .claim_fee_transactions(&agent_wallet, &req.token_mint)
        .await
    {
        Ok(txs) => txs,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("claim-txs: {e}")})),
            )
                .into_response()
        }
    };

    let mut txids: Vec<String> = Vec::new();
    for ctx in &claim_txs {
        if let Ok(tx_bytes) = B64.decode(&ctx.tx) {
            if let Ok(mut tx) =
                bincode::deserialize::<solana_sdk::transaction::Transaction>(&tx_bytes)
            {
                if tx.message.recent_blockhash == solana_sdk::hash::Hash::default() {
                    tracing::warn!("Claim tx has zero blockhash — skipping");
                    continue;
                }
                let kp = to_solana_keypair(&state.0.node_signing_key);
                tx.partial_sign(&[&kp], tx.message.recent_blockhash);
                if let Ok(serialized) = bincode::serialize(&tx) {
                    match broadcast_transaction(
                        &state.0.trade_rpc_url,
                        &state.0.http_client,
                        &B64.encode(&serialized),
                    )
                    .await
                    {
                        Ok(txid) => {
                            tracing::info!("Bags fee claimed: {txid}");
                            txids.push(txid);
                        }
                        Err(e) => tracing::warn!("Bags claim broadcast failed: {e}"),
                    }
                }
            }
        }
    }

    if !txids.is_empty() {
        state
            .record_portfolio_event(PortfolioEvent::BagsClaim {
                token_mint: req.token_mint.clone(),
                claimed_txs: txids.len(),
                timestamp: now_secs(),
            })
            .await;
    }

    Json(serde_json::json!({
        "claimed_txs": txids.len(),
        "txids": txids,
    }))
    .into_response()
}

/// GET /bags/positions — list tokens launched by this agent with claimable fees.
#[cfg(feature = "bags")]
async fn bags_positions_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Bags API key not configured"})),
            )
                .into_response()
        }
    };

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    match launch.launched_tokens(&agent_wallet).await {
        Ok(positions) => Json(serde_json::json!({"positions": positions})).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("positions: {e}")})),
        )
            .into_response(),
    }
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
