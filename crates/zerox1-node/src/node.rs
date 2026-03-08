use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;
use url::Host;

use base64::Engine as _;

use ed25519_dalek::{Signer, VerifyingKey};
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response,
    swarm::SwarmEvent, PeerId, Swarm,
};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use zerox1_sati_client::client::SatiClient;

use zerox1_protocol::{
    batch::{FeedbackEvent, TaskSelection, TypedBid, VerifierAssignment},
    constants::{TOPIC_BROADCAST, TOPIC_NOTARY, TOPIC_REPUTATION},
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::FeedbackPayload,
};

use solana_sdk::pubkey::Pubkey;

use crate::{
    api::{
        ApiEvent, ApiState, BatchSnapshot, OutboundRequest, PeerSnapshot, PortfolioEvent,
        ReputationSnapshot, SentConfirmation,
    },
    batch::{current_epoch, now_micros, BatchAccumulator},
    config::Config,
    identity::AgentIdentity,
    inactive,
    kora::KoraClient,
    lease,
    logger::EnvelopeLogger,
    network::{Zx01Behaviour, Zx01BehaviourEvent},
    peer_state::PeerStateMap,
    push_notary,
    registry_8004::Registry8004Client,
    reputation::ReputationTracker,
    submit,
};

// ============================================================================
// Payload layout conventions (documented for agent application authors)
//
// BEACON:          [agent_id(32)][verifying_key(32)][name(utf-8)]
// PROPOSE/COUNTER: [bid_value(16, LE i128)][opaque agent payload...]
// NOTARIZE_ASSIGN: [verifier_agent_id(32)][opaque...]
// ============================================================================

const BEACON_VK_OFFSET: usize = 32;
const BEACON_NAME_OFFSET: usize = 64;
const BID_VALUE_LEN: usize = 16;
const NOTARIZE_ASSIGN_VERIFIER_OFFSET: usize = 32;

/// Maximum bytes read from BEACON name field.
const MAX_NAME_LEN: usize = 64;
/// Maximum tracked conversations (bilateral message sender ↔ conversation).
const MAX_ACTIVE_CONVERSATIONS: usize = 10_000;
/// Maximum number of notary candidates tracked.
const MAX_NOTARY_POOL: usize = 100;
/// Maximum broadcast envelopes queued while waiting for mesh peers.
const MAX_PENDING_BROADCASTS: usize = 20;
/// Maximum number of distinct peers tracked in the rate-limit table.
/// When full, expired entries are evicted; if still full the new peer is skipped.
const MAX_RATE_LIMITER_PEERS: usize = 10_000;
/// Maximum number of SATI RPC failure cache entries retained.
const MAX_SATI_FAILURE_CACHE: usize = 50_000;
/// Maximum number of 8004 registry failure cache entries retained.
const MAX_REG8004_FAILURE_CACHE: usize = 50_000;

// ============================================================================
// Zx01Node
// ============================================================================

pub struct Zx01Node {
    pub config: Config,
    pub identity: AgentIdentity,
    pub peer_states: PeerStateMap,
    pub reputation: ReputationTracker,
    pub logger: EnvelopeLogger,
    pub batch: BatchAccumulator,

    /// Nonblocking Solana RPC client (slot polling + batch submission).
    rpc: RpcClient,
    /// SATI registration checker.
    sati: SatiClient,
    /// Kora paymaster client — present when --kora-url is configured.
    /// Enables gasless on-chain transactions (gas reimbursed in USDC, §4.4).
    kora: Option<KoraClient>,
    /// True when running without a SATI mint (testing / local dev).
    /// In dev mode, SATI failures produce warnings instead of message drops.
    dev_mode: bool,
    /// Visualization API shared state (always present; server only started when
    /// --api-addr is configured).
    api: ApiState,

    nonce: u64,
    current_slot: u64,
    current_epoch: u64,
    conversations: HashMap<[u8; 16], PeerId>,
    conversation_lru: VecDeque<[u8; 16]>,

    /// Receives outbound envelope requests from the Agent API (POST /envelopes/send).
    outbound_rx: tokio::sync::mpsc::Receiver<OutboundRequest>,
    /// Receives pre-signed envelopes from the hosted-agent API (POST /hosted/send).
    hosted_outbound_rx: tokio::sync::mpsc::Receiver<zerox1_protocol::envelope::Envelope>,

    /// USDC mint pubkey — used for inactivity slash bounty payout.
    usdc_mint: Option<Pubkey>,
    /// Reputation aggregator base URL — FEEDBACK/VERDICT envelopes are pushed here.
    aggregator_url: Option<String>,
    /// Shared secret sent in Authorization header when pushing to the aggregator.
    aggregator_secret: Option<String>,
    /// Shared HTTP client for aggregator pushes — avoids per-push TCP setup.
    http_client: reqwest::Client,
    /// Per-peer message rate limiter: PeerId → (count_in_window, window_start).
    rate_limiter: std::collections::HashMap<libp2p::PeerId, (u32, std::time::Instant)>,
    /// Agents known to offer notary services (populated from NOTARIZE_BID broadcasts).
    /// Used to auto-assign a notary when this node sends ACCEPT.
    /// agent_id → libp2p PeerId (needed for bilateral send).
    notary_pool: HashMap<[u8; 32], PeerId>,
    /// Bootstrap peer multiaddrs — used to redial when the node loses all connections.
    bootstrap_peers: Vec<libp2p::Multiaddr>,
    /// Broadcasts queued when gossipsub had no mesh peers (InsufficientPeers).
    /// Flushed the moment any peer subscribes to our topic.
    pending_broadcasts: Vec<Envelope>,
    /// Throttle map for latency reports: last time we pushed a LATENCY event
    /// for each peer. Prevents flooding the aggregator with per-ping pushes.
    /// Only populated when --node-region is set.
    last_ping_push: HashMap<PeerId, std::time::Instant>,
    /// Per-agent SATI RPC failure timestamps.
    /// When `verify_sati_registration` returns an error (e.g. AccountNotFound on
    /// devnet for infrastructure nodes), we record the time here and skip the
    /// next check for 1 hour.  Without this, every BEACON from a reference node
    /// that has no SATI mint triggers a fresh RPC call every ~30 seconds.
    sati_rpc_failures: HashMap<[u8; 32], std::time::Instant>,
    /// 8004 Solana Agent Registry client (primary registration gate).
    /// Verifies peers by querying `agents(where:{owner:$base58})` against the
    /// public GraphQL indexer — no on-chain RPC required.
    registry8004: Registry8004Client,
    /// Per-agent 8004 registry HTTP failure timestamps (same 1-hour backoff as SATI).
    reg8004_failures: HashMap<[u8; 32], std::time::Instant>,
    /// Agent IDs exempt from lease and registration checks.
    /// Shared with ApiState so the admin API can mutate it at runtime without restart.
    exempt_agents: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
}

impl Zx01Node {
    pub fn new(
        mut config: Config,
        identity: AgentIdentity,
        bootstrap_peers: Vec<libp2p::Multiaddr>,
    ) -> anyhow::Result<Self> {
        // If no name was configured, derive one from the first 4 bytes of the
        // agent ID (8 hex chars) so every node has a unique, stable default.
        if config.agent_name.is_empty() {
            config.agent_name = hex::encode(&identity.agent_id[..4]);
        }
        let epoch = current_epoch();
        let log_dir = config.log_dir.clone();
        let rpc = RpcClient::new(config.rpc_url.clone());
        let sati = SatiClient::new(&config.rpc_url);
        // "none" disables Kora entirely; otherwise use the configured URL.
        let kora = if config.kora_url.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(KoraClient::new(&config.kora_url))
        };
        // Dev mode: both the primary (8004) and legacy (SATI) registration gates
        // are inactive.  In dev mode, unregistered peers produce warnings instead
        // of being dropped, allowing local testing without on-chain registration.
        let dev_mode = config.registry_8004_disabled && config.sati_mint.is_none();
        let http_client = reqwest::Client::new();
        let registry8004 = Registry8004Client::new(
            &config.registry_8004_url,
            http_client.clone(),
            config.registry_8004_min_tier,
        );
        let usdc_mint = config.usdc_mint_pubkey().ok().flatten();
        let aggregator_url = validated_aggregator_url(config.aggregator_url.clone());
        let aggregator_secret = config.aggregator_secret.clone();
        // ── Exempt agents: load persisted runtime mutations + merge env/CLI config ──
        let exempt_persist_path = config.log_dir.join("exempt_agents.json");
        let mut exempt_set = std::collections::HashSet::<[u8; 32]>::new();

        if let Ok(data) = std::fs::read_to_string(&exempt_persist_path) {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&data) {
                for hex_str in ids {
                    if let Ok(bytes) = hex::decode(&hex_str) {
                        if let Ok(arr) = bytes.try_into() {
                            exempt_set.insert(arr);
                            tracing::info!("Loaded exempt agent from persist: {}", hex_str);
                        }
                    }
                }
            }
        }

        for hex_str in &config.exempt_agents {
            if let Ok(bytes) = hex::decode(hex_str) {
                if let Ok(arr) = bytes.try_into() {
                    if exempt_set.insert(arr) {
                        tracing::info!("Registered exempt agent: {}", hex_str);
                    }
                } else {
                    tracing::warn!(
                        "Invalid exempt agent length (expected 32 bytes): {}",
                        hex_str
                    );
                }
            } else {
                tracing::warn!("Invalid hex for exempt agent: {}", hex_str);
            }
        }

        let exempt_agents = std::sync::Arc::new(std::sync::RwLock::new(exempt_set));

        // ── Bags fee-sharing: resolve distribution address at startup ─────────
        #[cfg(feature = "bags")]
        let bags_config: Option<std::sync::Arc<crate::bags::BagsConfig>> = {
            use std::str::FromStr as _;
            if config.bags_fee_bps == 0 {
                None
            } else {
                if config.bags_fee_bps > 500 {
                    anyhow::bail!(
                        "--bags-fee-bps {} exceeds maximum allowed value of 500 (5%)",
                        config.bags_fee_bps
                    );
                }
                let distribution_wallet = if let Some(ref w) = config.bags_wallet {
                    solana_sdk::pubkey::Pubkey::from_str(w)
                        .map_err(|e| anyhow::anyhow!("Invalid --bags-wallet '{w}': {e}"))?
                } else {
                    let api_client = crate::bags::BagsApiClient::new(
                        config.bags_api_url.clone(),
                        http_client.clone(),
                    )?;
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(api_client.resolve_distribution_address())
                    })
                    .map_err(|e| {
                        anyhow::anyhow!("Bags API unavailable and --bags-wallet not set: {e}")
                    })?
                };
                tracing::info!(
                    "Bags fee-sharing enabled: {} bps → {}",
                    config.bags_fee_bps,
                    distribution_wallet
                );
                Some(std::sync::Arc::new(crate::bags::BagsConfig {
                    fee_bps: config.bags_fee_bps,
                    distribution_wallet,
                    min_fee_micro: 1_000,
                }))
            }
        };

        #[cfg(feature = "bags")]
        let bags_launch: Option<std::sync::Arc<crate::bags::BagsLaunchClient>> =
            config.bags_api_key.as_ref().map(|key| {
                tracing::info!("Bags launch API enabled (key configured)");
                std::sync::Arc::new(crate::bags::BagsLaunchClient::new(
                    key.clone(),
                    http_client.clone(),
                ))
            });

        let (api, outbound_rx, hosted_outbound_rx) = ApiState::new(
            identity.agent_id,
            config.agent_name.clone(),
            config.api_secret.clone(),
            config.api_read_keys.clone(),
            config.hosting_fee_bps,
            config.rpc_url.clone(),
            config.trade_rpc_url.clone(),
            http_client.clone(),
            config.registry_8004_collection.clone(),
            std::sync::Arc::new(identity.signing_key.clone()),
            kora.clone(),
            std::sync::Arc::clone(&exempt_agents),
            exempt_persist_path,
            #[cfg(feature = "bags")]
            bags_config,
            #[cfg(feature = "bags")]
            bags_launch,
            config.skill_workspace.clone(),
        );

        // Load portfolio history from disk
        let portfolio_path = config.log_dir.join("portfolio_history.json");
        let _ =
            tokio::runtime::Handle::current().block_on(api.load_portfolio_history(portfolio_path));

        let batch = BatchAccumulator::new(epoch, 0);
        let logger = EnvelopeLogger::new(log_dir, epoch);

        if dev_mode {
            tracing::warn!(
                "Running in dev mode (no 8004 registry and no --sati-mint). \
                 Registration verification is advisory only — unregistered peers are allowed."
            );
        } else if config.registry_8004_disabled {
            tracing::info!(
                "8004 registry disabled — using SATI-only registration gate (legacy mode)."
            );
        } else {
            tracing::info!(
                "8004 Solana Agent Registry enabled as primary gate ({}). \
                 SATI is legacy fallback.",
                config.registry_8004_url
            );
        }

        if kora.is_some() {
            tracing::info!("Kora paymaster enabled — on-chain transactions use gasless USDC path.");
        } else {
            tracing::info!("No --kora-url set — on-chain transactions require SOL for gas.");
        }

        Ok(Self {
            config,
            identity,
            peer_states: PeerStateMap::new(),
            reputation: ReputationTracker::new(),
            logger,
            batch,
            rpc,
            sati,
            kora,
            dev_mode,
            api,
            nonce: 0,
            current_slot: 0,
            current_epoch: epoch,
            conversations: HashMap::new(),
            conversation_lru: VecDeque::new(),
            outbound_rx,
            hosted_outbound_rx,
            usdc_mint,
            aggregator_url,
            aggregator_secret,
            http_client,
            rate_limiter: std::collections::HashMap::new(),
            notary_pool: HashMap::new(),
            bootstrap_peers,
            pending_broadcasts: Vec::new(),
            last_ping_push: HashMap::new(),
            sati_rpc_failures: HashMap::new(),
            registry8004,
            reg8004_failures: HashMap::new(),
            exempt_agents,
        })
    }

    // ========================================================================
    // Main event loop
    // ========================================================================

    pub async fn run(&mut self, swarm: &mut Swarm<Zx01Behaviour>) -> anyhow::Result<()> {
        // ── Visualization API server ─────────────────────────────────────────
        if let Some(ref addr_str) = self.config.api_addr.clone() {
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(addr) => {
                    // Safety: refuse to bind to a non-loopback address without an API secret.
                    // Without a secret every mutating endpoint (/envelopes/send, /wallet/sweep,
                    // /registry/8004/register-*) would be open to anyone on the network.
                    if !addr.ip().is_loopback() && self.config.api_secret.is_none() {
                        anyhow::bail!(
                            "--api-addr {} is a non-loopback address but --api-secret is not \
                             set. All mutating endpoints would be unauthenticated. \
                             Set ZX01_API_SECRET or bind to 127.0.0.1.",
                            addr
                        );
                    }
                    let api = self.api.clone();
                    tokio::spawn(crate::api::serve(
                        api,
                        addr,
                        self.config.api_cors_origins.clone(),
                    ));
                }
                Err(e) => tracing::warn!("Invalid --api-addr '{addr_str}': {e}"),
            }
        }

        // ── Hosting registration heartbeat ────────────────────────────────────
        // When --hosting is set, advertise this node to the aggregator every 60s.
        if self.config.hosting {
            if let Some(ref agg_url) = self.aggregator_url.clone() {
                let agg_url_log = agg_url.clone();
                let agg_url = agg_url.clone();
                let public_url = self.config.public_api_url.clone().unwrap_or_default();
                let node_id = hex::encode(self.identity.agent_id);
                let name = self.config.agent_name.clone();
                let fee_bps = self.config.hosting_fee_bps;
                let aggregator_secret = self.config.aggregator_secret.clone();
                let signing_key = self.identity.signing_key.clone();

                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    loop {
                        let body = serde_json::json!({
                            "node_id": node_id,
                            "name":    name,
                            "fee_bps": fee_bps,
                            "api_url": public_url,
                        });
                        let body_bytes = match serde_json::to_vec(&body) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("Failed to serialize hosting heartbeat body: {e}");
                                break;
                            }
                        };
                        let signature = signing_key.sign(&body_bytes);

                        let mut req = client
                            .post(format!("{agg_url}/hosting/register"))
                            .header("X-Signature", hex::encode(signature.to_bytes()))
                            .body(body_bytes);

                        if let Some(ref secret) = aggregator_secret {
                            req = req.header("Authorization", format!("Bearer {secret}"));
                        }
                        if let Err(e) = req.send().await {
                            tracing::warn!("Hosting registration heartbeat failed: {e}");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }
                });

                tracing::info!("Hosting mode enabled — advertising to aggregator at {agg_url_log}");
            } else {
                tracing::warn!(
                    "--hosting set but no --aggregator-url configured; \
                     hosting registration heartbeat disabled."
                );
            }
        }

        // ── Auto-onboard: stake + lease ───────────────────────────────────────
        self.ensure_stake_and_lease().await;

        // ── Startup lease check ───────────────────────────────────────────────
        // Verify our own agent's lease before joining the mesh.
        self.check_own_lease().await?;

        // ── Geo self-registration ─────────────────────────────────────────────
        if let Some(ref country) = self.config.geo_country {
            self.push_to_aggregator(serde_json::json!({
                "msg_type":     "ADVERTISE",
                "sender":       hex::encode(self.identity.agent_id),
                "capabilities": [],
                "slot":         self.current_slot,
                "geo": {
                    "country": country,
                    "city":    self.config.geo_city.clone(),
                }
            }));
            tracing::info!("Geo registered: country={country}");
        }

        // ── FCM registration (phone-as-node) ─────────────────────────────────
        // If a Firebase device token is configured, register it with the
        // aggregator and pull any messages that arrived while sleeping.
        if let (Some(ref fcm_token), Some(ref agg_url)) =
            (self.config.fcm_token.clone(), self.aggregator_url.clone())
        {
            let agent_id_hex = hex::encode(self.identity.agent_id);
            // Register token.
            if let Err(e) = push_notary::register_fcm_token(
                agg_url,
                &agent_id_hex,
                fcm_token,
                &self.identity.signing_key,
                &self.http_client,
            )
            .await
            {
                tracing::warn!("FCM token registration failed: {e}");
            } else {
                tracing::info!("FCM token registered with aggregator.");
            }
            // Mark this node as awake.
            if let Err(e) = push_notary::set_sleep_mode(
                agg_url,
                &agent_id_hex,
                false,
                &self.identity.signing_key,
                &self.http_client,
            )
            .await
            {
                tracing::warn!("FCM wake notification failed: {e}");
            }
            // Pull any messages held while sleeping.
            match push_notary::pull_pending_messages(
                agg_url,
                &agent_id_hex,
                &self.identity.signing_key,
                &self.http_client,
            )
            .await
            {
                Ok::<Vec<push_notary::PendingMessage>, _>(msgs) if !msgs.is_empty() => {
                    tracing::info!(
                        "{} pending message(s) retrieved from aggregator while sleeping.",
                        msgs.len()
                    );
                    for msg in &msgs {
                        tracing::info!("Pending [{}] from {} — {}", msg.msg_type, msg.from, msg.id);
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("Failed to pull pending messages: {e}"),
            }
        }

        let mut beacon_timer = tokio::time::interval(Duration::from_secs(30));
        let mut epoch_timer = tokio::time::interval(Duration::from_secs(30));
        let mut slot_timer = tokio::time::interval(Duration::from_millis(400));
        // Inactivity check: once per hour is sufficient; skip in dev mode.
        let mut inactive_timer = tokio::time::interval(Duration::from_secs(3_600));
        // Reconnect check: if we have no peers, redial bootstrap nodes.
        let mut reconnect_timer = tokio::time::interval(Duration::from_secs(60));

        self.send_beacon(swarm).await;

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    self.handle_swarm_event(swarm, event).await;
                }
                Some(req) = self.outbound_rx.recv() => {
                    self.handle_outbound(swarm, req).await;
                }
                Some(env) = self.hosted_outbound_rx.recv() => {
                    // Pre-verify hosted envelopes exactly like inbound ones to prevent DoS broadcast.
                    if env.msg_type == MsgType::Beacon {
                        if self.peer_states.sati_status(&env.sender).is_none() {
                            if !self.config.registry_8004_disabled {
                                let failed_8004 = self.reg8004_failures.get(&env.sender).map(|t| t.elapsed().as_secs() < 3600).unwrap_or(false);
                                if !failed_8004 {
                                    self.verify_8004_registration(env.sender).await;
                                }
                            }
                            // SATI fallback
                            if self.peer_states.sati_status(&env.sender).is_none() {
                                let recently_failed = self.sati_rpc_failures.get(&env.sender).map(|t| t.elapsed().as_secs() < 3600).unwrap_or(false);
                                if !recently_failed {
                                    self.verify_sati_registration(env.sender).await;
                                }
                            }
                        }
                        if self.peer_states.lease_status(&env.sender).is_none()
                            || self.peer_states.last_active_epoch(&env.sender) < self.current_epoch
                        {
                            self.verify_peer_lease(env.sender).await;
                        }
                    }

                    if !self.sati_gate_allows(&env.sender) {
                        tracing::warn!("Blocked hosted agent {} (unregistered)", hex::encode(env.sender));
                        continue;
                    }
                    if !self.lease_gate_allows(&env.sender) {
                        tracing::warn!("Blocked hosted agent {} (deactivated)", hex::encode(env.sender));
                        continue;
                    }

                    // Record it in the batch so it's not bypassing the epoch logging!
                    self.batch.record_message(env.msg_type, env.sender, self.current_slot);
                    if let Err(e) = self.logger.log(&env) {
                        tracing::warn!("Logger error on hosted outbound: {e}");
                    }

                    if env.msg_type.is_bilateral() {
                        // Route bilateral hosted messages via request-response.
                        match self.peer_states.peer_id_for_agent(&env.recipient) {
                            Some(peer_id) => {
                                if let Err(e) = self.send_bilateral(swarm, peer_id, &env) {
                                    tracing::warn!(
                                        "Hosted bilateral send failed ({} → {}): {e}",
                                        env.msg_type,
                                        hex::encode(env.recipient),
                                    );
                                }
                            }
                            None => {
                                tracing::warn!(
                                    "Hosted bilateral {}: no known peer_id for recipient {}",
                                    env.msg_type,
                                    hex::encode(env.recipient),
                                );
                            }
                        }
                    } else if let Err(e) = self.publish_envelope(swarm, &env) {
                        tracing::warn!("Hosted outbound publish failed: {e}");
                    }
                }
                _ = beacon_timer.tick() => {
                    self.send_beacon(swarm).await;
                }
                _ = epoch_timer.tick() => {
                    self.check_epoch_boundary(swarm).await;
                }
                _ = slot_timer.tick() => {
                    self.poll_slot().await;
                }
                _ = inactive_timer.tick() => {
                    self.check_inactive_agents().await;
                }
                _ = reconnect_timer.tick() => {
                    let n = swarm.connected_peers().count();
                    if n == 0 && !self.bootstrap_peers.is_empty() {
                        tracing::info!("No peers connected — redialling {} bootstrap node(s)", self.bootstrap_peers.len());
                        for addr in self.bootstrap_peers.clone() {
                            if let Err(e) = swarm.dial(addr.clone()) {
                                tracing::warn!("Reconnect dial failed for {addr}: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Own lease management
    // ========================================================================

    /// Ensure this agent has both a stake lock and an initialized lease.
    /// Called once at startup before check_own_lease().
    /// In dev mode, skip entirely.
    async fn ensure_stake_and_lease(&mut self) {
        if self.dev_mode
            || self
                .exempt_agents
                .read()
                .unwrap()
                .contains(&self.identity.agent_id)
        {
            tracing::debug!("Dev mode or exempt agent — skipping auto-onboard.");
            return;
        }

        // GAP-1: Auto-stake if no stake account exists.
        match crate::stake_lock::stake_exists(&self.rpc, &self.identity.agent_id).await {
            Ok(false) => {
                tracing::info!(
                    "No stake account found — auto-staking {} USDC...",
                    crate::stake_lock::MIN_STAKE_USDC as f64 / 1_000_000.0
                );
                if let Err(e) = crate::stake_lock::lock_stake_onchain(
                    &self.rpc,
                    &self.identity,
                    self.kora.as_ref(),
                )
                .await
                {
                    tracing::warn!("Auto-stake failed: {e}. Agent may not pass peer verification.");
                }
            }
            Ok(true) => tracing::debug!("Stake account exists."),
            Err(e) => tracing::warn!("Stake check failed: {e}. Continuing optimistically."),
        }

        // GAP-2: Auto-init lease if no lease account exists.
        match crate::lease::get_lease_status(&self.rpc, &self.identity.agent_id).await {
            Ok(None) => {
                tracing::info!("No lease account found — auto-initializing lease...");
                if let Err(e) =
                    crate::lease::init_lease_onchain(&self.rpc, &self.identity, self.kora.as_ref())
                        .await
                {
                    tracing::warn!("Auto-init lease failed: {e}. Agent may be rejected by peers.");
                }
            }
            Ok(Some(_)) => {} // Lease exists — check_own_lease() will handle renewal
            Err(e) => tracing::warn!("Lease status check failed: {e}. Continuing optimistically."),
        }
    }

    /// Check this agent's own lease on startup.
    ///
    /// - No account: warn (agent must call `init_lease` before running)
    /// - Deactivated: fatal — refuse to start
    /// - Grace period: warn, continue (but should pay ASAP)
    /// - Needs renewal: auto-renew immediately
    async fn check_own_lease(&mut self) -> anyhow::Result<()> {
        if self.dev_mode
            || self
                .exempt_agents
                .read()
                .unwrap()
                .contains(&self.identity.agent_id)
        {
            tracing::debug!("Dev mode or exempt agent — skipping own lease check.");
            return Ok(());
        }

        match lease::get_lease_status(&self.rpc, &self.identity.agent_id).await {
            Ok(None) => {
                tracing::warn!(
                    "No lease account found for agent {}. \
                     Call `init_lease` before running on the mesh.",
                    hex::encode(self.identity.agent_id),
                );
            }
            Ok(Some(status)) => {
                if status.deactivated {
                    anyhow::bail!(
                        "Agent {} is DEACTIVATED — lease expired beyond grace period. \
                         Cannot join the mesh.",
                        hex::encode(self.identity.agent_id),
                    );
                }
                if status.in_grace_period {
                    tracing::warn!(
                        "Agent {} is in grace period (paid_through={}, current={}). \
                         Pay lease immediately to avoid deactivation.",
                        hex::encode(self.identity.agent_id),
                        status.paid_through_epoch,
                        status.current_epoch,
                    );
                }
                if status.needs_renewal() {
                    tracing::info!("Lease near expiry — auto-renewing.");
                    self.renew_own_lease().await;
                } else {
                    tracing::info!(
                        "Lease OK: paid_through_epoch={} current_epoch={}",
                        status.paid_through_epoch,
                        status.current_epoch,
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Lease check failed (RPC): {e}. Continuing in optimistic mode.");
            }
        }
        Ok(())
    }

    /// Check if own lease needs renewal and pay if so.
    /// Called at each epoch boundary.
    async fn maybe_renew_own_lease(&mut self) {
        if self.dev_mode
            || self
                .exempt_agents
                .read()
                .unwrap()
                .contains(&self.identity.agent_id)
        {
            return;
        }
        match lease::get_lease_status(&self.rpc, &self.identity.agent_id).await {
            Ok(Some(status)) if status.needs_renewal() => {
                self.renew_own_lease().await;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!("Own lease account not found at epoch boundary.");
            }
            Err(e) => {
                tracing::warn!("Lease check at epoch boundary failed: {e}");
            }
        }
    }

    async fn renew_own_lease(&mut self) {
        if let Err(e) =
            lease::pay_lease_onchain(&self.rpc, &self.identity, self.kora.as_ref()).await
        {
            tracing::error!("Lease renewal failed: {e}");
        }
    }

    // ========================================================================
    // Peer lease verification
    // ========================================================================

    /// Query lease status for `agent_id` and cache in peer_states.
    ///
    /// On RPC error: leaves status as None (will retry on next BEACON).
    async fn verify_peer_lease(&mut self, agent_id: [u8; 32]) {
        match lease::get_lease_status(&self.rpc, &agent_id).await {
            Ok(Some(status)) => {
                let active = status.is_active();
                self.peer_states.set_lease_status(agent_id, active);
                self.api.send_event(ApiEvent::LeaseStatus {
                    agent_id: hex::encode(agent_id),
                    active,
                });
                if active {
                    tracing::debug!(
                        "Lease: agent {} ✓ active (paid_through={})",
                        hex::encode(agent_id),
                        status.paid_through_epoch,
                    );
                } else {
                    tracing::warn!(
                        "Lease: agent {} DEACTIVATED — messages will be dropped",
                        hex::encode(agent_id),
                    );
                }
            }
            Ok(None) => {
                // No lease account — treat as inactive in prod mode.
                self.peer_states.set_lease_status(agent_id, false);
                tracing::warn!(
                    "Lease: no account for agent {} — treating as inactive",
                    hex::encode(agent_id),
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Lease check failed for {}: {e} (will retry on next BEACON)",
                    hex::encode(agent_id),
                );
            }
        }
    }

    /// Returns true if this agent's messages should pass the lease gate.
    ///
    /// - Dev mode: always true
    /// - Prod mode: false only when lease_status = Some(false)
    fn lease_gate_allows(&self, agent_id: &[u8; 32]) -> bool {
        if self.dev_mode || self.exempt_agents.read().unwrap().contains(agent_id) {
            return true;
        }
        !matches!(self.peer_states.lease_status(agent_id), Some(false))
    }

    // ========================================================================
    // Slot polling
    // ========================================================================

    async fn poll_slot(&mut self) {
        match self.rpc.get_slot().await {
            Ok(slot) => {
                self.current_slot = slot;
                self.api.set_current_slot(slot);
            }
            Err(e) => tracing::trace!("Slot poll failed: {e}"),
        }
    }

    // ========================================================================
    // SATI registration verification
    // ========================================================================

    /// Query SATI for `agent_id` and cache the result in peer_states.
    ///
    /// On RPC error the status is left as `None` (unchecked) so the next
    /// message triggers a fresh attempt — infrastructure failures must not
    /// permanently block legitimate agents.
    async fn verify_sati_registration(&mut self, agent_id: [u8; 32]) {
        match self.sati.is_registered(&agent_id).await {
            Ok(true) => {
                self.peer_states.set_sati_status(agent_id, true);
                self.api.send_event(ApiEvent::SatiStatus {
                    agent_id: hex::encode(agent_id),
                    registered: true,
                });
                tracing::info!("SATI: agent {} ✓ registered", hex::encode(agent_id),);
            }
            Ok(false) => {
                self.peer_states.set_sati_status(agent_id, false);
                self.api.send_event(ApiEvent::SatiStatus {
                    agent_id: hex::encode(agent_id),
                    registered: false,
                });
                if self.dev_mode {
                    tracing::debug!(
                        "SATI: agent {} not registered (dev mode — allowed)",
                        hex::encode(agent_id),
                    );
                } else {
                    tracing::warn!(
                        "SATI: agent {} NOT registered — future messages will be dropped",
                        hex::encode(agent_id),
                    );
                }
            }
            Err(e) => {
                // RPC failure (incl. AccountNotFound for infra nodes without a
                // SATI mint).  Record the failure time so we back off for 1 hour
                // before retrying — avoids flooding devnet RPC and log spam.
                self.sati_rpc_failures
                    .insert(agent_id, std::time::Instant::now());
                tracing::warn!(
                    "SATI check failed for {}: {e} (will retry in 1 h)",
                    hex::encode(agent_id),
                );
            }
        }
    }

    // ========================================================================
    // 8004 Solana Agent Registry (primary gate)
    // ========================================================================

    /// Query the 8004 registry for `agent_id` and, if found, mark them as
    /// verified in `peer_states` so the gate check passes.
    ///
    /// This is the "connect existing identity" path: an agent already registered
    /// in the 8004 Solana registry is accepted without needing a SATI mint.
    /// Their Ed25519 `agent_id` bytes == their Solana pubkey == their `owner`
    /// field in the 8004 registry — no extra key material needed.
    async fn verify_8004_registration(&mut self, agent_id: [u8; 32]) {
        match self.registry8004.is_registered(&agent_id).await {
            Ok(true) => {
                // Agent found and meets min_tier — connect their existing identity.
                self.peer_states.set_sati_status(agent_id, true);
                self.api.send_event(ApiEvent::SatiStatus {
                    agent_id: hex::encode(agent_id),
                    registered: true,
                });
                tracing::info!(
                    "8004: agent {} verified (existing identity connected)",
                    hex::encode(agent_id),
                );
            }
            Ok(false) => {
                // Not found in 8004 registry (or below min_tier).
                // Do NOT set peer_states — let SATI fallback decide.
                tracing::debug!(
                    "8004: agent {} not found in registry",
                    hex::encode(agent_id),
                );
            }
            Err(e) => {
                // Network / HTTP error — back off for 1 hour.
                self.reg8004_failures
                    .insert(agent_id, std::time::Instant::now());
                tracing::warn!(
                    "8004 check failed for {}: {e} (will retry in 1 h)",
                    hex::encode(agent_id),
                );
            }
        }
    }

    /// Returns true if this agent's messages should be forwarded.
    ///
    /// In dev mode: always true (warn on unregistered).
    /// In prod mode: true only if SATI status is confirmed `Some(true)` or
    ///               still `None` (not yet checked — optimistic until BEACON fires check).
    fn sati_gate_allows(&self, agent_id: &[u8; 32]) -> bool {
        if self.dev_mode || self.exempt_agents.read().unwrap().contains(agent_id) {
            return true;
        }
        !matches!(self.peer_states.sati_status(agent_id), Some(false))
    }

    // ========================================================================
    // Swarm event dispatch
    // ========================================================================

    async fn handle_swarm_event(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        event: SwarmEvent<Zx01BehaviourEvent>,
    ) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Listening on {address}");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                tracing::debug!("Connected to {peer_id} via {endpoint:?}");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::debug!("Disconnected from {peer_id}");
                self.last_ping_push.remove(&peer_id);
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(swarm, behaviour_event).await;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!("Outgoing connection error to {peer_id:?}: {error}");
            }
            _ => {}
        }
    }

    async fn handle_behaviour_event(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        event: Zx01BehaviourEvent,
    ) {
        match event {
            Zx01BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                self.handle_pubsub_message(swarm, propagation_source, message)
                    .await;
            }
            Zx01BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                tracing::debug!("{peer_id} subscribed to {topic}");
                self.flush_pending_broadcasts(swarm);
            }
            Zx01BehaviourEvent::Gossipsub(_) => {}

            Zx01BehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer_id, addr) in peers {
                    tracing::info!("mDNS discovered {peer_id} at {addr}");
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    let _ = swarm.dial(peer_id);
                }
            }
            Zx01BehaviourEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer_id, _addr) in peers {
                    tracing::debug!("mDNS expired {peer_id}");
                }
            }

            Zx01BehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. }) => {
                tracing::debug!("Kademlia routing updated: {peer}");
            }
            Zx01BehaviourEvent::Kademlia(_) => {}

            Zx01BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                tracing::debug!("Identified {peer_id}: agent={}", info.agent_version);
                for addr in &info.listen_addrs {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                if let Ok(ed_pk) = info.public_key.try_into_ed25519() {
                    if let Ok(vk) = VerifyingKey::from_bytes(&ed_pk.to_bytes()) {
                        self.peer_states.set_key_for_peer(&peer_id, vk);
                    }
                }
            }
            Zx01BehaviourEvent::Identify(_) => {}

            Zx01BehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
                ..
            }) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.handle_bilateral_request(swarm, peer, request, channel)
                        .await;
                }
                request_response::Message::Response { response, .. } => {
                    tracing::trace!("Bilateral ACK from {peer}: {:?}", response);
                }
            },
            Zx01BehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                peer,
                error,
                ..
            }) => {
                tracing::warn!("Bilateral outbound failure to {peer}: {error}");
            }
            Zx01BehaviourEvent::RequestResponse(request_response::Event::InboundFailure {
                peer,
                error,
                ..
            }) => {
                tracing::warn!("Bilateral inbound failure from {peer}: {error}");
            }
            Zx01BehaviourEvent::RequestResponse(_) => {}

            // ── Relay server events (genesis nodes) ──────────────────────────
            Zx01BehaviourEvent::RelayServer(relay::Event::ReservationReqAccepted {
                src_peer_id,
                ..
            }) => {
                tracing::info!("Relay: reservation accepted from {src_peer_id}");
            }
            Zx01BehaviourEvent::RelayServer(relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            }) => {
                tracing::debug!("Relay: circuit opened {src_peer_id} → {dst_peer_id}");
            }
            Zx01BehaviourEvent::RelayServer(relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                ..
            }) => {
                tracing::debug!("Relay: circuit closed {src_peer_id} → {dst_peer_id}");
            }
            Zx01BehaviourEvent::RelayServer(_) => {}

            // ── Relay client events (mobile / NAT-restricted nodes) ──────────
            Zx01BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                ..
            }) => {
                tracing::info!("Circuit relay reservation accepted by {relay_peer_id}");
            }
            Zx01BehaviourEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished {
                relay_peer_id,
                ..
            }) => {
                tracing::debug!("Relay circuit established via {relay_peer_id}");
            }
            Zx01BehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
                src_peer_id,
                ..
            }) => {
                tracing::debug!("Inbound relay circuit from {src_peer_id}");
            }

            // ── dcutr — upgrades relay connections to direct connections ─────
            // dcutr::Event is a struct with remote_peer_id and result fields.
            Zx01BehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => match result {
                Ok(_) => {
                    tracing::info!("dcutr: direct connection established with {remote_peer_id}")
                }
                Err(e) => tracing::debug!("dcutr: upgrade failed with {remote_peer_id}: {e}"),
            },

            // ── AutoNAT — external reachability probe ────────────────────────
            Zx01BehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new }) => {
                tracing::info!("AutoNAT status: {old:?} → {new:?}");
            }
            Zx01BehaviourEvent::Autonat(_) => {}

            // ── Ping — RTT measurement for geo plausibility ───────────────────
            // Only report when --node-region is configured (genesis/reference nodes).
            Zx01BehaviourEvent::Ping(ping::Event { peer, result, .. }) => {
                if let (Ok(rtt), Some(ref region)) = (result, self.config.node_region.clone()) {
                    if let Some(agent_id) = self.peer_states.agent_id_for_peer(&peer) {
                        let now = std::time::Instant::now();
                        let should_push = self
                            .last_ping_push
                            .get(&peer)
                            .map(|t| now.duration_since(*t).as_secs() >= 60)
                            .unwrap_or(true);
                        if should_push {
                            let rtt_ms = rtt.as_millis() as u64;
                            self.push_to_aggregator(serde_json::json!({
                                "msg_type": "LATENCY",
                                "agent_id": hex::encode(agent_id),
                                "region":   region,
                                "rtt_ms":   rtt_ms,
                                "slot":     self.current_slot,
                            }));
                            self.last_ping_push.insert(peer, now);
                            tracing::debug!(
                                "Latency: agent={} region={region} rtt={rtt_ms}ms",
                                hex::encode(agent_id),
                            );
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Pubsub message handling
    // ========================================================================

    async fn handle_pubsub_message(
        &mut self,
        _swarm: &mut Swarm<Zx01Behaviour>,
        source_peer: PeerId,
        message: gossipsub::Message,
    ) {
        // Drop if peer is flooding above the allowed rate.
        if !self.check_rate_limit(&source_peer) {
            tracing::debug!("Rate limit exceeded for pubsub peer {source_peer} — dropping");
            return;
        }

        let topic_str = message.topic.as_str();

        if let Err(e) = Envelope::check_size(message.data.len()) {
            tracing::debug!("Pubsub envelope too large from {source_peer}: {e}");
            return;
        }

        let env = match Envelope::from_cbor(&message.data) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("Pubsub CBOR decode failed from {source_peer}: {e}");
                return;
            }
        };

        // Resolve VK and validate envelope.
        // BEACONs are self-authenticating: extract VK from payload, validate
        // FIRST, then store only if the signature is valid. This prevents
        // attackers from overwriting a legitimate agent's VK with a forged one.
        let last_nonce = self.peer_states.last_nonce(&env.sender);
        if env.msg_type == MsgType::Beacon {
            let vk = match self.extract_beacon_vk(&env) {
                Some(vk) => vk,
                None => {
                    tracing::debug!("BEACON from {source_peer}: invalid VK in payload");
                    return;
                }
            };
            if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
                tracing::debug!("BEACON validation failed from {source_peer}: {e}");
                return;
            }
            self.process_beacon_payload(&env, source_peer);
        } else {
            let vk = match self.peer_states.verifying_key(&env.sender) {
                Some(vk) => *vk,
                None => {
                    tracing::debug!(
                        "No VK for {} — dropping (BEACON required first)",
                        hex::encode(env.sender),
                    );
                    return;
                }
            };
            if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
                tracing::debug!("Envelope validation failed from {source_peer}: {e}");
                return;
            }
        }

        // Registration + Lease gates — checked after signature validation.
        // BEACONs are exempt: they ARE the trigger for both checks.
        if env.msg_type == MsgType::Beacon {
            if self.peer_states.sati_status(&env.sender).is_none() {
                // Primary gate: 8004 Solana Agent Registry (HTTP GraphQL, no RPC).
                // If the agent is already registered in 8004, their existing
                // identity is connected and they pass without needing a SATI mint.
                if !self.config.registry_8004_disabled {
                    let failed_8004 = self
                        .reg8004_failures
                        .get(&env.sender)
                        .map(|t| t.elapsed().as_secs() < 3600)
                        .unwrap_or(false);
                    if !failed_8004 {
                        self.verify_8004_registration(env.sender).await;
                    }
                }
                // Legacy fallback: SATI SPL-mint check (only if 8004 did not verify).
                if self.peer_states.sati_status(&env.sender).is_none() {
                    let recently_failed = self
                        .sati_rpc_failures
                        .get(&env.sender)
                        .map(|t| t.elapsed().as_secs() < 3600)
                        .unwrap_or(false);
                    if !recently_failed {
                        self.verify_sati_registration(env.sender).await;
                    }
                }
            }
            if self.peer_states.lease_status(&env.sender).is_none()
                || self.peer_states.last_active_epoch(&env.sender) < self.current_epoch
            {
                self.verify_peer_lease(env.sender).await;
            }
        }

        if !self.sati_gate_allows(&env.sender) {
            tracing::warn!(
                "Dropping {} from unregistered agent {}",
                env.msg_type,
                hex::encode(env.sender),
            );
            return;
        }
        if !self.lease_gate_allows(&env.sender) {
            tracing::warn!(
                "Dropping {} from deactivated agent {}",
                env.msg_type,
                hex::encode(env.sender),
            );
            return;
        }

        // Update peer state.
        self.peer_states.update_nonce(env.sender, env.nonce);
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation
            .record_activity(env.sender, self.current_epoch);

        // Log envelope.
        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        // Emit visualization event.
        self.api.send_event(ApiEvent::Envelope {
            sender: hex::encode(env.sender),
            msg_type: format!("{:?}", env.msg_type),
            slot: self.current_slot,
        });

        // Push to agent inbox.
        self.api.push_inbound(&env, self.current_slot);

        self.batch
            .record_message(env.msg_type, env.sender, self.current_slot);

        // Route.
        if topic_str == TOPIC_REPUTATION && env.msg_type == MsgType::Feedback {
            self.handle_feedback_envelope(&env);
        } else if topic_str == TOPIC_NOTARY && env.msg_type == MsgType::NotarizeBid {
            tracing::info!(
                "NOTARIZE_BID from {} (conversation {})",
                hex::encode(env.sender),
                hex::encode(env.conversation_id),
            );
            // Track as notary candidate (cap pool to prevent memory exhaustion).
            if env.sender != self.identity.agent_id && self.notary_pool.len() < MAX_NOTARY_POOL {
                self.notary_pool.insert(env.sender, source_peer);
            }
            self.push_to_aggregator(serde_json::json!({
                "msg_type":        "NOTARIZE_BID",
                "sender":          hex::encode(env.sender),
                "conversation_id": hex::encode(env.conversation_id),
                "slot":            self.current_slot,
            }));
        } else if topic_str == TOPIC_BROADCAST {
            match env.msg_type {
                MsgType::Advertise => {
                    tracing::info!(
                        "ADVERTISE from {} ({} bytes)",
                        hex::encode(env.sender),
                        env.payload.len(),
                    );
                    // Parse capabilities JSON: {"capabilities": ["translation", "price-feed"]}
                    if let Ok(text) = std::str::from_utf8(&env.payload) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
                            let caps: Vec<String> = val
                                .get("capabilities")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|c| c.as_str().map(|s| s.to_string()))
                                        .take(32)
                                        .collect()
                                })
                                .unwrap_or_default();
                            let has_geo = val.get("geo").is_some();
                            // Forward whenever there are caps OR geo — they are independent.
                            if !caps.is_empty() || has_geo {
                                let mut push = serde_json::json!({
                                    "msg_type":     "ADVERTISE",
                                    "sender":       hex::encode(env.sender),
                                    "capabilities": caps,
                                    "slot":         self.current_slot,
                                });
                                if let Some(geo) = val.get("geo") {
                                    push["geo"] = geo.clone();
                                }
                                self.push_to_aggregator(push);
                            }
                        }
                    }
                }
                MsgType::Discover => {
                    tracing::debug!("DISCOVER from {}", hex::encode(env.sender));
                }
                MsgType::Beacon => { /* already handled above */ }
                _ => {}
            }
        }
    }

    // ========================================================================
    // Bilateral (request-response) handling
    // ========================================================================

    async fn handle_bilateral_request(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        peer_id: PeerId,
        data: Vec<u8>,
        channel: request_response::ResponseChannel<Vec<u8>>,
    ) {
        // Rate limit check — ACK anyway to avoid hanging the sender's channel.
        if !self.check_rate_limit(&peer_id) {
            tracing::debug!("Rate limit exceeded for bilateral peer {peer_id} — dropping");
            let _ = swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, b"ACK".to_vec());
            return;
        }

        // Always ACK immediately (§5.5).
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, b"ACK".to_vec());

        if let Err(e) = Envelope::check_size(data.len()) {
            tracing::debug!("Bilateral envelope too large from {peer_id}: {e}");
            return;
        }

        let env = match Envelope::from_cbor(&data) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("Bilateral CBOR decode failed from {peer_id}: {e}");
                return;
            }
        };

        let vk = match self.peer_states.verifying_key(&env.sender).copied() {
            Some(vk) => vk,
            None => {
                tracing::debug!("No VK for bilateral sender {}", hex::encode(env.sender),);
                return;
            }
        };

        let last_nonce = self.peer_states.last_nonce(&env.sender);
        if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
            tracing::debug!("Bilateral validation failed from {peer_id}: {e}");
            return;
        }

        // Registration check for bilateral senders not yet verified.
        // Mirrors the BEACON path: 8004 first, SATI as fallback.
        if self.peer_states.sati_status(&env.sender).is_none() {
            if !self.config.registry_8004_disabled {
                let failed_8004 = self
                    .reg8004_failures
                    .get(&env.sender)
                    .map(|t| t.elapsed().as_secs() < 3600)
                    .unwrap_or(false);
                if !failed_8004 {
                    self.verify_8004_registration(env.sender).await;
                }
            }
            if self.peer_states.sati_status(&env.sender).is_none() {
                let recently_failed = self
                    .sati_rpc_failures
                    .get(&env.sender)
                    .map(|t| t.elapsed().as_secs() < 3600)
                    .unwrap_or(false);
                if !recently_failed {
                    self.verify_sati_registration(env.sender).await;
                }
            }
        }

        // Registration + Lease gates for bilateral messages.
        if !self.sati_gate_allows(&env.sender) {
            tracing::warn!(
                "Dropping bilateral {} from unregistered agent {}",
                env.msg_type,
                hex::encode(env.sender),
            );
            return;
        }
        if self.peer_states.last_active_epoch(&env.sender) < self.current_epoch {
            self.verify_peer_lease(env.sender).await;
        }
        if !self.lease_gate_allows(&env.sender) {
            tracing::warn!(
                "Dropping bilateral {} from deactivated agent {}",
                env.msg_type,
                hex::encode(env.sender),
            );
            return;
        }

        self.peer_states.update_nonce(env.sender, env.nonce);
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation
            .record_activity(env.sender, self.current_epoch);

        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        self.batch
            .record_message(env.msg_type, env.sender, self.current_slot);
        self.track_conversation_peer(env.conversation_id, peer_id);

        // Push to agent inbox.
        self.api.push_inbound(&env, self.current_slot);

        match env.msg_type {
            MsgType::Propose => {
                // Convention: first 16 bytes of payload = LE i128 bid amount.
                let bid_value: i128 = if env.payload.len() >= BID_VALUE_LEN {
                    i128::from_le_bytes(env.payload[..BID_VALUE_LEN].try_into().unwrap())
                } else {
                    0
                };
                self.batch.add_bid(TypedBid {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    bid_value,
                    slot: self.current_slot,
                });
            }
            MsgType::Counter => {
                // Same bid extraction as PROPOSE — the counter-offered amount
                // is in the first 16 bytes of the payload.
                let bid_value: i128 = if env.payload.len() >= BID_VALUE_LEN {
                    i128::from_le_bytes(env.payload[..BID_VALUE_LEN].try_into().unwrap())
                } else {
                    0
                };
                self.batch.add_bid(TypedBid {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    bid_value,
                    slot: self.current_slot,
                });
                tracing::info!(
                    "COUNTER from {} for conversation {} (bid={})",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                    bid_value,
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "COUNTER",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "bid_value":       bid_value,
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Accept => {
                self.batch.record_accept(TaskSelection {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    slot: self.current_slot,
                });
            }
            MsgType::NotarizeAssign => {
                if env.payload.len() >= NOTARIZE_ASSIGN_VERIFIER_OFFSET {
                    let mut vid = [0u8; 32];
                    vid.copy_from_slice(&env.payload[..NOTARIZE_ASSIGN_VERIFIER_OFFSET]);
                    self.batch.record_notarize_assign(VerifierAssignment {
                        conversation_id: env.conversation_id,
                        verifier_id: vid,
                        slot: self.current_slot,
                    });
                } else {
                    tracing::debug!(
                        "NOTARIZE_ASSIGN from {} has short payload — verifier_id not recorded",
                        hex::encode(env.sender),
                    );
                }
            }
            MsgType::Verdict => {
                self.batch.record_verdict_received();
                tracing::info!(
                    "VERDICT received from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "VERDICT",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Reject => {
                tracing::info!(
                    "REJECT from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "REJECT",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Deliver => {
                tracing::info!(
                    "DELIVER from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "DELIVER",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Dispute => {
                self.batch.record_dispute();
                self.reputation.record_dispute(env.sender);
                tracing::warn!(
                    "DISPUTE from {} on conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "DISPUTE",
                    "sender":          hex::encode(env.sender),
                    "disputed_agent":  hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            _ => {}
        }
    }

    // ========================================================================
    // FEEDBACK
    // ========================================================================

    fn handle_feedback_envelope(&mut self, env: &Envelope) {
        match FeedbackPayload::decode(&env.payload) {
            Ok(fb) => {
                tracing::info!(
                    "FEEDBACK from {} → {} score={} outcome={}",
                    hex::encode(env.sender),
                    hex::encode(fb.target_agent),
                    fb.score,
                    fb.outcome,
                );
                self.reputation.apply_feedback(
                    fb.target_agent,
                    fb.score,
                    fb.role,
                    self.current_epoch,
                );

                // Encode envelope to CBOR for Merkle proof support (GAP-07).
                let raw_b64 = env
                    .to_cbor()
                    .ok()
                    .map(|b| base64::engine::general_purpose::STANDARD.encode(&b));

                // Push to aggregator.
                self.push_to_aggregator(serde_json::json!({
                    "msg_type": "FEEDBACK",
                    "sender":          hex::encode(env.sender),
                    "target_agent":    hex::encode(fb.target_agent),
                    "score":           fb.score,
                    "outcome":         fb.outcome,
                    "is_dispute":      fb.is_dispute,
                    "role":            fb.role,
                    "conversation_id": hex::encode(fb.conversation_id),
                    "slot":            self.current_slot,
                    "raw_b64":         raw_b64,
                }));

                // Update reputation snapshot.
                if let Some(rv) = self.reputation.get(&fb.target_agent) {
                    let snap = ReputationSnapshot {
                        agent_id: hex::encode(fb.target_agent),
                        reliability: rv.reliability_score,
                        cooperation: rv.cooperation_index,
                        notary_accuracy: rv.notary_accuracy,
                        total_tasks: rv.total_tasks,
                        total_disputes: rv.total_disputes,
                        last_active_epoch: rv.last_active_epoch,
                    };
                    self.api.send_event(ApiEvent::ReputationUpdate {
                        agent_id: hex::encode(fb.target_agent),
                        reliability: rv.reliability_score,
                        cooperation: rv.cooperation_index,
                    });
                    let api = self.api.clone();
                    let target = fb.target_agent;
                    tokio::spawn(async move { api.upsert_reputation(target, snap).await });
                }
                if fb.target_agent == self.identity.agent_id {
                    self.batch.record_feedback(FeedbackEvent {
                        conversation_id: fb.conversation_id,
                        from_agent: env.sender,
                        score: fb.score,
                        outcome: fb.outcome,
                        role: fb.role,
                        slot: self.current_slot,
                        sati_attestation_hash: [0u8; 32],
                    });

                    // Record bounty in portfolio if positive score
                    if fb.score > 0 {
                        let api = self.api.clone();
                        let from = env.sender;
                        let cid = hex::encode(fb.conversation_id);
                        let score = fb.score;
                        tokio::spawn(async move {
                            api.record_portfolio_event(PortfolioEvent::Bounty {
                                amount_usdc: score as f64 / 10.0, // 10 score = $1.00
                                from_agent: hex::encode(from),
                                conversation_id: cid,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            })
                            .await;
                        });
                    }
                }
            }
            Err(e) => tracing::debug!("FEEDBACK payload parse failed: {e}"),
        }
    }

    // ========================================================================
    // BEACON processing
    // ========================================================================

    fn extract_beacon_vk(&self, env: &Envelope) -> Option<VerifyingKey> {
        let p = &env.payload;
        if p.len() < BEACON_NAME_OFFSET {
            return None;
        }
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&p[BEACON_VK_OFFSET..BEACON_VK_OFFSET + 32]);
        VerifyingKey::from_bytes(&vk_bytes).ok()
    }

    fn process_beacon_payload(&mut self, env: &Envelope, source_peer: PeerId) {
        let p = &env.payload;
        if p.len() < BEACON_NAME_OFFSET {
            return;
        }

        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&p[BEACON_VK_OFFSET..BEACON_VK_OFFSET + 32]);

        if let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) {
            self.peer_states.set_verifying_key(env.sender, vk);
            self.peer_states.register_peer(env.sender, source_peer);
            tracing::info!(
                "BEACON: registered agent {} (peer {source_peer})",
                hex::encode(env.sender),
            );

            // Update peer snapshot and emit event.
            let snap = PeerSnapshot {
                agent_id: hex::encode(env.sender),
                peer_id: Some(source_peer.to_string()),
                sati_ok: self.peer_states.sati_status(&env.sender),
                lease_ok: self.peer_states.lease_status(&env.sender),
                last_active_epoch: self.peer_states.last_active_epoch(&env.sender),
            };
            self.api.send_event(ApiEvent::PeerRegistered {
                agent_id: hex::encode(env.sender),
                peer_id: source_peer.to_string(),
            });
            let api = self.api.clone();
            let sender = env.sender;
            tokio::spawn(async move { api.upsert_peer(sender, snap).await });
        }

        if p.len() > BEACON_NAME_OFFSET {
            // Limit to MAX_NAME_LEN bytes and filter non-printable ASCII to
            // prevent log injection via crafted BEACON payloads.
            let raw_len = (p.len() - BEACON_NAME_OFFSET).min(MAX_NAME_LEN);
            let raw = &p[BEACON_NAME_OFFSET..BEACON_NAME_OFFSET + raw_len];
            if let Ok(name) = std::str::from_utf8(raw) {
                let safe: String = name
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect();
                tracing::debug!("Agent name: {safe}");

                self.push_to_aggregator(serde_json::json!({
                    "msg_type": "BEACON",
                    "sender":   hex::encode(env.sender),
                    "name":     safe,
                    "slot":     self.current_slot,
                }));
            }
        }
    }

    // ========================================================================
    // Outbound helpers
    // ========================================================================

    pub fn build_envelope(
        &mut self,
        msg_type: MsgType,
        recipient: [u8; 32],
        conversation_id: [u8; 16],
        payload: Vec<u8>,
    ) -> Envelope {
        self.nonce += 1;
        Envelope::build(
            msg_type,
            self.identity.agent_id,
            recipient,
            self.current_slot,
            self.nonce,
            conversation_id,
            payload,
            &self.identity.signing_key,
        )
    }

    pub fn publish_envelope(
        &self,
        swarm: &mut Swarm<Zx01Behaviour>,
        env: &Envelope,
    ) -> anyhow::Result<()> {
        let topic_str = if env.msg_type.is_broadcast() {
            TOPIC_BROADCAST
        } else if env.msg_type.is_notary_pubsub() {
            TOPIC_NOTARY
        } else if env.msg_type.is_reputation_pubsub() {
            TOPIC_REPUTATION
        } else {
            anyhow::bail!("msg_type {:?} is not a pubsub type", env.msg_type);
        };

        let cbor = env.to_cbor()?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossipsub::IdentTopic::new(topic_str), cbor)
            .map_err(|e| anyhow::anyhow!("gossipsub publish: {e:?}"))?;
        Ok(())
    }

    /// Deliver any broadcasts that were queued due to InsufficientPeers.
    /// Called each time a peer subscribes to a gossipsub topic.
    fn flush_pending_broadcasts(&mut self, swarm: &mut Swarm<Zx01Behaviour>) {
        if self.pending_broadcasts.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending_broadcasts);
        tracing::info!(
            "Mesh peer joined — flushing {} queued broadcast(s)",
            pending.len()
        );
        for env in pending {
            if let Err(e) = self.publish_envelope(swarm, &env) {
                tracing::warn!("Queued broadcast flush failed ({}): {e}", env.msg_type);
            }
        }
    }

    pub fn send_bilateral(
        &self,
        swarm: &mut Swarm<Zx01Behaviour>,
        peer_id: PeerId,
        env: &Envelope,
    ) -> anyhow::Result<()> {
        let cbor = env.to_cbor()?;
        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, cbor);
        Ok(())
    }

    // ========================================================================
    // Outbound request handler (from Agent API)
    // ========================================================================

    async fn handle_outbound(&mut self, swarm: &mut Swarm<Zx01Behaviour>, req: OutboundRequest) {
        let env = self.build_envelope(
            req.msg_type,
            req.recipient,
            req.conversation_id,
            req.payload,
        );

        let payload_hash = hex::encode(env.payload_hash);
        let nonce = env.nonce;

        // Route: pubsub or bilateral.
        let result = if req.msg_type.is_broadcast()
            || req.msg_type.is_notary_pubsub()
            || req.msg_type.is_reputation_pubsub()
        {
            match self.publish_envelope(swarm, &env) {
                Ok(()) => Ok(()),
                Err(e) if e.to_string().contains("InsufficientPeers") => {
                    // No mesh peers yet — queue and deliver once the first peer joins.
                    // Return early: queued envelopes are not logged/batched until sent.
                    if self.pending_broadcasts.len() < MAX_PENDING_BROADCASTS {
                        tracing::debug!(
                            "No mesh peers — queuing {} (queue len {})",
                            req.msg_type,
                            self.pending_broadcasts.len() + 1,
                        );
                        self.pending_broadcasts.push(env);
                    } else {
                        tracing::warn!(
                            "Pending broadcast queue full ({}); dropping {}",
                            MAX_PENDING_BROADCASTS,
                            req.msg_type,
                        );
                    }
                    let _ = req.reply.send(Ok(SentConfirmation {
                        nonce,
                        payload_hash,
                    }));
                    return;
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            match self.peer_states.peer_id_for_agent(&req.recipient) {
                Some(peer_id) => self
                    .send_bilateral(swarm, peer_id, &env)
                    .map_err(|e| e.to_string()),
                None => Err(format!(
                    "no known peer_id for agent {}",
                    hex::encode(req.recipient),
                )),
            }
        };

        match &result {
            Ok(_) => {
                // Log and accumulate.
                if let Err(e) = self.logger.log(&env) {
                    tracing::warn!("Logger error on outbound: {e}");
                }
                self.batch
                    .record_message(req.msg_type, self.identity.agent_id, self.current_slot);
                tracing::debug!("Sent {} nonce={nonce}", req.msg_type);

                // VERDICT with approve payload → trigger escrow approve_payment on-chain.
                // Payload convention: [0x00=approve | 0x01=reject][requester(32)][provider(32)]
                if req.msg_type == MsgType::Verdict
                    && env.payload.len() >= 65
                    && env.payload[0] == 0x00
                {
                    let mut requester = [0u8; 32];
                    let mut provider = [0u8; 32];
                    requester.copy_from_slice(&env.payload[1..33]);
                    provider.copy_from_slice(&env.payload[33..65]);
                    let rpc_url = self.config.rpc_url.clone();
                    let sk_bytes = self.identity.signing_key.to_bytes();
                    let vk_bytes = self.identity.verifying_key.to_bytes();
                    let conv_id = req.conversation_id;
                    // notary_bytes = our own vk (we are the notary sending this VERDICT).
                    let notary_bytes = vk_bytes;
                    let kora = self.kora.clone();
                    tokio::spawn(async move {
                        use solana_rpc_client::nonblocking::rpc_client::RpcClient as SolanaRpc;
                        if let Err(e) = crate::escrow::approve_payment_onchain(
                            &SolanaRpc::new(rpc_url),
                            sk_bytes,
                            vk_bytes,
                            requester,
                            provider,
                            conv_id,
                            notary_bytes,
                            kora.as_ref(),
                        )
                        .await
                        {
                            tracing::warn!("Escrow approve_payment failed: {e}");
                        }
                    });
                }

                // ACCEPT sent → auto-assign a notary for this conversation (if pool non-empty).
                // This populates batch.verifier_ids, making hv (GAP-04) non-None.
                if req.msg_type == MsgType::Accept {
                    self.try_assign_notary(swarm, req.conversation_id);
                    // Escrow lock is SDK-layer responsibility — called explicitly via POST /escrow/lock.
                }
            }
            Err(e) => tracing::warn!("Outbound send failed: {e}"),
        }

        let _ = req.reply.send(result.map(|_| SentConfirmation {
            nonce,
            payload_hash,
        }));
    }

    // ========================================================================
    // Notary auto-assignment (triggered on ACCEPT send)
    // ========================================================================

    /// Pick a notary from the pool and send NOTARIZE_ASSIGN for `conversation_id`.
    ///
    /// Uses the first 8 bytes of conversation_id as a selection seed so different
    /// conversations pick different notaries — maximising verifier entropy (hv).
    fn try_assign_notary(&mut self, swarm: &mut Swarm<Zx01Behaviour>, conversation_id: [u8; 16]) {
        // Build a snapshot excluding ourselves.
        let candidates: Vec<([u8; 32], PeerId)> = self
            .notary_pool
            .iter()
            .filter(|(agent_id, _)| **agent_id != self.identity.agent_id)
            .map(|(a, p)| (*a, *p))
            .collect();

        if candidates.is_empty() {
            return;
        }

        // Use conversation_id[0..8] as an index seed for diverse selection.
        let seed = u64::from_le_bytes(conversation_id[..8].try_into().unwrap());
        let idx = (seed as usize) % candidates.len();
        let (notary_agent_id, notary_peer_id) = candidates[idx];

        // Payload: notary's agent_id (32 bytes), confirming who is being assigned.
        let env = self.build_envelope(
            MsgType::NotarizeAssign,
            notary_agent_id,
            conversation_id,
            notary_agent_id.to_vec(),
        );

        match self.send_bilateral(swarm, notary_peer_id, &env) {
            Ok(_) => {
                self.batch.record_notarize_assign(VerifierAssignment {
                    conversation_id,
                    verifier_id: notary_agent_id,
                    slot: self.current_slot,
                });
                tracing::info!(
                    "NOTARIZE_ASSIGN → {} for conversation {}",
                    &hex::encode(notary_agent_id)[..12],
                    hex::encode(conversation_id),
                );
            }
            Err(e) => tracing::warn!(
                "NOTARIZE_ASSIGN send failed for {}: {e}",
                &hex::encode(notary_agent_id)[..12],
            ),
        }
    }

    // ========================================================================
    // BEACON heartbeat
    // ========================================================================

    async fn send_beacon(&mut self, swarm: &mut Swarm<Zx01Behaviour>) {
        let mut payload = Vec::with_capacity(64 + self.config.agent_name.len());
        payload.extend_from_slice(&self.identity.agent_id);
        payload.extend_from_slice(&self.identity.verifying_key.to_bytes());
        payload.extend_from_slice(self.config.agent_name.as_bytes());

        let env = self.build_envelope(MsgType::Beacon, BROADCAST_RECIPIENT, [0u8; 16], payload);

        match self.publish_envelope(swarm, &env) {
            Ok(()) => {
                tracing::debug!("BEACON sent (nonce={})", self.nonce);
                // Gossipsub does not loop published messages back to the publisher,
                // so we push our own BEACON directly to the aggregator here.
                self.push_to_aggregator(serde_json::json!({
                    "msg_type": "BEACON",
                    "sender":   hex::encode(self.identity.agent_id),
                    "name":     self.config.agent_name,
                    "slot":     self.current_slot,
                }));
            }
            Err(e) if e.to_string().contains("InsufficientPeers") => {
                // No mesh peers yet — queue exactly one BEACON so it fires the
                // moment the first peer subscribes.  Deduplicate: if one is
                // already queued from a previous tick, replace it with the fresh
                // (higher-nonce) envelope so peers always see the latest state.
                self.pending_broadcasts
                    .retain(|e| e.msg_type != MsgType::Beacon);
                if self.pending_broadcasts.len() < MAX_PENDING_BROADCASTS {
                    tracing::debug!("No mesh peers — queuing BEACON for flush");
                    self.pending_broadcasts.push(env);
                }
            }
            Err(e) => {
                tracing::warn!("BEACON publish failed: {e}");
            }
        }
    }

    // ========================================================================
    // Epoch management + on-chain batch submission
    // ========================================================================

    async fn check_epoch_boundary(&mut self, _swarm: &mut Swarm<Zx01Behaviour>) {
        let new_epoch = current_epoch();
        if new_epoch <= self.current_epoch {
            return;
        }

        tracing::info!(
            "Epoch boundary: {} → {}. Finalising batch.",
            self.current_epoch,
            new_epoch,
        );

        let leaves = match self.logger.advance_epoch(new_epoch) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Logger advance failed: {e}");
                return;
            }
        };

        let (batch, message_slots) =
            self.batch
                .finalize(self.identity.agent_id, self.current_slot, &leaves);
        let epoch = self.current_epoch;

        let batch_hash_hex = match batch.batch_hash() {
            Ok(hash) => {
                let h = hex::encode(hash);
                tracing::info!(
                    "Epoch {epoch} batch finalised: hash={h} messages={}",
                    batch.message_count,
                );
                h
            }
            Err(e) => {
                tracing::error!("Batch hash error: {e}");
                String::new()
            }
        };

        // Push batch snapshot to visualization API.
        let batch_snap = BatchSnapshot {
            agent_id: hex::encode(self.identity.agent_id),
            epoch,
            message_count: batch.message_count,
            log_merkle_root: hex::encode(batch.log_merkle_root),
            batch_hash: batch_hash_hex.clone(),
        };
        self.api.push_batch(batch_snap).await;
        self.api.send_event(ApiEvent::BatchSubmitted {
            epoch,
            message_count: batch.message_count,
            batch_hash: batch_hash_hex,
        });

        // GAP-04: Compute verifier ID histogram and push to aggregator
        let mut verifier_histogram: HashMap<String, u32> = HashMap::new();
        for assignment in &batch.verifier_ids {
            let vid = hex::encode(assignment.verifier_id);
            *verifier_histogram.entry(vid).or_insert(0) += 1;
        }

        if !verifier_histogram.is_empty() {
            self.push_to_aggregator(serde_json::json!({
                "msg_type":  "VERIFIER_HISTOGRAM",
                "agent_id":  hex::encode(batch.agent_id),
                "epoch":     batch.epoch_number,
                "histogram": verifier_histogram,
            }));
        }

        // Compute entropy vector and push to aggregator.
        let ev = zerox1_protocol::entropy::compute(
            &batch,
            &message_slots,
            &zerox1_protocol::entropy::EntropyParams::default(),
        );
        tracing::info!(
            "Epoch {epoch} entropy: ht={:?} hb={:?} hs={:?} hv={:?} anomaly={:.4}",
            ev.ht,
            ev.hb,
            ev.hs,
            ev.hv,
            ev.anomaly,
        );
        self.push_to_aggregator(serde_json::json!({
            "msg_type":  "ENTROPY",
            "agent_id":  hex::encode(ev.agent_id),
            "epoch":     ev.epoch,
            "ht":        ev.ht,
            "hb":        ev.hb,
            "hs":        ev.hs,
            "hv":        ev.hv,
            "anomaly":   ev.anomaly,
            "n_ht":      ev.n_ht,
            "n_hb":      ev.n_hb,
            "n_hs":      ev.n_hs,
            "n_hv":      ev.n_hv,
        }));

        // GAP-06: Check SRI circuit breaker before on-chain submission.
        // If the network-wide Systemic Risk Index exceeds the threshold the
        // aggregator sets circuit_breaker_active=true; we pause submission to
        // avoid contributing to a compromised epoch record.
        let circuit_breaker = self.check_sri_circuit_breaker().await;
        if circuit_breaker {
            tracing::warn!(
                "SRI circuit breaker ACTIVE — skipping on-chain batch submission for epoch {epoch}. \
                 Network anomaly level exceeds 50%. Submission will resume when SRI drops."
            );
        } else if let Err(e) = submit::submit_batch_onchain(
            &self.rpc,
            &self.identity,
            &batch,
            epoch,
            self.kora.as_ref(),
        )
        .await
        {
            tracing::error!("Batch submission failed for epoch {epoch}: {e}");
        }

        self.current_epoch = new_epoch;
        self.batch = BatchAccumulator::new(new_epoch, self.current_slot);
        self.reputation.advance_epoch(new_epoch);

        // Purge stale registration failure cache entries (TTL = 1 hour).
        let sati_ttl = std::time::Duration::from_secs(3_600);
        self.sati_rpc_failures
            .retain(|_, ts| ts.elapsed() < sati_ttl);
        // Hard cap: if still over limit (many fresh failures), evict oldest entries.
        if self.sati_rpc_failures.len() > MAX_SATI_FAILURE_CACHE {
            let over = self.sati_rpc_failures.len() - MAX_SATI_FAILURE_CACHE;
            // Sort by elapsed descending (oldest first), take `over` to remove.
            let mut by_age: Vec<_> = self
                .sati_rpc_failures
                .iter()
                .map(|(k, ts)| (*k, ts.elapsed()))
                .collect();
            by_age.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            for (k, _) in by_age.into_iter().take(over) {
                self.sati_rpc_failures.remove(&k);
            }
        }
        // Same TTL + cap for the 8004 HTTP failure cache.
        self.reg8004_failures
            .retain(|_, ts| ts.elapsed() < sati_ttl);
        if self.reg8004_failures.len() > MAX_REG8004_FAILURE_CACHE {
            let over = self.reg8004_failures.len() - MAX_REG8004_FAILURE_CACHE;
            let mut by_age: Vec<_> = self
                .reg8004_failures
                .iter()
                .map(|(k, ts)| (*k, ts.elapsed()))
                .collect();
            by_age.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            for (k, _) in by_age.into_iter().take(over) {
                self.reg8004_failures.remove(&k);
            }
        }

        // Check own lease renewal at each epoch boundary.
        self.maybe_renew_own_lease().await;
    }

    // ========================================================================
    // Inactivity enforcement
    // ========================================================================

    async fn check_inactive_agents(&self) {
        if self.dev_mode {
            return;
        }
        let usdc_mint = match self.usdc_mint {
            Some(ref m) => *m,
            None => {
                tracing::debug!("Skipping inactivity check — no --usdc-mint configured.");
                return;
            }
        };

        let agents = self.peer_states.all_agent_ids();
        if agents.is_empty() {
            return;
        }

        tracing::debug!("Running inactivity check for {} known agents", agents.len());
        inactive::check_and_slash_inactive(
            &self.rpc,
            &self.identity,
            self.kora.as_ref(),
            &usdc_mint,
            &agents,
            &self.api,
        )
        .await;
    }

    // ========================================================================
    // Aggregator push
    // ========================================================================

    // ========================================================================
    // SRI circuit breaker (GAP-06)
    // ========================================================================

    /// Query the aggregator's /system/sri endpoint.
    /// Returns true if the circuit breaker is active (SRI > 0.50).
    /// Fails open (returns false) if no aggregator is configured or the
    /// request fails, so a network partition never blocks honest nodes.
    async fn check_sri_circuit_breaker(&self) -> bool {
        let url = match &self.aggregator_url {
            Some(u) => format!("{}/system/sri", u.trim_end_matches('/')),
            None => return false,
        };
        let client = self.http_client.clone();
        let secret = self.aggregator_secret.clone();
        let result: Result<bool, _> = async move {
            let mut req = client.get(&url);
            if let Some(s) = secret {
                req = req.header("Authorization", format!("Bearer {s}"));
            }
            let text = req.send().await?.text().await?;
            let val: serde_json::Value = serde_json::from_str(&text)?;
            Ok::<bool, anyhow::Error>(
                val.get("circuit_breaker_active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            )
        }
        .await;
        match result {
            Ok(active) => {
                if active {
                    tracing::warn!("SRI circuit breaker is active (aggregator reports SRI > 0.50)");
                }
                active
            }
            Err(e) => {
                tracing::debug!("SRI check failed (fail-open): {e}");
                false
            }
        }
    }

    fn push_to_aggregator(&self, payload: serde_json::Value) {
        let url = match &self.aggregator_url {
            Some(u) => format!("{}/ingest/envelope", u.trim_end_matches('/')),
            None => return,
        };
        let client = self.http_client.clone();
        let secret = self.aggregator_secret.clone();
        tokio::spawn(async move {
            let mut req = client.post(&url).json(&payload);
            if let Some(s) = secret {
                req = req.header("Authorization", format!("Bearer {s}"));
            }
            if let Err(e) = req.send().await {
                tracing::warn!("Aggregator push failed: {e}");
            }
        });
    }

    fn track_conversation_peer(&mut self, conversation_id: [u8; 16], peer_id: PeerId) {
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.conversations.entry(conversation_id)
        {
            entry.insert(peer_id);
            self.conversation_lru.retain(|cid| *cid != conversation_id);
            self.conversation_lru.push_back(conversation_id);
            return;
        }

        while self.conversations.len() >= MAX_ACTIVE_CONVERSATIONS {
            if let Some(oldest) = self.conversation_lru.pop_front() {
                self.conversations.remove(&oldest);
            } else {
                break;
            }
        }

        self.conversations.insert(conversation_id, peer_id);
        self.conversation_lru.push_back(conversation_id);
    }

    // ========================================================================
    // Per-peer rate limiting
    // ========================================================================

    /// Returns false if the peer has exceeded MESSAGE_RATE_LIMIT in the
    /// current 1-second window. The caller should drop the message silently.
    fn check_rate_limit(&mut self, peer: &libp2p::PeerId) -> bool {
        use zerox1_protocol::constants::MESSAGE_RATE_LIMIT;
        let now = std::time::Instant::now();

        // Fast path: peer already tracked.
        if let Some(entry) = self.rate_limiter.get_mut(peer) {
            if now.duration_since(entry.1).as_secs() >= 1 {
                *entry = (1, now);
                return true;
            }
            if entry.0 >= MESSAGE_RATE_LIMIT {
                return false;
            }
            entry.0 += 1;
            return true;
        }

        // New peer — enforce cap before inserting.
        if self.rate_limiter.len() >= MAX_RATE_LIMITER_PEERS {
            // Evict entries whose window has already expired.
            self.rate_limiter
                .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 1);
            // If still at capacity, skip tracking this peer (allow the message).
            if self.rate_limiter.len() >= MAX_RATE_LIMITER_PEERS {
                tracing::debug!("rate_limiter at capacity — skipping tracking for {peer}");
                return true;
            }
        }

        self.rate_limiter.insert(*peer, (1, now));
        true
    }
}

fn validated_aggregator_url(url: Option<String>) -> Option<String> {
    let raw = url?;

    let parsed = match reqwest::Url::parse(&raw) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("Ignoring invalid --aggregator-url '{raw}': {e}");
            return None;
        }
    };

    let is_internal = match parsed.host() {
        Some(Host::Domain(h)) => {
            h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local")
        }
        Some(Host::Ipv4(ip)) => is_private_or_local_ip(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => is_private_or_local_ip(IpAddr::V6(ip)),
        None => false,
    };

    if parsed.scheme() != "https" && !is_internal {
        tracing::warn!("Ignoring non-HTTPS aggregator URL: {raw}");
        return None;
    }

    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => {
            tracing::warn!("Ignoring aggregator URL without host: {raw}");
            return None;
        }
    };

    if !is_internal {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_or_local_ip(ip) {
                tracing::warn!("Ignoring aggregator URL with local/private host: {raw}");
                return None;
            }
        } else {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let addrs: Vec<_> = match (host.as_str(), port).to_socket_addrs() {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    tracing::warn!("Ignoring aggregator URL; failed to resolve host '{host}': {e}");
                    return None;
                }
            };
            if addrs.is_empty() {
                tracing::warn!("Ignoring aggregator URL; host '{host}' resolved to no addresses");
                return None;
            }
            if addrs.iter().any(|addr| is_private_or_local_ip(addr.ip())) {
                tracing::warn!(
                    "Ignoring aggregator URL with host resolving to local/private IPs: {raw}"
                );
                return None;
            }
        }
    }

    Some(parsed.to_string())
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
        }
    }
}
