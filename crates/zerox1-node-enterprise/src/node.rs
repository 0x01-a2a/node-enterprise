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

use zerox1_protocol::{
    batch::{FeedbackEvent, TaskSelection, TypedBid},
    constants::{TOPIC_BROADCAST, TOPIC_REPUTATION},
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::FeedbackPayload,
};

use crate::{
    api::{
        ApiEvent, ApiState, BatchSnapshot, OutboundRequest, PeerSnapshot,
        ReputationSnapshot, SentConfirmation,
    },
    batch::{current_epoch, now_micros, BatchAccumulator},
    config::Config,
    identity::AgentIdentity,
    logger::EnvelopeLogger,
    network::{Zx01Behaviour, Zx01BehaviourEvent},
    peer_state::PeerStateMap,
    reputation::ReputationTracker,
};

// ============================================================================
// Payload layout conventions (documented for agent application authors)
//
// BEACON:          [agent_id(32)][verifying_key(32)][name(utf-8)]
// PROPOSE/COUNTER: [bid_value(16, LE i128)][opaque agent payload...]
// ============================================================================

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const BEACON_VK_OFFSET: usize = 32;
const BEACON_NAME_OFFSET: usize = 64;
const BID_VALUE_LEN: usize = 16;
/// Maximum bytes read from BEACON name field.
const MAX_NAME_LEN: usize = 64;
/// Maximum tracked conversations (bilateral message sender ↔ conversation).
const MAX_ACTIVE_CONVERSATIONS: usize = 10_000;
/// Maximum broadcast envelopes queued while waiting for mesh peers.
const MAX_PENDING_BROADCASTS: usize = 20;
/// Maximum number of distinct peers tracked in the rate-limit table.
/// When full, expired entries are evicted; if still full the new peer is skipped.
const MAX_RATE_LIMITER_PEERS: usize = 10_000;

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

    /// Visualization API shared state (always present; server only started when
    /// --api-addr is configured).
    api: ApiState,

    nonce: u64,
    current_epoch: u64,
    conversations: HashMap<[u8; 16], PeerId>,
    conversation_lru: VecDeque<[u8; 16]>,

    /// Receives outbound envelope requests from the Agent API (POST /envelopes/send).
    outbound_rx: tokio::sync::mpsc::Receiver<OutboundRequest>,
    /// Receives pre-signed envelopes from the hosted-agent API (POST /hosted/send).
    hosted_outbound_rx: tokio::sync::mpsc::Receiver<zerox1_protocol::envelope::Envelope>,

    /// Reputation aggregator base URL — FEEDBACK/VERDICT envelopes are pushed here.
    aggregator_url: Option<String>,
    /// Shared secret sent in Authorization header when pushing to the aggregator.
    aggregator_secret: Option<String>,
    /// Shared HTTP client for aggregator pushes — avoids per-push TCP setup.
    http_client: reqwest::Client,
    /// Per-peer message rate limiter: PeerId → (count_in_window, window_start).
    rate_limiter: std::collections::HashMap<libp2p::PeerId, (u32, std::time::Instant)>,
    /// Bootstrap peer multiaddrs — used to redial when the node loses all connections.
    bootstrap_peers: Vec<libp2p::Multiaddr>,
    /// Broadcasts queued when gossipsub had no mesh peers (InsufficientPeers).
    /// Flushed the moment any peer subscribes to our topic.
    pending_broadcasts: Vec<Envelope>,
    /// Throttle map for latency reports: last time we pushed a LATENCY event
    /// for each peer. Prevents flooding the aggregator with per-ping pushes.
    /// Only populated when --node-region is set.
    last_ping_push: HashMap<PeerId, std::time::Instant>,
}

impl Zx01Node {
    pub async fn new(
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
        let http_client = reqwest::Client::new();
        let aggregator_url = validated_aggregator_url(config.aggregator_url.clone());
        let aggregator_secret = config.aggregator_secret.clone();

        let (api, outbound_rx, hosted_outbound_rx) = ApiState::new(
            identity.agent_id,
            config.agent_name.clone(),
            config.api_secret.clone(),
            config.api_read_keys.clone(),
            config.hosting_fee_bps,
            http_client.clone(),
            config.skill_workspace.clone(),
        );

        let batch = BatchAccumulator::new(epoch, 0);
        let logger = EnvelopeLogger::new(log_dir, epoch);

        Ok(Self {
            config,
            identity,
            peer_states: PeerStateMap::new(),
            reputation: ReputationTracker::new(),
            logger,
            batch,
            api,
            nonce: 0,
            current_epoch: epoch,
            conversations: HashMap::new(),
            conversation_lru: VecDeque::new(),
            outbound_rx,
            hosted_outbound_rx,
            aggregator_url,
            aggregator_secret,
            http_client,
            rate_limiter: std::collections::HashMap::new(),
            bootstrap_peers,
            pending_broadcasts: Vec::new(),
            last_ping_push: HashMap::new(),
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
                    // Without a secret every mutating endpoint (/envelopes/send) would be
                    // open to anyone on the network.
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

        // ── Geo self-registration ─────────────────────────────────────────────
        if let Some(ref country) = self.config.geo_country {
            self.push_to_aggregator(serde_json::json!({
                "msg_type":     "ADVERTISE",
                "sender":       hex::encode(self.identity.agent_id),
                "capabilities": [],
                "slot":         now_secs(),
                "geo": {
                    "country": country,
                    "city":    self.config.geo_city.clone(),
                }
            }));
            tracing::info!("Geo registered: country={country}");
        }

        let mut beacon_timer = tokio::time::interval(Duration::from_secs(30));
        let mut epoch_timer = tokio::time::interval(Duration::from_secs(30));
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
                    // Record it in the batch so it's not bypassing the epoch logging!
                    self.batch.record_message(env.msg_type, env.sender, now_secs());
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
                                "slot":     now_secs(),
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
            slot: now_secs(),
        });

        // Push to agent inbox.
        self.api.push_inbound(&env);

        self.batch
            .record_message(env.msg_type, env.sender, now_secs());

        // Route.
        if topic_str == TOPIC_REPUTATION && env.msg_type == MsgType::Feedback {
            self.handle_feedback_envelope(&env);
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
                                    "slot":         now_secs(),
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

        self.peer_states.update_nonce(env.sender, env.nonce);
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation
            .record_activity(env.sender, self.current_epoch);

        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        self.batch
            .record_message(env.msg_type, env.sender, now_secs());
        self.track_conversation_peer(env.conversation_id, peer_id);

        // Push to agent inbox.
        self.api.push_inbound(&env);

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
                    slot: now_secs(),
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
                    slot: now_secs(),
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
                    "slot":            now_secs(),
                }));
            }
            MsgType::Accept => {
                self.batch.record_accept(TaskSelection {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    slot: now_secs(),
                });
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
                    "slot":            now_secs(),
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
                    "slot":            now_secs(),
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
                    "slot":            now_secs(),
                }));
            }
            // ── Collaboration messages (0x1_) ─────────────────────────────────
            MsgType::Assign => {
                tracing::info!(
                    "ASSIGN from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "ASSIGN",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::Ack => {
                tracing::info!(
                    "ACK from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "ACK",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::Clarify => {
                tracing::info!(
                    "CLARIFY from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "CLARIFY",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::Report => {
                tracing::info!(
                    "REPORT from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "REPORT",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::Approve => {
                tracing::info!(
                    "APPROVE from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "APPROVE",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::TaskCancel => {
                tracing::info!(
                    "TASK_CANCEL from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "TASK_CANCEL",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::Escalate => {
                tracing::warn!(
                    "ESCALATE from {} for conversation {} - human decision required",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "ESCALATE",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
                }));
            }
            MsgType::Sync => {
                tracing::debug!(
                    "SYNC from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "SYNC",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            now_secs(),
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
                    0,
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
                    "conversation_id": hex::encode(fb.conversation_id),
                    "slot":            now_secs(),
                    "raw_b64":         raw_b64,
                }));

                // Update reputation snapshot.
                if let Some(rv) = self.reputation.get(&fb.target_agent) {
                    let snap = ReputationSnapshot {
                        agent_id: hex::encode(fb.target_agent),
                        reliability: rv.reliability_score,
                        cooperation: rv.cooperation_index,
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
                        slot: now_secs(),
                    });

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
                    "slot":     now_secs(),
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
            now_secs(),
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
        let result = if req.msg_type.is_broadcast() || req.msg_type.is_reputation_pubsub() {
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
                    .record_message(req.msg_type, self.identity.agent_id, now_secs());
                tracing::debug!("Sent {} nonce={nonce}", req.msg_type);
            }
            Err(e) => tracing::warn!("Outbound send failed: {e}"),
        }

        let _ = req.reply.send(result.map(|_| SentConfirmation {
            nonce,
            payload_hash,
        }));
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
                    "slot":     now_secs(),
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

        let batch =
            self.batch
                .finalize(self.identity.agent_id, now_secs(), &leaves);
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

        self.current_epoch = new_epoch;
        self.batch = BatchAccumulator::new(new_epoch, now_secs());
        self.reputation.advance_epoch(new_epoch);
    }

    // ========================================================================
    // Aggregator push
    // ========================================================================

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
