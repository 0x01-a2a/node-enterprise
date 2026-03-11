use ed25519_dalek::VerifyingKey;
use libp2p::PeerId;
use std::collections::HashMap;

/// Maximum number of distinct 0x01 agents tracked in memory.
/// Prevents unbounded growth from BEACON floods with rotating sender IDs.
const MAX_PEERS: usize = 10_000;

/// Maximum number of identify keys buffered before a BEACON arrives.
const MAX_PENDING_KEYS: usize = 200;

/// Per-peer cached state for envelope validation.
#[derive(Default)]
pub struct PeerEntry {
    /// Last validated nonce from this sender (replay protection).
    pub last_nonce: u64,
    /// Ed25519 verifying key (populated from BEACON payload or identify).
    pub verifying_key: Option<VerifyingKey>,
    /// libp2p PeerId for this agent (populated on connect + BEACON).
    pub peer_id: Option<PeerId>,
    /// Last active epoch (for decay tracking).
    pub last_active_epoch: u64,
}

/// Thread-local in-memory peer state map.
pub struct PeerStateMap {
    by_agent_id: HashMap<[u8; 32], PeerEntry>,
    /// Durable replay floor for known agents.
    /// Preserved across in-memory `by_agent_id` evictions so nonce replay
    /// protection does not reset under churn.
    confirmed_nonce_floor: HashMap<[u8; 32], u64>,
    /// Reverse lookup: libp2p PeerId → 0x01 agent_id.
    peer_to_agent: HashMap<PeerId, [u8; 32]>,
    /// Keys received from the `identify` protocol before the peer has sent a
    /// BEACON.  Stored here temporarily and applied once register_peer() is
    /// called for that PeerId.
    pending_keys: HashMap<PeerId, VerifyingKey>,
}

impl PeerStateMap {
    pub fn new() -> Self {
        Self {
            by_agent_id: HashMap::new(),
            confirmed_nonce_floor: HashMap::new(),
            peer_to_agent: HashMap::new(),
            pending_keys: HashMap::new(),
        }
    }

    fn entry(&mut self, agent_id: [u8; 32]) -> &mut PeerEntry {
        if !self.by_agent_id.contains_key(&agent_id) && self.by_agent_id.len() >= MAX_PEERS {
            // Evict an arbitrary entry to enforce MAX_PEERS and prevent
            // unbounded growth from BEACON floods.
            let evict_key = self.by_agent_id.keys().next().copied();
            if let Some(evict_key) = evict_key {
                if let Some(entry) = self.by_agent_id.remove(&evict_key) {
                    if let Some(pid) = entry.peer_id {
                        self.peer_to_agent.remove(&pid);
                    }
                    // Preserve the replay nonce floor across eviction.
                    let floor = self.confirmed_nonce_floor.entry(evict_key).or_insert(0);
                    *floor = (*floor).max(entry.last_nonce);
                }
            }
        }
        self.by_agent_id.entry(agent_id).or_default()
    }

    pub fn last_nonce(&self, agent_id: &[u8; 32]) -> u64 {
        let in_mem = self.by_agent_id.get(agent_id).map_or(0, |e| e.last_nonce);
        let floor = self
            .confirmed_nonce_floor
            .get(agent_id)
            .copied()
            .unwrap_or(0);
        in_mem.max(floor)
    }

    pub fn update_nonce(&mut self, agent_id: [u8; 32], nonce: u64) {
        let entry = self.entry(agent_id);
        entry.last_nonce = nonce;
        let floor = self.confirmed_nonce_floor.entry(agent_id).or_insert(0);
        *floor = (*floor).max(nonce);
    }

    pub fn verifying_key(&self, agent_id: &[u8; 32]) -> Option<&VerifyingKey> {
        self.by_agent_id.get(agent_id)?.verifying_key.as_ref()
    }

    pub fn set_verifying_key(&mut self, agent_id: [u8; 32], vk: VerifyingKey) {
        self.entry(agent_id).verifying_key = Some(vk);
    }

    /// Register the agent_id ↔ PeerId mapping.
    ///
    /// If a key was received from `identify` before this peer had sent a
    /// BEACON (stored in `pending_keys`), it is applied immediately.
    pub fn register_peer(&mut self, agent_id: [u8; 32], peer_id: PeerId) {
        let entry = self.entry(agent_id);
        entry.peer_id = Some(peer_id);
        self.peer_to_agent.insert(peer_id, agent_id);

        // Apply any pending key that arrived before the BEACON.
        if let Some(vk) = self.pending_keys.remove(&peer_id) {
            self.by_agent_id
                .get_mut(&agent_id)
                .unwrap()
                .verifying_key
                .get_or_insert(vk);
        }
    }

    pub fn peer_id_for_agent(&self, agent_id: &[u8; 32]) -> Option<PeerId> {
        self.by_agent_id.get(agent_id)?.peer_id
    }

    #[allow(dead_code)]
    pub fn agent_id_for_peer(&self, peer_id: &PeerId) -> Option<[u8; 32]> {
        self.peer_to_agent.get(peer_id).copied()
    }

    pub fn last_active_epoch(&self, agent_id: &[u8; 32]) -> u64 {
        self.by_agent_id
            .get(agent_id)
            .map_or(0, |e| e.last_active_epoch)
    }

    pub fn touch_epoch(&mut self, agent_id: [u8; 32], epoch: u64) {
        let e = self.entry(agent_id);
        if epoch > e.last_active_epoch {
            e.last_active_epoch = epoch;
        }
    }

    /// Associate a libp2p verifying key (from identify) with a peer.
    ///
    /// If the peer_id → agent_id mapping is already known (the peer has sent a
    /// BEACON), stores the key immediately.  Otherwise, stashes it in
    /// `pending_keys`; it will be applied when `register_peer` is called.
    pub fn set_key_for_peer(&mut self, peer_id: &PeerId, vk: VerifyingKey) {
        if let Some(&agent_id) = self.peer_to_agent.get(peer_id) {
            let entry = self.entry(agent_id);
            // Only set if not already populated — BEACON payload takes priority.
            entry.verifying_key.get_or_insert(vk);
        } else {
            // Cap pending_keys to avoid unbounded growth from identify storms.
            if self.pending_keys.len() >= MAX_PENDING_KEYS {
                if let Some(&old_peer) = self.pending_keys.keys().next() {
                    self.pending_keys.remove(&old_peer);
                }
            }
            self.pending_keys.insert(*peer_id, vk);
        }
    }
}
