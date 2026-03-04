//! In-memory reputation store with optional SQLite persistence.
//!
//! All reads are served from a fast in-memory HashMap.
//! Every ingest event is also written to SQLite (when `--db-path` is set)
//! so data survives restarts without replaying node pushes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

// ============================================================================
// Input validation
// ============================================================================

/// Validate agent IDs: accepts both legacy hex (64 chars) and 8004 base58 (32-44 chars).
fn is_valid_agent_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    // Legacy: 64 hex chars (SATI mint)
    if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // 8004: base58 Solana pubkey (32-44 chars, alphanumeric no 0/O/I/l)
    if id.len() >= 32 && id.len() <= 44 && bs58::decode(id).into_vec().is_ok() {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_agents_pagination() {
        let store = ReputationStore::new();

        // Populate with 25 dummy agents
        // Using "agent-{i:02}" ensures lexicographical order matches numerical order for easy testing
        for i in 0..25 {
            let agent_id = format!("agent-{:02}", i);
            let mut inner = store.inner.write().unwrap();
            inner
                .agents
                .insert(agent_id.clone(), AgentReputation::new(agent_id));
        }

        // Test case 1: Basic pagination (limit 10, offset 0)
        let page1 = store.list_agents(10, 0, "id", None);
        assert_eq!(page1.len(), 10);
        assert_eq!(page1[0].agent_id, "agent-00");
        assert_eq!(page1[9].agent_id, "agent-09");

        // Test case 2: Second page (limit 10, offset 10)
        let page2 = store.list_agents(10, 10, "id", None);
        assert_eq!(page2.len(), 10);
        assert_eq!(page2[0].agent_id, "agent-10");
        assert_eq!(page2[9].agent_id, "agent-19");

        // Test case 3: Partial last page (limit 10, offset 20) -> should get 5 items
        let page3 = store.list_agents(10, 20, "id", None);
        assert_eq!(page3.len(), 5);
        assert_eq!(page3[0].agent_id, "agent-20");
        assert_eq!(page3[4].agent_id, "agent-24");

        // Test case 4: Offset beyond range
        let page4 = store.list_agents(10, 50, "id", None);
        assert!(page4.is_empty());

        // Test case 5: Limit larger than total
        let page5 = store.list_agents(100, 0, "id", None);
        assert_eq!(page5.len(), 25);
    }
}

// ============================================================================
// Wire types (matches node.rs push format + serde tag)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEvent {
    pub sender: String,
    pub target_agent: String,
    pub score: i32,
    pub outcome: u8,
    pub is_dispute: bool,
    pub role: u8,
    pub conversation_id: String,
    pub slot: u64,
    /// Base64-encoded raw CBOR envelope bytes — used for Merkle proof construction.
    /// None when pushed by older node versions.
    pub raw_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictEvent {
    pub sender: String,
    pub recipient: String,
    pub conversation_id: String,
    pub slot: u64,
}

/// Entropy vector pushed by a node at epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyEvent {
    pub agent_id: String,
    pub epoch: u64,
    pub ht: Option<f64>,
    pub hb: Option<f64>,
    pub hs: Option<f64>,
    pub hv: Option<f64>,
    pub anomaly: f64,
    pub n_ht: u32,
    pub n_hb: u32,
    pub n_hs: u32,
    pub n_hv: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizeBidEvent {
    pub sender: String,
    pub conversation_id: String,
    pub slot: u64,
}

/// Latency measurement pushed by a reference node (--node-region).
/// agent_id is the measured peer; region identifies the reference point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyEvent {
    pub agent_id: String,
    pub region: String,
    pub rtt_ms: u64,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvertiseEvent {
    pub sender: String,
    pub capabilities: Vec<String>,
    pub slot: u64,
    #[serde(default)]
    pub geo: Option<GeoInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeEvent {
    pub sender: String,
    pub disputed_agent: String,
    pub conversation_id: String,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconEvent {
    pub sender: String,
    pub name: String,
    pub slot: u64,
}

/// A message held by the aggregator for a sleeping phone node.
/// Drained on the next `GET /agents/{id}/pending` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessage {
    /// Unique ID — nanosecond hex timestamp on arrival.
    pub id: String,
    /// Hex-encoded agent_id of the sender.
    pub from: String,
    /// Protocol message type, e.g. "PROPOSE".
    pub msg_type: String,
    /// Base64-encoded raw CBOR envelope bytes.
    pub payload: String,
    /// Unix timestamp (seconds) when the aggregator received this message.
    pub ts: u64,
}

/// A single dispute record — used by GET /disputes/{agent_id}.
#[derive(Debug, Clone, Serialize)]
pub struct DisputeRecord {
    pub id: i64,
    pub sender: String,
    pub disputed_agent: String,
    pub conversation_id: String,
    pub slot: u64,
    pub ts: u64,
}

/// Capability match — used by GET /agents/search.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityMatch {
    pub agent_id: String,
    pub capability: String,
    pub last_seen: u64,
}

/// A full registry entry populated by BEACON tracking
#[derive(Debug, Clone, Serialize)]
pub struct AgentRegistryEntry {
    pub agent_id: String,
    pub name: String,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Full agent profile — reputation + entropy + capabilities + recent disputes + name.
/// Returned by GET /agents/{agent_id}/profile to avoid multiple round trips.
#[derive(Debug, Clone, Serialize)]
pub struct AgentProfile {
    pub agent_id: String,
    pub name: Option<String>,
    pub reputation: Option<AgentReputation>,
    pub entropy: Option<EntropyEvent>,
    pub capabilities: Vec<CapabilityMatch>,
    pub disputes: Vec<DisputeRecord>,
    pub last_seen: Option<u64>,
}

/// Activity event broadcast to WebSocket clients and stored in activity_log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub ts: i64,
    pub event_type: String, // "JOIN" | "FEEDBACK" | "DISPUTE" | "VERDICT"
    pub agent_id: String,
    pub target_id: Option<String>,
    pub score: Option<i64>,
    pub name: Option<String>,
    pub target_name: Option<String>,
    pub slot: Option<i64>,
    pub conversation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type")]
pub enum IngestEvent {
    #[serde(rename = "FEEDBACK")]
    Feedback(FeedbackEvent),
    #[serde(rename = "VERDICT")]
    Verdict(VerdictEvent),
    #[serde(rename = "ENTROPY")]
    Entropy(EntropyEvent),
    #[serde(rename = "NOTARIZE_BID")]
    NotarizeBid(NotarizeBidEvent),
    #[serde(rename = "ADVERTISE")]
    Advertise(AdvertiseEvent),
    #[serde(rename = "DISPUTE")]
    Dispute(DisputeEvent),
    #[serde(rename = "BEACON")]
    Beacon(BeaconEvent),
    #[serde(rename = "LATENCY")]
    Latency(LatencyEvent),
}

// ============================================================================
// Reputation record
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct AgentReputation {
    pub agent_id: String,
    pub feedback_count: u64,
    pub total_score: i64,
    pub positive_count: u64,
    pub neutral_count: u64,
    pub negative_count: u64,
    pub verdict_count: u64,
    pub average_score: f64,
    pub last_updated: u64,
    /// Computed on read from DB; not stored. "rising" | "falling" | "stable".
    #[serde(default = "default_trend")]
    pub trend: String,
    #[serde(default)]
    pub last_seen: u64,
    /// Human-readable name from the last BEACON, empty string if unknown.
    #[serde(default)]
    pub name: String,
    /// ISO 3166-1 alpha-2 country code (self-reported via ADVERTISE geo field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// City name (self-reported via ADVERTISE geo field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Measured RTT in ms from each reference node: region → rtt_ms.
    /// Populated by genesis nodes running with --node-region.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub latency: std::collections::HashMap<String, u64>,
    /// Whether the measured latency profile is consistent with the claimed
    /// geo country. None = not enough data; true/false = verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_consistent: Option<bool>,
}

fn default_trend() -> String {
    "stable".to_string()
}

/// Check whether a measured latency profile is plausible for a claimed country.
///
/// Returns `Some(true)` if consistent, `Some(false)` if implausible, `None` if
/// there is not enough data to make a determination.
///
/// Uses generous upper-bound RTT thresholds so honest agents are not falsely
/// flagged. The check mainly catches agents that claim one continent but have
/// sub-50ms RTT to a reference node on another continent.
fn compute_geo_consistent(
    country: &str,
    latency: &std::collections::HashMap<String, u64>,
) -> Option<bool> {
    if latency.is_empty() {
        return None;
    }
    // (max_rtt_from_us_east_ms, max_rtt_from_eu_west_ms)
    // None means "no bound for this reference point" (e.g. country is on same
    // side of the world as one reference but far from the other).
    let (us_max, eu_max): (u64, u64) = match country.to_uppercase().as_str() {
        // North America
        "US" | "CA" | "MX" => (80, 220),
        // Caribbean / Central America
        "CU" | "DO" | "HT" | "JM" | "TT" | "BB" | "CR" | "PA" | "GT" | "HN" | "SV" | "NI"
        | "BZ" => (140, 260),
        // South America
        "BR" | "AR" | "CL" | "CO" | "PE" | "VE" | "EC" | "BO" | "PY" | "UY" | "GY" | "SR"
        | "GF" => (220, 300),
        // Western Europe
        "DE" | "FR" | "GB" | "NL" | "BE" | "CH" | "AT" | "SE" | "NO" | "DK" | "FI" | "IE"
        | "PT" | "ES" | "IT" | "LU" | "IS" => (200, 60),
        // Eastern / Southern Europe
        "PL" | "CZ" | "SK" | "HU" | "RO" | "BG" | "HR" | "RS" | "SI" | "GR" | "EE" | "LV"
        | "LT" | "UA" | "BY" | "MD" | "CY" | "AL" | "MK" | "BA" | "ME" | "XK" => (220, 100),
        // North Africa + Middle East
        "EG" | "MA" | "DZ" | "TN" | "LY" | "AE" | "SA" | "QA" | "KW" | "BH" | "OM" | "IQ"
        | "IR" | "IL" | "JO" | "LB" | "SY" | "TR" => (260, 180),
        // Sub-Saharan Africa
        "NG" | "GH" | "KE" | "ZA" | "ET" | "TZ" | "UG" | "RW" | "SN" | "CI" | "CM" | "CD"
        | "AO" | "MZ" | "ZM" | "ZW" | "BW" | "NA" | "MG" | "MU" | "TG" | "BJ" | "ML"
        | "BF" | "NE" | "TD" | "SO" | "ER" | "SS" => (300, 220),
        // South Asia
        "IN" | "PK" | "BD" | "LK" | "NP" | "AF" | "MV" => (360, 300),
        // Southeast Asia
        "SG" | "MY" | "TH" | "PH" | "ID" | "VN" | "MM" | "KH" | "LA" | "BN" | "TL" => {
            (380, 340)
        }
        // East Asia
        "JP" | "KR" | "CN" | "TW" | "HK" | "MO" | "MN" => (340, 360),
        // Central Asia
        "KZ" | "UZ" | "TM" | "KG" | "TJ" => (280, 220),
        // Oceania
        "AU" | "NZ" | "FJ" | "PG" | "SB" | "VU" | "WS" | "TO" => (380, 420),
        _ => return None,
    };

    // Only produce a verdict when at least one known reference point has data.
    // If the latency map holds only future/unknown regions, return None rather
    // than a spurious Some(true).
    let us_rtt = latency.get("us-east").copied();
    let eu_rtt = latency.get("eu-west").copied();
    if us_rtt.is_none() && eu_rtt.is_none() {
        return None;
    }

    let mut consistent = true;
    if let Some(rtt) = us_rtt {
        if rtt > us_max {
            consistent = false;
        }
    }
    if let Some(rtt) = eu_rtt {
        if rtt > eu_max {
            consistent = false;
        }
    }
    Some(consistent)
}

impl AgentReputation {
    fn new(agent_id: String) -> Self {
        Self {
            agent_id,
            feedback_count: 0,
            total_score: 0,
            positive_count: 0,
            neutral_count: 0,
            negative_count: 0,
            verdict_count: 0,
            average_score: 0.0,
            last_updated: now_secs(),
            trend: default_trend(),
            last_seen: now_secs(),
            name: String::new(),
            country: None,
            city: None,
            latency: std::collections::HashMap::new(),
            geo_consistent: None,
        }
    }

    fn apply_feedback(&mut self, score: i32, outcome: u8) {
        // Clamp score to protocol range to prevent total_score corruption.
        let score = score.clamp(-100, 100);
        self.feedback_count += 1;
        self.total_score += score as i64;
        match outcome {
            0 => self.negative_count += 1,
            1 => self.neutral_count += 1,
            _ => self.positive_count += 1,
        }
        self.average_score = self.total_score as f64 / self.feedback_count as f64;
        self.last_updated = now_secs();
    }

    fn apply_verdict(&mut self) {
        self.verdict_count += 1;
        self.last_updated = now_secs();
    }
}

// ============================================================================
// Interaction + timeseries output types
// ============================================================================

/// A single raw feedback event — used by GET /interactions.
#[derive(Debug, Clone, Serialize)]
pub struct RawInteraction {
    pub sender: String,
    pub target_agent: String,
    pub score: i32,
    pub outcome: u8,
    pub is_dispute: bool,
    pub role: u8,
    pub conversation_id: String,
    pub slot: u64,
    /// Unix timestamp (seconds) when the aggregator received this event.
    pub ts: u64,
}

/// One hourly bucket — used by GET /stats/timeseries.
#[derive(Debug, Clone, Serialize)]
pub struct TimeseriesBucket {
    /// Start of the 1-hour window (unix seconds).
    pub bucket: u64,
    pub feedback_count: u64,
    pub positive_count: u64,
    pub negative_count: u64,
    pub dispute_count: u64,
}

/// Rolling entropy result — used by GET /entropy/{id}/rolling
#[derive(Debug, Clone, Serialize)]
pub struct RollingEntropyResult {
    pub agent_id: String,
    pub window_epochs: u32,
    pub epochs_found: u32,
    pub mean_anomaly: f64,
    pub anomaly_variance: f64,
    /// True when variance is below 0.005 AND mean_anomaly > 0.3 — patient cartel signal.
    pub low_variance_flag: bool,
    /// True when mean_anomaly > 0.55.
    pub high_anomaly_flag: bool,
}

/// Verifier concentration entry — used by GET /leaderboard/verifier-concentration
#[derive(Debug, Clone, Serialize)]
pub struct VerifierConcentrationEntry {
    pub agent_id: String,
    pub epochs_sampled: u32,
    pub mean_hv: f64,
    pub epochs_below_threshold: u32,
    pub concentration_score: f64, // 1.0 - (mean_hv / hv_threshold)  clamped [0,1]
}

/// Ownership cluster — used by GET /leaderboard/ownership-clusters
#[derive(Debug, Clone, Serialize)]
pub struct OwnershipCluster {
    pub cluster_id: u32,
    pub agents: Vec<String>,
    pub mean_anomaly_mad: f64, // mean absolute diff of anomaly scores — lower = more correlated
}

/// Calibrated β parameters derived from live data — GET /params/calibrated
#[derive(Debug, Clone, Serialize)]
pub struct CalibratedParams {
    pub beta_1_anomaly: f64,
    pub beta_2_rep_decay: f64,
    pub beta_3_coordination: f64,
    pub beta_4_systemic: f64,
    pub sample_agents: u32,
    pub flagged_agents: u32,
    pub calibrated_at: u64,
}

/// Systemic Risk Index — GET /system/sri
#[derive(Debug, Clone, Serialize)]
pub struct SriStatus {
    pub sri: f64,                     // fraction of agents with anomaly > 0.55
    pub circuit_breaker_active: bool, // true when sri > 0.50
    pub mean_anomaly: f64,
    pub active_agents: u32,
    pub flagged_agents: u32,
    pub computed_at: u64,
}

/// Per-agent required stake — GET /stake/required/{id}
#[derive(Debug, Clone, Serialize)]
pub struct RequiredStakeResult {
    pub agent_id: String,
    pub base_stake_usdc: f64,
    pub current_anomaly: f64,
    pub c_coefficient: f64, // ownership clustering score (0-1)
    pub beta_1: f64,
    pub beta_3: f64,
    pub required_stake_usdc: f64, // base * (1 + β₁·A + β₃·C)
    pub deficit_usdc: f64,        // max(0, required - base)
}

// ============================================================================
// Capital flow graph types (GAP-02)
// ============================================================================

/// One directed edge in the capital flow graph.
///
/// `positive_flow` = sum of positive scores flowing from → to over the window.
/// High mutual positive_flow between two agents signals score inflation.
#[derive(Debug, Clone, Serialize)]
pub struct CapitalFlowEdge {
    pub from_agent: String,
    pub to_agent: String,
    pub interaction_count: u32,
    pub positive_flow: i64,
    pub total_abs_flow: i64,
    pub avg_score: f64,
}

/// A cluster of suspected same-owner agents detected via mutual flow analysis.
#[derive(Debug, Clone, Serialize)]
pub struct FlowCluster {
    pub cluster_id: u32,
    pub agents: Vec<String>,
    /// 0-1: (cluster_size - 1) / 10, capped at 1.0.
    pub cluster_suspicion: f64,
    /// C coefficient fed into the stake multiplier formula.
    pub c_coefficient: f64,
    pub total_mutual_flow: i64,
}

/// Graph position and C coefficient for one agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentFlowInfo {
    pub agent_id: String,
    pub cluster_id: Option<u32>,
    pub c_coefficient: f64,
    /// Fraction of total outgoing positive flow directed at the top-3 counterparties.
    /// > 0.70 is suspicious for large networks.
    pub concentration_ratio: f64,
    pub top_counterparties: Vec<String>,
    pub total_outgoing_flow: i64,
    pub unique_counterparties: u32,
}

/// One ordered CBOR envelope entry — used by GET /epochs/{agent_id}/{epoch}/envelopes.
#[derive(Debug, Clone, Serialize)]
pub struct EpochEnvelopeEntry {
    pub seq: i64,
    pub leaf_hash: String,
    pub bytes_b64: String,
}

// ============================================================================
// Union-Find for clustering
// ============================================================================

struct UnionFind {
    parent: HashMap<String, String>,
}

impl UnionFind {
    fn new() -> Self {
        Self {
            parent: HashMap::new(),
        }
    }

    fn find(&mut self, x: &str) -> String {
        if !self.parent.contains_key(x) {
            self.parent.insert(x.to_string(), x.to_string());
            return x.to_string();
        }
        // Iterative path compression.
        let mut root = x.to_string();
        while self.parent[&root] != root {
            root = self.parent[&root].clone();
        }
        let mut cur = x.to_string();
        while self.parent[&cur] != root {
            let next = self.parent[&cur].clone();
            self.parent.insert(cur, root.clone());
            cur = next;
        }
        root
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(rb, ra);
        }
    }
}

/// Build ownership clusters from capital flow edges.
///
/// Two agents are linked when they have mutual positive feedback with
/// mutual_ratio > 0.5 (i.e. both sides are giving nearly equal scores,
/// suggesting coordinated score inflation).
fn compute_clusters_from_edges(
    edges: &[CapitalFlowEdge],
) -> (HashMap<String, u32>, Vec<FlowCluster>) {
    // Index edge weights for O(1) reverse lookup.
    let mut flow_map: HashMap<(&str, &str), i64> = HashMap::new();
    for e in edges {
        flow_map.insert((&e.from_agent, &e.to_agent), e.positive_flow);
    }

    let mut uf = UnionFind::new();
    // Canonically-keyed mutual flow totals to avoid double-counting.
    let mut mutual_cache: HashMap<(String, String), i64> = HashMap::new();

    for e in edges {
        if e.positive_flow <= 0 {
            continue;
        }
        let rev = flow_map
            .get(&(e.to_agent.as_str(), e.from_agent.as_str()))
            .copied()
            .unwrap_or(0);
        if rev <= 0 {
            continue;
        }

        let lo = e.positive_flow.min(rev);
        let hi = e.positive_flow.max(rev);
        if lo as f64 / hi as f64 > 0.5 {
            uf.union(&e.from_agent, &e.to_agent);
            // Store under canonical (alphabetically smaller) key.
            let (ka, kb) = if e.from_agent <= e.to_agent {
                (e.from_agent.clone(), e.to_agent.clone())
            } else {
                (e.to_agent.clone(), e.from_agent.clone())
            };
            mutual_cache.entry((ka, kb)).or_insert(lo + hi);
        }
    }

    // Collect all nodes that appeared in any edge.
    let all_nodes: std::collections::HashSet<&str> = edges
        .iter()
        .flat_map(|e| [e.from_agent.as_str(), e.to_agent.as_str()])
        .collect();

    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for &node in &all_nodes {
        let root = uf.find(node);
        groups.entry(root).or_default().push(node.to_string());
    }

    let mut agent_cluster: HashMap<String, u32> = HashMap::new();
    let mut clusters: Vec<FlowCluster> = vec![];

    for (cid, mut members) in groups.into_values().filter(|v| v.len() >= 2).enumerate() {
        let cid = cid as u32;
        members.sort(); // deterministic ordering
        let member_set: std::collections::HashSet<&str> =
            members.iter().map(|s| s.as_str()).collect();
        let total_flow: i64 = mutual_cache
            .iter()
            .filter(|((a, b), _)| {
                member_set.contains(a.as_str()) && member_set.contains(b.as_str())
            })
            .map(|(_, &v)| v)
            .sum();
        let suspicion = ((members.len() - 1) as f64 / 10.0).min(1.0);
        for m in &members {
            agent_cluster.insert(m.clone(), cid);
        }
        clusters.push(FlowCluster {
            cluster_id: cid,
            agents: members,
            cluster_suspicion: suspicion,
            c_coefficient: suspicion,
            total_mutual_flow: total_flow,
        });
    }

    (agent_cluster, clusters)
}

// ============================================================================
// SQLite persistence layer
// ============================================================================

const MIGRATIONS: &[&str] = &[
    // v1: Initial schema
    "
CREATE TABLE IF NOT EXISTS agent_reputation (
    agent_id       TEXT    PRIMARY KEY,
    feedback_count INTEGER NOT NULL DEFAULT 0,
    total_score    INTEGER NOT NULL DEFAULT 0,
    positive_count INTEGER NOT NULL DEFAULT 0,
    neutral_count  INTEGER NOT NULL DEFAULT 0,
    negative_count INTEGER NOT NULL DEFAULT 0,
    verdict_count  INTEGER NOT NULL DEFAULT 0,
    last_updated   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS feedback_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT    NOT NULL,
    target_agent    TEXT    NOT NULL,
    score           INTEGER NOT NULL,
    outcome         INTEGER NOT NULL,
    is_dispute      INTEGER NOT NULL DEFAULT 0,
    role            INTEGER NOT NULL DEFAULT 0,
    conversation_id TEXT    NOT NULL,
    slot            INTEGER NOT NULL DEFAULT 0,
    ts              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fe_sender  ON feedback_events(sender);
CREATE INDEX IF NOT EXISTS idx_fe_target  ON feedback_events(target_agent);
CREATE INDEX IF NOT EXISTS idx_fe_ts      ON feedback_events(ts);

CREATE TABLE IF NOT EXISTS raw_envelopes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT    NOT NULL,
    epoch      INTEGER NOT NULL,
    seq_num    INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    leaf_hash  TEXT    NOT NULL,
    bytes      BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_re_agent_epoch ON raw_envelopes(agent_id, epoch);

CREATE TABLE IF NOT EXISTS entropy_vectors (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id  TEXT    NOT NULL,
    epoch     INTEGER NOT NULL,
    ht        REAL,
    hb        REAL,
    hs        REAL,
    hv        REAL,
    anomaly   REAL    NOT NULL DEFAULT 0,
    n_ht      INTEGER NOT NULL DEFAULT 0,
    n_hb      INTEGER NOT NULL DEFAULT 0,
    n_hs      INTEGER NOT NULL DEFAULT 0,
    n_hv      INTEGER NOT NULL DEFAULT 0,
    ts        INTEGER NOT NULL,
    UNIQUE(agent_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_ev_agent ON entropy_vectors(agent_id);
CREATE INDEX IF NOT EXISTS idx_ev_ts    ON entropy_vectors(ts);

CREATE TABLE IF NOT EXISTS notarize_bids (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT    NOT NULL,
    conversation_id TEXT    NOT NULL,
    slot            INTEGER NOT NULL DEFAULT 0,
    ts              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nb_sender ON notarize_bids(sender);
CREATE INDEX IF NOT EXISTS idx_nb_ts     ON notarize_bids(ts);

CREATE TABLE IF NOT EXISTS capabilities (
    agent_id   TEXT    NOT NULL,
    capability TEXT    NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (agent_id, capability)
);
CREATE INDEX IF NOT EXISTS idx_cap_capability ON capabilities(capability);
CREATE INDEX IF NOT EXISTS idx_cap_agent      ON capabilities(agent_id);

CREATE TABLE IF NOT EXISTS disputes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT    NOT NULL,
    disputed_agent  TEXT    NOT NULL,
    conversation_id TEXT    NOT NULL,
    slot            INTEGER NOT NULL DEFAULT 0,
    ts              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_disp_agent ON disputes(disputed_agent);
CREATE INDEX IF NOT EXISTS idx_disp_ts    ON disputes(ts);

CREATE TABLE IF NOT EXISTS agent_registry (
    agent_id   TEXT NOT NULL PRIMARY KEY,
    name       TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
",
    // v2: Add persistent beacon_count and estimate historical data
    "
ALTER TABLE agent_registry ADD COLUMN beacon_count INTEGER NOT NULL DEFAULT 0;
UPDATE agent_registry SET beacon_count = MAX(1, (last_seen - first_seen) / 60) WHERE beacon_count = 0;
",
    // v3: Activity log for social feed
    "
CREATE TABLE IF NOT EXISTS activity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    event_type      TEXT    NOT NULL,
    agent_id        TEXT    NOT NULL,
    target_id       TEXT,
    score           INTEGER,
    name            TEXT,
    target_name     TEXT,
    slot            INTEGER,
    conversation_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_activity_log_ts ON activity_log(ts DESC);
",
    // v4: Node hosting registry
    "
CREATE TABLE IF NOT EXISTS hosting_nodes (
    node_id    TEXT    PRIMARY KEY,
    name       TEXT    NOT NULL DEFAULT '',
    fee_bps    INTEGER NOT NULL DEFAULT 0,
    api_url    TEXT    NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosted_agents (
    agent_id      TEXT    NOT NULL,
    host_node_id  TEXT    NOT NULL,
    registered_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, host_node_id),
    FOREIGN KEY (host_node_id) REFERENCES hosting_nodes(node_id) ON DELETE CASCADE
);
",
    // v5: Agent ownership proposals and accepted claims
    "
CREATE TABLE IF NOT EXISTS ownership_proposals (
    agent_id       TEXT    PRIMARY KEY,
    proposed_owner TEXT    NOT NULL,
    proposed_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ownership_claims (
    agent_id   TEXT    PRIMARY KEY,
    owner      TEXT    NOT NULL,
    claimed_at INTEGER NOT NULL
);
",
    // v6: Agent geo metadata (self-reported, upserted on ADVERTISE)
    "
CREATE TABLE IF NOT EXISTS agent_geo (
    agent_id   TEXT    NOT NULL PRIMARY KEY,
    country    TEXT    NOT NULL,
    city       TEXT,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_geo_country ON agent_geo(country);
",
    // v7: Latency measurements from reference nodes (--node-region)
    "
CREATE TABLE IF NOT EXISTS agent_latency (
    agent_id   TEXT    NOT NULL,
    region     TEXT    NOT NULL,
    rtt_ms     INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, region)
);
CREATE INDEX IF NOT EXISTS idx_agent_latency_agent ON agent_latency(agent_id);
",
];

struct Db(rusqlite::Connection);

impl Db {
    fn open(path: &Path) -> rusqlite::Result<Self> {
        let mut conn = rusqlite::Connection::open(path)?;

        conn.execute_batch(
            "
            PRAGMA journal_mode   = WAL;
            PRAGMA synchronous    = NORMAL;
            PRAGMA foreign_keys   = ON;
            CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
        ",
        )?;

        let current_version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let tx = conn.transaction()?;
        for (i, &migration_sql) in MIGRATIONS.iter().enumerate() {
            let migration_version = (i + 1) as i64;
            if migration_version > current_version {
                tx.execute_batch(migration_sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?)",
                    [migration_version],
                )?;
                tracing::info!("Applied SQLite database migration v{}", migration_version);
            }
        }
        tx.commit()?;

        Ok(Db(conn))
    }

    /// Load all reputation rows into a HashMap.
    fn load_all(&self) -> rusqlite::Result<HashMap<String, AgentReputation>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, feedback_count, total_score,
                    positive_count, neutral_count, negative_count,
                    verdict_count, last_updated
             FROM agent_reputation",
        )?;
        let rows = stmt.query_map([], |row| {
            let agent_id: String = row.get(0)?;
            let feedback_count: u64 = row.get::<_, i64>(1)? as u64;
            let total_score: i64 = row.get(2)?;
            let positive_count: u64 = row.get::<_, i64>(3)? as u64;
            let neutral_count: u64 = row.get::<_, i64>(4)? as u64;
            let negative_count: u64 = row.get::<_, i64>(5)? as u64;
            let verdict_count: u64 = row.get::<_, i64>(6)? as u64;
            let last_updated: u64 = row.get::<_, i64>(7)? as u64;
            let average_score = if feedback_count > 0 {
                total_score as f64 / feedback_count as f64
            } else {
                0.0
            };
            Ok(AgentReputation {
                agent_id: agent_id.clone(),
                feedback_count,
                total_score,
                positive_count,
                neutral_count,
                negative_count,
                verdict_count,
                average_score,
                last_updated,
                trend: default_trend(),
                last_seen: last_updated, // Default to last_updated if loaded from DB where BEACON wasn't active
                name: String::new(),
                country: None,
                city: None,
                latency: std::collections::HashMap::new(),
                geo_consistent: None,
            })
        })?;

        let mut map = HashMap::new();
        for row in rows {
            let rep = row?;
            map.insert(rep.agent_id.clone(), rep);
        }
        Ok(map)
    }

    /// Upsert a full reputation row.
    fn upsert(&self, rep: &AgentReputation) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO agent_reputation
                 (agent_id, feedback_count, total_score, positive_count,
                  neutral_count, negative_count, verdict_count, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id) DO UPDATE SET
                 feedback_count = excluded.feedback_count,
                 total_score    = excluded.total_score,
                 positive_count = excluded.positive_count,
                 neutral_count  = excluded.neutral_count,
                 negative_count = excluded.negative_count,
                 verdict_count  = excluded.verdict_count,
                 last_updated   = excluded.last_updated",
            rusqlite::params![
                rep.agent_id,
                rep.feedback_count as i64,
                rep.total_score,
                rep.positive_count as i64,
                rep.neutral_count as i64,
                rep.negative_count as i64,
                rep.verdict_count as i64,
                rep.last_updated as i64,
            ],
        )?;
        Ok(())
    }

    /// Upsert an agent registry record from a BEACON event.
    fn upsert_registry(&self, ev: &BeaconEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO agent_registry (agent_id, name, first_seen, last_seen, beacon_count)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT(agent_id) DO UPDATE SET
                 name         = excluded.name,
                 last_seen    = excluded.last_seen,
                 beacon_count = beacon_count + 1",
            rusqlite::params![ev.sender, ev.name, ts as i64, ts as i64,],
        )?;
        Ok(())
    }

    /// Load all geo rows into a HashMap (agent_id → (country, city)).
    fn load_geo(&self) -> rusqlite::Result<HashMap<String, (String, Option<String>)>> {
        let mut stmt = self
            .0
            .prepare("SELECT agent_id, country, city FROM agent_geo")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (agent_id, country, city) = row?;
            map.insert(agent_id, (country, city));
        }
        Ok(map)
    }

    /// Load all latency rows: agent_id → HashMap<region, rtt_ms>.
    fn load_latency(
        &self,
    ) -> rusqlite::Result<std::collections::HashMap<String, std::collections::HashMap<String, u64>>>
    {
        let mut stmt = self
            .0
            .prepare("SELECT agent_id, region, rtt_ms FROM agent_latency")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u64,
            ))
        })?;
        let mut map: std::collections::HashMap<
            String,
            std::collections::HashMap<String, u64>,
        > = std::collections::HashMap::new();
        for row in rows {
            let (agent_id, region, rtt_ms) = row?;
            map.entry(agent_id).or_default().insert(region, rtt_ms);
        }
        Ok(map)
    }

    /// Upsert a latency measurement for one agent from one reference region.
    fn upsert_latency(
        &self,
        agent_id: &str,
        region: &str,
        rtt_ms: u64,
        now: u64,
    ) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO agent_latency (agent_id, region, rtt_ms, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent_id, region) DO UPDATE SET
               rtt_ms     = excluded.rtt_ms,
               updated_at = excluded.updated_at",
            rusqlite::params![agent_id, region, rtt_ms as i64, now as i64],
        )?;
        Ok(())
    }

    /// Upsert agent geo metadata.
    fn upsert_geo(
        &self,
        agent_id: &str,
        country: &str,
        city: Option<&str>,
        now: u64,
    ) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO agent_geo (agent_id, country, city, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent_id) DO UPDATE SET
               country    = excluded.country,
               city       = excluded.city,
               updated_at = excluded.updated_at",
            rusqlite::params![agent_id, country, city, now as i64],
        )?;
        Ok(())
    }

    /// Insert a raw feedback event.
    fn insert_feedback(&self, fb: &FeedbackEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO feedback_events
                 (sender, target_agent, score, outcome, is_dispute, role,
                  conversation_id, slot, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                fb.sender,
                fb.target_agent,
                fb.score,
                fb.outcome as i64,
                fb.is_dispute as i64,
                fb.role as i64,
                fb.conversation_id,
                fb.slot as i64,
                ts as i64,
            ],
        )?;
        Ok(())
    }

    /// Query raw interactions with optional sender/target filters.
    fn query_interactions(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<Vec<RawInteraction>> {
        let mut stmt = self.0.prepare(
            "SELECT sender, target_agent, score, outcome, is_dispute, role,
                    conversation_id, slot, ts
             FROM feedback_events
             WHERE (?1 IS NULL OR sender       = ?1)
               AND (?2 IS NULL OR target_agent = ?2)
             ORDER BY ts DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(rusqlite::params![from, to, limit as i64], |row| {
            Ok(RawInteraction {
                sender: row.get(0)?,
                target_agent: row.get(1)?,
                score: row.get(2)?,
                outcome: row.get::<_, i64>(3)? as u8,
                is_dispute: row.get::<_, i64>(4)? != 0,
                role: row.get::<_, i64>(5)? as u8,
                conversation_id: row.get(6)?,
                slot: row.get::<_, i64>(7)? as u64,
                ts: row.get::<_, i64>(8)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Get all registered agents from BEACON tracking.
    fn get_registry(&self) -> rusqlite::Result<Vec<AgentRegistryEntry>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, name, first_seen, last_seen
             FROM agent_registry
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AgentRegistryEntry {
                agent_id: row.get(0)?,
                name: row.get(1)?,
                first_seen: row.get::<_, i64>(2)? as u64,
                last_seen: row.get::<_, i64>(3)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Fetch last N feedback scores for an agent (newest first). Used for trend computation.
    fn query_recent_scores(&self, agent_id: &str, n: usize) -> rusqlite::Result<Vec<i32>> {
        let mut stmt = self.0.prepare(
            "SELECT score FROM feedback_events
             WHERE target_agent = ?1
             ORDER BY ts DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![agent_id, n as i64], |row| {
            row.get::<_, i32>(0)
        })?;
        rows.collect()
    }

    /// Search agent_registry by name (case-insensitive prefix/contains match).
    fn query_agents_by_name(
        &self,
        name: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<AgentRegistryEntry>> {
        let pattern = format!("%{}%", name.to_lowercase());
        let mut stmt = self.0.prepare(
            "SELECT agent_id, name, first_seen, last_seen
             FROM agent_registry
             WHERE LOWER(name) LIKE ?1
             ORDER BY last_seen DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![pattern, limit as i64], |row| {
            Ok(AgentRegistryEntry {
                agent_id: row.get(0)?,
                name: row.get(1)?,
                first_seen: row.get::<_, i64>(2)? as u64,
                last_seen: row.get::<_, i64>(3)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Look up a single agent's name from the registry.
    fn query_agent_name(&self, agent_id: &str) -> rusqlite::Result<Option<String>> {
        self.0
            .query_row(
                "SELECT name FROM agent_registry WHERE agent_id = ?1",
                rusqlite::params![agent_id],
                |row| row.get(0),
            )
            .optional()
    }

    /// Upsert an entropy vector (agent_id + epoch is the unique key).
    fn upsert_entropy(&self, ev: &EntropyEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO entropy_vectors
                 (agent_id, epoch, ht, hb, hs, hv, anomaly,
                  n_ht, n_hb, n_hs, n_hv, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(agent_id, epoch) DO UPDATE SET
                 ht      = excluded.ht,
                 hb      = excluded.hb,
                 hs      = excluded.hs,
                 hv      = excluded.hv,
                 anomaly = excluded.anomaly,
                 n_ht    = excluded.n_ht,
                 n_hb    = excluded.n_hb,
                 n_hs    = excluded.n_hs,
                 n_hv    = excluded.n_hv,
                 ts      = excluded.ts",
            rusqlite::params![
                ev.agent_id,
                ev.epoch as i64,
                ev.ht,
                ev.hb,
                ev.hs,
                ev.hv,
                ev.anomaly,
                ev.n_ht as i64,
                ev.n_hb as i64,
                ev.n_hs as i64,
                ev.n_hv as i64,
                ts as i64,
            ],
        )?;
        Ok(())
    }

    /// Latest entropy vector for an agent.
    fn query_entropy_latest(&self, agent_id: &str) -> rusqlite::Result<Option<EntropyEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, epoch, ht, hb, hs, hv, anomaly,
                    n_ht, n_hb, n_hs, n_hv
             FROM entropy_vectors
             WHERE agent_id = ?1
             ORDER BY epoch DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], row_to_entropy)?;
        rows.next().transpose()
    }

    /// Top agents by anomaly score (highest first), most recent epoch only.
    fn query_anomaly_leaderboard(&self, limit: usize) -> rusqlite::Result<Vec<EntropyEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, epoch, ht, hb, hs, hv, anomaly,
                    n_ht, n_hb, n_hs, n_hv
             FROM entropy_vectors
             WHERE (agent_id, epoch) IN (
                 SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
             )
             ORDER BY anomaly DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64], row_to_entropy)?;
        rows.collect()
    }

    /// All entropy vectors for an agent, oldest first.
    fn query_entropy_history(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<EntropyEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, epoch, ht, hb, hs, hv, anomaly,
                    n_ht, n_hb, n_hs, n_hv
             FROM entropy_vectors
             WHERE agent_id = ?1
             ORDER BY epoch DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![agent_id, limit as i64], row_to_entropy)?;
        rows.collect()
    }

    /// Aggregate feedback events into 1-hour buckets since `since`.
    fn query_timeseries(&self, since: u64) -> rusqlite::Result<Vec<TimeseriesBucket>> {
        let mut stmt = self.0.prepare(
            "SELECT
                 (ts / 3600) * 3600                              AS bucket,
                 COUNT(*)                                        AS feedback_count,
                 SUM(CASE WHEN outcome    = 2 THEN 1 ELSE 0 END) AS positive_count,
                 SUM(CASE WHEN outcome    = 0 THEN 1 ELSE 0 END) AS negative_count,
                 SUM(CASE WHEN is_dispute = 1 THEN 1 ELSE 0 END) AS dispute_count
             FROM feedback_events
             WHERE ts >= ?1
             GROUP BY bucket
             ORDER BY bucket ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![since as i64], |row| {
            Ok(TimeseriesBucket {
                bucket: row.get::<_, i64>(0)? as u64,
                feedback_count: row.get::<_, i64>(1)? as u64,
                positive_count: row.get::<_, i64>(2)? as u64,
                negative_count: row.get::<_, i64>(3)? as u64,
                dispute_count: row.get::<_, i64>(4)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Rolling anomaly stats for an agent over the last `window` epochs.
    fn query_rolling_entropy(
        &self,
        agent_id: &str,
        window: u32,
    ) -> rusqlite::Result<RollingEntropyResult> {
        let row: (f64, f64, i64, Option<f64>) = self.0.query_row(
            "SELECT AVG(anomaly),
                    AVG(anomaly * anomaly) - AVG(anomaly) * AVG(anomaly),
                    COUNT(*),
                    AVG(hv)
             FROM (
                 SELECT anomaly, hv FROM entropy_vectors
                 WHERE agent_id = ?1
                 ORDER BY epoch DESC
                 LIMIT ?2
             )",
            rusqlite::params![agent_id, window as i64],
            |r| {
                Ok((
                    r.get::<_, f64>(0).unwrap_or(0.0),
                    r.get::<_, f64>(1).unwrap_or(0.0),
                    r.get::<_, i64>(2).unwrap_or(0),
                    r.get::<_, Option<f64>>(3)?,
                ))
            },
        )?;
        let (mean_anomaly, variance, n, _mean_hv) = row;
        Ok(RollingEntropyResult {
            agent_id: agent_id.to_string(),
            window_epochs: window,
            epochs_found: n as u32,
            mean_anomaly,
            anomaly_variance: variance.max(0.0),
            low_variance_flag: variance < 0.005 && mean_anomaly > 0.30 && n >= 5,
            high_anomaly_flag: mean_anomaly > 0.55,
        })
    }

    /// Verifier concentration: agents with consistently low hv (verifier entropy).
    fn query_verifier_concentration(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<VerifierConcentrationEntry>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id,
                    COUNT(*)                                               AS epochs_sampled,
                    COALESCE(AVG(hv), 0.0)                                AS mean_hv,
                    SUM(CASE WHEN hv IS NOT NULL AND hv < 1.0 THEN 1 ELSE 0 END) AS epochs_below
             FROM entropy_vectors
             WHERE hv IS NOT NULL
             GROUP BY agent_id
             HAVING COUNT(*) >= 3
             ORDER BY mean_hv ASC
             LIMIT ?1",
        )?;
        let hv_threshold = 1.0_f64;
        let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
            let mean_hv: f64 = row.get(2)?;
            let score = (1.0 - (mean_hv / hv_threshold)).clamp(0.0, 1.0);
            Ok(VerifierConcentrationEntry {
                agent_id: row.get(0)?,
                epochs_sampled: row.get::<_, i64>(1)? as u32,
                mean_hv,
                epochs_below_threshold: row.get::<_, i64>(3)? as u32,
                concentration_score: score,
            })
        })?;
        rows.collect()
    }

    /// Systemic Risk Index: fraction of active agents with anomaly > 0.55.
    fn query_sri_status(&self) -> rusqlite::Result<SriStatus> {
        let (total, flagged, mean_anomaly): (i64, i64, f64) = self.0.query_row(
            "SELECT COUNT(*),
                    SUM(CASE WHEN anomaly > 0.55 THEN 1 ELSE 0 END),
                    COALESCE(AVG(anomaly), 0.0)
             FROM (
                 SELECT anomaly FROM entropy_vectors
                 WHERE (agent_id, epoch) IN (
                     SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
                 )
             )",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0).unwrap_or(0),
                    r.get::<_, i64>(1).unwrap_or(0),
                    r.get::<_, f64>(2).unwrap_or(0.0),
                ))
            },
        )?;
        let sri = if total > 0 {
            flagged as f64 / total as f64
        } else {
            0.0
        };
        Ok(SriStatus {
            sri,
            circuit_breaker_active: sri > 0.50,
            mean_anomaly,
            active_agents: total as u32,
            flagged_agents: flagged as u32,
            computed_at: now_secs(),
        })
    }

    /// Latest anomaly score for required_stake computation.
    fn query_latest_anomaly(&self, agent_id: &str) -> rusqlite::Result<Option<f64>> {
        let mut stmt = self.0.prepare(
            "SELECT anomaly FROM entropy_vectors
             WHERE agent_id = ?1
             ORDER BY epoch DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], |r| r.get::<_, f64>(0))?;
        rows.next().transpose()
    }

    /// Capital flow edges: directed positive-feedback graph over a time window.
    ///
    /// Only pairs with ≥ 2 interactions are returned to reduce noise.
    fn query_capital_flow_edges(
        &self,
        since: u64,
        limit: usize,
    ) -> rusqlite::Result<Vec<CapitalFlowEdge>> {
        let mut stmt = self.0.prepare(
            "SELECT sender,
                    target_agent,
                    COUNT(*)                                                  AS interaction_count,
                    SUM(CASE WHEN score > 0 THEN score ELSE 0 END)            AS positive_flow,
                    SUM(ABS(score))                                           AS total_abs_flow,
                    CAST(AVG(score) AS REAL)                                  AS avg_score
             FROM feedback_events
             WHERE ts >= ?1
             GROUP BY sender, target_agent
             HAVING COUNT(*) >= 2
             ORDER BY positive_flow DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![since as i64, limit as i64], |row| {
            Ok(CapitalFlowEdge {
                from_agent: row.get(0)?,
                to_agent: row.get(1)?,
                interaction_count: row.get::<_, i64>(2)? as u32,
                positive_flow: row.get::<_, i64>(3)?,
                total_abs_flow: row.get::<_, i64>(4)?,
                avg_score: row.get::<_, f64>(5)?,
            })
        })?;
        rows.collect()
    }

    /// Per-agent outgoing flow summary — top counterparties by positive flow.
    fn query_agent_outgoing(
        &self,
        agent_id: &str,
        since: u64,
    ) -> rusqlite::Result<Vec<(String, u32, i64)>> {
        let mut stmt = self.0.prepare(
            "SELECT target_agent,
                    COUNT(*)                                       AS cnt,
                    SUM(CASE WHEN score > 0 THEN score ELSE 0 END) AS positive_flow
             FROM feedback_events
             WHERE sender = ?1 AND ts >= ?2
             GROUP BY target_agent
             ORDER BY positive_flow DESC
             LIMIT 20",
        )?;
        let rows = stmt.query_map(rusqlite::params![agent_id, since as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u32,
                row.get::<_, i64>(2)?,
            ))
        })?;
        rows.collect()
    }

    fn store_raw_envelope(
        &self,
        agent_id: &str,
        epoch: u64,
        seq_num: i64,
        ts: u64,
        leaf_hash: &str,
        bytes: &[u8],
    ) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO raw_envelopes (agent_id, epoch, seq_num, ts, leaf_hash, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![agent_id, epoch as i64, seq_num, ts as i64, leaf_hash, bytes],
        )?;
        Ok(())
    }

    fn query_epoch_envelopes(
        &self,
        agent_id: &str,
        epoch: u64,
        limit: usize,
    ) -> rusqlite::Result<Vec<(i64, String, Vec<u8>)>> {
        let mut stmt = self.0.prepare(
            "SELECT seq_num, leaf_hash, bytes FROM raw_envelopes
             WHERE agent_id = ?1 AND epoch = ?2
             ORDER BY seq_num ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(
                rusqlite::params![agent_id, epoch as i64, limit as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    fn next_envelope_seq(&self, agent_id: &str, epoch: u64) -> rusqlite::Result<i64> {
        let count: i64 = self.0.query_row(
            "SELECT COUNT(*) FROM raw_envelopes WHERE agent_id = ?1 AND epoch = ?2",
            rusqlite::params![agent_id, epoch as i64],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    fn insert_notarize_bid(&self, bid: &NotarizeBidEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO notarize_bids (sender, conversation_id, slot, ts)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![bid.sender, bid.conversation_id, bid.slot as i64, ts as i64],
        )?;
        Ok(())
    }

    fn upsert_capability(
        &self,
        agent_id: &str,
        capability: &str,
        last_seen: u64,
    ) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO capabilities (agent_id, capability, last_seen)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id, capability) DO UPDATE SET last_seen = excluded.last_seen",
            rusqlite::params![agent_id, capability, last_seen as i64],
        )?;
        Ok(())
    }

    fn query_agents_by_capability(
        &self,
        capability: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<CapabilityMatch>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, capability, last_seen FROM capabilities
             WHERE capability = ?1
             ORDER BY last_seen DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![capability, limit as i64], |row| {
            Ok(CapabilityMatch {
                agent_id: row.get(0)?,
                capability: row.get(1)?,
                last_seen: row.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect()
    }

    fn insert_dispute(&self, d: &DisputeEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO disputes (sender, disputed_agent, conversation_id, slot, ts)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                d.sender,
                d.disputed_agent,
                d.conversation_id,
                d.slot as i64,
                ts as i64,
            ],
        )?;
        Ok(())
    }

    fn query_disputes_for_agent(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<DisputeRecord>> {
        let mut stmt = self.0.prepare(
            "SELECT id, sender, disputed_agent, conversation_id, slot, ts
             FROM disputes
             WHERE disputed_agent = ?1
             ORDER BY ts DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![agent_id, limit as i64], |row| {
            Ok(DisputeRecord {
                id: row.get(0)?,
                sender: row.get(1)?,
                disputed_agent: row.get(2)?,
                conversation_id: row.get(3)?,
                slot: row.get::<_, i64>(4)? as u64,
                ts: row.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Insert an activity event and return it with the assigned rowid.
    fn insert_activity(&self, ev: &ActivityEvent) -> rusqlite::Result<ActivityEvent> {
        self.0.execute(
            "INSERT INTO activity_log
                 (ts, event_type, agent_id, target_id, score, name, target_name, slot, conversation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                ev.ts,
                ev.event_type,
                ev.agent_id,
                ev.target_id,
                ev.score,
                ev.name,
                ev.target_name,
                ev.slot,
                ev.conversation_id,
            ],
        )?;
        let id = self.0.last_insert_rowid();
        Ok(ActivityEvent { id, ..ev.clone() })
    }

    fn query_activity(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> rusqlite::Result<Vec<ActivityEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT id, ts, event_type, agent_id, target_id, score, name, target_name, slot, conversation_id
             FROM activity_log
             WHERE (?1 IS NULL OR id < ?1)
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![before_id, limit as i64], |row| {
            Ok(ActivityEvent {
                id: row.get(0)?,
                ts: row.get(1)?,
                event_type: row.get(2)?,
                agent_id: row.get(3)?,
                target_id: row.get(4)?,
                score: row.get(5)?,
                name: row.get(6)?,
                target_name: row.get(7)?,
                slot: row.get(8)?,
                conversation_id: row.get(9)?,
            })
        })?;
        rows.collect()
    }
}

fn row_to_entropy(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntropyEvent> {
    Ok(EntropyEvent {
        agent_id: row.get(0)?,
        epoch: row.get::<_, i64>(1)? as u64,
        ht: row.get(2)?,
        hb: row.get(3)?,
        hs: row.get(4)?,
        hv: row.get(5)?,
        anomaly: row.get(6)?,
        n_ht: row.get::<_, i64>(7)? as u32,
        n_hb: row.get::<_, i64>(8)? as u32,
        n_hs: row.get::<_, i64>(9)? as u32,
        n_hv: row.get::<_, i64>(10)? as u32,
    })
}

// ── Ownership persistence helpers (part of impl Db) ───────────────────────────

impl Db {
    /// Upsert / overwrite a pending ownership proposal.
    pub fn upsert_ownership_proposal(
        &self,
        agent_id: &str,
        proposed_owner: &str,
        proposed_at: u64,
    ) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO ownership_proposals (agent_id, proposed_owner, proposed_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id) DO UPDATE SET
                 proposed_owner = excluded.proposed_owner,
                 proposed_at    = excluded.proposed_at",
            rusqlite::params![agent_id, proposed_owner, proposed_at as i64],
        )?;
        Ok(())
    }

    /// Insert an accepted claim (immutable — ignored if already exists).
    pub fn insert_ownership_claim(
        &self,
        agent_id: &str,
        owner: &str,
        claimed_at: u64,
    ) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT OR IGNORE INTO ownership_claims (agent_id, owner, claimed_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![agent_id, owner, claimed_at as i64],
        )?;
        Ok(())
    }

    /// Load all pending proposals into a HashMap.
    pub fn load_ownership_proposals(&self) -> rusqlite::Result<HashMap<String, OwnerProposal>> {
        let mut stmt = self
            .0
            .prepare("SELECT agent_id, proposed_owner, proposed_at FROM ownership_proposals")?;
        let rows = stmt.query_map([], |row| {
            let agent_id: String = row.get(0)?;
            let proposed_owner: String = row.get(1)?;
            let proposed_at: i64 = row.get(2)?;
            Ok((
                agent_id.clone(),
                OwnerProposal {
                    agent_id,
                    proposed_owner,
                    proposed_at: proposed_at as u64,
                },
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }

    /// Load all accepted claims into a HashMap.
    pub fn load_ownership_claims(&self) -> rusqlite::Result<HashMap<String, OwnerRecord>> {
        let mut stmt = self
            .0
            .prepare("SELECT agent_id, owner, claimed_at FROM ownership_claims")?;
        let rows = stmt.query_map([], |row| {
            let agent_id: String = row.get(0)?;
            let owner: String = row.get(1)?;
            let claimed_at: i64 = row.get(2)?;
            Ok((
                agent_id.clone(),
                OwnerRecord {
                    agent_id,
                    owner,
                    claimed_at: claimed_at as u64,
                },
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }
}

// ============================================================================
// ReputationStore
// ============================================================================

/// In-memory cap for raw interactions when running without SQLite.
const MAX_IN_MEMORY_INTERACTIONS: usize = 10_000;

#[derive(Default)]
struct Inner {
    agents: HashMap<String, AgentReputation>,
    /// Bounded ring buffer of recent interactions (used as fallback when no SQLite).
    interactions: VecDeque<RawInteraction>,
    /// Maps agent_id -> c_coefficient (clustering factor) derived from on-chain Solana tokens.
    solana_flow_clusters: HashMap<String, f64>,
}

// ============================================================================
// Network stats
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStats {
    /// Number of distinct agents seen by the aggregator.
    pub agent_count: usize,
    /// Total feedback events recorded (all-time).
    pub interaction_count: u64,
    /// Total BEACON events recorded (persistent since v2 migration).
    pub beacon_count: u64,
    /// Beacons per minute (sliding 60s window).
    pub beacon_bpm: u64,
    /// Unix timestamp (seconds) when the aggregator process started.
    pub started_at: u64,
}

/// A hosting node entry returned by GET /hosting/nodes.
#[derive(Debug, Clone, Serialize)]
pub struct HostingNode {
    pub node_id: String,
    pub name: String,
    pub fee_bps: u32,
    pub api_url: String,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Live count of hosted agents on this node.
    pub hosted_count: u32,
}

/// A pending ownership proposal recorded by POST /agents/:id/propose-owner.
#[derive(Debug, Clone, Serialize)]
pub struct OwnerProposal {
    pub agent_id: String,
    pub proposed_owner: String, // base58 Solana wallet
    pub proposed_at: u64,
}

/// An accepted ownership claim recorded by POST /agents/:id/claim-owner.
/// Created only after on-chain AgentOwnership PDA is verified.
#[derive(Debug, Clone, Serialize)]
pub struct OwnerRecord {
    pub agent_id: String,
    pub owner: String, // base58 Solana wallet
    pub claimed_at: u64,
}

/// Result of `get_owner()` — three possible states.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum OwnerStatus {
    Unclaimed,
    Pending(OwnerProposal),
    Claimed(OwnerRecord),
}

#[derive(Clone)]
pub struct ReputationStore {
    inner: Arc<RwLock<Inner>>,
    /// SQLite connection; None = in-memory only (no --db-path supplied).
    db: Arc<Mutex<Option<Db>>>,
    /// Process start time — never changes after init.
    started_at: u64,
    /// Sliding window of BEACON timestamps for BPM calculation.
    beacon_window: Arc<Mutex<VecDeque<u64>>>,
    /// FCM device tokens: agent_id (hex) → Firebase device token.
    /// In-memory only; not persisted to SQLite (tokens are re-registered on each app start).
    fcm_tokens: Arc<Mutex<HashMap<String, String>>>,
    /// Set of agent_ids currently in sleep mode (app backgrounded / offline).
    sleep_states: Arc<Mutex<HashSet<String>>>,
    /// Messages held for sleeping agents: agent_id → queue of pending messages.
    /// Capped at 100 messages per agent; oldest are dropped when the cap is reached.
    /// The queue is drained (and cleared) on the next pull request from the agent.
    pending_messages: Arc<Mutex<HashMap<String, VecDeque<PendingMessage>>>>,
    /// Pending ownership proposals: agent_id → proposed_owner wallet (base58).
    /// Set when the agent calls POST /agents/:id/propose-owner.
    ownership_pending: Arc<Mutex<HashMap<String, OwnerProposal>>>,
    /// Accepted ownership claims: agent_id → human wallet (base58), claimed_at.
    /// Set when the human calls POST /agents/:id/claim-owner.
    ownership_claimed: Arc<Mutex<HashMap<String, OwnerRecord>>>,
}

impl Default for ReputationStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            db: Arc::new(Mutex::new(None)),
            started_at: now_secs(),
            beacon_window: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            fcm_tokens: Arc::new(Mutex::new(HashMap::new())),
            sleep_states: Arc::new(Mutex::new(HashSet::new())),
            pending_messages: Arc::new(Mutex::new(HashMap::new())),
            ownership_pending: Arc::new(Mutex::new(HashMap::new())),
            ownership_claimed: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ReputationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_db(path: &Path) -> anyhow::Result<Self> {
        let db = Db::open(path).map_err(|e| anyhow::anyhow!("SQLite open failed: {e}"))?;
        let mut agents = db
            .load_all()
            .map_err(|e| anyhow::anyhow!("SQLite load failed: {e}"))?;

        if let Ok(registry) = db.get_registry() {
            for entry in registry {
                let rep = agents.entry(entry.agent_id.clone()).or_insert_with(|| {
                    let mut r = AgentReputation::new(entry.agent_id);
                    r.last_seen = entry.last_seen;
                    r
                });
                if entry.last_seen > rep.last_seen {
                    rep.last_seen = entry.last_seen;
                }
                if rep.name.is_empty() {
                    rep.name = entry.name;
                }
            }
        }

        // Populate geo from DB.
        if let Ok(geo_map) = db.load_geo() {
            for (agent_id, (country, city)) in geo_map {
                if let Some(rep) = agents.get_mut(&agent_id) {
                    rep.country = Some(country);
                    rep.city = city;
                }
            }
        }

        // Populate latency from DB and recompute geo_consistent.
        if let Ok(latency_map) = db.load_latency() {
            for (agent_id, regions) in latency_map {
                if let Some(rep) = agents.get_mut(&agent_id) {
                    rep.latency = regions;
                    if let Some(ref country) = rep.country.clone() {
                        rep.geo_consistent = compute_geo_consistent(country, &rep.latency);
                    }
                }
            }
        }

        tracing::info!(
            "Loaded {} reputation records from {}",
            agents.len(),
            path.display()
        );

        // Load ownership state so it survives aggregator restarts.
        let ownership_pending = db
            .load_ownership_proposals()
            .map_err(|e| anyhow::anyhow!("SQLite load_ownership_proposals failed: {e}"))?;
        let ownership_claimed = db
            .load_ownership_claims()
            .map_err(|e| anyhow::anyhow!("SQLite load_ownership_claims failed: {e}"))?;
        tracing::info!(
            "Loaded {} ownership proposals, {} ownership claims from {}",
            ownership_pending.len(),
            ownership_claimed.len(),
            path.display()
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                agents,
                interactions: VecDeque::new(),
                solana_flow_clusters: HashMap::new(),
            })),
            db: Arc::new(Mutex::new(Some(db))),
            started_at: now_secs(),
            beacon_window: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            fcm_tokens: Arc::new(Mutex::new(HashMap::new())),
            sleep_states: Arc::new(Mutex::new(HashSet::new())),
            pending_messages: Arc::new(Mutex::new(HashMap::new())),
            ownership_pending: Arc::new(Mutex::new(ownership_pending)),
            ownership_claimed: Arc::new(Mutex::new(ownership_claimed)),
        })
    }

    /// Return a reputation score for an agent, or 0 if unknown.
    pub fn get_agent_reputation_score(&self, agent_id: &str) -> i64 {
        self.inner
            .read()
            .unwrap()
            .agents
            .get(agent_id)
            .map(|r| r.total_score)
            .unwrap_or(0)
    }

    /// Return true if the agent has a claimed owner.
    pub fn is_agent_claimed(&self, agent_id: &str) -> bool {
        self.ownership_claimed
            .lock()
            .unwrap()
            .contains_key(agent_id)
    }

    // ========================================================================
    // FCM / Sleeping node
    // ========================================================================

    /// Store or update the FCM device token for an agent.
    pub fn store_fcm_token(&self, agent_id: String, token: String) {
        self.fcm_tokens.lock().unwrap().insert(agent_id, token);
    }

    /// Retrieve the FCM device token for an agent, if registered.
    pub fn get_fcm_token(&self, agent_id: &str) -> Option<String> {
        self.fcm_tokens.lock().unwrap().get(agent_id).cloned()
    }

    /// Mark an agent as sleeping (true) or awake (false).
    pub fn set_sleeping(&self, agent_id: &str, sleeping: bool) {
        let mut states = self.sleep_states.lock().unwrap();
        if sleeping {
            states.insert(agent_id.to_string());
        } else {
            states.remove(agent_id);
        }
    }

    /// Returns true if the agent is currently in sleep mode.
    pub fn is_sleeping(&self, agent_id: &str) -> bool {
        self.sleep_states.lock().unwrap().contains(agent_id)
    }

    /// Enqueue a pending message for a sleeping agent.
    ///
    /// Drops the oldest message if the per-agent queue is at capacity (100).
    pub fn push_pending(&self, agent_id: &str, msg: PendingMessage) {
        const CAP: usize = 100;
        let mut map = self.pending_messages.lock().unwrap();
        let queue = map.entry(agent_id.to_string()).or_default();
        if queue.len() >= CAP {
            queue.pop_front();
        }
        queue.push_back(msg);
    }

    /// Drain and return all pending messages for an agent.
    ///
    /// The queue is cleared on pull — messages are delivered exactly once.
    pub fn drain_pending(&self, agent_id: &str) -> Vec<PendingMessage> {
        let mut map = self.pending_messages.lock().unwrap();
        map.remove(agent_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    // ========================================================================
    // Agent ownership claims
    // ========================================================================

    /// Record an ownership proposal (called when agent POSTs /propose-owner).
    /// Overwrites any previous pending proposal for this agent.
    /// Rejected if the agent already has an accepted owner.
    pub fn propose_owner(&self, agent_id: &str, proposed_owner: &str) -> Result<(), &'static str> {
        let claimed = self.ownership_claimed.lock().unwrap();
        if claimed.contains_key(agent_id) {
            return Err("agent already has an accepted owner");
        }
        drop(claimed);
        let proposed_at = now_secs();
        let mut pending = self.ownership_pending.lock().unwrap();
        pending.insert(
            agent_id.to_string(),
            OwnerProposal {
                agent_id: agent_id.to_string(),
                proposed_owner: proposed_owner.to_string(),
                proposed_at,
            },
        );
        drop(pending);
        // Persist to SQLite so the proposal survives restarts.
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.upsert_ownership_proposal(agent_id, proposed_owner, proposed_at) {
                tracing::warn!("SQLite upsert_ownership_proposal failed: {e}");
            }
        }
        tracing::info!(
            "Ownership proposal: agent={} owner={}",
            &agent_id[..8.min(agent_id.len())],
            proposed_owner
        );
        Ok(())
    }

    /// Record an accepted ownership claim (called when human POSTs /claim-owner).
    /// Returns Err if (a) no pending proposal exists, (b) the signing wallet
    /// doesn't match the proposed_owner, or (c) already claimed.
    pub fn claim_owner(
        &self,
        agent_id: &str,
        owner_wallet: &str,
    ) -> Result<OwnerRecord, &'static str> {
        let mut claimed = self.ownership_claimed.lock().unwrap();
        if claimed.contains_key(agent_id) {
            return Err("agent already has an accepted owner");
        }
        let pending = self.ownership_pending.lock().unwrap();
        let proposal = pending
            .get(agent_id)
            .ok_or("no pending ownership proposal for this agent")?;
        if proposal.proposed_owner != owner_wallet {
            return Err("owner wallet does not match the pending proposal");
        }
        drop(pending);
        let record = OwnerRecord {
            agent_id: agent_id.to_string(),
            owner: owner_wallet.to_string(),
            claimed_at: now_secs(),
        };
        claimed.insert(agent_id.to_string(), record.clone());
        drop(claimed);
        // Persist to SQLite — INSERT OR IGNORE keeps the claim immutable.
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.insert_ownership_claim(agent_id, owner_wallet, record.claimed_at) {
                tracing::warn!("SQLite insert_ownership_claim failed: {e}");
            }
        }
        tracing::info!(
            "Ownership claimed: agent={} owner={}",
            &agent_id[..8.min(agent_id.len())],
            owner_wallet
        );
        Ok(record)
    }

    /// Return ownership status for an agent.
    pub fn get_owner(&self, agent_id: &str) -> OwnerStatus {
        if let Some(rec) = self.ownership_claimed.lock().unwrap().get(agent_id) {
            return OwnerStatus::Claimed(rec.clone());
        }
        if let Some(prop) = self.ownership_pending.lock().unwrap().get(agent_id) {
            return OwnerStatus::Pending(prop.clone());
        }
        OwnerStatus::Unclaimed
    }

    // ========================================================================
    // Ingest
    // ========================================================================

    pub fn ingest(&self, event: IngestEvent) -> Option<ActivityEvent> {
        let mut inner = self.inner.write().unwrap();
        match event {
            IngestEvent::Feedback(fb) => {
                if !is_valid_agent_id(&fb.target_agent) {
                    tracing::warn!(
                        "Ingest: invalid target_agent '{}' — dropped",
                        &fb.target_agent
                    );
                    return None;
                }
                let rep = inner
                    .agents
                    .entry(fb.target_agent.clone())
                    .or_insert_with(|| AgentReputation::new(fb.target_agent.clone()));
                rep.apply_feedback(fb.score, fb.outcome);
                let rep = rep.clone();

                // Store raw interaction for /interactions and /stats/timeseries.
                let ts = now_secs();
                let interaction = RawInteraction {
                    sender: fb.sender.clone(),
                    target_agent: fb.target_agent.clone(),
                    score: fb.score.clamp(-100, 100),
                    outcome: fb.outcome,
                    is_dispute: fb.is_dispute,
                    role: fb.role,
                    conversation_id: fb.conversation_id.clone(),
                    slot: fb.slot,
                    ts,
                };
                if inner.interactions.len() >= MAX_IN_MEMORY_INTERACTIONS {
                    inner.interactions.pop_front();
                }
                inner.interactions.push_back(interaction);

                drop(inner);
                self.persist(&rep);
                self.persist_feedback(&fb, ts);
                if let Some(ref raw) = fb.raw_b64 {
                    let epoch = ts / 86_400u64;
                    self.store_raw_envelope(&fb.sender, epoch, ts, raw);
                }

                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let sender_name = conn.query_agent_name(&fb.sender).ok().flatten();
                    let target_name = conn.query_agent_name(&fb.target_agent).ok().flatten();
                    let ev = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "FEEDBACK".to_string(),
                        agent_id: fb.sender.clone(),
                        target_id: Some(fb.target_agent.clone()),
                        score: Some(fb.score as i64),
                        name: sender_name,
                        target_name,
                        slot: Some(fb.slot as i64),
                        conversation_id: Some(fb.conversation_id.clone()),
                    };
                    match conn.insert_activity(&ev) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(FEEDBACK) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Verdict(v) => {
                if !is_valid_agent_id(&v.recipient) {
                    tracing::warn!("Ingest: invalid recipient '{}' — dropped", &v.recipient);
                    return None;
                }
                let rep = inner
                    .agents
                    .entry(v.recipient.clone())
                    .or_insert_with(|| AgentReputation::new(v.recipient.clone()));
                rep.apply_verdict();
                let rep = rep.clone();
                drop(inner);
                self.persist(&rep);

                let ts = now_secs();
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let name = conn.query_agent_name(&v.sender).ok().flatten();
                    let target_name = conn.query_agent_name(&v.recipient).ok().flatten();
                    let ev = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "VERDICT".to_string(),
                        agent_id: v.sender.clone(),
                        target_id: Some(v.recipient.clone()),
                        score: None,
                        name,
                        target_name,
                        slot: Some(v.slot as i64),
                        conversation_id: Some(v.conversation_id.clone()),
                    };
                    match conn.insert_activity(&ev) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(VERDICT) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Entropy(ev) => {
                if !is_valid_agent_id(&ev.agent_id) {
                    tracing::warn!(
                        "Ingest: invalid agent_id in ENTROPY '{}' — dropped",
                        &ev.agent_id
                    );
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::debug!(
                    "ENTROPY epoch={} agent={} anomaly={:.4}",
                    ev.epoch,
                    &ev.agent_id[..8],
                    ev.anomaly,
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    if let Err(e) = conn.upsert_entropy(&ev, ts) {
                        tracing::warn!("SQLite upsert_entropy failed: {e}");
                    }
                }
                None
            }
            IngestEvent::NotarizeBid(bid) => {
                if !is_valid_agent_id(&bid.sender) {
                    tracing::warn!(
                        "Ingest: invalid sender in NOTARIZE_BID '{}' — dropped",
                        &bid.sender
                    );
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::debug!("NOTARIZE_BID sender={}", &bid.sender[..8]);
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    if let Err(e) = conn.insert_notarize_bid(&bid, ts) {
                        tracing::warn!("SQLite insert_notarize_bid failed: {e}");
                    }
                }
                None
            }
            IngestEvent::Advertise(ad) => {
                if !is_valid_agent_id(&ad.sender) {
                    tracing::warn!(
                        "Ingest: invalid sender in ADVERTISE '{}' — dropped",
                        &ad.sender
                    );
                    return None;
                }
                // Ensure sender has a reputation entry so they appear in /agents.
                inner
                    .agents
                    .entry(ad.sender.clone())
                    .or_insert_with(|| AgentReputation::new(ad.sender.clone()));
                drop(inner);
                let ts = now_secs();
                // Sanitise: max 32 caps, each ≤64 chars, alphanumeric + dash/underscore.
                let caps: Vec<String> = ad
                    .capabilities
                    .iter()
                    .filter(|c| {
                        !c.is_empty()
                            && c.len() <= 64
                            && c.chars()
                                .all(|ch| ch.is_alphanumeric() || ch == '-' || ch == '_')
                    })
                    .take(32)
                    .cloned()
                    .collect();
                tracing::debug!("ADVERTISE agent={} caps={:?}", &ad.sender[..8], caps);
                // Validate geo before taking any lock.
                // country: 2–8 ASCII alpha chars (ISO 3166-1 alpha-2 = 2; allow sub-codes).
                // city:    1–64 chars, alphanumeric + space + hyphen + apostrophe.
                let validated_geo: Option<(String, Option<String>)> =
                    ad.geo.as_ref().and_then(|geo| {
                        let country = geo.country.trim();
                        let country_ok = country.len() >= 2
                            && country.len() <= 8
                            && country.chars().all(|ch| ch.is_ascii_alphabetic());
                        if !country_ok {
                            return None;
                        }
                        let city = geo
                            .city
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| {
                                !s.is_empty()
                                    && s.len() <= 64
                                    && s.chars().all(|ch| {
                                        ch.is_alphanumeric()
                                            || ch == ' '
                                            || ch == '-'
                                            || ch == '\''
                                    })
                            })
                            .map(str::to_string);
                        Some((country.to_string(), city))
                    });
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    for cap in &caps {
                        if let Err(e) = conn.upsert_capability(&ad.sender, cap, ts) {
                            tracing::warn!("SQLite upsert_capability failed: {e}");
                        }
                    }
                    if let Some((ref country, ref city)) = validated_geo {
                        conn.upsert_geo(&ad.sender, country, city.as_deref(), ts)
                            .unwrap_or_else(|e| tracing::warn!("upsert_geo failed: {e}"));
                    }
                }
                drop(db);
                // Update in-memory geo if present and valid.
                if let Some((country, city)) = validated_geo {
                    let mut inner = self.inner.write().unwrap();
                    if let Some(rep) = inner.agents.get_mut(&ad.sender) {
                        rep.country = Some(country);
                        rep.city = city;
                    }
                }
                None
            }
            IngestEvent::Dispute(d) => {
                if !is_valid_agent_id(&d.disputed_agent) {
                    tracing::warn!(
                        "Ingest: invalid disputed_agent '{}' — dropped",
                        &d.disputed_agent
                    );
                    return None;
                }
                // Apply synthetic negative feedback so reputation and anomaly scores reflect the dispute.
                let rep = inner
                    .agents
                    .entry(d.disputed_agent.clone())
                    .or_insert_with(|| AgentReputation::new(d.disputed_agent.clone()));
                rep.apply_feedback(-50, 0); // score=-50, outcome=0 (negative)
                let rep = rep.clone();
                drop(inner);
                let ts = now_secs();
                tracing::warn!(
                    "DISPUTE disputed_agent={}",
                    &d.disputed_agent[..8.min(d.disputed_agent.len())]
                );
                self.persist(&rep);
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    if let Err(e) = conn.insert_dispute(&d, ts) {
                        tracing::warn!("SQLite insert_dispute failed: {e}");
                    }
                    let name = conn.query_agent_name(&d.sender).ok().flatten();
                    let target_name = conn.query_agent_name(&d.disputed_agent).ok().flatten();
                    let ev = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "DISPUTE".to_string(),
                        agent_id: d.sender.clone(),
                        target_id: Some(d.disputed_agent.clone()),
                        score: None,
                        name,
                        target_name,
                        slot: Some(d.slot as i64),
                        conversation_id: Some(d.conversation_id.clone()),
                    };
                    match conn.insert_activity(&ev) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(DISPUTE) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Beacon(ev) => {
                // Record for BPM sliding window
                let now = now_secs();
                {
                    let mut window = self.beacon_window.lock().unwrap();
                    window.push_back(now);
                }

                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!(
                        "Ingest: invalid sender in BEACON '{}' — dropped",
                        &ev.sender
                    );
                    return None;
                }
                let ts = now_secs();
                let is_new = !inner.agents.contains_key(&ev.sender);
                let rep = inner
                    .agents
                    .entry(ev.sender.clone())
                    .or_insert_with(|| AgentReputation::new(ev.sender.clone()));
                rep.last_seen = ts;
                rep.name = ev.name.clone();
                drop(inner);

                tracing::debug!(
                    "BEACON agent={} name={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.name
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    if let Err(e) = conn.upsert_registry(&ev, ts) {
                        tracing::warn!("SQLite upsert_registry failed: {e}");
                    }
                    if is_new {
                        let join_ev = ActivityEvent {
                            id: 0,
                            ts: ts as i64,
                            event_type: "JOIN".to_string(),
                            agent_id: ev.sender.clone(),
                            target_id: None,
                            score: None,
                            name: Some(ev.name.clone()),
                            target_name: None,
                            slot: Some(ev.slot as i64),
                            conversation_id: None,
                        };
                        match conn.insert_activity(&join_ev) {
                            Ok(saved) => return Some(saved),
                            Err(e) => tracing::warn!("SQLite insert_activity(JOIN) failed: {e}"),
                        }
                    }
                }
                None
            }
            IngestEvent::Latency(lev) => {
                if !is_valid_agent_id(&lev.agent_id) {
                    tracing::warn!(
                        "Ingest: invalid agent_id in LATENCY '{}' — dropped",
                        &lev.agent_id
                    );
                    return None;
                }
                // Sanity-check region: max 32 chars, alphanumeric + hyphen.
                let region = lev.region.trim();
                if region.is_empty()
                    || region.len() > 32
                    || !region
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    tracing::warn!("Ingest: invalid region in LATENCY '{}' — dropped", region);
                    return None;
                }
                // Cap RTT at 10 000 ms — anything higher is noise / timeout.
                let rtt_ms = lev.rtt_ms.min(10_000);
                let ts = now_secs();
                drop(inner);

                // Persist to DB.
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    if let Err(e) = conn.upsert_latency(&lev.agent_id, region, rtt_ms, ts) {
                        tracing::warn!("upsert_latency failed: {e}");
                    }
                }
                drop(db);

                // Update in-memory latency and recompute geo_consistent.
                let mut inner = self.inner.write().unwrap();
                if let Some(rep) = inner.agents.get_mut(&lev.agent_id) {
                    rep.latency.insert(region.to_string(), rtt_ms);
                    if let Some(ref country) = rep.country.clone() {
                        rep.geo_consistent = compute_geo_consistent(country, &rep.latency);
                    }
                }
                tracing::debug!(
                    "LATENCY agent={} region={region} rtt={rtt_ms}ms",
                    &lev.agent_id[..8],
                );
                None
            }
        }
    }

    pub fn get(&self, agent_id: &str) -> Option<AgentReputation> {
        let mut rep = self.inner.read().unwrap().agents.get(agent_id).cloned()?;
        // Compute trend from DB when available; keep "stable" otherwise.
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Ok(scores) = conn.query_recent_scores(agent_id, 10) {
                rep.trend = compute_trend(&scores).to_string();
            }
        }
        Some(rep)
    }

    pub fn leaderboard(&self, limit: usize) -> Vec<AgentReputation> {
        let inner = self.inner.read().unwrap();
        let mut agents: Vec<AgentReputation> = inner.agents.values().cloned().collect();
        agents.sort_by(|a, b| {
            b.average_score
                .partial_cmp(&a.average_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        agents.truncate(limit);
        agents
    }

    pub fn list_agents(
        &self,
        limit: usize,
        offset: usize,
        sort_by: &str,
        country_filter: Option<&str>,
    ) -> Vec<AgentReputation> {
        let inner = self.inner.read().unwrap();
        let mut agents: Vec<&AgentReputation> = inner.agents.values().collect();
        if let Some(country) = country_filter {
            agents.retain(|a| {
                a.country
                    .as_deref()
                    .map(|c| c.eq_ignore_ascii_case(country))
                    .unwrap_or(false)
            });
        }
        if sort_by == "recent" || sort_by == "active" || sort_by == "new" {
            agents.sort_by(|a, b| {
                b.last_seen
                    .cmp(&a.last_seen)
                    .then(a.agent_id.cmp(&b.agent_id))
            });
        } else if sort_by == "reputation" {
            agents.sort_by(|a, b| {
                b.total_score
                    .cmp(&a.total_score)
                    .then(a.agent_id.cmp(&b.agent_id))
            });
        } else {
            agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        }
        agents
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// List activity events, newest first, with optional cursor-based pagination.
    pub fn list_activity(&self, limit: usize, before_id: Option<i64>) -> Vec<ActivityEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_activity(limit, before_id) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_activity failed: {e}"),
            }
        }
        vec![]
    }

    /// Network-wide summary stats: agent count, total interactions, uptime.
    pub fn network_stats(&self) -> NetworkStats {
        let inner = self.inner.read().unwrap();
        let agent_count = inner.agents.len();

        // Prefer the authoritative SQLite count; fall back to in-memory ring buffer.
        let interaction_count = {
            let db = self.db.lock().unwrap();
            if let Some(ref conn) = *db {
                conn.0
                    .query_row("SELECT COUNT(*) FROM feedback_events", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap_or(0) as u64
            } else {
                self.inner.read().unwrap().interactions.len() as u64
            }
        };

        let beacon_count = {
            let db = self.db.lock().unwrap();
            if let Some(ref conn) = *db {
                conn.0
                    .query_row("SELECT SUM(beacon_count) FROM agent_registry", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap_or(0) as u64
            } else {
                0
            }
        };

        // Calculate BPM (Beacons Per Minute)
        let now = now_secs();
        let bpm = {
            let mut window = self.beacon_window.lock().unwrap();
            // Evict timestamps older than 60 seconds
            while window
                .front()
                .is_some_and(|&ts| ts < now.saturating_sub(60))
            {
                window.pop_front();
            }
            window.len() as u64
        };

        NetworkStats {
            agent_count,
            interaction_count,
            beacon_count,
            beacon_bpm: bpm,
            started_at: self.at_start_time(),
        }
    }

    fn at_start_time(&self) -> u64 {
        self.started_at
    }

    /// Latest entropy vector for an agent.
    pub fn entropy_latest(&self, agent_id: &str) -> Option<EntropyEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_entropy_latest(agent_id) {
                Ok(row) => return row,
                Err(e) => tracing::warn!("query_entropy_latest failed: {e}"),
            }
        }
        None
    }

    /// Agents sorted by highest anomaly score (most recent epoch per agent).
    pub fn anomaly_leaderboard(&self, limit: usize) -> Vec<EntropyEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_anomaly_leaderboard(limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_anomaly_leaderboard failed: {e}"),
            }
        }
        vec![]
    }

    /// All entropy vectors for an agent, newest first (up to `limit`).
    pub fn entropy_history(&self, agent_id: &str, limit: usize) -> Vec<EntropyEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_entropy_history(agent_id, limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_entropy_history failed: {e}"),
            }
        }
        vec![]
    }

    /// Return raw feedback events, optionally filtered by sender/target.
    /// When SQLite is available queries the full history; otherwise returns
    /// from the in-memory ring buffer (last 10 000 events).
    pub fn interactions(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        limit: usize,
    ) -> Vec<RawInteraction> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_interactions(from, to, limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_interactions failed: {e}"),
            }
        }
        // In-memory fallback.
        let inner = self.inner.read().unwrap();
        inner
            .interactions
            .iter()
            .rev()
            .filter(|i| from.is_none_or(|f| i.sender == f))
            .filter(|i| to.is_none_or(|t| i.target_agent == t))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Return hourly feedback buckets covering the last `window_secs` seconds.
    pub fn timeseries(&self, window_secs: u64) -> Vec<TimeseriesBucket> {
        let since = now_secs().saturating_sub(window_secs);
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_timeseries(since) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_timeseries failed: {e}"),
            }
        }
        // In-memory fallback: bucket the ring buffer.
        let inner = self.inner.read().unwrap();
        let mut map: HashMap<u64, TimeseriesBucket> = HashMap::new();
        for i in inner.interactions.iter().filter(|i| i.ts >= since) {
            let bucket = (i.ts / 3600) * 3600;
            let entry = map.entry(bucket).or_insert(TimeseriesBucket {
                bucket,
                feedback_count: 0,
                positive_count: 0,
                negative_count: 0,
                dispute_count: 0,
            });
            entry.feedback_count += 1;
            if i.outcome == 2 {
                entry.positive_count += 1;
            }
            if i.outcome == 0 {
                entry.negative_count += 1;
            }
            if i.is_dispute {
                entry.dispute_count += 1;
            }
        }
        let mut buckets: Vec<_> = map.into_values().collect();
        buckets.sort_by_key(|b| b.bucket);
        buckets
    }

    /// Rolling anomaly window for an agent (GAP-03: patient cartel detection).
    pub fn rolling_entropy(&self, agent_id: &str, window: u32) -> RollingEntropyResult {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_rolling_entropy(agent_id, window) {
                Ok(result) => return result,
                Err(e) => tracing::warn!("query_rolling_entropy failed: {e}"),
            }
        }
        RollingEntropyResult {
            agent_id: agent_id.to_string(),
            window_epochs: window,
            epochs_found: 0,
            mean_anomaly: 0.0,
            anomaly_variance: 0.0,
            low_variance_flag: false,
            high_anomaly_flag: false,
        }
    }

    /// Agents with consistently low verifier entropy (GAP-04: verifier collusion).
    pub fn verifier_concentration(&self, limit: usize) -> Vec<VerifierConcentrationEntry> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_verifier_concentration(limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_verifier_concentration failed: {e}"),
            }
        }
        vec![]
    }

    /// Suspected same-owner agent clusters (GAP-02: ownership clustering).
    ///
    /// Compares the last 10 anomaly scores for each agent pair.
    /// Agents whose anomaly trajectories have mean absolute difference < 0.05
    /// are placed in the same cluster.
    pub fn ownership_clusters(&self) -> Vec<OwnershipCluster> {
        let db = self.db.lock().unwrap();
        let rows: Vec<(String, f64)> = if let Some(ref conn) = *db {
            conn.0
                .prepare(
                    "SELECT agent_id, anomaly FROM entropy_vectors
                 WHERE (agent_id, epoch) IN (
                     SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
                 )
                 ORDER BY anomaly DESC
                 LIMIT 50",
                )
                .and_then(|mut s| {
                    s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)))
                        .and_then(|rows| rows.collect())
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        drop(db);

        if rows.len() < 2 {
            return vec![];
        }

        // Simple single-linkage clustering on anomaly score proximity.
        let mut assigned: Vec<Option<u32>> = vec![None; rows.len()];
        let mut next_cluster = 0u32;

        for i in 0..rows.len() {
            if assigned[i].is_some() {
                continue;
            }
            for j in (i + 1)..rows.len() {
                if assigned[j].is_some() {
                    continue;
                }
                let mad = (rows[i].1 - rows[j].1).abs();
                if mad < 0.05 {
                    let cid = assigned[i].get_or_insert_with(|| {
                        let c = next_cluster;
                        next_cluster += 1;
                        c
                    });
                    assigned[j] = Some(*cid);
                }
            }
            if assigned[i].is_none() {
                assigned[i] = Some(next_cluster);
                next_cluster += 1;
            }
        }

        let mut cluster_map: std::collections::HashMap<u32, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, cid) in assigned.iter().enumerate() {
            cluster_map.entry(cid.unwrap()).or_default().push(i);
        }

        cluster_map
            .into_iter()
            .filter(|(_, members)| members.len() >= 2)
            .map(|(cid, members)| {
                let agents: Vec<String> = members.iter().map(|&i| rows[i].0.clone()).collect();
                let scores: Vec<f64> = members.iter().map(|&i| rows[i].1).collect();
                let mean = scores.iter().sum::<f64>() / scores.len() as f64;
                let mad =
                    scores.iter().map(|s| (s - mean).abs()).sum::<f64>() / scores.len() as f64;
                OwnershipCluster {
                    cluster_id: cid,
                    agents,
                    mean_anomaly_mad: mad,
                }
            })
            .collect()
    }

    /// Calibrated β parameters from live entropy data (GAP-05).
    ///
    /// Compares entropy component contributions for flagged vs clean agents.
    /// Flagged = latest anomaly > 0.55.  Clean = latest anomaly < 0.10.
    pub fn calibrated_params(&self) -> CalibratedParams {
        let db = self.db.lock().unwrap();
        type EntropyRow = (f64, Option<f64>, Option<f64>, Option<f64>, Option<f64>);
        let rows: Vec<EntropyRow> = if let Some(ref conn) = *db {
            conn.0
                .prepare(
                    "SELECT anomaly, ht, hb, hs, hv FROM entropy_vectors
                     WHERE (agent_id, epoch) IN (
                         SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
                     )",
                )
                .and_then(|mut s| {
                    s.query_map([], |r| {
                        Ok((
                            r.get::<_, f64>(0)?,
                            r.get::<_, Option<f64>>(1)?,
                            r.get::<_, Option<f64>>(2)?,
                            r.get::<_, Option<f64>>(3)?,
                            r.get::<_, Option<f64>>(4)?,
                        ))
                    })
                    .and_then(|rows| rows.collect())
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        drop(db);

        // Default EntropyParams thresholds.
        let (ht_thresh, hb_thresh, hs_thresh, hv_thresh) = (2.0, 1.5, 1.5, 1.0);
        let (w_ht, w_hb, w_hs, w_hv) = (0.35, 0.20, 0.30, 0.15);

        let flagged: Vec<_> = rows.iter().filter(|r| r.0 > 0.55).collect();
        let total = rows.len() as u32;
        let n_flag = flagged.len() as u32;

        if flagged.is_empty() {
            return CalibratedParams {
                beta_1_anomaly: 0.870,
                beta_2_rep_decay: 0.130,
                beta_3_coordination: 0.0,
                beta_4_systemic: 0.0,
                sample_agents: total,
                flagged_agents: n_flag,
                calibrated_at: now_secs(),
            };
        }

        // Mean component contribution for flagged agents.
        let mut c_ht = 0.0_f64;
        let mut c_hb = 0.0_f64;
        let mut c_hs = 0.0_f64;
        let mut c_hv = 0.0_f64;
        let n = flagged.len() as f64;

        for &(_, ht, hb, hs, hv) in &flagged {
            if let Some(h) = ht {
                c_ht += w_ht * (ht_thresh - h).max(0.0);
            }
            if let Some(h) = hb {
                c_hb += w_hb * (hb_thresh - h).max(0.0);
            }
            if let Some(h) = hs {
                c_hs += w_hs * (hs_thresh - h).max(0.0);
            }
            if let Some(h) = hv {
                c_hv += w_hv * (hv_thresh - h).max(0.0);
            }
        }
        c_ht /= n;
        c_hb /= n;
        c_hs /= n;
        c_hv /= n;

        let entropy_total = c_ht + c_hb + c_hs + c_hv;
        let total_weight = entropy_total + 0.15; // 0.15 reserved for rep decay
        let b1 = if total_weight > 0.0 {
            entropy_total / total_weight
        } else {
            0.870
        };
        let b2 = 1.0 - b1;

        CalibratedParams {
            beta_1_anomaly: b1,
            beta_2_rep_decay: b2,
            beta_3_coordination: 0.0,
            beta_4_systemic: 0.0,
            sample_agents: total,
            flagged_agents: n_flag,
            calibrated_at: now_secs(),
        }
    }

    /// Systemic Risk Index and circuit breaker status (GAP-06).
    pub fn sri_status(&self) -> SriStatus {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_sri_status() {
                Ok(s) => return s,
                Err(e) => tracing::warn!("query_sri_status failed: {e}"),
            }
        }
        drop(db);
        // In-memory fallback: scan agent anomaly from leaderboard.
        let evs = self.anomaly_leaderboard(10_000);
        let total = evs.len() as u32;
        let flagged = evs.iter().filter(|e| e.anomaly > 0.55).count() as u32;
        let mean = if total > 0 {
            evs.iter().map(|e| e.anomaly).sum::<f64>() / total as f64
        } else {
            0.0
        };
        let sri = if total > 0 {
            flagged as f64 / total as f64
        } else {
            0.0
        };
        SriStatus {
            sri,
            circuit_breaker_active: sri > 0.50,
            mean_anomaly: mean,
            active_agents: total,
            flagged_agents: flagged,
            computed_at: now_secs(),
        }
    }

    /// Dynamic required stake for an agent (GAP-08, now includes C coefficient from GAP-02).
    ///
    /// Formula: required = BASE × (1 + β₁·A + β₃·C)
    pub fn required_stake(&self, agent_id: &str) -> RequiredStakeResult {
        const BASE_STAKE_USDC: f64 = 10.0;
        const BETA_1: f64 = 0.870;
        const BETA_3: f64 = 0.300;

        let anomaly = {
            let db = self.db.lock().unwrap();
            if let Some(ref conn) = *db {
                conn.query_latest_anomaly(agent_id)
                    .unwrap_or(None)
                    .unwrap_or(0.0)
            } else {
                0.0
            }
        };
        let c = self.agent_c_coefficient(agent_id);

        let required = BASE_STAKE_USDC * (1.0 + BETA_1 * anomaly + BETA_3 * c);
        let deficit = (required - BASE_STAKE_USDC).max(0.0);

        RequiredStakeResult {
            agent_id: agent_id.to_string(),
            base_stake_usdc: BASE_STAKE_USDC,
            current_anomaly: anomaly,
            c_coefficient: c,
            beta_1: BETA_1,
            beta_3: BETA_3,
            required_stake_usdc: required,
            deficit_usdc: deficit,
        }
    }

    // =========================================================================
    // Capital flow graph (GAP-02)
    // =========================================================================

    /// Capital flow edges over the last `window_secs` seconds.
    pub fn capital_flow_edges(&self, window_secs: u64, limit: usize) -> Vec<CapitalFlowEdge> {
        let since = now_secs().saturating_sub(window_secs);
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_capital_flow_edges(since, limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_capital_flow_edges failed: {e}"),
            }
        }
        vec![]
    }

    /// All ownership clusters detected via mutual flow analysis.
    pub fn flow_clusters(&self, window_secs: u64) -> Vec<FlowCluster> {
        let edges = self.capital_flow_edges(window_secs, 5_000);
        let (_, clusters) = compute_clusters_from_edges(&edges);
        clusters
    }

    /// Graph position + C coefficient for one agent.
    pub fn agent_flow_info(&self, agent_id: &str, window_secs: u64) -> AgentFlowInfo {
        let since = now_secs().saturating_sub(window_secs);

        // Outgoing flows for this agent.
        let outgoing: Vec<(String, u32, i64)> = {
            let db = self.db.lock().unwrap();
            if let Some(ref conn) = *db {
                conn.query_agent_outgoing(agent_id, since)
                    .unwrap_or_default()
            } else {
                vec![]
            }
        };

        let total_flow: i64 = outgoing.iter().map(|(_, _, f)| f).sum();
        let unique = outgoing.len() as u32;

        // Concentration ratio: fraction of flow to top-3 counterparties.
        let top3_flow: i64 = outgoing.iter().take(3).map(|(_, _, f)| f).sum();
        let concentration = if total_flow > 0 {
            top3_flow as f64 / total_flow as f64
        } else {
            0.0
        };
        let top_counterparties: Vec<String> = outgoing
            .iter()
            .take(5)
            .map(|(id, _, _)| id.clone())
            .collect();

        // Cluster membership.
        let edges = self.capital_flow_edges(window_secs, 5_000);
        let (agent_cluster, clusters) = compute_clusters_from_edges(&edges);
        let cluster_id = agent_cluster.get(agent_id).copied();
        let c_coeff = cluster_id
            .and_then(|cid| clusters.iter().find(|c| c.cluster_id == cid))
            .map(|c| c.c_coefficient)
            .unwrap_or(0.0);

        AgentFlowInfo {
            agent_id: agent_id.to_string(),
            cluster_id,
            c_coefficient: c_coeff,
            concentration_ratio: concentration,
            top_counterparties,
            total_outgoing_flow: total_flow,
            unique_counterparties: unique,
        }
    }

    /// C coefficient for a single agent (0.0 when not in any cluster).
    /// Uses the Solana on-chain Capital Flow graph (GAP-02) computed by the background indexer.
    pub fn agent_c_coefficient(&self, agent_id: &str) -> f64 {
        let inner = self.inner.read().unwrap();
        inner
            .solana_flow_clusters
            .get(agent_id)
            .copied()
            .unwrap_or(0.0)
    }

    // =========================================================================
    // External Indexer Hooks (GAP-02)
    // =========================================================================

    /// Returns the pubkeys of all agents currently in the local reputation store.
    pub async fn get_active_agent_pubkeys(&self) -> anyhow::Result<Vec<String>> {
        let inner = self.inner.read().unwrap();
        Ok(inner.agents.keys().cloned().collect())
    }

    /// Stores the computed on-chain clusters. The C coefficient is derived from cluster size.
    pub async fn update_capital_flow_clusters(
        &self,
        clusters: Vec<Vec<String>>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.solana_flow_clusters.clear();

        for cluster_agents in clusters {
            // C multiplier calculation based closely on the paper/placeholder logic.
            // i.e., larger group of linked ownership = higher multiplier.
            let suspicion = ((cluster_agents.len() - 1) as f64 / 10.0).min(1.0);
            for agent_id in cluster_agents {
                inner.solana_flow_clusters.insert(agent_id, suspicion);
            }
        }

        tracing::debug!("Updated solana_flow_clusters map with on-chain data.");
        Ok(())
    }

    /// Write a single reputation record to SQLite (fire-and-forget; failures are logged).
    fn persist(&self, rep: &AgentReputation) {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.upsert(rep) {
                tracing::warn!("SQLite upsert failed for {}: {e}", rep.agent_id);
            }
        }
    }

    /// Write a raw feedback event to SQLite (fire-and-forget; failures are logged).
    fn persist_feedback(&self, fb: &FeedbackEvent, ts: u64) {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.insert_feedback(fb, ts) {
                tracing::warn!("SQLite insert_feedback failed: {e}");
            }
        }
    }

    /// Store a raw CBOR envelope byte slice for an agent's epoch.
    /// Called during FEEDBACK ingest when the node provides raw bytes.
    /// The seq_num is assigned by insertion order (count of existing rows for that agent+epoch).
    pub fn store_raw_envelope(&self, agent_id: &str, epoch: u64, ts: u64, raw_b64: &str) {
        use base64::Engine as _;
        let bytes = match base64::engine::general_purpose::STANDARD.decode(raw_b64) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to decode raw_b64 for {agent_id}: {e}");
                return;
            }
        };
        let leaf_hash = {
            use tiny_keccak::{Hasher, Keccak};
            let mut k = Keccak::v256();
            let mut out = [0u8; 32];
            // Merkle leaf domain separation: keccak256(0x00 || raw_cbor).
            k.update(&[0x00]);
            k.update(&bytes);
            k.finalize(&mut out);
            hex::encode(out)
        };
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            let seq = conn.next_envelope_seq(agent_id, epoch).unwrap_or(0);
            if let Err(e) = conn.store_raw_envelope(agent_id, epoch, seq, ts, &leaf_hash, &bytes) {
                tracing::warn!("SQLite store_raw_envelope failed: {e}");
            }
        }
    }

    /// Retrieve ordered CBOR envelope bytes for an agent's epoch (for Merkle proof construction).
    /// Returns up to 1000 entries, ordered by sequence (insertion order).
    pub fn epoch_envelopes(&self, agent_id: &str, epoch: u64) -> Vec<EpochEnvelopeEntry> {
        use base64::Engine as _;
        let db = self.db.lock().unwrap();
        match *db {
            Some(ref conn) => conn
                .query_epoch_envelopes(agent_id, epoch, 1_000)
                .unwrap_or_default()
                .into_iter()
                .map(|(seq, leaf_hash, bytes)| EpochEnvelopeEntry {
                    seq,
                    leaf_hash,
                    bytes_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                })
                .collect(),
            None => vec![],
        }
    }

    /// Search agents that have advertised a specific capability.
    /// Returns up to `limit` results, most recently seen first.
    pub fn search_by_capability(&self, capability: &str, limit: usize) -> Vec<CapabilityMatch> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_agents_by_capability(capability, limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_agents_by_capability failed: {e}"),
            }
        }
        vec![]
    }

    /// Return recent dispute records targeting a specific agent.
    pub fn disputes_for_agent(&self, agent_id: &str, limit: usize) -> Vec<DisputeRecord> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_disputes_for_agent(agent_id, limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_disputes_for_agent failed: {e}"),
            }
        }
        vec![]
    }
    /// Query the agent registry built from BEACON events.
    pub fn get_registry(&self) -> Vec<AgentRegistryEntry> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.get_registry() {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("get_registry failed: {e}"),
            }
        }
        vec![]
    }

    /// Full agent profile — combines reputation, entropy, capabilities, disputes, and name
    /// into a single response to avoid multiple round trips.
    pub fn agent_profile(&self, agent_id: &str) -> AgentProfile {
        let reputation = self.get(agent_id);
        let entropy = self.entropy_latest(agent_id);
        let capabilities = self.search_by_capability_for_agent(agent_id);
        let disputes = self.disputes_for_agent(agent_id, 5);
        let last_seen = reputation.as_ref().map(|r| r.last_seen);

        let name = {
            let db = self.db.lock().unwrap();
            db.as_ref()
                .and_then(|conn| conn.query_agent_name(agent_id).ok().flatten())
        };

        AgentProfile {
            agent_id: agent_id.to_string(),
            name,
            reputation,
            entropy,
            capabilities,
            disputes,
            last_seen,
        }
    }

    /// Capabilities advertised by a specific agent (for use in profile assembly).
    fn search_by_capability_for_agent(&self, agent_id: &str) -> Vec<CapabilityMatch> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            let res = conn
                .0
                .prepare(
                    "SELECT agent_id, capability, last_seen FROM capabilities WHERE agent_id = ?1",
                )
                .and_then(|mut stmt| {
                    stmt.query_map(rusqlite::params![agent_id], |row| {
                        Ok(CapabilityMatch {
                            agent_id: row.get(0)?,
                            capability: row.get(1)?,
                            last_seen: row.get::<_, i64>(2)? as u64,
                        })
                    })
                    .and_then(|rows| rows.collect())
                });
            if let Ok(rows) = res {
                return rows;
            }
        }
        vec![]
    }

    /// Search agents by name (case-insensitive substring match on BEACON names).
    pub fn search_by_name(&self, name: &str, limit: usize) -> Vec<AgentRegistryEntry> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_agents_by_name(name, limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_agents_by_name failed: {e}"),
            }
        }
        vec![]
    }
    // ── Hosting node registry ─────────────────────────────────────────────

    /// Upsert a hosting node heartbeat.
    ///
    /// Sets `first_seen` only on INSERT; always updates `last_seen`.
    pub fn register_hosting_node(&self, node_id: &str, name: &str, fee_bps: u32, api_url: &str) {
        let now = now_secs() as i64;
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            let _ = conn.0.execute(
                "INSERT INTO hosting_nodes (node_id, name, fee_bps, api_url, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(node_id) DO UPDATE SET
                     name      = excluded.name,
                     fee_bps   = excluded.fee_bps,
                     api_url   = excluded.api_url,
                     last_seen = excluded.last_seen",
                rusqlite::params![node_id, name, fee_bps as i64, api_url, now],
            );
        }
    }

    /// Return hosting nodes seen within the last 120 seconds, ordered by most recent.
    pub fn list_hosting_nodes(&self) -> Vec<HostingNode> {
        let cutoff = now_secs() as i64 - 120;
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            let mut stmt = match conn.0.prepare(
                "SELECT hn.node_id, hn.name, hn.fee_bps, hn.api_url, hn.first_seen,
                        hn.last_seen, COUNT(ha.agent_id) as hosted_count
                 FROM hosting_nodes hn
                 LEFT JOIN hosted_agents ha ON hn.node_id = ha.host_node_id
                 WHERE hn.last_seen > ?1
                 GROUP BY hn.node_id
                 ORDER BY hn.last_seen DESC",
            ) {
                Ok(s) => s,
                Err(_) => return vec![],
            };
            let rows = stmt.query_map([cutoff], |row| {
                Ok(HostingNode {
                    node_id: row.get(0)?,
                    name: row.get(1)?,
                    fee_bps: row.get::<_, i64>(2)? as u32,
                    api_url: row.get(3)?,
                    first_seen: row.get::<_, i64>(4)? as u64,
                    last_seen: row.get::<_, i64>(5)? as u64,
                    hosted_count: row.get::<_, i64>(6)? as u32,
                })
            });
            if let Ok(iter) = rows {
                return iter.flatten().collect();
            }
        }
        vec![]
    }

    /// Upsert a hosted-agent record.
    #[allow(dead_code)]
    pub fn register_hosted_agent(&self, agent_id: &str, host_node_id: &str) {
        let now = now_secs() as i64;
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            let _ = conn.0.execute(
                "INSERT INTO hosted_agents (agent_id, host_node_id, registered_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(agent_id, host_node_id) DO UPDATE SET registered_at = excluded.registered_at",
                rusqlite::params![agent_id, host_node_id, now],
            );
        }
    }
} // end impl ReputationStore

/// Compute trend from recent feedback scores (newest first).
/// Splits scores in half: if the newer half averages >5 points above the older half → "rising",
/// >5 below → "falling", otherwise "stable". Requires at least 6 samples.
fn compute_trend(scores: &[i32]) -> &'static str {
    if scores.len() < 6 {
        return "stable";
    }
    let mid = scores.len() / 2;
    let recent: f64 = scores[..mid].iter().sum::<i32>() as f64 / mid as f64;
    let older: f64 = scores[mid..].iter().sum::<i32>() as f64 / (scores.len() - mid) as f64;
    if recent > older + 5.0 {
        "rising"
    } else if recent < older - 5.0 {
        "falling"
    } else {
        "stable"
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
