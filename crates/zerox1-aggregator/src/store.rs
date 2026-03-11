//! In-memory reputation store with optional SQLite persistence.
//!
//! All reads are served from a fast in-memory HashMap.
//! Every ingest event is also written to SQLite (when `--db-path` is set)
//! so data survives restarts without replaying node pushes.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

// ============================================================================
// Input validation
// ============================================================================

fn is_valid_agent_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
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
    pub conversation_id: String,
    pub slot: u64,
    /// Base64-encoded raw CBOR envelope bytes — used for Merkle proof construction.
    /// None when pushed by older node versions.
    pub raw_b64: Option<String>,
}

/// Generic envelope event for collaboration and negotiation messages.
/// Covers ASSIGN, ACK, CLARIFY, REPORT, APPROVE, TASK_CANCEL, ESCALATE, SYNC,
/// COUNTER, ACCEPT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEvent {
    pub sender: String,
    pub recipient: String,
    pub conversation_id: String,
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
pub struct RejectEvent {
    pub sender: String,
    pub recipient: String,
    pub conversation_id: String,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverEvent {
    pub sender: String,
    pub recipient: String,
    pub conversation_id: String,
    pub slot: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconEvent {
    pub sender: String,
    pub name: String,
    pub slot: u64,
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

/// Full agent profile — reputation + capabilities + name.
/// Returned by GET /agents/{agent_id}/profile to avoid multiple round trips.
#[derive(Debug, Clone, Serialize)]
pub struct AgentProfile {
    pub agent_id: String,
    pub name: Option<String>,
    pub reputation: Option<AgentReputation>,
    pub capabilities: Vec<CapabilityMatch>,
    pub last_seen: Option<u64>,
}

/// Activity event broadcast to WebSocket clients and stored in activity_log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub ts: i64,
    pub event_type: String, // "JOIN" | "FEEDBACK" | "DISPUTE" | "VERDICT" | "REJECT" | "DELIVER"
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
    // Infrastructure
    #[serde(rename = "FEEDBACK")]
    Feedback(FeedbackEvent),
    #[serde(rename = "ADVERTISE")]
    Advertise(AdvertiseEvent),
    #[serde(rename = "BEACON")]
    Beacon(BeaconEvent),
    // Collaboration (0x1_)
    #[serde(rename = "ASSIGN")]
    Assign(EnvelopeEvent),
    #[serde(rename = "ACK")]
    Ack(EnvelopeEvent),
    #[serde(rename = "CLARIFY")]
    Clarify(EnvelopeEvent),
    #[serde(rename = "REPORT")]
    Report(EnvelopeEvent),
    #[serde(rename = "APPROVE")]
    Approve(EnvelopeEvent),
    #[serde(rename = "TASK_CANCEL")]
    TaskCancel(EnvelopeEvent),
    #[serde(rename = "ESCALATE")]
    Escalate(EnvelopeEvent),
    #[serde(rename = "SYNC")]
    Sync(EnvelopeEvent),
    // Negotiation (0x2_)
    #[serde(rename = "PROPOSE")]
    Propose(EnvelopeEvent),
    #[serde(rename = "COUNTER")]
    Counter(EnvelopeEvent),
    #[serde(rename = "ACCEPT")]
    Accept(EnvelopeEvent),
    #[serde(rename = "DELIVER")]
    Deliver(DeliverEvent),
    #[serde(rename = "DISPUTE")]
    Dispute(DisputeEvent),
    #[serde(rename = "REJECT")]
    Reject(RejectEvent),
    #[serde(rename = "DEAL_CANCEL")]
    DealCancel(EnvelopeEvent),
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
        | "AO" | "MZ" | "ZM" | "ZW" | "BW" | "NA" | "MG" | "MU" | "TG" | "BJ" | "ML" | "BF"
        | "NE" | "TD" | "SO" | "ER" | "SS" => (300, 220),
        // South Asia
        "IN" | "PK" | "BD" | "LK" | "NP" | "AF" | "MV" => (360, 300),
        // Southeast Asia
        "SG" | "MY" | "TH" | "PH" | "ID" | "VN" | "MM" | "KH" | "LA" | "BN" | "TL" => (380, 340),
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
        self.average_score =
            (self.total_score as f64 / self.feedback_count as f64).clamp(-100.0, 100.0);
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
    last_updated   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS feedback_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT    NOT NULL,
    target_agent    TEXT    NOT NULL,
    score           INTEGER NOT NULL,
    outcome         INTEGER NOT NULL,
    is_dispute      INTEGER NOT NULL DEFAULT 0,
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
    // v5: Drop ownership tables (not used in enterprise)
    "
DROP TABLE IF EXISTS ownership_proposals;
DROP TABLE IF EXISTS ownership_claims;
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
    // v8: Unique constraint on (sender, conversation_id) to prevent duplicate feedback.
    // Deduplicate first (keep the earliest row per pair), then create the unique index.
    "
DELETE FROM feedback_events
WHERE id NOT IN (
    SELECT MIN(id) FROM feedback_events
    GROUP BY sender, conversation_id
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fe_sender_conv
    ON feedback_events(sender, conversation_id);
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
                    last_updated
             FROM agent_reputation",
        )?;
        let rows = stmt.query_map([], |row| {
            let agent_id: String = row.get(0)?;
            let feedback_count: u64 = row.get::<_, i64>(1)? as u64;
            let total_score: i64 = row.get(2)?;
            let positive_count: u64 = row.get::<_, i64>(3)? as u64;
            let neutral_count: u64 = row.get::<_, i64>(4)? as u64;
            let negative_count: u64 = row.get::<_, i64>(5)? as u64;
            let last_updated: u64 = row.get::<_, i64>(6)? as u64;
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
                  neutral_count, negative_count, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(agent_id) DO UPDATE SET
                 feedback_count = excluded.feedback_count,
                 total_score    = excluded.total_score,
                 positive_count = excluded.positive_count,
                 neutral_count  = excluded.neutral_count,
                 negative_count = excluded.negative_count,
                 last_updated   = excluded.last_updated",
            rusqlite::params![
                rep.agent_id,
                rep.feedback_count as i64,
                rep.total_score,
                rep.positive_count as i64,
                rep.neutral_count as i64,
                rep.negative_count as i64,
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
        let mut map: std::collections::HashMap<String, std::collections::HashMap<String, u64>> =
            std::collections::HashMap::new();
        for row in rows {
            let (agent_id, region, rtt_ms) = row?;
            map.entry(agent_id).or_default().insert(region, rtt_ms);
        }
        Ok(map)
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

    /// Return true if a feedback row for this (sender, conversation_id) already exists.
    fn feedback_exists(&self, sender: &str, conversation_id: &str) -> rusqlite::Result<bool> {
        let count: i64 = self.0.query_row(
            "SELECT COUNT(*) FROM feedback_events WHERE sender = ?1 AND conversation_id = ?2",
            rusqlite::params![sender, conversation_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Insert a raw feedback event. Uses INSERT OR IGNORE so the (sender, conversation_id)
    /// unique index silently drops duplicates without returning an error.
    fn insert_feedback(&self, fb: &FeedbackEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT OR IGNORE INTO feedback_events
                 (sender, target_agent, score, outcome, is_dispute,
                  conversation_id, slot, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                fb.sender,
                fb.target_agent,
                fb.score,
                fb.outcome as i64,
                fb.is_dispute as i64,
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
            "SELECT sender, target_agent, score, outcome, is_dispute,
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
                conversation_id: row.get(5)?,
                slot: row.get::<_, i64>(6)? as u64,
                ts: row.get::<_, i64>(7)? as u64,
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

    fn next_envelope_seq(&self, agent_id: &str, epoch: u64) -> rusqlite::Result<i64> {
        let count: i64 = self.0.query_row(
            "SELECT COUNT(*) FROM raw_envelopes WHERE agent_id = ?1 AND epoch = ?2",
            rusqlite::params![agent_id, epoch as i64],
            |row| row.get(0),
        )?;
        Ok(count)
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


// ============================================================================
// ReputationStore
// ============================================================================

/// In-memory cap for raw interactions when running without SQLite.
const MAX_IN_MEMORY_INTERACTIONS: usize = 10_000;
/// Max feedback submissions per sender per hour (sliding window, in-memory).
const MAX_FEEDBACK_PER_HOUR: usize = 10;

#[derive(Default)]
struct Inner {
    agents: HashMap<String, AgentReputation>,
    /// Bounded ring buffer of recent interactions (used as fallback when no SQLite).
    interactions: VecDeque<RawInteraction>,
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

#[derive(Clone)]
pub struct ReputationStore {
    inner: Arc<RwLock<Inner>>,
    /// SQLite connection; None = in-memory only (no --db-path supplied).
    db: Arc<Mutex<Option<Db>>>,
    /// Process start time — never changes after init.
    started_at: u64,
    /// Sliding window of BEACON timestamps for BPM calculation.
    beacon_window: Arc<Mutex<VecDeque<u64>>>,
    /// Per-sender sliding window of feedback timestamps (last 1 hour).
    /// Used to rate-limit feedback submissions to MAX_FEEDBACK_PER_HOUR per sender.
    feedback_rate_limit: Arc<Mutex<HashMap<String, VecDeque<u64>>>>,
}

impl Default for ReputationStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            db: Arc::new(Mutex::new(None)),
            started_at: now_secs(),
            beacon_window: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            feedback_rate_limit: Arc::new(Mutex::new(HashMap::new())),
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

        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                agents,
                interactions: VecDeque::new(),
            })),
            db: Arc::new(Mutex::new(Some(db))),
            started_at: now_secs(),
            beacon_window: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            feedback_rate_limit: Arc::new(Mutex::new(HashMap::new())),
        })
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
                if !is_valid_agent_id(&fb.sender) {
                    tracing::warn!("Ingest: invalid sender '{}' — dropped", &fb.sender);
                    return None;
                }
                if fb.sender == fb.target_agent {
                    tracing::warn!("Ingest: self-feedback from '{}' — dropped", &fb.sender);
                    return None;
                }
                // DB dedup check: if (sender, conversation_id) already exists in SQLite,
                // this is a replayed or duplicate event — skip to avoid double-counting.
                {
                    let db = self.db.lock().unwrap();
                    if let Some(ref conn) = *db {
                        match conn.feedback_exists(&fb.sender, &fb.conversation_id) {
                            Ok(true) => {
                                tracing::debug!(
                                    "Ingest: duplicate feedback ({}, {}) — dropped",
                                    &fb.sender,
                                    &fb.conversation_id
                                );
                                return None;
                            }
                            Err(e) => {
                                tracing::warn!("Ingest: feedback_exists query failed: {e}");
                            }
                            Ok(false) => {}
                        }
                    }
                }
                // Rate limit: max MAX_FEEDBACK_PER_HOUR per sender per hour.
                {
                    let now = now_secs();
                    let cutoff = now.saturating_sub(3600);
                    let mut rl = self.feedback_rate_limit.lock().unwrap();
                    let window = rl.entry(fb.sender.clone()).or_default();
                    // Evict timestamps older than 1 hour.
                    while window.front().map(|&t| t < cutoff).unwrap_or(false) {
                        window.pop_front();
                    }
                    if window.len() >= MAX_FEEDBACK_PER_HOUR {
                        tracing::warn!(
                            "Ingest: rate limit exceeded for sender '{}' — dropped",
                            &fb.sender
                        );
                        return None;
                    }
                    window.push_back(now);
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
                                        ch.is_alphanumeric() || ch == ' ' || ch == '-' || ch == '\''
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
                // Record for BPM sliding window. Evict entries older than 60s
                // on every push so the window stays bounded regardless of
                // whether /stats/network is ever polled.
                let now = now_secs();
                {
                    let mut window = self.beacon_window.lock().unwrap();
                    let cutoff = now.saturating_sub(60);
                    while window.front().is_some_and(|&ts| ts < cutoff) {
                        window.pop_front();
                    }
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
            IngestEvent::Reject(ev) => {
                if !is_valid_agent_id(&ev.sender) || !is_valid_agent_id(&ev.recipient) {
                    tracing::warn!("Ingest: invalid agent_id in REJECT — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::debug!(
                    "REJECT sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "REJECT".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(REJECT) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Deliver(ev) => {
                if !is_valid_agent_id(&ev.sender) || !is_valid_agent_id(&ev.recipient) {
                    tracing::warn!("Ingest: invalid agent_id in DELIVER — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::debug!(
                    "DELIVER sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "DELIVER".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(DELIVER) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Assign(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in ASSIGN — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "ASSIGN sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "ASSIGN".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(ASSIGN) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Ack(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in ACK — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "ACK sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "ACK".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(ACK) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Clarify(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in CLARIFY — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "CLARIFY sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "CLARIFY".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(CLARIFY) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Report(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in REPORT — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "REPORT sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "REPORT".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(REPORT) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Approve(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in APPROVE — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "APPROVE sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "APPROVE".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(APPROVE) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::TaskCancel(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in TASK_CANCEL — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "TASK_CANCEL sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "TASK_CANCEL".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(TASK_CANCEL) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Escalate(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in ESCALATE — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::warn!(
                    "ESCALATE sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "ESCALATE".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(ESCALATE) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Sync(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in SYNC — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "SYNC sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "SYNC".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(SYNC) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Propose(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in PROPOSE — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "PROPOSE sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "PROPOSE".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(PROPOSE) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Counter(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in COUNTER — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "COUNTER sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "COUNTER".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(COUNTER) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::Accept(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in ACCEPT — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "ACCEPT sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "ACCEPT".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(ACCEPT) failed: {e}"),
                    }
                }
                None
            }
            IngestEvent::DealCancel(ev) => {
                if !is_valid_agent_id(&ev.sender) {
                    tracing::warn!("Ingest: invalid sender in DEAL_CANCEL — dropped");
                    return None;
                }
                drop(inner);
                let ts = now_secs();
                tracing::info!(
                    "DEAL_CANCEL sender={} recipient={}",
                    &ev.sender[..8.min(ev.sender.len())],
                    &ev.recipient[..8.min(ev.recipient.len())],
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    let act = ActivityEvent {
                        id: 0,
                        ts: ts as i64,
                        event_type: "DEAL_CANCEL".to_string(),
                        agent_id: ev.sender.clone(),
                        target_id: Some(ev.recipient.clone()),
                        score: None,
                        name: conn.query_agent_name(&ev.sender).ok().flatten(),
                        target_name: conn.query_agent_name(&ev.recipient).ok().flatten(),
                        slot: Some(ev.slot as i64),
                        conversation_id: Some(ev.conversation_id.clone()),
                    };
                    match conn.insert_activity(&act) {
                        Ok(saved) => return Some(saved),
                        Err(e) => tracing::warn!("SQLite insert_activity(DEAL_CANCEL) failed: {e}"),
                    }
                }
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

    /// Full agent profile — combines reputation, capabilities, and name
    /// into a single response to avoid multiple round trips.
    pub fn agent_profile(&self, agent_id: &str) -> AgentProfile {
        let reputation = self.get(agent_id);
        let capabilities = self.search_by_capability_for_agent(agent_id);
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
            capabilities,
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
