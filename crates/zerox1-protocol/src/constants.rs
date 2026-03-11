// ============================================================================
// Protocol constants
// ============================================================================

/// Protocol version byte included in every envelope.
pub const PROTOCOL_VERSION: u8 = 0x01;

// --- Epoch ------------------------------------------------------------------

/// 0x01 epoch length in seconds (1 day).
pub const EPOCH_LENGTH_SECS: u64 = 86_400;

// --- Transport --------------------------------------------------------------

/// Maximum envelope size in bytes (envelope + payload).
pub const MAX_MESSAGE_SIZE: usize = 65_536; // 64 KB

/// Maximum simultaneous libp2p connections per peer.
pub const MAX_CONNECTIONS: usize = 50;

/// Maximum inbound messages per second per peer before rate-limiting kicks in.
pub const MESSAGE_RATE_LIMIT: u32 = 100;

/// Acceptable clock skew between local and envelope timestamp (seconds).
pub const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

// --- Reputation -------------------------------------------------------------

/// Decay factor applied per idle epoch as a fixed-precision ratio (numerator/denominator).
/// Equivalent to 0.95 decay per epoch.
pub const REPUTATION_DECAY_NUMERATOR: u64 = 95;
pub const REPUTATION_DECAY_DENOMINATOR: u64 = 100;

/// Number of consecutive idle epochs before decay begins.
pub const DECAY_WINDOW_EPOCHS: u64 = 6;

// --- Batch ------------------------------------------------------------------

/// Maximum entries per economic array in a BehaviorBatch before overflow.
pub const MAX_BATCH_ENTRIES: usize = 1_000;

// --- Challenge --------------------------------------------------------------

/// Challenge window in seconds (2 days). After this, no new challenges accepted.
pub const CHALLENGE_WINDOW_SECS: u64 = 172_800;

// --- Pubsub topics ----------------------------------------------------------

pub const TOPIC_BROADCAST: &str = "/0x01/v1/broadcast";
pub const TOPIC_REPUTATION: &str = "/0x01/v1/reputation";
