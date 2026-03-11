use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use zerox1_protocol::{
    batch::{BehaviorBatch, FeedbackEvent, TaskSelection, TypedBid},
    constants::EPOCH_LENGTH_SECS,
    hash::merkle_root,
    message::MsgType,
};

// ============================================================================
// Time helpers
// ============================================================================

/// Current 0x01 epoch number (Unix time / EPOCH_LENGTH_SECS).
pub fn current_epoch() -> u64 {
    unix_secs() / EPOCH_LENGTH_SECS
}

pub fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

// ============================================================================
// BatchAccumulator
// ============================================================================

/// Accumulates per-epoch economic data for daily BehaviorBatch construction (doc 5, §8.2).
pub struct BatchAccumulator {
    pub epoch_number: u64,
    pub slot_start: u64,

    // Activity counters
    pub message_count: u32,
    pub msg_type_counts: [u32; 16],
    unique_counterparties: HashSet<[u8; 32]>,
    pub disputes: u32,

    // Activity arrays
    pub bids: Vec<TypedBid>,
    pub task_selections: Vec<TaskSelection>,
    pub feedback_events: Vec<FeedbackEvent>,
}

impl BatchAccumulator {
    pub fn new(epoch_number: u64, epoch_start: u64) -> Self {
        Self {
            epoch_number,
            slot_start: epoch_start,
            message_count: 0,
            msg_type_counts: [0u32; 16],
            unique_counterparties: HashSet::new(),
            disputes: 0,
            bids: Vec::new(),
            task_selections: Vec::new(),
            feedback_events: Vec::new(),
        }
    }

    /// Record that a message was sent or received with a given counterparty.
    pub fn record_message(&mut self, msg_type: MsgType, counterparty: [u8; 32], _ts: u64) {
        self.message_count += 1;
        let idx = (msg_type.as_u16() as usize).min(15);
        self.msg_type_counts[idx] += 1;
        self.unique_counterparties.insert(counterparty);
    }

    pub fn add_bid(&mut self, bid: TypedBid) {
        self.bids.push(bid);
    }

    pub fn record_accept(&mut self, sel: TaskSelection) {
        self.task_selections.push(sel);
    }

    pub fn record_feedback(&mut self, fe: FeedbackEvent) {
        self.feedback_events.push(fe);
    }

    pub fn record_dispute(&mut self) {
        self.disputes += 1;
    }

    /// Finalise the epoch batch and return a `BehaviorBatch`.
    ///
    /// `leaf_hashes` = keccak256(0x00 || CBOR) of each logged envelope (from EnvelopeLogger).
    pub fn finalize(
        &mut self,
        agent_id: [u8; 32],
        epoch_end: u64,
        leaf_hashes: &[[u8; 32]],
    ) -> BehaviorBatch {
        let log_merkle_root = if leaf_hashes.is_empty() {
            [0u8; 32]
        } else {
            merkle_root(leaf_hashes)
        };

        let mut batch = BehaviorBatch {
            agent_id,
            epoch_number: self.epoch_number,
            slot_start: self.slot_start,
            slot_end: epoch_end,
            message_count: self.message_count,
            msg_type_counts: self.msg_type_counts,
            unique_counterparties: self.unique_counterparties.len() as u32,
            tasks_completed: 0,
            disputes: self.disputes,
            bid_values: std::mem::take(&mut self.bids),
            task_selections: std::mem::take(&mut self.task_selections),
            feedback_events: std::mem::take(&mut self.feedback_events),
            overflow: false,
            overflow_data_hash: [0u8; 32],
            log_merkle_root,
        };

        batch.apply_overflow_cap();
        batch
    }
}
