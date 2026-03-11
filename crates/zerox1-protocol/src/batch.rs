use crate::{constants::MAX_BATCH_ENTRIES, error::ProtocolError, hash::keccak256};
use ciborium::value::Value;

// ============================================================================
// Economic array types (doc 5, §8.3)
// ============================================================================

/// A single bid placed by this agent during the epoch.
/// Corresponds to a PROPOSE, COUNTER, or ACCEPT message.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedBid {
    /// Links bid to negotiation.
    pub conversation_id: [u8; 16],
    /// Agent receiving the bid.
    pub counterparty: [u8; 32],
    /// Fixed-precision bid value, 18 decimal scaling.
    pub bid_value: i128,
    /// Unix timestamp (seconds) when bid was placed.
    pub slot: u64,
}

/// A task accepted by this agent during the epoch.
/// Corresponds to an ACCEPT message.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskSelection {
    /// Negotiation accepted.
    pub conversation_id: [u8; 16],
    /// Agent selected.
    pub counterparty: [u8; 32],
    /// Unix timestamp (seconds) of ACCEPT message.
    pub slot: u64,
}

/// A feedback event received by this agent during the epoch.
/// This is the authoritative reputation input — computed from these
/// entries in the daily BehaviorBatch.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedbackEvent {
    /// Task rated.
    pub conversation_id: [u8; 16],
    /// Agent who gave the feedback.
    pub from_agent: [u8; 32],
    /// Score: -100 to +100.
    pub score: i8,
    /// Outcome: 0=Negative, 1=Neutral, 2=Positive.
    pub outcome: u8,
    /// Unix timestamp (seconds) of FEEDBACK message.
    pub slot: u64,
}

// ============================================================================
// BehaviorBatch (doc 5, §8.2)
// ============================================================================

/// Per-epoch self-reported economic record.
///
/// Self-reported arrays are challengeable within CHALLENGE_WINDOW.
/// Arrays capped at MAX_BATCH_ENTRIES; overflow committed via overflow_data_hash.
#[derive(Debug, Clone)]
pub struct BehaviorBatch {
    // --- Identity and epoch bounds ------------------------------------------
    /// Agent ID (Ed25519 verifying key bytes).
    pub agent_id: [u8; 32],
    /// Zero-based epoch counter (increments each 0x01 day).
    pub epoch_number: u64,
    /// Unix timestamp (seconds) at epoch start.
    pub slot_start: u64,
    /// Unix timestamp (seconds) at epoch end.
    pub slot_end: u64,

    // --- Activity summary ---------------------------------------------------
    /// Total messages sent this epoch.
    pub message_count: u32,
    /// Count per msg_type (indexed by msg_type value 0x01–0x0D; index 0 unused).
    pub msg_type_counts: [u32; 16],
    /// Distinct agents interacted with.
    pub unique_counterparties: u32,
    /// VERDICT received count (tasks completed).
    pub tasks_completed: u32,
    /// DISPUTE sent or received count.
    pub disputes: u32,

    // --- Self-reported economic arrays (challengeable) ----------------------
    pub bid_values: Vec<TypedBid>,
    pub task_selections: Vec<TaskSelection>,
    pub feedback_events: Vec<FeedbackEvent>,

    // --- Overflow handling --------------------------------------------------
    /// True if any array was truncated to MAX_BATCH_ENTRIES.
    pub overflow: bool,
    /// keccak256 of full untruncated arrays (all four concatenated).
    /// [0u8; 32] when no overflow.
    pub overflow_data_hash: [u8; 32],

    // --- Audit anchor -------------------------------------------------------
    /// Merkle root of the full epoch envelope log.
    pub log_merkle_root: [u8; 32],
}

impl BehaviorBatch {
    /// Encode to canonical CBOR bytes for on-chain submission / signing.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let value = Value::Map(vec![
            (sv("agent_id"), Value::Bytes(self.agent_id.to_vec())),
            (sv("epoch_number"), Value::Integer(self.epoch_number.into())),
            (sv("slot_start"), Value::Integer(self.slot_start.into())),
            (sv("slot_end"), Value::Integer(self.slot_end.into())),
            (
                sv("message_count"),
                Value::Integer(self.message_count.into()),
            ),
            (
                sv("msg_type_counts"),
                Value::Array(
                    self.msg_type_counts
                        .iter()
                        .map(|&c| Value::Integer(c.into()))
                        .collect(),
                ),
            ),
            (
                sv("unique_counterparties"),
                Value::Integer(self.unique_counterparties.into()),
            ),
            (
                sv("tasks_completed"),
                Value::Integer(self.tasks_completed.into()),
            ),
            (sv("disputes"), Value::Integer(self.disputes.into())),
            (sv("bid_values"), encode_typed_bids(&self.bid_values)),
            (
                sv("task_selections"),
                encode_task_selections(&self.task_selections),
            ),
            (
                sv("feedback_events"),
                encode_feedback_events(&self.feedback_events),
            ),
            (sv("overflow"), Value::Bool(self.overflow)),
            (
                sv("overflow_data_hash"),
                Value::Bytes(self.overflow_data_hash.to_vec()),
            ),
            (
                sv("log_merkle_root"),
                Value::Bytes(self.log_merkle_root.to_vec()),
            ),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Compute the batch_hash = keccak256(canonical CBOR encoding).
    pub fn batch_hash(&self) -> Result<[u8; 32], ProtocolError> {
        Ok(keccak256(&self.to_cbor()?))
    }

    /// Compute the overflow_data_hash from full untruncated arrays.
    ///
    /// Call this before truncating to MAX_BATCH_ENTRIES when overflow occurs.
    pub fn compute_overflow_hash(
        bids: &[TypedBid],
        selections: &[TaskSelection],
        feedback: &[FeedbackEvent],
    ) -> [u8; 32] {
        // Serialize all arrays canonically and hash concatenation.
        let mut buf = Vec::new();

        let bids_val = encode_typed_bids(bids);
        let sel_val = encode_task_selections(selections);
        let fb_val = encode_feedback_events(feedback);

        for v in [bids_val, sel_val, fb_val] {
            // Writing to Vec<u8> is infallible.
            ciborium::into_writer(&v, &mut buf)
                .unwrap_or_else(|_| unreachable!("CBOR encode to Vec<u8> is infallible"));
        }

        keccak256(&buf)
    }

    /// Truncate all arrays to MAX_BATCH_ENTRIES and set overflow fields.
    ///
    /// Call this on the fully-populated batch before finalizing.
    pub fn apply_overflow_cap(&mut self) {
        let overflows = self.bid_values.len() > MAX_BATCH_ENTRIES
            || self.task_selections.len() > MAX_BATCH_ENTRIES
            || self.feedback_events.len() > MAX_BATCH_ENTRIES;

        if overflows {
            self.overflow_data_hash = Self::compute_overflow_hash(
                &self.bid_values,
                &self.task_selections,
                &self.feedback_events,
            );
            self.overflow = true;

            self.bid_values.truncate(MAX_BATCH_ENTRIES);
            self.task_selections.truncate(MAX_BATCH_ENTRIES);
            self.feedback_events.truncate(MAX_BATCH_ENTRIES);
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers for economic array types
// ---------------------------------------------------------------------------

fn sv(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn encode_typed_bids(bids: &[TypedBid]) -> Value {
    Value::Array(
        bids.iter()
            .map(|b| {
                Value::Array(vec![
                    Value::Bytes(b.conversation_id.to_vec()),
                    Value::Bytes(b.counterparty.to_vec()),
                    Value::Integer(
                        ciborium::value::Integer::try_from(b.bid_value).unwrap_or(0.into()),
                    ),
                    Value::Integer(b.slot.into()),
                ])
            })
            .collect(),
    )
}

fn encode_task_selections(sel: &[TaskSelection]) -> Value {
    Value::Array(
        sel.iter()
            .map(|s| {
                Value::Array(vec![
                    Value::Bytes(s.conversation_id.to_vec()),
                    Value::Bytes(s.counterparty.to_vec()),
                    Value::Integer(s.slot.into()),
                ])
            })
            .collect(),
    )
}

fn encode_feedback_events(events: &[FeedbackEvent]) -> Value {
    Value::Array(
        events
            .iter()
            .map(|e| {
                Value::Array(vec![
                    Value::Bytes(e.conversation_id.to_vec()),
                    Value::Bytes(e.from_agent.to_vec()),
                    Value::Integer((e.score as i64).into()),
                    Value::Integer(e.outcome.into()),
                    Value::Integer(e.slot.into()),
                ])
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_batch() -> BehaviorBatch {
        BehaviorBatch {
            agent_id: [1u8; 32],
            epoch_number: 0,
            slot_start: 1_000,
            slot_end: 1_200,
            message_count: 5,
            msg_type_counts: [0u32; 16],
            unique_counterparties: 2,
            tasks_completed: 1,
            disputes: 0,
            bid_values: vec![TypedBid {
                conversation_id: [2u8; 16],
                counterparty: [3u8; 32],
                bid_value: 1_000_000 * 10i128.pow(18),
                slot: 1_050,
            }],
            task_selections: vec![],
            feedback_events: vec![FeedbackEvent {
                conversation_id: [2u8; 16],
                from_agent: [3u8; 32],
                score: 80,
                outcome: 2,
                slot: 1_100,
            }],
            overflow: false,
            overflow_data_hash: [0u8; 32],
            log_merkle_root: [0u8; 32],
        }
    }

    #[test]
    fn batch_cbor_encodes() {
        let batch = dummy_batch();
        let cbor = batch.to_cbor().unwrap();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn batch_hash_is_deterministic() {
        let batch = dummy_batch();
        let h1 = batch.batch_hash().unwrap();
        let h2 = batch.batch_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn overflow_cap_truncates_and_sets_flag() {
        let mut batch = dummy_batch();
        // Push MAX_BATCH_ENTRIES + 1 bids.
        batch.bid_values = (0u64..=(MAX_BATCH_ENTRIES as u64))
            .map(|slot| TypedBid {
                conversation_id: [0u8; 16],
                counterparty: [0u8; 32],
                bid_value: 0,
                slot,
            })
            .collect();

        assert!(!batch.overflow);
        batch.apply_overflow_cap();
        assert!(batch.overflow);
        assert_eq!(batch.bid_values.len(), MAX_BATCH_ENTRIES);
        assert_ne!(batch.overflow_data_hash, [0u8; 32]);
    }

    #[test]
    fn no_overflow_cap_leaves_flag_false() {
        let mut batch = dummy_batch();
        batch.apply_overflow_cap();
        assert!(!batch.overflow);
        assert_eq!(batch.overflow_data_hash, [0u8; 32]);
    }
}
