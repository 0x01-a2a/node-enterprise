use std::collections::HashMap;
use zerox1_protocol::constants::{
    DECAY_WINDOW_EPOCHS, REPUTATION_DECAY_DENOMINATOR, REPUTATION_DECAY_NUMERATOR,
};

/// Real-time (gossip) reputation vector (doc 5, §7.1).
///
/// Scores are in fixed-precision units (×1_000). So score 0 = neutral,
/// +100_000 = maximum positive, -100_000 = maximum negative.
/// Used for local decisions and UI display only — not authoritative.
#[derive(Debug, Clone, Default)]
pub struct ReputationVector {
    #[allow(dead_code)]
    pub agent_id: [u8; 32],
    /// Reliability / task completion quality.
    pub reliability_score: i64,
    /// Cooperation / counterparty satisfaction.
    pub cooperation_index: i64,
    pub total_tasks: u32,
    pub total_disputes: u32,
    pub last_active_epoch: u64,
}

/// Gossip-based real-time reputation tracker (doc 5, §7.3).
pub struct ReputationTracker {
    scores: HashMap<[u8; 32], ReputationVector>,
    current_epoch: u64,
}

impl ReputationTracker {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            current_epoch: 0,
        }
    }

    pub fn get(&self, agent_id: &[u8; 32]) -> Option<&ReputationVector> {
        self.scores.get(agent_id)
    }

    #[allow(dead_code)]
    pub fn all(&self) -> impl Iterator<Item = &ReputationVector> {
        self.scores.values()
    }

    /// Apply a FEEDBACK message to the gossip scores.
    pub fn apply_feedback(&mut self, target: [u8; 32], score: i8, _role: u8, epoch: u64) {
        let entry = self
            .scores
            .entry(target)
            .or_insert_with(|| ReputationVector {
                agent_id: target,
                ..Default::default()
            });

        entry.last_active_epoch = entry.last_active_epoch.max(epoch);

        // Running average: new_score = (old × (n-1) + delta) / n
        let delta = score as i64 * 1_000; // fixed-precision ×1000
        let n = (entry.total_tasks + 1) as i64;
        entry.reliability_score = (entry.reliability_score * (n - 1) + delta) / n;
        entry.cooperation_index = (entry.cooperation_index * (n - 1) + delta) / n;
        entry.total_tasks += 1;
    }

    pub fn record_dispute(&mut self, agent_id: [u8; 32]) {
        self.scores
            .entry(agent_id)
            .or_insert_with(|| ReputationVector {
                agent_id,
                ..Default::default()
            })
            .total_disputes += 1;
    }

    pub fn record_activity(&mut self, agent_id: [u8; 32], epoch: u64) {
        let e = self
            .scores
            .entry(agent_id)
            .or_insert_with(|| ReputationVector {
                agent_id,
                ..Default::default()
            });
        if epoch > e.last_active_epoch {
            e.last_active_epoch = epoch;
        }
    }

    /// Advance to a new epoch and apply decay to idle agents (§7.4).
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        let prev = self.current_epoch;
        self.current_epoch = new_epoch;

        for entry in self.scores.values_mut() {
            let idle = new_epoch.saturating_sub(entry.last_active_epoch);
            if idle > DECAY_WINDOW_EPOCHS {
                let decay_steps = (idle - DECAY_WINDOW_EPOCHS).min(new_epoch - prev);
                for _ in 0..decay_steps {
                    entry.reliability_score = entry.reliability_score
                        * REPUTATION_DECAY_NUMERATOR as i64
                        / REPUTATION_DECAY_DENOMINATOR as i64;
                    entry.cooperation_index = entry.cooperation_index
                        * REPUTATION_DECAY_NUMERATOR as i64
                        / REPUTATION_DECAY_DENOMINATOR as i64;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // --- apply_feedback (role 0 = participant) ---

    #[test]
    fn first_feedback_sets_score_to_delta() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(1), 100, 0, 1);
        let v = tracker.get(&agent(1)).unwrap();
        // delta = 100 * 1_000 = 100_000; n=1 → score = (0*0 + 100_000)/1 = 100_000
        assert_eq!(v.reliability_score, 100_000);
        assert_eq!(v.cooperation_index, 100_000);
        assert_eq!(v.total_tasks, 1);
    }

    #[test]
    fn second_feedback_averages_scores() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(1), 100, 0, 1);
        tracker.apply_feedback(agent(1), 0, 0, 2);
        let v = tracker.get(&agent(1)).unwrap();
        // After 2 tasks: avg of 100_000 and 0 = 50_000
        assert_eq!(v.reliability_score, 50_000);
        assert_eq!(v.total_tasks, 2);
    }

    #[test]
    fn negative_feedback_reduces_score() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(2), -100, 0, 1);
        let v = tracker.get(&agent(2)).unwrap();
        assert_eq!(v.reliability_score, -100_000);
    }

    #[test]
    fn mixed_feedback_converges_toward_zero() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(3), 100, 0, 1);
        tracker.apply_feedback(agent(3), -100, 0, 2);
        let v = tracker.get(&agent(3)).unwrap();
        assert_eq!(v.reliability_score, 0);
    }

    // --- record_dispute ---

    #[test]
    fn record_dispute_increments_counter() {
        let mut tracker = ReputationTracker::new();
        tracker.record_dispute(agent(5));
        tracker.record_dispute(agent(5));
        let v = tracker.get(&agent(5)).unwrap();
        assert_eq!(v.total_disputes, 2);
    }

    #[test]
    fn record_dispute_creates_entry_if_absent() {
        let mut tracker = ReputationTracker::new();
        assert!(tracker.get(&agent(6)).is_none());
        tracker.record_dispute(agent(6));
        assert!(tracker.get(&agent(6)).is_some());
    }

    // --- record_activity ---

    #[test]
    fn record_activity_advances_last_active_epoch() {
        let mut tracker = ReputationTracker::new();
        tracker.record_activity(agent(7), 10);
        assert_eq!(tracker.get(&agent(7)).unwrap().last_active_epoch, 10);
        // smaller epoch does not regress
        tracker.record_activity(agent(7), 5);
        assert_eq!(tracker.get(&agent(7)).unwrap().last_active_epoch, 10);
        // larger epoch advances
        tracker.record_activity(agent(7), 20);
        assert_eq!(tracker.get(&agent(7)).unwrap().last_active_epoch, 20);
    }

    // --- advance_epoch (decay) ---

    #[test]
    fn advance_epoch_does_not_decay_active_agents() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(8), 100, 0, 10);
        // current_epoch=0 after first feedback; advance to 10 (same as last_active)
        tracker.advance_epoch(10);
        let v = tracker.get(&agent(8)).unwrap();
        // idle = 10 - 10 = 0 ≤ DECAY_WINDOW_EPOCHS(6) → no decay
        assert_eq!(v.reliability_score, 100_000);
    }

    #[test]
    fn advance_epoch_decays_idle_agents() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(9), 100, 0, 0);
        // DECAY_WINDOW_EPOCHS = 6; advance 8 epochs so idle = 8 > 6 → 2 decay steps
        tracker.advance_epoch(8);
        let v = tracker.get(&agent(9)).unwrap();
        // expected: 100_000 * (95/100)^2 = 100_000 * 0.9025 = 90_250
        let expected = 100_000i64 * 95 / 100 * 95 / 100;
        assert_eq!(v.reliability_score, expected);
    }

    #[test]
    fn advance_epoch_decay_reaches_near_zero_after_many_epochs() {
        let mut tracker = ReputationTracker::new();
        tracker.apply_feedback(agent(10), 100, 0, 0);
        // Advance 200 epochs — score should be very small (but may not be exactly 0 due to int division)
        tracker.advance_epoch(200);
        let v = tracker.get(&agent(10)).unwrap();
        assert!(v.reliability_score.abs() < 10, "score should decay near zero");
    }
}
