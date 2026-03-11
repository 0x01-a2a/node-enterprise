use crate::error::ProtocolError;
use ciborium::value::Value;

// ============================================================================
// FEEDBACK payload (doc 5, §7.2)
// ============================================================================

/// Protocol-defined payload for FEEDBACK (0x0B) messages.
///
/// This payload is parsed by all nodes to update reputation state.
#[derive(Debug, Clone)]
pub struct FeedbackPayload {
    /// Which task (= conversation_id used throughout).
    pub conversation_id: [u8; 16],
    /// Agent being rated (Ed25519 verifying key, 32 bytes).
    pub target_agent: [u8; 32],
    /// Score: -100 to +100.
    pub score: i8,
    /// Outcome: 0 = Negative, 1 = Neutral, 2 = Positive.
    pub outcome: u8,
    /// True if this feedback flags a contested outcome.
    pub is_dispute: bool,
}

impl FeedbackPayload {
    pub const OUTCOME_NEGATIVE: u8 = 0;
    pub const OUTCOME_NEUTRAL: u8 = 1;
    pub const OUTCOME_POSITIVE: u8 = 2;

    pub fn encode(&self) -> Vec<u8> {
        // CBOR array encoding for canonical serialization.
        let value = Value::Array(vec![
            Value::Bytes(self.conversation_id.to_vec()),
            Value::Bytes(self.target_agent.to_vec()),
            Value::Integer((self.score as i64).into()),
            Value::Integer(self.outcome.into()),
            Value::Bool(self.is_dispute),
        ]);
        let mut buf = Vec::new();
        // Writing to Vec<u8> is infallible; ciborium encoding of integer/bytes/bool is infallible.
        ciborium::into_writer(&value, &mut buf)
            .unwrap_or_else(|_| unreachable!("CBOR encode to Vec<u8> is infallible"));
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: e.to_string(),
            })?;

        let arr = match value {
            Value::Array(a) if a.len() == 5 => a,
            Value::Array(a) => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x0B,
                    reason: format!("expected 5 fields, got {}", a.len()),
                })
            }
            _ => {
                return Err(ProtocolError::PayloadParseError {
                    msg_type: 0x0B,
                    reason: "expected CBOR array".into(),
                })
            }
        };

        let conversation_id = bytes16_from_value(&arr[0], 0x0B)?;
        let target_agent = bytes32_from_value(&arr[1], 0x0B)?;
        let score = i8_from_value(&arr[2], 0x0B)?;
        let outcome = u8_from_value(&arr[3], 0x0B)?;
        let is_dispute = bool_from_value(&arr[4], 0x0B)?;

        if outcome > 2 {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: format!("invalid outcome value: {outcome}"),
            });
        }
        if !(-100..=100).contains(&score) {
            return Err(ProtocolError::PayloadParseError {
                msg_type: 0x0B,
                reason: format!("score out of range: {score}"),
            });
        }

        Ok(Self {
            conversation_id,
            target_agent,
            score,
            outcome,
            is_dispute,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn u8_from_value(v: &Value, msg_type: u16) -> Result<u8, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into().map_err(|_| ProtocolError::PayloadParseError {
                msg_type,
                reason: "u8 overflow".into(),
            })
        }
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected integer".into(),
        }),
    }
}

fn i8_from_value(v: &Value, msg_type: u16) -> Result<i8, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into().map_err(|_| ProtocolError::PayloadParseError {
                msg_type,
                reason: "i8 overflow".into(),
            })
        }
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected integer".into(),
        }),
    }
}

fn bool_from_value(v: &Value, msg_type: u16) -> Result<bool, ProtocolError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected bool".into(),
        }),
    }
}

fn bytes_from_value(v: &Value, msg_type: u16) -> Result<Vec<u8>, ProtocolError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ProtocolError::PayloadParseError {
            msg_type,
            reason: "expected bytes".into(),
        }),
    }
}

fn bytes16_from_value(v: &Value, msg_type: u16) -> Result<[u8; 16], ProtocolError> {
    let b = bytes_from_value(v, msg_type)?;
    b.try_into().map_err(|_| ProtocolError::PayloadParseError {
        msg_type,
        reason: "expected 16-byte field".into(),
    })
}

fn bytes32_from_value(v: &Value, msg_type: u16) -> Result<[u8; 32], ProtocolError> {
    let b = bytes_from_value(v, msg_type)?;
    b.try_into().map_err(|_| ProtocolError::PayloadParseError {
        msg_type,
        reason: "expected 32-byte field".into(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_payload_round_trip() {
        let p = FeedbackPayload {
            conversation_id: [1u8; 16],
            target_agent: [2u8; 32],
            score: -42,
            outcome: FeedbackPayload::OUTCOME_NEGATIVE,
            is_dispute: true,
        };
        let encoded = p.encode();
        let decoded = FeedbackPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.conversation_id, p.conversation_id);
        assert_eq!(decoded.target_agent, p.target_agent);
        assert_eq!(decoded.score, p.score);
        assert_eq!(decoded.outcome, p.outcome);
        assert_eq!(decoded.is_dispute, p.is_dispute);
    }

    #[test]
    fn feedback_payload_rejects_invalid_score() {
        let p = FeedbackPayload {
            conversation_id: [0u8; 16],
            target_agent: [0u8; 32],
            score: 100, // valid boundary
            outcome: 2,
            is_dispute: false,
        };
        let encoded = p.encode();
        assert!(FeedbackPayload::decode(&encoded).is_ok());

        // Manually craft a payload with score = 101 (out of range)
        let bad = FeedbackPayload {
            score: 101_u8 as i8, // wraps; testing range check
            ..p
        };
        // score=101 is out of i8::MAX=127 but > 100 check:
        // Actually 101i8 is valid i8 but out of protocol range.
        let encoded_bad = bad.encode();
        assert!(FeedbackPayload::decode(&encoded_bad).is_err());
    }
}
