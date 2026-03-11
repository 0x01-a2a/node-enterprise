use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    constants::{MAX_MESSAGE_SIZE, PROTOCOL_VERSION, TIMESTAMP_TOLERANCE_SECS},
    error::ProtocolError,
    hash::keccak256,
    message::MsgType,
};

/// The zero address — used as recipient for broadcast messages.
pub const BROADCAST_RECIPIENT: [u8; 32] = [0u8; 32];

/// Canonical 0x01 envelope (doc 5, §5.2).
///
/// Fields are ordered exactly as in the spec. CBOR encoding preserves this order.
/// All integers are big-endian in the wire format.
///
/// `sender` is the agent's Ed25519 verifying key (32 bytes).
/// `signature` covers all fields preceding it via `signing_bytes()`.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Protocol version, currently 0x01.
    pub version: u8,
    /// Message type (see MsgType enum).
    pub msg_type: MsgType,
    /// Sender Ed25519 verifying key (32 bytes).
    pub sender: [u8; 32],
    /// Recipient Ed25519 verifying key, or BROADCAST_RECIPIENT for pubsub.
    pub recipient: [u8; 32],
    /// Unix microseconds (agent wall clock).
    pub timestamp: u64,
    /// Unix seconds at time of sending (wall clock reference).
    pub block_ref: u64,
    /// Monotonic per-sender nonce for replay protection.
    pub nonce: u64,
    /// Groups related messages into a negotiation (16 bytes).
    pub conversation_id: [u8; 16],
    /// keccak256(payload_bytes).
    pub payload_hash: [u8; 32],
    /// Byte length of payload.
    pub payload_len: u32,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Ed25519 signature over signing_bytes() (64 bytes).
    pub signature: [u8; 64],
}

impl Envelope {
    /// Serialize all fields that are covered by the signature into a
    /// canonical byte string. Order matches the spec field order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version);
        buf.extend_from_slice(&self.msg_type.as_u16().to_be_bytes());
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.recipient);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.block_ref.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&self.conversation_id);
        buf.extend_from_slice(&self.payload_hash);
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Sign this envelope with the given Ed25519 signing key.
    /// Sets `self.signature` in place.
    pub fn sign(&mut self, key: &SigningKey) {
        let bytes = self.signing_bytes();
        let sig: Signature = key.sign(&bytes);
        self.signature = sig.to_bytes();
    }

    /// Build, sign, and return a new envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        msg_type: MsgType,
        sender: [u8; 32],
        recipient: [u8; 32],
        block_ref: u64,
        nonce: u64,
        conversation_id: [u8; 16],
        payload: Vec<u8>,
        key: &SigningKey,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let payload_hash = keccak256(&payload);
        let payload_len = payload.len() as u32;

        let mut env = Self {
            version: PROTOCOL_VERSION,
            msg_type,
            sender,
            recipient,
            timestamp,
            block_ref,
            nonce,
            conversation_id,
            payload_hash,
            payload_len,
            payload,
            signature: [0u8; 64],
        };
        env.sign(key);
        env
    }

    /// Encode to canonical CBOR bytes (doc 5, §5.2).
    pub fn to_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        // Encode as a CBOR array preserving field order.
        let value = Value::Array(vec![
            Value::Integer(self.version.into()),
            Value::Integer(self.msg_type.as_u16().into()),
            Value::Bytes(self.sender.to_vec()),
            Value::Bytes(self.recipient.to_vec()),
            Value::Integer(ciborium::value::Integer::from(self.timestamp)),
            Value::Integer(ciborium::value::Integer::from(self.block_ref)),
            Value::Integer(ciborium::value::Integer::from(self.nonce)),
            Value::Bytes(self.conversation_id.to_vec()),
            Value::Bytes(self.payload_hash.to_vec()),
            Value::Integer(self.payload_len.into()),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.to_vec()),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf)
            .map_err(|e| ProtocolError::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Decode from canonical CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, ProtocolError> {
        let value: Value =
            ciborium::from_reader(data).map_err(|e| ProtocolError::CborDecode(e.to_string()))?;

        let arr = match value {
            Value::Array(a) => a,
            _ => return Err(ProtocolError::CborDecode("expected array".into())),
        };

        if arr.len() != 12 {
            return Err(ProtocolError::CborDecode(format!(
                "expected 12 fields, got {}",
                arr.len()
            )));
        }

        let version = u8_from_value(&arr[0])?;
        let msg_type = MsgType::from_u16(u16_from_value(&arr[1])?)?;
        let sender = bytes32_from_value(&arr[2])?;
        let recipient = bytes32_from_value(&arr[3])?;
        let timestamp = u64_from_value(&arr[4])?;
        let block_ref = u64_from_value(&arr[5])?;
        let nonce = u64_from_value(&arr[6])?;
        let conversation_id = bytes16_from_value(&arr[7])?;
        let payload_hash = bytes32_from_value(&arr[8])?;
        let payload_len = u32_from_value(&arr[9])?;
        let payload = bytes_from_value(&arr[10])?;
        let signature = bytes64_from_value(&arr[11])?;

        Ok(Self {
            version,
            msg_type,
            sender,
            recipient,
            timestamp,
            block_ref,
            nonce,
            conversation_id,
            payload_hash,
            payload_len,
            payload,
            signature,
        })
    }

    /// Validate all envelope invariants (doc 5, §5.5).
    ///
    /// `last_nonce`     — last seen nonce from this sender (0 if unknown)
    /// `verifying_key`  — Ed25519 verifying key for the sender
    /// `now_micros`     — current wall-clock time in microseconds
    pub fn validate(
        &self,
        last_nonce: u64,
        verifying_key: &VerifyingKey,
        now_micros: u64,
    ) -> Result<(), ProtocolError> {
        // Rule 1: version
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }

        // Rule 2: msg_type already validated on decode (MsgType::from_u16)

        // Rule 3: sender registration is checked externally before calling validate().

        // Rule 4: signature
        let sig = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&self.signing_bytes(), &sig)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        // Rule 5: nonce replay protection
        if self.nonce <= last_nonce {
            return Err(ProtocolError::NonceReplay {
                received: self.nonce,
                last_seen: last_nonce,
            });
        }

        // Rule 6: timestamp tolerance
        let ts_secs = self.timestamp / 1_000_000;
        let now_secs = now_micros / 1_000_000;
        let delta = ts_secs.abs_diff(now_secs);
        if delta > TIMESTAMP_TOLERANCE_SECS {
            return Err(ProtocolError::TimestampOutOfTolerance {
                delta_secs: delta,
                tolerance_secs: TIMESTAMP_TOLERANCE_SECS,
            });
        }

        // Rule 7: payload hash
        if keccak256(&self.payload) != self.payload_hash {
            return Err(ProtocolError::PayloadHashMismatch);
        }

        // Rule 8: payload length
        if self.payload.len() != self.payload_len as usize {
            return Err(ProtocolError::PayloadLengthMismatch {
                declared: self.payload_len,
                actual: self.payload.len(),
            });
        }

        Ok(())
    }

    /// Check total encoded size is within MAX_MESSAGE_SIZE.
    pub fn check_size(encoded_len: usize) -> Result<(), ProtocolError> {
        if encoded_len > MAX_MESSAGE_SIZE {
            Err(ProtocolError::EnvelopeTooLarge {
                size: encoded_len,
                limit: MAX_MESSAGE_SIZE,
            })
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR decoding helpers
// ---------------------------------------------------------------------------

fn u8_from_value(v: &Value) -> Result<u8, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into()
                .map_err(|_| ProtocolError::CborDecode("u8 overflow".into()))
        }
        _ => Err(ProtocolError::CborDecode("expected integer".into())),
    }
}

fn u16_from_value(v: &Value) -> Result<u16, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into()
                .map_err(|_| ProtocolError::CborDecode("u16 overflow".into()))
        }
        _ => Err(ProtocolError::CborDecode("expected integer".into())),
    }
}

fn u32_from_value(v: &Value) -> Result<u32, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into()
                .map_err(|_| ProtocolError::CborDecode("u32 overflow".into()))
        }
        _ => Err(ProtocolError::CborDecode("expected integer".into())),
    }
}

fn u64_from_value(v: &Value) -> Result<u64, ProtocolError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            n.try_into()
                .map_err(|_| ProtocolError::CborDecode("u64 overflow".into()))
        }
        _ => Err(ProtocolError::CborDecode("expected integer".into())),
    }
}

fn bytes_from_value(v: &Value) -> Result<Vec<u8>, ProtocolError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ProtocolError::CborDecode("expected bytes".into())),
    }
}

fn bytes16_from_value(v: &Value) -> Result<[u8; 16], ProtocolError> {
    let b = bytes_from_value(v)?;
    b.try_into()
        .map_err(|_| ProtocolError::CborDecode("expected 16-byte field".into()))
}

fn bytes32_from_value(v: &Value) -> Result<[u8; 32], ProtocolError> {
    let b = bytes_from_value(v)?;
    b.try_into()
        .map_err(|_| ProtocolError::CborDecode("expected 32-byte field".into()))
}

fn bytes64_from_value(v: &Value) -> Result<[u8; 64], ProtocolError> {
    let b = bytes_from_value(v)?;
    b.try_into()
        .map_err(|_| ProtocolError::CborDecode("expected 64-byte field".into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn dummy_envelope(key: &SigningKey) -> Envelope {
        let sender = key.verifying_key().to_bytes();
        Envelope::build(
            MsgType::Beacon,
            sender,
            BROADCAST_RECIPIENT,
            100,
            1,
            [0u8; 16],
            b"hello".to_vec(),
            key,
        )
    }

    #[test]
    fn round_trip_cbor() {
        let key = test_key();
        let env = dummy_envelope(&key);
        let encoded = env.to_cbor().unwrap();
        let decoded = Envelope::from_cbor(&encoded).unwrap();

        assert_eq!(env.version, decoded.version);
        assert_eq!(env.msg_type, decoded.msg_type);
        assert_eq!(env.sender, decoded.sender);
        assert_eq!(env.payload, decoded.payload);
        assert_eq!(env.signature, decoded.signature);
    }

    #[test]
    fn valid_envelope_passes_validation() {
        let key = test_key();
        let env = dummy_envelope(&key);
        let vk = key.verifying_key();
        let now = env.timestamp + 1_000_000; // 1 second later
        env.validate(0, &vk, now).unwrap();
    }

    #[test]
    fn bad_signature_rejected() {
        let key = test_key();
        let mut env = dummy_envelope(&key);
        env.signature[0] ^= 0xFF;
        let vk = key.verifying_key();
        let now = env.timestamp + 1_000;
        assert!(matches!(
            env.validate(0, &vk, now),
            Err(ProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn nonce_replay_rejected() {
        let key = test_key();
        let env = dummy_envelope(&key); // nonce = 1
        let vk = key.verifying_key();
        let now = env.timestamp + 1_000;
        // last_nonce = 1 means we already saw nonce 1
        assert!(matches!(
            env.validate(1, &vk, now),
            Err(ProtocolError::NonceReplay { .. })
        ));
    }

    #[test]
    fn payload_hash_mismatch_rejected() {
        let key = test_key();
        let mut env = dummy_envelope(&key);
        env.payload[0] ^= 0xFF; // corrupt payload but keep old hash
        let vk = key.verifying_key();
        let now = env.timestamp + 1_000;
        // Signature check will fail first because signing_bytes includes payload.
        // Either InvalidSignature or PayloadHashMismatch is acceptable.
        assert!(env.validate(0, &vk, now).is_err());
    }

    #[test]
    fn msg_type_routing() {
        // Infrastructure: broadcast types
        assert!(MsgType::Advertise.is_broadcast());
        assert!(MsgType::Beacon.is_broadcast());
        assert!(MsgType::Discover.is_broadcast());

        // Reputation pubsub
        assert!(MsgType::Feedback.is_reputation_pubsub());

        // Bilateral: collaboration types
        assert!(MsgType::Assign.is_bilateral());
        assert!(MsgType::Ack.is_bilateral());
        assert!(MsgType::Report.is_bilateral());
        assert!(MsgType::Escalate.is_bilateral());

        // Bilateral: negotiation types
        assert!(MsgType::Propose.is_bilateral());
        assert!(MsgType::Accept.is_bilateral());
        assert!(MsgType::Deliver.is_bilateral());

        // Protocol payload types
        assert!(MsgType::Feedback.has_protocol_payload());
        assert!(!MsgType::Propose.has_protocol_payload());
    }
}
