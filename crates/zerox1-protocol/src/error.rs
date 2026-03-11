use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("unknown message type: {0:#04x}")]
    UnknownMsgType(u16),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("nonce replay: received {received}, last seen {last_seen}")]
    NonceReplay { received: u64, last_seen: u64 },

    #[error("timestamp out of tolerance: delta {delta_secs}s exceeds {tolerance_secs}s")]
    TimestampOutOfTolerance {
        delta_secs: u64,
        tolerance_secs: u64,
    },

    #[error("payload hash mismatch")]
    PayloadHashMismatch,

    #[error("payload length mismatch: declared {declared}, actual {actual}")]
    PayloadLengthMismatch { declared: u32, actual: usize },

    #[error("payload parse error for msg_type {msg_type:#04x}: {reason}")]
    PayloadParseError { msg_type: u16, reason: String },

    #[error("envelope too large: {size} bytes exceeds {limit}")]
    EnvelopeTooLarge { size: usize, limit: usize },

    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    #[error("sender not registered")]
    SenderNotRegistered,
}
