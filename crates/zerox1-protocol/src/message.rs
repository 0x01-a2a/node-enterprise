use crate::error::ProtocolError;

/// Message class, derived from the high nibble of the MsgType value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgClass {
    /// Infrastructure: broadcast, presence, reputation (0x0_)
    Infrastructure,
    /// Collaboration: intra-org task coordination (0x1_)
    Collaboration,
    /// Negotiation: inter-org commercial coordination (0x2_)
    Negotiation,
}

/// All 0x01 Enterprise message types.
///
/// The high nibble encodes the message class:
///   0x0_ = infrastructure (broadcast, presence, reputation)
///   0x1_ = collaboration  (intra-org task delegation and status)
///   0x2_ = negotiation    (inter-org commercial coordination)
///
/// This makes the class self-describing from the wire value alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MsgType {
    // ── Infrastructure (0x01–0x0F) ──────────────────────────────────────────

    /// Broadcast: "I exist, here are my capabilities"
    Advertise  = 0x01,
    /// Broadcast: "Who can do X?"
    Discover   = 0x02,
    /// Broadcast: "I'm alive" (heartbeat)
    Beacon     = 0x03,
    /// Pubsub (reputation topic): rating of a counterparty after an interaction
    Feedback   = 0x04,

    // ── Collaboration (0x10–0x1F) ────────────────────────────────────────────
    // Intra-org: agents working together inside a single organisation or team.
    // No payment leg. Sender/receiver share a trust context.

    /// Delegate a task with scope, inputs, and deadline.
    Assign     = 0x10,
    /// Acknowledge receipt and acceptance of an ASSIGN; work will proceed.
    Ack        = 0x11,
    /// Blocking question from assignee before work can start.
    Clarify    = 0x12,
    /// Progress update or completion notice from assignee to assigner.
    Report     = 0x13,
    /// Approve a reported outcome or an escalated decision.
    Approve    = 0x14,
    /// Cancel an in-progress task assignment; no further work expected.
    TaskCancel = 0x15,
    /// Escalate to a human supervisor; includes context and options.
    Escalate   = 0x16,
    /// Synchronise shared task or conversation state between parties.
    Sync       = 0x17,

    // ── Negotiation (0x20–0x2F) ──────────────────────────────────────────────
    // Inter-org: agents from different organisations coordinating commercially.
    // Each step is cryptographically signed; dispute resolution is built in.

    /// Offer a task with proposed terms (scope, fee, deadline).
    Propose    = 0x20,
    /// Counter-offer with revised terms.
    Counter    = 0x21,
    /// Accept terms as stated; work may begin.
    Accept     = 0x22,
    /// Submit completed work product for acceptance.
    Deliver    = 0x23,
    /// Challenge a delivery; opens a resolution process.
    Dispute    = 0x24,
    /// Final refusal of a proposal or delivery.
    Reject     = 0x25,
    /// Withdraw from an accepted deal before delivery.
    DealCancel = 0x26,
}

impl MsgType {
    pub fn from_u16(v: u16) -> Result<Self, ProtocolError> {
        match v {
            0x01 => Ok(Self::Advertise),
            0x02 => Ok(Self::Discover),
            0x03 => Ok(Self::Beacon),
            0x04 => Ok(Self::Feedback),
            0x10 => Ok(Self::Assign),
            0x11 => Ok(Self::Ack),
            0x12 => Ok(Self::Clarify),
            0x13 => Ok(Self::Report),
            0x14 => Ok(Self::Approve),
            0x15 => Ok(Self::TaskCancel),
            0x16 => Ok(Self::Escalate),
            0x17 => Ok(Self::Sync),
            0x20 => Ok(Self::Propose),
            0x21 => Ok(Self::Counter),
            0x22 => Ok(Self::Accept),
            0x23 => Ok(Self::Deliver),
            0x24 => Ok(Self::Dispute),
            0x25 => Ok(Self::Reject),
            0x26 => Ok(Self::DealCancel),
            other => Err(ProtocolError::UnknownMsgType(other)),
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the message class derived from the high nibble.
    pub fn class(self) -> MsgClass {
        match self.as_u16() >> 4 {
            0x0 => MsgClass::Infrastructure,
            0x1 => MsgClass::Collaboration,
            0x2 => MsgClass::Negotiation,
            _ => unreachable!("all variants are within 0x00–0x2F"),
        }
    }

    /// Returns true if this message type is sent via pubsub broadcast.
    pub fn is_broadcast(self) -> bool {
        matches!(self, Self::Advertise | Self::Discover | Self::Beacon)
    }

    /// Returns true if this message type goes to the reputation pubsub topic.
    pub fn is_reputation_pubsub(self) -> bool {
        matches!(self, Self::Feedback)
    }

    /// Returns true if this message type uses direct bilateral streams.
    pub fn is_bilateral(self) -> bool {
        !self.is_broadcast() && !self.is_reputation_pubsub()
    }

    /// Returns true if this message type has a protocol-defined (parseable) payload.
    pub fn has_protocol_payload(self) -> bool {
        matches!(self, Self::Feedback)
    }
}

impl std::fmt::Display for MsgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Advertise  => "ADVERTISE",
            Self::Discover   => "DISCOVER",
            Self::Beacon     => "BEACON",
            Self::Feedback   => "FEEDBACK",
            Self::Assign     => "ASSIGN",
            Self::Ack        => "ACK",
            Self::Clarify    => "CLARIFY",
            Self::Report     => "REPORT",
            Self::Approve    => "APPROVE",
            Self::TaskCancel => "TASK_CANCEL",
            Self::Escalate   => "ESCALATE",
            Self::Sync       => "SYNC",
            Self::Propose    => "PROPOSE",
            Self::Counter    => "COUNTER",
            Self::Accept     => "ACCEPT",
            Self::Deliver    => "DELIVER",
            Self::Dispute    => "DISPUTE",
            Self::Reject     => "REJECT",
            Self::DealCancel => "DEAL_CANCEL",
        };
        write!(f, "{}", name)
    }
}
