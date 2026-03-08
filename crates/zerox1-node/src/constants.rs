#![allow(dead_code)]
//! Shared constants for the 0x01 node.

use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// Mints and Treasury
// ============================================================================

/// USDC mint address.
#[cfg(feature = "devnet")]
pub const USDC_MINT_STR: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

#[cfg(not(feature = "devnet"))]
pub const USDC_MINT_STR: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Protocol treasury.
pub const TREASURY_PUBKEY_STR: &str = "qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX";

pub fn usdc_mint() -> Pubkey {
    Pubkey::from_str(USDC_MINT_STR).unwrap()
}

pub fn treasury_pubkey() -> Pubkey {
    Pubkey::from_str(TREASURY_PUBKEY_STR).unwrap()
}

// ============================================================================
// Program IDs
// ============================================================================

pub const BEHAVIOR_LOG_PROGRAM_ID_STR: &str = "35DAMPQVu6wsmMEGv67URFAGgyauEYD73egd74uiX1sM";
pub const LEASE_PROGRAM_ID_STR: &str = "5P8uXqavnQFGXbHKE3tQDezh41D7ZutHsT2jY6gZ3C3x";
pub const CHALLENGE_PROGRAM_ID_STR: &str = "7FoisCiS1gyUx7osQkCLk4A1zNKGq37yHpVhL2BFgk1Y";
pub const STAKE_LOCK_PROGRAM_ID_STR: &str = "Dvf1qPzzvW1BkSUogRMaAvxZpXrmeTqYutTCBKpzHB1A";
pub const ESCROW_PROGRAM_ID_STR: &str = "Es69yGQ7XnwhHjoj3TRv5oigUsQzCvbRYGXJTFcJrT9F";
pub const AGENT_OWNERSHIP_PROGRAM_ID_STR: &str = "9GYVDTgc345bBa2k7j9a15aJSeKjzC75eyxdL3XCYVS9";

pub const TOKEN_2022_PROGRAM_ID_STR: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const SPL_TOKEN_PROGRAM_ID_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ASSOCIATED_TOKEN_PROGRAM_ID_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";

pub fn behavior_log_program_id() -> Pubkey {
    Pubkey::from_str(BEHAVIOR_LOG_PROGRAM_ID_STR).unwrap()
}
pub fn lease_program_id() -> Pubkey {
    Pubkey::from_str(LEASE_PROGRAM_ID_STR).unwrap()
}
pub fn challenge_program_id() -> Pubkey {
    Pubkey::from_str(CHALLENGE_PROGRAM_ID_STR).unwrap()
}
pub fn stake_lock_program_id() -> Pubkey {
    Pubkey::from_str(STAKE_LOCK_PROGRAM_ID_STR).unwrap()
}
pub fn escrow_program_id() -> Pubkey {
    Pubkey::from_str(ESCROW_PROGRAM_ID_STR).unwrap()
}
pub fn agent_ownership_program_id() -> Pubkey {
    Pubkey::from_str(AGENT_OWNERSHIP_PROGRAM_ID_STR).unwrap()
}
pub fn token_2022_program_id() -> Pubkey {
    Pubkey::from_str(TOKEN_2022_PROGRAM_ID_STR).unwrap()
}
pub fn spl_token_program_id() -> Pubkey {
    Pubkey::from_str(SPL_TOKEN_PROGRAM_ID_STR).unwrap()
}
pub fn associated_token_program_id() -> Pubkey {
    Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).unwrap()
}
