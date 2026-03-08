use anchor_lang::prelude::*;
use anchor_lang::solana_program;

declare_id!("35DAMPQVu6wsmMEGv67URFAGgyauEYD73egd74uiX1sM");

const ED25519_OFFSETS_START: usize = 2;
const ED25519_OFFSETS_LEN: usize = 14;
const ED25519_THIS_INSTRUCTION: u16 = u16::MAX;
const SIGNED_BATCH_DOMAIN: &[u8] = b"behavior-batch-v1";

// ============================================================================
// BehaviorLog Program (doc 5, §10.2)
//
// Stores per-epoch BehaviorBatch commitments on-chain.
// Full batch data lives off-chain; on-chain commitment anchors challenge/audit.
// ============================================================================

#[program]
pub mod behavior_log {
    use super::*;

    /// Submit a daily BehaviorBatch commitment.
    ///
    /// Verifies the Ed25519 signature over the batch, then stores the
    /// merkle root and batch hash. Anyone can call this — signature
    /// verification against the agent's registered public key is the gate.
    pub fn submit_batch(ctx: Context<SubmitBatch>, args: SubmitBatchArgs) -> Result<()> {
        let batch = &mut ctx.accounts.batch_account;
        let clock = Clock::get()?;

        require!(
            args.epoch_number == ctx.accounts.registry.next_epoch,
            BehaviorLogError::InvalidEpochNumber
        );
        require!(
            args.batch_hash != [0u8; 32],
            BehaviorLogError::EmptyBatchHash
        );

        // Ed25519 signature is pre-verified by the Solana Ed25519 program
        // via instruction introspection. The caller MUST include an Ed25519
        // verify instruction immediately before this one in the same transaction.
        let current_index = solana_program::sysvar::instructions::load_current_index_checked(
            &ctx.accounts.instructions.to_account_info(),
        )?;
        require!(
            current_index > 0,
            BehaviorLogError::MissingSignatureInstruction
        );

        let ed25519_ix = solana_program::sysvar::instructions::load_instruction_at_checked(
            (current_index - 1) as usize,
            &ctx.accounts.instructions.to_account_info(),
        )?;
        require!(
            ed25519_ix.program_id == solana_program::ed25519_program::ID,
            BehaviorLogError::MissingSignatureInstruction
        );

        let parsed_ix = parse_ed25519_ix(&ed25519_ix.data)?;
        let expected_msg = build_signed_batch_message(
            &args.agent_id,
            args.epoch_number,
            &args.log_merkle_root,
            &args.batch_hash,
        );

        require!(
            parsed_ix.pubkey == args.agent_id,
            BehaviorLogError::SignerMismatch
        );
        require!(
            parsed_ix.signature == args.signature,
            BehaviorLogError::SignatureMismatch
        );
        require!(
            parsed_ix.message == expected_msg,
            BehaviorLogError::MessageMismatch
        );

        batch.version = 1;
        batch.agent_id = args.agent_id;
        batch.epoch_number = args.epoch_number;
        batch.log_merkle_root = args.log_merkle_root;
        batch.batch_hash = args.batch_hash;
        batch.submitted_slot = clock.slot;
        batch.bump = ctx.bumps.batch_account;

        // Initialize registry agent_id if this is the first time (init_if_needed).
        let registry = &mut ctx.accounts.registry;
        registry.version = 1;
        registry.agent_id = args.agent_id;
        if registry.bump == 0 {
            registry.bump = ctx.bumps.registry;
        }
        // Advance registry epoch counter
        registry.next_epoch += 1;

        emit!(BatchSubmitted {
            agent_id: args.agent_id,
            epoch_number: args.epoch_number,
            batch_hash: args.batch_hash,
            submitted_slot: clock.slot,
        });

        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(args: SubmitBatchArgs)]
pub struct SubmitBatch<'info> {
    /// Payer / submitter — need not be the agent owner.
    /// Signature is verified against agent public_key via Ed25519 program.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Per-agent, per-epoch batch commitment.
    /// PDA: seeds = ["batch", agent_id, epoch_number.to_le_bytes()]
    #[account(
        init,
        payer = payer,
        space = BatchAccount::SIZE,
        seeds = [
            b"batch",
            args.agent_id.as_ref(),
            &args.epoch_number.to_le_bytes(),
        ],
        bump
    )]
    pub batch_account: Account<'info, BatchAccount>,

    /// Per-agent registry tracking next expected epoch.
    /// PDA: seeds = ["agent_registry", agent_id]
    #[account(
        init_if_needed,
        payer = payer,
        space = AgentBatchRegistry::SIZE,
        seeds = [b"agent_registry", args.agent_id.as_ref()],
        bump
    )]
    pub registry: Account<'info, AgentBatchRegistry>,

    /// Instructions sysvar to verify the Ed25519 signature instruction.
    /// CHECK: Instructions sysvar checked by address.
    #[account(address = solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// State
// ============================================================================

/// On-chain commitment for a single agent epoch batch.
/// PDA: seeds = ["batch", agent_id, epoch_number.to_le_bytes()]
#[account]
pub struct BatchAccount {
    /// Struct version for migration safety.
    pub version: u8,
    /// Agent ID = SATI mint address (32 bytes).
    pub agent_id: [u8; 32],
    /// Zero-based 0x01 epoch counter.
    pub epoch_number: u64,
    /// Merkle root of the full epoch envelope log.
    pub log_merkle_root: [u8; 32],
    /// keccak256(canonical CBOR encoding of full BehaviorBatch).
    pub batch_hash: [u8; 32],
    /// Solana slot at submission time.
    pub submitted_slot: u64,
    /// PDA bump.
    pub bump: u8,
}

impl BatchAccount {
    /// 8 (discriminator) + 1 + 32 + 8 + 32 + 32 + 8 + 1 = 122 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 8 + 32 + 32 + 8 + 1;
}

/// Tracks the next expected epoch number per agent.
/// Prevents epoch skipping and duplicate submissions.
/// PDA: seeds = ["agent_registry", agent_id]
#[account]
pub struct AgentBatchRegistry {
    pub version: u8,
    pub agent_id: [u8; 32],
    pub next_epoch: u64,
    pub bump: u8,
}

impl AgentBatchRegistry {
    /// 8 + 1 + 32 + 8 + 1 = 50 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 8 + 1;
}

// ============================================================================
// Instruction arguments
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitBatchArgs {
    pub agent_id: [u8; 32],
    pub epoch_number: u64,
    pub log_merkle_root: [u8; 32],
    pub batch_hash: [u8; 32],
    /// Ed25519 signature over the domain-separated batch commitment:
    /// "behavior-batch-v1" || agent_id || epoch_number || log_merkle_root || batch_hash.
    /// Must be verified by the Solana Ed25519 program in the same tx.
    pub signature: [u8; 64],
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct BatchSubmitted {
    pub agent_id: [u8; 32],
    pub epoch_number: u64,
    pub batch_hash: [u8; 32],
    pub submitted_slot: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum BehaviorLogError {
    #[msg("Epoch number must be sequential — submit epochs in order")]
    InvalidEpochNumber,
    #[msg("Batch hash must not be zero")]
    EmptyBatchHash,
    #[msg("Missing preceding Ed25519 signature verification instruction")]
    MissingSignatureInstruction,
    #[msg("Invalid Ed25519 signature instruction data format")]
    InvalidSignatureInstruction,
    #[msg("Ed25519 signer pubkey does not match agent_id")]
    SignerMismatch,
    #[msg("Ed25519 signature bytes do not match the submitted signature")]
    SignatureMismatch,
    #[msg("Ed25519 signed message does not match the expected batch commitment")]
    MessageMismatch,
}

struct ParsedEd25519Ix {
    pub signature: [u8; 64],
    pub pubkey: [u8; 32],
    pub message: Vec<u8>,
}

fn build_signed_batch_message(
    agent_id: &[u8; 32],
    epoch_number: u64,
    log_merkle_root: &[u8; 32],
    batch_hash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNED_BATCH_DOMAIN.len() + 32 + 8 + 32 + 32);
    msg.extend_from_slice(SIGNED_BATCH_DOMAIN);
    msg.extend_from_slice(agent_id);
    msg.extend_from_slice(&epoch_number.to_le_bytes());
    msg.extend_from_slice(log_merkle_root);
    msg.extend_from_slice(batch_hash);
    msg
}

fn parse_ed25519_ix(data: &[u8]) -> Result<ParsedEd25519Ix> {
    require!(
        data.len() >= ED25519_OFFSETS_START + ED25519_OFFSETS_LEN,
        BehaviorLogError::InvalidSignatureInstruction
    );
    require!(data[0] == 1, BehaviorLogError::InvalidSignatureInstruction);

    let signature_offset = u16::from_le_bytes([data[2], data[3]]) as usize;
    let signature_instruction_index = u16::from_le_bytes([data[4], data[5]]);
    let pubkey_offset = u16::from_le_bytes([data[6], data[7]]) as usize;
    let pubkey_instruction_index = u16::from_le_bytes([data[8], data[9]]);
    let msg_offset = u16::from_le_bytes([data[10], data[11]]) as usize;
    let msg_size = u16::from_le_bytes([data[12], data[13]]) as usize;
    let msg_instruction_index = u16::from_le_bytes([data[14], data[15]]);

    require!(
        signature_instruction_index == ED25519_THIS_INSTRUCTION
            && pubkey_instruction_index == ED25519_THIS_INSTRUCTION
            && msg_instruction_index == ED25519_THIS_INSTRUCTION,
        BehaviorLogError::InvalidSignatureInstruction
    );
    require!(
        signature_offset + 64 <= data.len()
            && pubkey_offset + 32 <= data.len()
            && msg_offset + msg_size <= data.len(),
        BehaviorLogError::InvalidSignatureInstruction
    );

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[signature_offset..signature_offset + 64]);

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[pubkey_offset..pubkey_offset + 32]);

    Ok(ParsedEd25519Ix {
        signature,
        pubkey,
        message: data[msg_offset..msg_offset + msg_size].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_batch_message_binds_all_commitment_fields() {
        let msg_a = build_signed_batch_message(&[1u8; 32], 7, &[2u8; 32], &[3u8; 32]);
        let msg_b = build_signed_batch_message(&[1u8; 32], 8, &[2u8; 32], &[3u8; 32]);
        let msg_c = build_signed_batch_message(&[1u8; 32], 7, &[9u8; 32], &[3u8; 32]);

        assert_ne!(msg_a, msg_b);
        assert_ne!(msg_a, msg_c);
    }

    #[test]
    fn parse_ed25519_ix_rejects_cross_instruction_offsets() {
        let mut data = vec![0u8; 16 + 64 + 32 + 4];
        data[0] = 1;
        data[2..4].copy_from_slice(&(16u16).to_le_bytes());
        data[4..6].copy_from_slice(&0u16.to_le_bytes());
        data[6..8].copy_from_slice(&(80u16).to_le_bytes());
        data[8..10].copy_from_slice(&ED25519_THIS_INSTRUCTION.to_le_bytes());
        data[10..12].copy_from_slice(&(112u16).to_le_bytes());
        data[12..14].copy_from_slice(&(4u16).to_le_bytes());
        data[14..16].copy_from_slice(&ED25519_THIS_INSTRUCTION.to_le_bytes());

        assert!(parse_ed25519_ix(&data).is_err());
    }
}
