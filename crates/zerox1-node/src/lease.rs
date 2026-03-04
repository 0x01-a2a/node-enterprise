//! Lease mechanism client (doc 5, §7 / §10.3).
//!
//! Handles:
//!   - Reading the LeaseAccount PDA from Solana
//!   - Building and submitting `pay_lease` instructions (USDC, via Kora or direct)
//!   - Checking peer lease status for the message gate

#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    transaction::Transaction,
};

use crate::{identity::AgentIdentity, kora::KoraClient};
use zerox1_protocol::constants::GRACE_PERIOD_EPOCHS;

// ============================================================================
// Constants
// ============================================================================

use crate::constants;

/// Pay 7 epochs when renewing (one week).
pub const RENEWAL_EPOCHS: u64 = 7;
/// Trigger renewal when fewer than this many paid epochs remain.
pub const RENEWAL_THRESHOLD: u64 = 2;

fn lease_program_id() -> Pubkey {
    constants::lease_program_id()
}

fn treasury_pubkey() -> Pubkey {
    constants::treasury_pubkey()
}

fn usdc_mint() -> Pubkey {
    constants::usdc_mint()
}

fn spl_token_program() -> Pubkey {
    constants::spl_token_program_id()
}

fn associated_token_program() -> Pubkey {
    constants::associated_token_program_id()
}

fn token_2022_program() -> Pubkey {
    constants::token_2022_program_id()
}

/// Derive the Associated Token Address for (wallet, mint).
///
/// ATA derivation: find_program_address(
///   &[wallet, token_program, mint],
///   &associated_token_program
/// )
pub fn get_ata(wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program(),
    )
    .0
}

// ============================================================================
// LeaseAccount deserialization (raw byte offsets — no on-chain dep needed)
//
// LeaseAccount layout (Anchor, all little-endian):
//   [0..8]   8-byte discriminator
//   [8]      version u8
//   [9..41]  agent_id [u8; 32]
//   [41..73] owner Pubkey [u8; 32]
//   [73..81] paid_through_epoch u64
//   [81..89] last_paid_slot u64
//   [89..97] current_epoch u64
//   [97]     in_grace_period bool (1 byte)
//   [98]     deactivated bool (1 byte)
//   [99]     bump u8
//   Total: 100 bytes (8+1+32+32+8+8+8+1+1+1)
// ============================================================================

/// Parsed view of an on-chain LeaseAccount.
#[derive(Debug, Clone)]
pub struct LeaseStatus {
    pub paid_through_epoch: u64,
    pub current_epoch: u64,
    pub in_grace_period: bool,
    pub deactivated: bool,
}

impl LeaseStatus {
    /// True if the lease is still valid (not deactivated, not in grace period).
    pub fn is_active(&self) -> bool {
        if self.deactivated {
            return false;
        }
        // Treat stale active flags conservatively: if epochs are already beyond
        // grace, the lease is effectively inactive even before tick_lease runs.
        self.current_epoch <= self.paid_through_epoch + GRACE_PERIOD_EPOCHS
    }

    /// True if renewal is needed soon (within RENEWAL_THRESHOLD epochs).
    pub fn needs_renewal(&self) -> bool {
        !self.deactivated && self.paid_through_epoch < self.current_epoch + RENEWAL_THRESHOLD
    }
}

/// Fetch and parse the LeaseAccount for `agent_id`.
///
/// Returns:
///   `Ok(Some(status))` — account found and parsed
///   `Ok(None)`         — account does not exist (agent has not called init_lease)
///   `Err(_)`           — RPC failure
pub async fn get_lease_status(
    rpc: &RpcClient,
    agent_id: &[u8; 32],
) -> anyhow::Result<Option<LeaseStatus>> {
    let (pda, _) =
        Pubkey::find_program_address(&[b"lease", agent_id.as_ref()], &lease_program_id());

    // Use get_multiple_accounts so missing accounts return Option::None
    // instead of an error, avoiding fragile string matching on error messages.
    let mut accounts = rpc
        .get_multiple_accounts(&[pda])
        .await
        .map_err(|e| anyhow::anyhow!("RPC error reading lease PDA: {e}"))?;

    match accounts.pop().flatten() {
        None => Ok(None),
        Some(account) => {
            let d = &account.data;
            if d.len() < 100 {
                anyhow::bail!("LeaseAccount data too short: {} bytes", d.len());
            }
            let expected_disc = anchor_account_discriminator("LeaseAccount");
            if d[..8] != expected_disc {
                anyhow::bail!("LeaseAccount discriminator mismatch for {}", pda);
            }
            Ok(Some(LeaseStatus {
                paid_through_epoch: u64::from_le_bytes(d[73..81].try_into().unwrap()),
                current_epoch: u64::from_le_bytes(d[89..97].try_into().unwrap()),
                in_grace_period: d[97] != 0,
                deactivated: d[98] != 0,
            }))
        }
    }
}

// ============================================================================
// init_lease instruction
// ============================================================================

/// Build and submit an `init_lease` transaction.
pub async fn init_lease_onchain(
    rpc: &RpcClient,
    identity: &AgentIdentity,
    kora: Option<&KoraClient>,
) -> anyhow::Result<()> {
    let program_id = lease_program_id();
    let usdc = usdc_mint();
    let agent_pubkey = Pubkey::new_from_array(identity.verifying_key.to_bytes());
    let agent_mint = Pubkey::new_from_array(identity.agent_id);

    let (lease_pda, _) = Pubkey::find_program_address(&[b"lease", &identity.agent_id], &program_id);
    let owner_ata = get_ata(&agent_pubkey, &usdc, &spl_token_program());
    let owner_sati_ata = get_ata(&agent_pubkey, &agent_mint, &token_2022_program());

    let treasury = treasury_pubkey();
    let treasury_ata = get_ata(&treasury, &usdc, &spl_token_program());

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    // Convert ed25519-dalek signing key to a Solana Keypair for partial signing.
    let solana_kp = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&identity.signing_key.to_bytes());
        b[32..].copy_from_slice(&identity.verifying_key.to_bytes());
        Keypair::try_from(b.as_slice()).map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
    };

    if let Some(kora) = kora {
        let fee_payer = kora.get_fee_payer().await?;

        let is_8004 = identity.agent_id == identity.verifying_key.to_bytes();

        let ix = if is_8004 {
            build_init_lease_ix_8004(
                &fee_payer,
                &agent_pubkey,
                &owner_ata,
                &lease_pda,
                &treasury_ata,
                &treasury,
                &usdc,
                &program_id,
                identity.agent_id,
            )
        } else {
            build_init_lease_ix(
                &fee_payer,
                &agent_pubkey,
                &owner_ata,
                &agent_mint,
                &owner_sati_ata,
                &lease_pda,
                &treasury_ata,
                &treasury,
                &usdc,
                &program_id,
                identity.agent_id,
            )
        };

        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &recent_blockhash);
        let mut tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        tx.partial_sign(&[&solana_kp], recent_blockhash);

        let tx_bytes =
            bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?;
        let tx_b64 = BASE64.encode(&tx_bytes);

        kora.sign_and_send(&tx_b64).await?;

        tracing::info!(agent = %hex::encode(identity.agent_id), "Lease initialized via Kora (gasless)");
    } else {
        let is_8004 = identity.agent_id == identity.verifying_key.to_bytes();

        let ix = if is_8004 {
            build_init_lease_ix_8004(
                &agent_pubkey,
                &agent_pubkey,
                &owner_ata,
                &lease_pda,
                &treasury_ata,
                &treasury,
                &usdc,
                &program_id,
                identity.agent_id,
            )
        } else {
            build_init_lease_ix(
                &agent_pubkey,
                &agent_pubkey,
                &owner_ata,
                &agent_mint,
                &owner_sati_ata,
                &lease_pda,
                &treasury_ata,
                &treasury,
                &usdc,
                &program_id,
                identity.agent_id,
            )
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&agent_pubkey),
            &[&solana_kp],
            recent_blockhash,
        );

        let sig = rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| anyhow::anyhow!("init_lease: {e}"))?;

        tracing::info!(tx = %sig, agent = %hex::encode(identity.agent_id), "Lease initialized directly (agent pays gas)");
    }

    Ok(())
}

// ============================================================================
// pay_lease instruction
// ============================================================================

/// Build and submit a `pay_lease` transaction for RENEWAL_EPOCHS.
///
/// Gas path:
///   Kora present  → fee_payer = Kora, owner = agent (partial sign), Kora broadcasts
///   Kora absent   → fee_payer = owner = agent, direct RPC submission (requires SOL)
///
/// Note: Anchor PayLease has no separate `payer` account slot — only `owner` signs
/// the instruction.  Kora pays the SOL transaction fee by being set as the message
/// fee_payer, while the agent's key remains the sole instruction signer.
pub async fn pay_lease_onchain(
    rpc: &RpcClient,
    identity: &AgentIdentity,
    kora: Option<&KoraClient>,
) -> anyhow::Result<()> {
    let program_id = lease_program_id();
    let usdc = usdc_mint();
    let treasury = treasury_pubkey();
    let agent_pubkey = Pubkey::new_from_array(identity.verifying_key.to_bytes());

    let (lease_pda, _) = Pubkey::find_program_address(&[b"lease", &identity.agent_id], &program_id);
    let owner_ata = get_ata(&agent_pubkey, &usdc, &spl_token_program());
    let treasury_ata = get_ata(&treasury, &usdc, &spl_token_program());

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    // Convert ed25519-dalek signing key to a Solana Keypair for partial signing.
    let solana_kp = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&identity.signing_key.to_bytes());
        b[32..].copy_from_slice(&identity.verifying_key.to_bytes());
        Keypair::try_from(b.as_slice()).map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
    };

    let ix = build_pay_lease_ix(
        &agent_pubkey,
        &owner_ata,
        &lease_pda,
        &treasury_ata,
        &treasury,
        &usdc,
        &program_id,
        RENEWAL_EPOCHS,
    );

    if let Some(kora) = kora {
        // ── Kora path ────────────────────────────────────────────────────────
        // Kora is the message fee_payer (pays SOL gas); agent is the sole
        // instruction signer (authorises USDC transfer from their ATA).
        let fee_payer = kora.get_fee_payer().await?;

        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &recent_blockhash);
        let mut tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        tx.partial_sign(&[&solana_kp], recent_blockhash);

        let tx_bytes =
            bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?;
        let tx_b64 = BASE64.encode(&tx_bytes);

        kora.sign_and_send(&tx_b64).await?;

        tracing::info!(
            epochs = RENEWAL_EPOCHS,
            agent  = %hex::encode(identity.agent_id),
            "Lease renewed via Kora (gasless)",
        );
    } else {
        // ── Direct path ──────────────────────────────────────────────────────
        // fee_payer = owner = agent
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&agent_pubkey),
            &[&solana_kp],
            recent_blockhash,
        );

        let sig = rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| anyhow::anyhow!("pay_lease: {e}"))?;

        tracing::info!(
            tx     = %sig,
            epochs = RENEWAL_EPOCHS,
            agent  = %hex::encode(identity.agent_id),
            "Lease renewed directly (agent pays gas)",
        );
    }

    Ok(())
}

// ============================================================================
// Instruction builder
// ============================================================================

/// Compute an Anchor instruction discriminator: sha256("global:<name>")[..8].
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

fn anchor_account_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("account:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn build_init_lease_ix(
    payer: &Pubkey,
    owner: &Pubkey,
    owner_usdc: &Pubkey,
    agent_mint: &Pubkey,
    owner_sati_token: &Pubkey,
    lease_account: &Pubkey,
    treasury_usdc: &Pubkey,
    treasury: &Pubkey,
    usdc_mint: &Pubkey,
    program_id: &Pubkey,
    agent_id: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&anchor_discriminator("init_lease"));
    data.extend_from_slice(&agent_id); // InitLeaseArgs { agent_id }

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*owner, true),
            AccountMeta::new(*owner_usdc, false),
            AccountMeta::new_readonly(*agent_mint, false),
            AccountMeta::new_readonly(*owner_sati_token, false),
            AccountMeta::new(*lease_account, false),
            AccountMeta::new(*treasury_usdc, false),
            AccountMeta::new_readonly(*treasury, false),
            AccountMeta::new_readonly(token_2022_program(), false), // sati_token_program (Token-2022)
            AccountMeta::new_readonly(*usdc_mint, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(associated_token_program(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

/// Build the `init_lease_8004` instruction (SATI-free variant for 8004 agents).
///
/// Identical to `build_init_lease_ix` but omits:
///   - agent_mint (no SATI NFT)
///   - owner_sati_token (no SATI token account)
///   - sati_token_program (Token-2022 not needed)
#[allow(clippy::too_many_arguments)]
fn build_init_lease_ix_8004(
    payer: &Pubkey,
    owner: &Pubkey,
    owner_usdc: &Pubkey,
    lease_account: &Pubkey,
    treasury_usdc: &Pubkey,
    treasury: &Pubkey,
    usdc_mint: &Pubkey,
    program_id: &Pubkey,
    agent_id: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&anchor_discriminator("init_lease_8004"));
    data.extend_from_slice(&agent_id); // InitLeaseArgs { agent_id }

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*owner, true),
            AccountMeta::new(*owner_usdc, false),
            AccountMeta::new(*lease_account, false),
            AccountMeta::new(*treasury_usdc, false),
            AccountMeta::new_readonly(*treasury, false),
            AccountMeta::new_readonly(*usdc_mint, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(associated_token_program(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

/// Build the `pay_lease` instruction.
///
/// Accounts (matching Anchor PayLease struct — 8 accounts):
///   0. owner                    (signer, writable) — agent (USDC authority)
///   1. owner_usdc               (writable) — owner's USDC ATA
///   2. lease_account            (PDA, writable)
///   3. treasury_usdc            (writable) — protocol treasury USDC ATA
///   4. treasury                 (readonly)
///   5. usdc_mint                (readonly)
///   6. token_program            (readonly)
///   7. associated_token_program (readonly)
///
/// Args: discriminator(8) + Borsh(PayLeaseArgs { n_epochs: u64 }) = 16 bytes.
#[allow(clippy::too_many_arguments)]
fn build_pay_lease_ix(
    owner: &Pubkey,
    owner_ata: &Pubkey,
    lease_pda: &Pubkey,
    treasury_usdc: &Pubkey,
    treasury: &Pubkey,
    usdc_mint: &Pubkey,
    program_id: &Pubkey,
    n_epochs: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&anchor_discriminator("pay_lease"));
    data.extend_from_slice(&n_epochs.to_le_bytes()); // PayLeaseArgs { n_epochs }

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(*owner_ata, false),
            AccountMeta::new(*lease_pda, false),
            AccountMeta::new(*treasury_usdc, false),
            AccountMeta::new_readonly(*treasury, false),
            AccountMeta::new_readonly(*usdc_mint, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(associated_token_program(), false),
        ],
        data,
    }
}
