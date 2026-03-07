//! Inactivity enforcement (doc 5, §10.5 — liveness requirement).
//!
//! Periodically scans known agents and submits `slash_inactive` transactions
//! to the StakeLock program for any agent whose last BehaviorBatch submission
//! is more than INACTIVITY_GRACE_EPOCHS epochs behind the current 0x01 epoch.
//!
//! The caller (this node) receives a 50% slash bounty deposited into its own
//! USDC ATA. Transactions are submitted via Kora (gasless) if configured,
//! otherwise directly (requires SOL for gas).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};

use crate::{api::{ApiState, PortfolioEvent}, identity::AgentIdentity, kora::KoraClient, lease::get_ata};

// ============================================================================
// Constants — must match stake-lock program
// ============================================================================

const STAKE_LOCK_PROGRAM_ID_STR: &str = "Dvf1qPzzvW1BkSUogRMaAvxZpXrmeTqYutTCBKpzHB1A";
const BEHAVIOR_LOG_PROGRAM_ID_STR: &str = "35DAMPQVu6wsmMEGv67URFAGgyauEYD73egd74uiX1sM";

/// SPL Token program.
const SPL_TOKEN_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Associated Token Account program.
const SPL_ATA_PROGRAM_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1brs";

// AgentBatchRegistry raw layout (under BehaviorLog).
// 8 (disc) + 1 (version) + 32 (agent_id) + 8 (next_epoch) + 1 (bump) = 50 bytes
const REGISTRY_NEXT_EPOCH_OFFSET: usize = 41;
const REGISTRY_MIN_LEN: usize = 50;

// StakeLockAccount: inactive_slashed bool is the last byte at offset 100
// Layout: 8+1+32+32+8+8+1+8+1+1+1 = 101 bytes
const STAKE_INACTIVE_SLASHED_OFFSET: usize = 100;
const STAKE_ACCOUNT_MIN_LEN: usize = 101;

// Protocol constants (must match stake-lock program)
const GENESIS_TIMESTAMP: i64 = 1_750_000_000;
const EPOCH_SECONDS: u64 = 86_400;
const INACTIVITY_GRACE_EPOCHS: u64 = 3;

// ============================================================================
// Public entry point
// ============================================================================

/// Scan `agents` and submit `slash_inactive` for any that are overdue.
///
/// Skips agents that are already slashed or within the grace period.
/// Fire-and-forget per agent — individual failures are logged and skipped.
pub async fn check_and_slash_inactive(
    rpc: &RpcClient,
    identity: &AgentIdentity,
    kora: Option<&KoraClient>,
    usdc_mint: &Pubkey,
    agents: &[[u8; 32]],
    api: &ApiState,
) {
    let unix_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let current_epoch = if unix_ts >= GENESIS_TIMESTAMP {
        ((unix_ts - GENESIS_TIMESTAMP) as u64) / EPOCH_SECONDS
    } else {
        0
    };

    if current_epoch <= INACTIVITY_GRACE_EPOCHS {
        // Too early — no agent can be overdue yet.
        return;
    }

    let stake_lock_program = stake_lock_program_id();
    let behavior_log_program = behavior_log_program_id();

    for agent_id in agents {
        // Derive PDAs.
        let (registry_pda, _) = Pubkey::find_program_address(
            &[b"agent_registry", agent_id.as_ref()],
            &behavior_log_program,
        );
        let (stake_pda, _) =
            Pubkey::find_program_address(&[b"stake", agent_id.as_ref()], &stake_lock_program);
        let (vault_authority_pda, _) =
            Pubkey::find_program_address(&[b"stake_vault", agent_id.as_ref()], &stake_lock_program);

        // Check registry: read next_epoch.
        let next_epoch = match rpc.get_account(&registry_pda).await {
            Ok(acc) if acc.data.len() >= REGISTRY_MIN_LEN => u64::from_le_bytes(
                acc.data[REGISTRY_NEXT_EPOCH_OFFSET..REGISTRY_NEXT_EPOCH_OFFSET + 8]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            ),
            Ok(_) => 0, // account exists but too short or no data — treat as never submitted
            Err(_) => 0, // no registry account — agent never submitted
        };

        if current_epoch <= next_epoch + INACTIVITY_GRACE_EPOCHS {
            continue; // still within grace period
        }

        // Check stake account: must exist and not already slashed.
        let stake_data = match rpc.get_account(&stake_pda).await {
            Ok(acc) => acc.data,
            Err(_) => continue, // not staked — nothing to slash
        };

        if stake_data.len() < STAKE_ACCOUNT_MIN_LEN {
            continue; // unexpected layout — skip
        }
        if stake_data[STAKE_INACTIVE_SLASHED_OFFSET] != 0 {
            continue; // already slashed
        }

        // Bounty goes to this node's USDC ATA.
        let node_pubkey = solana_sdk::pubkey::Pubkey::from(identity.verifying_key.to_bytes());
        let caller_ata = get_ata(&node_pubkey, usdc_mint, &spl_token_program());

        // Derive vault ATA (source of slash funds).
        let vault_ata = get_ata(&vault_authority_pda, usdc_mint, &spl_token_program());

        if let Err(e) = submit_slash_inactive(
            rpc,
            identity,
            kora,
            usdc_mint,
            &node_pubkey,
            &caller_ata,
            &stake_pda,
            &vault_authority_pda,
            &vault_ata,
            &registry_pda,
            &stake_lock_program,
            api,
            agent_id,
        )
        .await
        {
            tracing::warn!(
                agent = %hex::encode(agent_id),
                "slash_inactive failed: {e}",
            );
        } else {
            tracing::info!(
                agent = %hex::encode(agent_id),
                epoch = current_epoch,
                "slash_inactive submitted",
            );
        }
    }
}

// ============================================================================
// Transaction builder
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn submit_slash_inactive(
    rpc: &RpcClient,
    identity: &AgentIdentity,
    kora: Option<&KoraClient>,
    usdc_mint: &Pubkey,
    caller_pubkey: &Pubkey,
    caller_ata: &Pubkey,
    stake_account: &Pubkey,
    vault_authority: &Pubkey,
    vault_ata: &Pubkey,
    agent_registry: &Pubkey,
    stake_lock_program: &Pubkey,
    api: &ApiState,
    slashed_agent: &[u8; 32],
) -> anyhow::Result<()> {
    let ix = build_slash_inactive_ix(
        caller_pubkey,
        caller_ata,
        stake_account,
        vault_authority,
        vault_ata,
        agent_registry,
        usdc_mint,
        stake_lock_program,
    );

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    if let Some(kora) = kora {
        let fee_payer = kora
            .get_fee_payer()
            .await
            .map_err(|e| anyhow::anyhow!("Kora get_fee_payer: {e}"))?;

        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &recent_blockhash);
        let tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        let tx_bytes =
            bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?;
        let tx_b64 = BASE64.encode(&tx_bytes);
        kora.sign_and_send(&tx_b64)
            .await
            .map_err(|e| anyhow::anyhow!("Kora sign_and_send: {e}"))?;
    } else {
        let vk_bytes = identity.verifying_key.to_bytes();
        let solana_kp = {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&identity.signing_key.to_bytes());
            b[32..].copy_from_slice(&vk_bytes);
            Keypair::try_from(b.as_slice())
                .map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&solana_kp.pubkey()),
            &[&solana_kp],
            recent_blockhash,
        );
        rpc.send_and_confirm_transaction(&tx).await
            .map_err(|e| anyhow::anyhow!("send_and_confirm: {e}"))?;
    }

    // Record bounty in portfolio history
    // For StakeLock v1, slash bounty is exactly 50% of MIN_STAKE_USDC = 50 USDC.
    api.record_portfolio_event(PortfolioEvent::Bounty {
        amount_usdc: (crate::stake_lock::MIN_STAKE_USDC as f64 / 2.0) / 1_000_000.0,
        from_agent: hex::encode(slashed_agent),
        conversation_id: "slash_bounty".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }).await;

    Ok(())
}

/// Build the StakeLock `slash_inactive` instruction.
///
/// Accounts (matching the Anchor `SlashInactive` struct):
///   0. caller              (signer, writable)
///   1. caller_usdc         (writable — ATA)
///   2. stake_account       (writable — PDA)
///   3. stake_vault_authority (readonly — PDA)
///   4. stake_vault         (writable — ATA)
///   5. agent_registry      (readonly — BehaviorLog PDA, may be empty)
///   6. usdc_mint           (readonly)
///   7. token_program       (readonly)
///   8. associated_token_program (readonly)
///
/// Instruction data: 8-byte Anchor discriminator, no args.
#[allow(clippy::too_many_arguments)]
fn build_slash_inactive_ix(
    caller: &Pubkey,
    caller_usdc: &Pubkey,
    stake_account: &Pubkey,
    vault_authority: &Pubkey,
    vault_ata: &Pubkey,
    agent_registry: &Pubkey,
    usdc_mint: &Pubkey,
    stake_lock_program: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&anchor_discriminator("slash_inactive"));

    Instruction {
        program_id: *stake_lock_program,
        accounts: vec![
            AccountMeta::new(*caller, true),
            AccountMeta::new(*caller_usdc, false),
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(*vault_authority, false),
            AccountMeta::new(*vault_ata, false),
            AccountMeta::new_readonly(*agent_registry, false),
            AccountMeta::new_readonly(*usdc_mint, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(spl_ata_program(), false),
        ],
        data,
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

fn stake_lock_program_id() -> Pubkey {
    STAKE_LOCK_PROGRAM_ID_STR
        .parse()
        .expect("static program ID")
}

fn behavior_log_program_id() -> Pubkey {
    BEHAVIOR_LOG_PROGRAM_ID_STR
        .parse()
        .expect("static program ID")
}

fn spl_token_program() -> Pubkey {
    SPL_TOKEN_STR.parse().expect("static program ID")
}

fn spl_ata_program() -> Pubkey {
    SPL_ATA_PROGRAM_STR.parse().expect("static program ID")
}
