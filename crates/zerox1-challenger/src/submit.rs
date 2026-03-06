use anyhow::Context;
use solana_client::nonblocking::rpc_client::RpcClient;
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

use sha2::Digest;
use zerox1_protocol::hash::keccak256;

// Program IDs
const CHALLENGE_PROGRAM_ID: &str = "7FoisCiS1gyUx7osQkCLk4A1zNKGq37yHpVhL2BFgk1Y";
const BEHAVIOR_LOG_PROGRAM_ID: &str = "35DAMPQVu6wsmMEGv67URFAGgyauEYD73egd74uiX1sM";
#[cfg(feature = "mainnet")]
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // Mainnet USDC
#[cfg(not(feature = "mainnet"))]
const USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"; // Devnet USDC

const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";
const TREASURY_PUBKEY: &str = "qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX";

fn challenge_program_id() -> Pubkey {
    CHALLENGE_PROGRAM_ID.parse().unwrap()
}
fn behavior_log_program_id() -> Pubkey {
    BEHAVIOR_LOG_PROGRAM_ID.parse().unwrap()
}
fn usdc_mint() -> Pubkey {
    USDC_MINT.parse().unwrap()
}
fn spl_token_id() -> Pubkey {
    SPL_TOKEN_PROGRAM_ID.parse().unwrap()
}
fn spl_ata_id() -> Pubkey {
    SPL_ATA_PROGRAM_ID.parse().unwrap()
}
fn treasury() -> Pubkey {
    TREASURY_PUBKEY.parse().unwrap()
}

pub fn get_associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    let (address, _) = Pubkey::find_program_address(
        &[wallet.as_ref(), spl_token_id().as_ref(), mint.as_ref()],
        &spl_ata_id(),
    );
    address
}

/// Compute an Anchor instruction discriminator: sha256("global:<name>")[..8].
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = sha2::Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

/// Generate a Merkle inclusion proof for the leaf at `leaf_index` in `leaves`.
/// Pads `leaves` to the next power of two with zero hashes [0u8; 32].
pub fn generate_merkle_proof(leaf_index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    const MERKLE_INTERNAL_DOMAIN: u8 = 0x01;
    if leaves.is_empty() {
        return vec![];
    }
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, [0u8; 32]);

    let mut proof = Vec::new();
    let mut idx = leaf_index;

    while layer.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        proof.push(layer[sibling_idx]);

        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            let mut combined = [0u8; 65];
            combined[0] = MERKLE_INTERNAL_DOMAIN;
            combined[1..33].copy_from_slice(&chunk[0]);
            combined[33..65].copy_from_slice(&chunk[1]);
            next.push(keccak256(&combined));
        }
        layer = next;
        idx /= 2;
    }
    proof
}

/// Anchor's `submit_challenge` args (Borsh layout)
fn build_submit_challenge_ix(
    payer: &Pubkey,
    challenger: &Pubkey,
    agent_id: &[u8; 32],
    epoch_number: u64,
    leaf_index: u64,
    entry: &[u8],
    merkle_proof: &[[u8; 32]],
) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&anchor_discriminator("submit_challenge"));

    // agent_id [u8; 32]
    data.extend_from_slice(agent_id);
    // epoch_number u64 (LE)
    data.extend_from_slice(&epoch_number.to_le_bytes());
    // contradicting_entry Vec<u8> => (u32 len + bytes)
    data.extend_from_slice(&(entry.len() as u32).to_le_bytes());
    data.extend_from_slice(entry);
    // merkle_proof Vec<[u8; 32]> => (u32 len + 32 * len bytes)
    data.extend_from_slice(&(merkle_proof.len() as u32).to_le_bytes());
    for p in merkle_proof {
        data.extend_from_slice(p);
    }
    // leaf_index u64 (LE)
    data.extend_from_slice(&leaf_index.to_le_bytes());

    let prog_id = challenge_program_id();

    // Derived pdas
    let (batch_pda, _) = Pubkey::find_program_address(
        &[b"batch", agent_id, &epoch_number.to_le_bytes()],
        &behavior_log_program_id(),
    );

    let (challenge_account, _) = Pubkey::find_program_address(
        &[b"challenge", batch_pda.as_ref(), challenger.as_ref()],
        &prog_id,
    );

    let (challenge_vault_authority, _) =
        Pubkey::find_program_address(&[b"challenge_vault", challenge_account.as_ref()], &prog_id);

    let challenge_vault = get_associated_token_address(&challenge_vault_authority, &usdc_mint());
    let challenger_usdc = get_associated_token_address(challenger, &usdc_mint());

    Instruction {
        program_id: prog_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*challenger, true),
            AccountMeta::new(challenger_usdc, false),
            AccountMeta::new(challenge_account, false),
            AccountMeta::new_readonly(challenge_vault_authority, false),
            AccountMeta::new(challenge_vault, false),
            AccountMeta::new_readonly(batch_pda, false),
            AccountMeta::new_readonly(usdc_mint(), false),
            AccountMeta::new_readonly(spl_token_id(), false),
            AccountMeta::new_readonly(spl_ata_id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

pub async fn submit_challenge_onchain(
    rpc: &RpcClient,
    signer: &Keypair,
    agent_id_hex: &str,
    epoch: u64,
    leaf_index: usize,
    entry: &[u8],
    merkle_proof: &[[u8; 32]],
) -> anyhow::Result<()> {
    let agent_id_bytes = hex::decode(agent_id_hex).context("hex decode agent_id")?;
    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&agent_id_bytes);

    let ix = build_submit_challenge_ix(
        &signer.pubkey(),
        &signer.pubkey(),
        &agent_id,
        epoch,
        leaf_index as u64,
        entry,
        merkle_proof,
    );

    let recent_blockhash = rpc.get_latest_blockhash().await?;
    let message = Message::new(&[ix], Some(&signer.pubkey()));
    let tx = Transaction::new(&[signer], message, recent_blockhash);

    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .context("send_and_confirm_transaction challenge")?;

    tracing::info!("Challenge submitted! TX: {}", sig);
    Ok(())
}

/// Build the `resolve_challenge` instruction (Borsh layout).
fn build_resolve_challenge_ix(
    resolver: &Pubkey,
    challenger: &Pubkey,
    agent_id: &[u8; 32],
    epoch: u64,
    entry: &[u8],
    merkle_proof: &[[u8; 32]],
) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&anchor_discriminator("resolve_challenge"));
    // contradicting_entry: Vec<u8>
    data.extend_from_slice(&(entry.len() as u32).to_le_bytes());
    data.extend_from_slice(entry);
    // merkle_proof: Vec<[u8; 32]>
    data.extend_from_slice(&(merkle_proof.len() as u32).to_le_bytes());
    for p in merkle_proof {
        data.extend_from_slice(p);
    }
    // contradicts_batch: bool (true — challenger asserts the entry contradicts the batch)
    data.push(1u8);

    let prog_id = challenge_program_id();

    let (batch_pda, _) = Pubkey::find_program_address(
        &[b"batch", agent_id, &epoch.to_le_bytes()],
        &behavior_log_program_id(),
    );
    let (challenge_account, _) = Pubkey::find_program_address(
        &[b"challenge", batch_pda.as_ref(), challenger.as_ref()],
        &prog_id,
    );
    let (challenge_vault_authority, _) =
        Pubkey::find_program_address(&[b"challenge_vault", challenge_account.as_ref()], &prog_id);

    let challenge_vault = get_associated_token_address(&challenge_vault_authority, &usdc_mint());
    let challenger_usdc = get_associated_token_address(challenger, &usdc_mint());
    let treasury_key = treasury();
    let treasury_usdc = get_associated_token_address(&treasury_key, &usdc_mint());

    Instruction {
        program_id: prog_id,
        accounts: vec![
            AccountMeta::new(*resolver, true),
            AccountMeta::new(challenge_account, false),
            AccountMeta::new_readonly(challenge_vault_authority, false),
            AccountMeta::new(challenge_vault, false),
            AccountMeta::new(challenger_usdc, false),
            AccountMeta::new(treasury_usdc, false),
            AccountMeta::new_readonly(treasury_key, false),
            AccountMeta::new_readonly(batch_pda, false),
            AccountMeta::new_readonly(usdc_mint(), false),
            AccountMeta::new_readonly(spl_token_id(), false),
        ],
        data,
    }
}

pub async fn resolve_challenge_onchain(
    rpc: &RpcClient,
    signer: &Keypair,
    agent_id_hex: &str,
    epoch: u64,
    entry: &[u8],
    merkle_proof: &[[u8; 32]],
) -> anyhow::Result<()> {
    let agent_id_bytes = hex::decode(agent_id_hex).context("hex decode agent_id")?;
    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&agent_id_bytes);

    let ix = build_resolve_challenge_ix(
        &signer.pubkey(),
        &signer.pubkey(),
        &agent_id,
        epoch,
        entry,
        merkle_proof,
    );

    let recent_blockhash = rpc.get_latest_blockhash().await?;
    let message = Message::new(&[ix], Some(&signer.pubkey()));
    let tx = Transaction::new(&[signer], message, recent_blockhash);

    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .context("send_and_confirm_transaction resolve_challenge")?;

    tracing::info!("Challenge resolved! TX: {}", sig);
    Ok(())
}
