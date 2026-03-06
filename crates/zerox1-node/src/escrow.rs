//! Escrow program client (approve_payment).
//!
//! Called automatically when this node sends a VERDICT with approve type (0x00).
//! Payload convention: [verdict_type(1)][requester(32)][provider(32)]
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

use crate::{kora::KoraClient, lease::get_ata};

// ============================================================================
// Constants
// ============================================================================

use crate::constants;

fn escrow_program_id() -> Pubkey {
    constants::escrow_program_id()
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

fn treasury() -> Pubkey {
    constants::treasury_pubkey()
}

// ============================================================================
// PDA helpers
// ============================================================================

fn escrow_pda(requester: &Pubkey, provider: &Pubkey, conversation_id: &[u8; 16]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"escrow",
            requester.as_ref(),
            provider.as_ref(),
            conversation_id.as_ref(),
        ],
        &escrow_program_id(),
    )
}

fn vault_authority_pda(escrow_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"escrow_vault", escrow_key.as_ref()],
        &escrow_program_id(),
    )
}

// ============================================================================
// Instruction discriminator
// ============================================================================

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{name}");
    let hash = Sha256::digest(preimage.as_bytes());
    hash[..8].try_into().unwrap()
}

// ============================================================================
// Public entry point
// ============================================================================

/// Call escrow `lock_payment` to initiate a payment to a provider.
#[allow(clippy::too_many_arguments)]
pub async fn lock_payment_onchain(
    rpc: &RpcClient,
    sk_bytes: [u8; 32],
    vk_bytes: [u8; 32],
    provider_bytes: [u8; 32],
    conversation_id: [u8; 16],
    amount: u64,
    notary_fee: u64,
    notary_pubkey: Option<Pubkey>,
    timeout_slots: u64,
    kora: Option<&KoraClient>,
) -> anyhow::Result<()> {
    let usdc = usdc_mint();
    let requester_pubkey = Pubkey::new_from_array(vk_bytes);
    let provider_pubkey = Pubkey::new_from_array(provider_bytes);

    let (escrow_key, _) = escrow_pda(&requester_pubkey, &provider_pubkey, &conversation_id);
    let (vault_auth, _) = vault_authority_pda(&escrow_key);
    let vault_ata = get_ata(&vault_auth, &usdc, &spl_token_program());
    let requester_ata = get_ata(&requester_pubkey, &usdc, &spl_token_program());

    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(&sk_bytes);
    kp_bytes[32..].copy_from_slice(&vk_bytes);
    let kp = Keypair::try_from(kp_bytes.as_slice()).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;

    let blockhash = rpc.get_latest_blockhash().await?;

    if let Some(kora) = kora {
        let fee_payer = kora.get_fee_payer().await?;
        let ix = build_lock_payment_ix(
            &requester_pubkey,
            &provider_pubkey,
            &escrow_key,
            &vault_auth,
            &vault_ata,
            &requester_ata,
            &usdc,
            conversation_id,
            amount,
            notary_fee,
            notary_pubkey,
            timeout_slots,
        );
        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &blockhash);
        let mut tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        tx.partial_sign(&[&kp], blockhash);
        let tx_b64 = BASE64.encode(
            &bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?,
        );
        kora.sign_and_send(&tx_b64).await?;
        tracing::info!(
            "Escrow lock_payment via Kora (gasless): provider={}, amount={}",
            hex::encode(provider_bytes),
            amount
        );
    } else {
        let ix = build_lock_payment_ix(
            &requester_pubkey,
            &provider_pubkey,
            &escrow_key,
            &vault_auth,
            &vault_ata,
            &requester_ata,
            &usdc,
            conversation_id,
            amount,
            notary_fee,
            notary_pubkey,
            timeout_slots,
        );
        let msg = Message::new_with_blockhash(&[ix], Some(&requester_pubkey), &blockhash);
        let mut tx = Transaction::new_unsigned(msg);
        tx.sign(&[&kp], blockhash);
        let sig = rpc.send_and_confirm_transaction(&tx).await?;
        tracing::info!(
            "Escrow lock_payment confirmed: {} (provider={}, amount={})",
            sig,
            hex::encode(provider_bytes),
            amount
        );
    }
    Ok(())
}

/// Call escrow `approve_payment` on behalf of the notary/requester.
/// `notary_bytes` — agent_id of the notary (needed to derive their USDC ATA for the fee).
///   Pass the same bytes as `vk_bytes` (self) when the requester is approving and no
///   separate notary was designated.
pub async fn approve_payment_onchain(
    rpc: &RpcClient,
    sk_bytes: [u8; 32],
    vk_bytes: [u8; 32],
    requester_bytes: [u8; 32],
    provider_bytes: [u8; 32],
    conversation_id: [u8; 16],
    notary_bytes: [u8; 32],
    kora: Option<&KoraClient>,
) -> anyhow::Result<()> {
    let usdc = usdc_mint();
    let treasury_key = treasury();

    let approver_pubkey = Pubkey::new_from_array(vk_bytes);
    let requester_pubkey = Pubkey::new_from_array(requester_bytes);
    let provider_pubkey = Pubkey::new_from_array(provider_bytes);
    let notary_pubkey = Pubkey::new_from_array(notary_bytes);

    let (escrow_key, _) = escrow_pda(&requester_pubkey, &provider_pubkey, &conversation_id);
    let (vault_auth, _) = vault_authority_pda(&escrow_key);
    let vault_ata = get_ata(&vault_auth, &usdc, &spl_token_program());
    let provider_ata = get_ata(&provider_pubkey, &usdc, &spl_token_program());
    let treasury_ata = get_ata(&treasury_key, &usdc, &spl_token_program());
    let notary_ata = get_ata(&notary_pubkey, &usdc, &spl_token_program());

    let ix = build_approve_payment_ix(ApprovePaymentAccounts {
        approver: &approver_pubkey,
        escrow_key: &escrow_key,
        requester_key: &requester_pubkey,
        vault_auth: &vault_auth,
        vault_ata: &vault_ata,
        provider_ata: &provider_ata,
        treasury_ata: &treasury_ata,
        treasury_key: &treasury_key,
        notary_ata: &notary_ata,
        usdc: &usdc,
    });

    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(&sk_bytes);
    kp_bytes[32..].copy_from_slice(&vk_bytes);
    let kp = Keypair::try_from(kp_bytes.as_slice()).map_err(|e| anyhow::anyhow!("keypair: {e}"))?;

    let blockhash = rpc.get_latest_blockhash().await?;

    if let Some(kora) = kora {
        let fee_payer = kora.get_fee_payer().await?;
        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &blockhash);
        let mut tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        tx.partial_sign(&[&kp], blockhash);
        let tx_b64 = BASE64.encode(
            &bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?,
        );
        kora.sign_and_send(&tx_b64).await?;
        tracing::info!(
            "Escrow approve_payment via Kora (gasless): requester={}, provider={}",
            hex::encode(requester_bytes),
            hex::encode(provider_bytes),
        );
    } else {
        let msg = Message::new_with_blockhash(&[ix], Some(&approver_pubkey), &blockhash);
        let mut tx = Transaction::new_unsigned(msg);
        tx.sign(&[&kp], blockhash);
        let sig = rpc.send_and_confirm_transaction(&tx).await?;
        tracing::info!(
            "Escrow approve_payment confirmed: {} (requester={}, provider={})",
            sig,
            hex::encode(requester_bytes),
            hex::encode(provider_bytes),
        );
    }
    Ok(())
}

// ============================================================================
// Instruction builder
// ============================================================================

pub struct LockPaymentAccounts<'a> {
    pub requester: &'a Pubkey,
    pub provider: &'a Pubkey,
    pub escrow_account: &'a Pubkey,
    pub escrow_vault_authority: &'a Pubkey,
    pub escrow_vault: &'a Pubkey,
    pub requester_usdc: &'a Pubkey,
    pub usdc_mint: &'a Pubkey,
}

pub struct ApprovePaymentAccounts<'a> {
    pub approver: &'a Pubkey,
    pub escrow_key: &'a Pubkey,
    pub requester_key: &'a Pubkey,
    pub vault_auth: &'a Pubkey,
    pub vault_ata: &'a Pubkey,
    pub provider_ata: &'a Pubkey,
    pub treasury_ata: &'a Pubkey,
    pub treasury_key: &'a Pubkey,
    pub notary_ata: &'a Pubkey,
    pub usdc: &'a Pubkey,
}

#[allow(clippy::too_many_arguments)]
fn build_lock_payment_ix(
    requester: &Pubkey,
    provider: &Pubkey,
    escrow_account: &Pubkey,
    vault_auth: &Pubkey,
    vault_ata: &Pubkey,
    requester_ata: &Pubkey,
    usdc: &Pubkey,
    conversation_id: [u8; 16],
    amount: u64,
    notary_fee: u64,
    notary: Option<Pubkey>,
    timeout_slots: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 16 + 8 + 8 + 33 + 8);
    data.extend_from_slice(&anchor_discriminator("lock_payment"));
    data.extend_from_slice(&conversation_id);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&notary_fee.to_le_bytes());
    // Option<Pubkey> Borsh encoding: [1, 32 bytes] or [0]
    match notary {
        Some(pk) => {
            data.push(1);
            data.extend_from_slice(pk.as_ref());
        }
        None => {
            data.push(0);
        }
    }
    data.extend_from_slice(&timeout_slots.to_le_bytes());

    Instruction {
        program_id: escrow_program_id(),
        accounts: vec![
            AccountMeta::new(*requester, true),
            AccountMeta::new_readonly(*provider, false),
            AccountMeta::new(*escrow_account, false),
            AccountMeta::new_readonly(*vault_auth, false),
            AccountMeta::new(*vault_ata, false),
            AccountMeta::new(*requester_ata, false),
            AccountMeta::new_readonly(*usdc, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(associated_token_program(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

fn build_approve_payment_ix(accs: ApprovePaymentAccounts) -> Instruction {
    // Account order must match ApprovePayment<'info> struct field order.
    let accounts = vec![
        AccountMeta::new_readonly(*accs.approver, true), // approver (signer)
        AccountMeta::new(*accs.escrow_key, false),       // escrow_account (writable, close=requester)
        AccountMeta::new(*accs.requester_key, false),    // requester (writable, target for close)
        AccountMeta::new_readonly(*accs.vault_auth, false), // escrow_vault_authority
        AccountMeta::new(*accs.vault_ata, false),        // escrow_vault (writable)
        AccountMeta::new(*accs.provider_ata, false),     // provider_usdc (writable)
        AccountMeta::new(*accs.treasury_ata, false),     // treasury_usdc (writable)
        AccountMeta::new_readonly(*accs.treasury_key, false), // treasury
        AccountMeta::new(*accs.notary_ata, false), // notary_usdc (writable)
        AccountMeta::new_readonly(*accs.usdc, false), // usdc_mint
        AccountMeta::new_readonly(spl_token_program(), false), // token_program
    ];

    // approve_payment has no instruction arguments — data is discriminator only.
    let data = anchor_discriminator("approve_payment").to_vec();

    Instruction {
        program_id: escrow_program_id(),
        accounts,
        data,
    }
}
