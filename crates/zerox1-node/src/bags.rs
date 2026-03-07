//! Bags fee-sharing integration (feature = "bags").
//!
//! Routes a configurable cut of swap output and escrow settlements to the
//! Bags distribution contract, turning every AI agent transaction on the
//! mesh into yield for BAGS holders.

use std::sync::Arc;

use anyhow::anyhow;
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;

use crate::api::{derive_ata, to_solana_keypair, USDC_MINT_DEVNET, USDC_MINT_MAINNET, SPL_TOKEN_PROGRAM_ID};
use crate::registry_8004::{broadcast_transaction, fetch_latest_blockhash};

// ============================================================================
// BagsConfig
// ============================================================================

/// Configuration for Bags fee-sharing.
#[derive(Debug)]
pub struct BagsConfig {
    /// Basis points of each swap output / escrow settlement to route to Bags.
    /// 0 = disabled. Max 500 (5%).
    pub fee_bps: u16,
    /// Resolved distribution wallet that receives fees and distributes to BAGS holders.
    pub distribution_wallet: Pubkey,
    /// Skip fee tx if fee amount (in atomic USDC units) is below this threshold.
    /// Default: 1_000 (= $0.001 USDC).
    pub min_fee_micro: u64,
}

// ============================================================================
// BagsApiClient
// ============================================================================

#[derive(Deserialize)]
struct BagsDistributionResponse {
    address: String,
}

pub struct BagsApiClient {
    api_url: String,
    client: reqwest::Client,
}

impl BagsApiClient {
    pub fn new(api_url: String, client: reqwest::Client) -> anyhow::Result<Self> {
        if !api_url.starts_with("https://") {
            anyhow::bail!(
                "--bags-api-url must use HTTPS, got '{api_url}'"
            );
        }
        Ok(Self { api_url, client })
    }

    /// Resolve the Bags protocol distribution address from the Bags API.
    ///
    /// Returns the wallet that receives fees and distributes them pro-rata to
    /// BAGS token holders.
    pub async fn resolve_distribution_address(&self) -> anyhow::Result<Pubkey> {
        let url = format!("{}/v1/distribution-address", self.api_url);
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| anyhow!("Bags API request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(anyhow!("Bags API returned {}", resp.status()));
        }

        let body: BagsDistributionResponse = resp
            .json()
            .await
            .map_err(|e| anyhow!("Bags API JSON parse error: {e}"))?;

        if body.address.len() > 44 {
            return Err(anyhow!(
                "Bags API returned suspiciously long address ({} chars)",
                body.address.len()
            ));
        }
        body.address
            .parse::<Pubkey>()
            .map_err(|e| anyhow!("Bags API returned invalid pubkey '{}': {e}", body.address))
    }
}

// ============================================================================
// distribute_fee
// ============================================================================

/// Distribute a fee to the Bags distribution wallet via SPL token transfer.
///
/// Fire-and-forget: callers should wrap in `tokio::spawn` so fee distribution
/// never blocks the response path.
///
/// Returns the transaction signature (base58).
pub async fn distribute_fee(
    signing_key: Arc<SigningKey>,
    amount_usdc_micro: u64,
    config: &BagsConfig,
    rpc_url: &str,
    http_client: &reqwest::Client,
    is_mainnet: bool,
) -> anyhow::Result<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let usdc_mint: Pubkey = if is_mainnet {
        USDC_MINT_MAINNET.parse().expect("valid USDC_MINT_MAINNET constant")
    } else {
        USDC_MINT_DEVNET.parse().expect("valid USDC_MINT_DEVNET constant")
    };

    let signer_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    let source_ata = derive_ata(&signer_pubkey, &usdc_mint);
    let dest_ata = derive_ata(&config.distribution_wallet, &usdc_mint);

    // Build SPL Token Transfer instruction (discriminant 3).
    let spl_token_program: Pubkey = SPL_TOKEN_PROGRAM_ID.parse().expect("valid SPL_TOKEN_PROGRAM_ID constant");
    let mut ix_data = vec![3u8];
    ix_data.extend_from_slice(&amount_usdc_micro.to_le_bytes());

    let transfer_ix = solana_sdk::instruction::Instruction {
        program_id: spl_token_program,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(source_ata, false),
            solana_sdk::instruction::AccountMeta::new(dest_ata, false),
            solana_sdk::instruction::AccountMeta::new(signer_pubkey, true),
        ],
        data: ix_data,
    };

    let blockhash = fetch_latest_blockhash(rpc_url, http_client).await?;
    let solana_kp = to_solana_keypair(&signing_key);

    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&signer_pubkey),
        &[&solana_kp],
        blockhash,
    );

    let serialized = bincode::serialize(&tx)?;
    let signed_b64 = B64.encode(&serialized);

    broadcast_transaction(rpc_url, http_client, &signed_b64).await
}
