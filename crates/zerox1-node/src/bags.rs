//! Bags fee-sharing + token launch integration (feature = "bags").
//!
//! Routes a configurable cut of swap output and escrow settlements to the
//! Bags distribution contract, and enables AI agents to launch tokens on
//! Bags.fm through a simple REST API.

use std::sync::Arc;

use anyhow::anyhow;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

use crate::api::{
    derive_ata, to_solana_keypair, SPL_TOKEN_PROGRAM_ID, USDC_MINT_DEVNET, USDC_MINT_MAINNET,
};
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
            anyhow::bail!("--bags-api-url must use HTTPS, got '{api_url}'");
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
        USDC_MINT_MAINNET
            .parse()
            .expect("valid USDC_MINT_MAINNET constant")
    } else {
        USDC_MINT_DEVNET
            .parse()
            .expect("valid USDC_MINT_DEVNET constant")
    };

    let signer_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    let source_ata = derive_ata(&signer_pubkey, &usdc_mint);
    let dest_ata = derive_ata(&config.distribution_wallet, &usdc_mint);

    // Build SPL Token Transfer instruction (discriminant 3).
    let spl_token_program: Pubkey = SPL_TOKEN_PROGRAM_ID
        .parse()
        .expect("valid SPL_TOKEN_PROGRAM_ID constant");
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

// ============================================================================
// BagsLaunchClient — token launch via bags.fm public API
// ============================================================================

const BAGS_API_BASE: &str = "https://public-api-v2.bags.fm/api/v1";

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateTokenInfoResponse {
    #[serde(rename = "tokenMint")]
    token_mint: String,
    #[serde(rename = "tokenMetadata")]
    token_metadata: String,
}

#[derive(Deserialize)]
struct FeeShareConfigResponse {
    transactions: Vec<String>,
    #[serde(rename = "configKey")]
    config_key: String,
}

#[derive(Deserialize)]
struct LaunchTxResponse {
    /// Base58-encoded partially-signed transaction (pre-signed by Bags mint keypair).
    transaction: String,
}

/// A claimable fee transaction returned by the Bags API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTx {
    /// Base64-encoded transaction bytes.
    pub tx: String,
    pub blockhash: String,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// HTTP client for the Bags.fm public token-launch API.
///
/// All endpoints require an `x-api-key` header (1 000 req/hr rate limit).
pub struct BagsLaunchClient {
    api_url: String,
    api_key: String,
    client: reqwest::Client,
}

impl BagsLaunchClient {
    pub fn new(api_key: String, client: reqwest::Client) -> Self {
        Self {
            api_url: BAGS_API_BASE.to_string(),
            api_key,
            client,
        }
    }

    async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<reqwest::Response> {
        let resp = self
            .client
            .post(format!("{}/{}", self.api_url, path))
            .header("x-api-key", &self.api_key)
            .json(body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| anyhow!("Bags API POST /{path} failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Bags API POST /{path} returned {status}: {text}"));
        }
        Ok(resp)
    }

    /// Step 1 — Create IPFS token metadata and derive the mint address.
    ///
    /// Returns `(token_mint_b58, ipfs_uri)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_token_info(
        &self,
        name: &str,
        symbol: &str,
        description: &str,
        image_url: Option<&str>,
        website_url: Option<&str>,
        twitter_url: Option<&str>,
        telegram_url: Option<&str>,
    ) -> anyhow::Result<(String, String)> {
        let mut body = serde_json::json!({
            "name": name,
            "symbol": symbol,
            "description": description,
        });
        if let Some(u) = image_url {
            body["imageUrl"] = u.into();
        }
        if let Some(u) = website_url {
            body["websiteUrl"] = u.into();
        }
        if let Some(u) = twitter_url {
            body["twitterUrl"] = u.into();
        }
        if let Some(u) = telegram_url {
            body["telegramUrl"] = u.into();
        }

        let r: CreateTokenInfoResponse = self
            .post_json("token-launch/create-token-info", &body)
            .await?
            .json()
            .await
            .map_err(|e| anyhow!("Bags create-token-info parse error: {e}"))?;
        Ok((r.token_mint, r.token_metadata))
    }

    /// Step 2 — Create on-chain fee-share config account.
    ///
    /// `payer` should be the Kora fee-payer pubkey for gasless execution, or
    /// the agent wallet if Kora is unavailable.
    /// `bps` values must sum to 10 000 (100%).
    ///
    /// Returns `(config_key_b58, Vec<base64_tx>)`.
    pub async fn create_fee_share_config(
        &self,
        payer: &str,
        base_mint: &str,
        claimers: &[&str],
        bps: &[u32],
    ) -> anyhow::Result<(String, Vec<String>)> {
        let body = serde_json::json!({
            "payer": payer,
            "baseMint": base_mint,
            "claimersArray": claimers,
            "basisPointsArray": bps,
        });
        let r: FeeShareConfigResponse = self
            .post_json("fee-share/config", &body)
            .await?
            .json()
            .await
            .map_err(|e| anyhow!("Bags fee-share config parse error: {e}"))?;
        Ok((r.config_key, r.transactions))
    }

    /// Step 3 — Build the partially-signed token launch transaction.
    ///
    /// Bags pre-signs with the mint keypair; the caller must add the agent
    /// signature before broadcasting.
    ///
    /// Returns raw transaction bytes (decoded from the base58 response field).
    pub async fn create_launch_transaction(
        &self,
        ipfs_uri: &str,
        token_mint: &str,
        wallet: &str,
        initial_buy_lamports: Option<u64>,
        config_key: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut body = serde_json::json!({
            "ipfs": ipfs_uri,
            "tokenMint": token_mint,
            "wallet": wallet,
            "configKey": config_key,
        });
        if let Some(l) = initial_buy_lamports {
            body["initialBuyLamports"] = l.into();
        }
        let r: LaunchTxResponse = self
            .post_json("token-launch/create-token-launch-transaction", &body)
            .await?
            .json()
            .await
            .map_err(|e| anyhow!("Bags launch-tx parse error: {e}"))?;
        bs58::decode(&r.transaction)
            .into_vec()
            .map_err(|e| anyhow!("Bags launch-tx base58 decode error: {e}"))
    }

    /// Fetch transactions needed to claim accumulated pool-fee revenue.
    pub async fn claim_fee_transactions(
        &self,
        fee_claimer: &str,
        token_mint: &str,
    ) -> anyhow::Result<Vec<ClaimTx>> {
        let body = serde_json::json!({ "feeClaimer": fee_claimer, "tokenMint": token_mint });
        self.post_json("token-launch/claim-txs/v3", &body)
            .await?
            .json()
            .await
            .map_err(|e| anyhow!("Bags claim-txs parse error: {e}"))
    }

    /// List tokens launched by a given wallet.
    pub async fn launched_tokens(&self, wallet: &str) -> anyhow::Result<serde_json::Value> {
        let encoded: String = wallet
            .chars()
            .flat_map(|c| {
                if c.is_alphanumeric() {
                    vec![c]
                } else {
                    format!("%{:02X}", c as u32).chars().collect()
                }
            })
            .collect();
        let resp = self
            .client
            .get(format!(
                "{}/token-launch/launched-tokens?wallet={}",
                self.api_url, encoded
            ))
            .header("x-api-key", &self.api_key)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| anyhow!("Bags GET launched-tokens failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Bags GET launched-tokens returned {status}: {text}"
            ));
        }
        resp.json()
            .await
            .map_err(|e| anyhow!("Bags GET launched-tokens parse error: {e}"))
    }
}
