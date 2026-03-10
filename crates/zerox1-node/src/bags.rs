//! Bags fee-sharing + token launch integration (feature = "bags").
//!
//! Routes a configurable cut of swap output and escrow settlements to the
//! Bags distribution contract, and enables AI agents to launch tokens on
//! Bags.fm through a simple REST API.

// bags implies trade — both are Android-only.
#[cfg(not(target_os = "android"))]
compile_error!(
    "feature \"bags\" may only be enabled for Android targets \
     (target_os = \"android\"). Use `cargo ndk --target aarch64-linux-android`."
);

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
// Protocol fee constants
// ============================================================================

/// 0x01 protocol treasury — receives 1% of SOL income from Bags fee claims.
const ZEROX1_TREASURY: &str = "7RTAnEokPmzycm5q3cwWZV9VXGv6KV3g8LEsfgeyJ7RK";

/// Protocol cut in basis points: 100 bps = 1%.
const PROTOCOL_FEE_BPS: u64 = 100;

/// Minimum fee to bother sending — skip if < 1 000 lamports (< $0.0001).
const MIN_PROTOCOL_FEE_LAMPORTS: u64 = 1_000;

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
    partner_key: Option<String>,
    client: reqwest::Client,
}

impl BagsLaunchClient {
    pub fn new(api_key: String, partner_key: Option<String>, client: reqwest::Client) -> Self {
        Self {
            api_url: BAGS_API_BASE.to_string(),
            api_key,
            partner_key,
            client,
        }
    }

    pub fn partner_mode_enabled(&self) -> bool {
        self.partner_key
            .as_ref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
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
    /// Pass either `image_bytes` (raw PNG/JPG/GIF/WebP, max 15 MB) **or**
    /// `image_url` (HTTPS URL) — Bags rejects requests that supply both.
    /// When bytes are provided the request is sent as `multipart/form-data`;
    /// otherwise a plain JSON body is used.
    ///
    /// Returns `(token_mint_b58, ipfs_uri)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_token_info(
        &self,
        name: &str,
        symbol: &str,
        description: &str,
        image_bytes: Option<Vec<u8>>,
        image_url: Option<&str>,
        website_url: Option<&str>,
        twitter_url: Option<&str>,
        telegram_url: Option<&str>,
    ) -> anyhow::Result<(String, String)> {
        let url = format!("{}/token-launch/create-token-info", self.api_url);

        let resp = if let Some(bytes) = image_bytes {
            // ── multipart/form-data path ───────────────────────────────────
            let image_part = reqwest::multipart::Part::bytes(bytes)
                .file_name("image.png")
                .mime_str("image/png")
                .map_err(|e| anyhow!("invalid mime type: {e}"))?;

            let mut form = reqwest::multipart::Form::new()
                .text("name", name.to_string())
                .text("symbol", symbol.to_string())
                .text("description", description.to_string())
                .part("image", image_part);

            if let Some(u) = website_url {
                form = form.text("website", u.to_string());
            }
            if let Some(u) = twitter_url {
                form = form.text("twitter", u.to_string());
            }
            if let Some(u) = telegram_url {
                form = form.text("telegram", u.to_string());
            }

            self.client
                .post(&url)
                .header("x-api-key", &self.api_key)
                .multipart(form)
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await
                .map_err(|e| anyhow!("Bags API POST create-token-info (multipart) failed: {e}"))?
        } else {
            // ── JSON path (imageUrl or no image) ──────────────────────────
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
            self.post_json("token-launch/create-token-info", &body).await?
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Bags API create-token-info returned {status}: {text}"));
        }

        let r: CreateTokenInfoResponse = resp
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
        if let Some(ref partner_key) = self.partner_key {
            if !partner_key.trim().is_empty() {
                body["partner"] = partner_key.clone().into();
            }
        }
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

// ============================================================================
// Protocol fee collection — 1% of SOL claimed via Bags
// ============================================================================

/// Query an account's confirmed SOL balance in lamports.
pub async fn get_sol_balance(
    rpc_url: &str,
    http_client: &reqwest::Client,
    pubkey: &Pubkey,
) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [pubkey.to_string(), {"commitment": "confirmed"}],
    });
    let resp = http_client
        .post(rpc_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    resp["result"]["value"]
        .as_u64()
        .ok_or_else(|| anyhow!("getBalance: unexpected response shape"))
}

/// Send a native SOL transfer signed by the node identity key.
pub async fn send_sol(
    signing_key: Arc<SigningKey>,
    destination: Pubkey,
    lamports: u64,
    rpc_url: &str,
    http_client: &reqwest::Client,
) -> anyhow::Result<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let signer_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    let transfer_ix =
        solana_sdk::system_instruction::transfer(&signer_pubkey, &destination, lamports);
    let blockhash = fetch_latest_blockhash(rpc_url, http_client).await?;
    let kp = to_solana_keypair(&signing_key);
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&signer_pubkey),
        &[&kp],
        blockhash,
    );
    let serialized = bincode::serialize(&tx)?;
    broadcast_transaction(rpc_url, http_client, &B64.encode(&serialized)).await
}

/// Spawn a background task that takes 1% of the SOL gained by the agent's
/// wallet after Bags claim transactions confirm, forwarding it to the
/// 0x01 treasury.
///
/// The task waits 5 seconds for transactions to settle, then computes the
/// balance delta and sends `delta * PROTOCOL_FEE_BPS / 10_000` lamports.
/// Completely fire-and-forget — never blocks the API response.
pub fn spawn_protocol_fee_collection(
    signing_key: Arc<SigningKey>,
    agent_pubkey: Pubkey,
    pre_balance: u64,
    rpc_url: String,
    http_client: reqwest::Client,
) {
    tokio::spawn(async move {
        // Wait for claim txs to confirm (~1-2 slots, 5 s is conservative).
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let post_balance =
            match get_sol_balance(&rpc_url, &http_client, &agent_pubkey).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("Protocol fee: getBalance failed: {e}");
                    return;
                }
            };

        let delta = post_balance.saturating_sub(pre_balance);
        if delta == 0 {
            return;
        }

        let fee_lamports = (delta as u128)
            .saturating_mul(PROTOCOL_FEE_BPS as u128)
            .checked_div(10_000)
            .unwrap_or(0) as u64;

        if fee_lamports < MIN_PROTOCOL_FEE_LAMPORTS {
            tracing::debug!(
                "Protocol fee too small ({fee_lamports} lamports, delta={delta}) — skipping"
            );
            return;
        }

        let treasury: Pubkey = match ZEROX1_TREASURY.parse() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Invalid ZEROX1_TREASURY constant: {e}");
                return;
            }
        };

        match send_sol(signing_key, treasury, fee_lamports, &rpc_url, &http_client).await {
            Ok(txid) => tracing::info!(
                "Protocol fee: {fee_lamports} lamports → treasury (txid={txid}, delta={delta})"
            ),
            Err(e) => tracing::warn!("Protocol fee SOL transfer failed: {e}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BagsApiClient::new ---

    #[test]
    fn bags_api_client_rejects_http_url() {
        let client = reqwest::Client::new();
        let result = BagsApiClient::new("http://api.bags.fm".to_string(), client);
        let err = result.err().expect("expected error for http:// URL");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn bags_api_client_rejects_non_https_scheme() {
        let client = reqwest::Client::new();
        let result = BagsApiClient::new("ws://api.bags.fm".to_string(), client);
        let err = result.err().expect("expected error for ws:// URL");
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn bags_api_client_accepts_https_url() {
        let client = reqwest::Client::new();
        assert!(BagsApiClient::new("https://api.bags.fm".to_string(), client).is_ok());
    }

    // --- BagsLaunchClient ---

    #[test]
    fn partner_mode_enabled_true_when_key_set() {
        let client = reqwest::Client::new();
        let lc = BagsLaunchClient::new("key".to_string(), Some("partner123".to_string()), client);
        assert!(lc.partner_mode_enabled());
    }

    #[test]
    fn partner_mode_enabled_false_when_key_none() {
        let client = reqwest::Client::new();
        let lc = BagsLaunchClient::new("key".to_string(), None, client);
        assert!(!lc.partner_mode_enabled());
    }

    #[test]
    fn partner_mode_enabled_false_when_key_blank() {
        let client = reqwest::Client::new();
        let lc = BagsLaunchClient::new("key".to_string(), Some("   ".to_string()), client);
        assert!(!lc.partner_mode_enabled());
    }

    // --- Protocol fee arithmetic ---

    #[test]
    fn protocol_fee_is_1_percent_of_delta() {
        let delta: u64 = 1_000_000; // 1 SOL in lamports
        let fee = (delta as u128)
            .saturating_mul(PROTOCOL_FEE_BPS as u128)
            .checked_div(10_000)
            .unwrap_or(0) as u64;
        assert_eq!(fee, 10_000); // 1% of 1_000_000 = 10_000 lamports
    }

    #[test]
    fn protocol_fee_skipped_when_below_minimum() {
        // delta just under threshold: fee = 9 lamports < MIN_PROTOCOL_FEE_LAMPORTS (1_000)
        let delta: u64 = 900;
        let fee = (delta as u128)
            .saturating_mul(PROTOCOL_FEE_BPS as u128)
            .checked_div(10_000)
            .unwrap_or(0) as u64;
        assert!(fee < MIN_PROTOCOL_FEE_LAMPORTS);
    }

    #[test]
    fn treasury_address_parses_as_valid_pubkey() {
        let pk: Result<Pubkey, _> = ZEROX1_TREASURY.parse();
        assert!(pk.is_ok(), "ZEROX1_TREASURY must be a valid Solana pubkey");
    }
}
