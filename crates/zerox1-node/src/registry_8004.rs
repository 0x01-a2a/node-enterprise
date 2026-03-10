use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
};

// ============================================================================
// 8004 program constants
// ============================================================================

pub const PROGRAM_ID_DEVNET: &str = "8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C";
pub const PROGRAM_ID_MAINNET: &str = "8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ";
pub const COLLECTION_DEVNET: &str = "C6W2bq4BoVT8FDvqhdp3sbcHFBjNBXE8TsNak2wTXQs9";
pub const COLLECTION_MAINNET: &str = "DbjsWo7iUs7QZyJxLgNyVxvAAjQZCXroJHoGok8h8Umg";
/// Mainnet Solana RPC — used exclusively for 8004 registration so that the
/// registration always lands on mainnet regardless of the mesh RPC setting.
pub const RPC_MAINNET: &str = "https://api.mainnet-beta.solana.com";
/// Devnet Solana RPC — used for 8004 registration when devnet is explicitly requested.
pub const RPC_DEVNET: &str = "https://api.devnet.solana.com";
const MPL_CORE_PROGRAM: &str = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d";
/// `register` instruction discriminator from the IDL.
const REGISTER_DISCRIMINATOR: [u8; 8] = [211, 124, 67, 15, 211, 194, 178, 240];

// ============================================================================
// Transaction building
// ============================================================================

/// Result of `build_register_tx`.
pub struct RegisterPrepared {
    /// base58 — the new agent asset pubkey on-chain.  The agent must save this;
    /// it becomes the canonical 8004 `assetPubkey` for their registration.
    pub asset_pubkey: String,
    /// base64 bincode — partially signed Solana transaction.
    /// The asset keypair has already signed; the owner signature slot is empty.
    /// The agent must sign this transaction with their Ed25519/owner keypair
    /// and broadcast it (or POST to /registry/8004/register-submit).
    pub transaction_b64: String,
    /// base64 — raw message bytes.  An alternative signing path: sign these
    /// bytes directly with the owner Ed25519 key, inject the 64-byte signature
    /// at position 0, then broadcast the transaction.
    pub message_b64: String,
}

/// Build a partially-signed 8004 `register` transaction.
///
/// The returned transaction has the `asset` keypair signature already in place.
/// The caller (agent) must add the `owner` signature (position 0) and broadcast.
///
/// `is_mainnet`: selects program IDs.  Mainnet collection address must be
/// provided via `collection_override` when `is_mainnet` is true (the devnet
/// collection is known and hardcoded; the mainnet collection is deployment-
/// specific and read from RootConfig on-chain).
pub fn build_register_tx(
    owner_pubkey: Pubkey,
    agent_uri: &str,
    recent_blockhash: Hash,
    is_mainnet: bool,
    collection_override: Option<Pubkey>,
    fee_payer_override: Option<Pubkey>,
) -> anyhow::Result<RegisterPrepared> {
    let program_id: Pubkey = if is_mainnet {
        PROGRAM_ID_MAINNET
            .parse()
            .expect("hardcoded mainnet program id")
    } else {
        PROGRAM_ID_DEVNET
            .parse()
            .expect("hardcoded devnet program id")
    };

    let collection: Pubkey = match collection_override {
        Some(c) => c,
        None if !is_mainnet => COLLECTION_DEVNET
            .parse()
            .expect("hardcoded devnet collection"),
        None => COLLECTION_MAINNET
            .parse()
            .expect("hardcoded mainnet collection"),
    };

    let mpl_core: Pubkey = MPL_CORE_PROGRAM.parse().expect("hardcoded mpl core");

    // Validate URI length (program enforces ≤ 250 bytes).
    if agent_uri.len() > 250 {
        anyhow::bail!("agent_uri exceeds 250 bytes");
    }

    // Generate a fresh asset keypair — unique identity for this registration.
    let asset_kp = Keypair::new();
    let asset_pubkey = asset_kp.pubkey();

    // Derive PDAs.
    let (root_config, _) = Pubkey::find_program_address(&[b"root_config"], &program_id);
    let (registry_config, _) =
        Pubkey::find_program_address(&[b"registry_config", collection.as_ref()], &program_id);
    let (agent_account, _) =
        Pubkey::find_program_address(&[b"agent", asset_pubkey.as_ref()], &program_id);

    // Instruction data: discriminator + borsh-encoded agent_uri (4-byte LE len + utf8).
    let mut data = REGISTER_DISCRIMINATOR.to_vec();
    let uri_bytes = agent_uri.as_bytes();
    data.extend_from_slice(&(uri_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(uri_bytes);

    // Accounts in IDL order.
    let accounts = vec![
        AccountMeta::new_readonly(root_config, false),
        AccountMeta::new_readonly(registry_config, false),
        AccountMeta::new(agent_account, false),
        AccountMeta::new(asset_pubkey, true),
        AccountMeta::new(collection, false),
        AccountMeta::new(owner_pubkey, true), // owner is also fee payer
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        AccountMeta::new_readonly(mpl_core, false),
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data,
    };

    // Build transaction. If fee_payer_override is provided, use it. Otherwise owner is fee payer.
    let fee_payer = fee_payer_override.unwrap_or(owner_pubkey);
    let mut tx = Transaction::new_with_payer(&[instruction], Some(&fee_payer));
    // Pre-sign with the asset keypair; owner signs externally.
    tx.partial_sign(&[&asset_kp], recent_blockhash);

    let tx_bytes = bincode::serialize(&tx)?;
    let transaction_b64 = B64.encode(&tx_bytes);
    let message_b64 = B64.encode(tx.message_data());

    Ok(RegisterPrepared {
        asset_pubkey: asset_pubkey.to_string(),
        transaction_b64,
        message_b64,
    })
}

// ============================================================================
// RPC helpers (used by API handlers)
// ============================================================================

/// Fetch the latest blockhash from a Solana JSON-RPC endpoint.
pub async fn fetch_latest_blockhash(
    rpc_url: &str,
    client: &reqwest::Client,
) -> anyhow::Result<Hash> {
    let resp = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  "getLatestBlockhash",
            "params":  [{"commitment": "confirmed"}]
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    let data: serde_json::Value = resp.json().await?;

    if let Some(err) = data.get("error") {
        anyhow::bail!("RPC getLatestBlockhash error: {err}");
    }

    let bh_str = data["result"]["value"]["blockhash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no blockhash in RPC response"))?;

    bh_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid blockhash '{bh_str}': {e}"))
}

/// Broadcast a base64-encoded signed transaction via JSON-RPC.
/// Returns the transaction signature (base58).
pub async fn broadcast_transaction(
    rpc_url: &str,
    client: &reqwest::Client,
    signed_tx_b64: &str,
) -> anyhow::Result<String> {
    let resp = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  "sendTransaction",
            "params":  [
                signed_tx_b64,
                {"encoding": "base64", "preflightCommitment": "confirmed"}
            ]
        }))
        .timeout(Duration::from_secs(30))
        .send()
        .await?;

    let data: serde_json::Value = resp.json().await?;

    if let Some(err) = data.get("error") {
        anyhow::bail!("RPC sendTransaction error: {err}");
    }

    data["result"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("no signature in sendTransaction response"))
}

/// Client for the 8004 Solana Agent Registry GraphQL API.
///
/// The 8004 registry stores agents as Metaplex Core NFTs where the `owner`
/// field equals the agent's Solana pubkey. Since every 0x01 node's Ed25519
/// identity key IS a valid Solana pubkey (same curve, same bytes), we can
/// verify any peer by base58-encoding their `agent_id` bytes and querying
/// `agents(where: { owner: $base58 })` against the public indexer API.
///
/// No Solana RPC connection needed — just HTTP to the indexer.
pub struct Registry8004Client {
    pub url: String,
    client: reqwest::Client,
    min_tier: u8,
}

impl Registry8004Client {
    pub fn new(url: &str, client: reqwest::Client, min_tier: u8) -> Self {
        Self {
            url: url.to_string(),
            client,
            min_tier,
        }
    }

    /// Query the 8004 registry for an agent by their Ed25519 pubkey (base58).
    ///
    /// Returns:
    /// - `Ok(true)`  — agent is registered and their trust tier >= `min_tier`
    /// - `Ok(false)` — agent not found, or trust tier below minimum
    /// - `Err(_)`    — network / HTTP error (caller should back off and retry)
    pub async fn is_registered(&self, agent_id: &[u8; 32]) -> anyhow::Result<bool> {
        let owner_b58 = bs58::encode(agent_id).into_string();

        // When min_tier > 0, add trustTier_gte to the where clause so we ask
        // "does this owner have ANY agent with tier >= min_tier?" rather than
        // checking the tier of whichever asset happens to be returned first.
        let (query, variables) = if self.min_tier > 0 {
            let q =
                "query($o:String!,$t:Int!){agents(first:1,where:{owner:$o,trustTier_gte:$t}){id}}";
            let v = serde_json::json!({ "o": owner_b58, "t": self.min_tier as i32 });
            (q, v)
        } else {
            let q = "query($o:String!){agents(first:1,where:{owner:$o}){id}}";
            let v = serde_json::json!({ "o": owner_b58 });
            (q, v)
        };

        let body = serde_json::json!({ "query": query, "variables": variables });

        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("8004 registry returned HTTP {}", resp.status());
        }

        let data: serde_json::Value = resp.json().await?;

        // GraphQL errors travel inside the body at HTTP 200.
        // Return Err so the caller backs off and retries in 1 hour rather than
        // silently treating every query failure as "not registered".
        if let Some(errors) = data.get("errors").and_then(|e| e.as_array()) {
            if !errors.is_empty() {
                let msg = errors[0]
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown GraphQL error");
                anyhow::bail!("8004 GraphQL error: {}", msg);
            }
        }

        let agents = data
            .get("data")
            .and_then(|d| d.get("agents"))
            .and_then(|a| a.as_array());

        Ok(matches!(agents, Some(arr) if !arr.is_empty()))
    }
}
