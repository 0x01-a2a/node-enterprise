//! Kora paymaster client (doc 5, §4.4).
//!
//! Kora is a Solana paymaster node that enables gasless on-chain transactions.
//! Agents build transactions with Kora's pubkey as the fee payer, submit via
//! JSON-RPC, and Kora adds its signature and broadcasts.
//!
//! Gas is reimbursed to the Kora operator in USDC — agents never need raw SOL.
//!
//! JSON-RPC endpoint: POST <kora_url>
//! Methods used:
//!   getPayerSigner         — returns Kora's fee payer pubkey
//!   signAndSendTransaction — validates, signs as fee payer, broadcasts

use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

// ============================================================================
// JSON-RPC primitives
// ============================================================================

#[derive(Serialize)]
struct JsonRpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: P,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

// ============================================================================
// Method-specific types
// ============================================================================

#[derive(Deserialize)]
struct GetPayerSignerResult {
    signer_address: String,
    #[allow(dead_code)]
    payment_address: String,
}

#[derive(Serialize)]
struct SignAndSendParams<'a> {
    transaction: &'a str,
    sig_verify: bool,
}

#[derive(Deserialize)]
struct SignAndSendResult {
    /// Base64-encoded signed transaction (Kora has added its fee payer sig).
    #[allow(dead_code)]
    signed_transaction: String,
    /// Kora's signer pubkey (for logging).
    signer_pubkey: String,
}

// ============================================================================
// KoraClient
// ============================================================================

/// Lightweight JSON-RPC client for a Kora paymaster node.
///
/// Usage pattern:
/// ```text
/// let fee_payer = kora.get_fee_payer().await?;
/// // build transaction with fee_payer as the payer account
/// let tx_b64 = base64_encode(bincode_serialize(tx));
/// kora.sign_and_send(&tx_b64).await?;
/// ```
#[derive(Clone)]
pub struct KoraClient {
    url: String,
    http: reqwest::Client,
}

impl KoraClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// Fetch Kora's fee payer pubkey.
    ///
    /// All on-chain transactions must set this as the `payer` account so that
    /// Kora can sign as fee payer and pay gas on behalf of the agent.
    pub async fn get_fee_payer(&self) -> anyhow::Result<Pubkey> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getPayerSigner",
            params: (),
        };

        let resp: JsonRpcResponse<GetPayerSignerResult> = self
            .http
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Kora HTTP error: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Kora response parse error: {e}"))?;

        let result = resp.result.ok_or_else(|| {
            let msg = resp
                .error
                .map(|e| format!("code={} msg={}", e.code, e.message))
                .unwrap_or_else(|| "no result and no error".into());
            anyhow::anyhow!("Kora getPayerSigner failed: {msg}")
        })?;

        Pubkey::from_str(&result.signer_address)
            .map_err(|e| anyhow::anyhow!("Kora returned invalid pubkey: {e}"))
    }

    /// Submit a base64-encoded, unsigned (or partially-signed) transaction.
    ///
    /// Kora validates the transaction against its allowlist, adds its fee payer
    /// signature, and broadcasts to the Solana network.
    ///
    /// Returns the Kora signer pubkey used (for logging).
    pub async fn sign_and_send(&self, tx_b64: &str) -> anyhow::Result<String> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 2,
            method: "signAndSendTransaction",
            params: SignAndSendParams {
                transaction: tx_b64,
                sig_verify: false,
            },
        };

        let resp: JsonRpcResponse<SignAndSendResult> = self
            .http
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Kora HTTP error: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Kora response parse error: {e}"))?;

        let result = resp.result.ok_or_else(|| {
            let msg = resp
                .error
                .map(|e| format!("code={} msg={}", e.code, e.message))
                .unwrap_or_else(|| "no result and no error".into());
            anyhow::anyhow!("Kora signAndSendTransaction failed: {msg}")
        })?;

        Ok(result.signer_pubkey)
    }
}
