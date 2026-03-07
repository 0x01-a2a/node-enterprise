use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use solana_sdk::transaction::VersionedTransaction;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use ed25519_dalek::Signer;

use crate::api::{require_api_secret_or_unauthorized, resolve_hosted_token, ApiState, PortfolioEvent};

#[derive(Deserialize)]
pub struct SwapRequest {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: u64,
    pub slippage_bps: Option<u16>,
}

#[derive(Serialize)]
pub struct SwapResponse {
    pub out_amount: u64,
    pub txid: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct JupiterQuoteResponse {
    #[serde(rename = "outAmount")]
    out_amount: String,
    // (Other fields are ignored)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JupiterSwapRequest {
    user_public_key: String,
    quote_response: serde_json::Value,
    dynamic_compute_unit_limit: bool,
    prioritization_fee_lamports: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_account: Option<String>,
}

#[derive(Deserialize, Debug)]
struct JupiterSwapResponse {
    #[serde(rename = "swapTransaction")]
    swap_transaction: String,
}

// ── Swap whitelist ────────────────────────────────────────────────────────

/// Token mints allowed in agent-to-agent swaps.
///
/// Enforced at the node level so the protection applies to every caller
/// (SDK, ZeroClaw, custom agents) regardless of which client they use.
/// Both mainnet and devnet mints are included.
const SWAP_WHITELIST: &[&str] = &[
    // SOL (wrapped)
    "So11111111111111111111111111111111111111112",
    // USDC — mainnet
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    // USDC — devnet
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    // USDT — mainnet
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    // JUP
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN",
    // BONK
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
    // RAY
    "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
    // WIF
    "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm",
    // BAGS — mainnet
    "Bags4uLBdNscWBnHmqBozrjSScnEqPx5qZBzLiqnRVN7",
];

fn is_whitelisted(mint: &str) -> bool {
    SWAP_WHITELIST.contains(&mint)
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Returns true if `s` looks like a valid base58-encoded Solana public key
/// (32-44 characters, base58 alphabet only).
fn is_valid_pubkey(s: &str) -> bool {
    matches!(s.len(), 32..=44)
        && s.chars().all(|c| matches!(c,
            '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
        ))
}

/// Known token mint decimal precision. Returns `None` for unrecognised mints.
fn mint_decimals(mint: &str) -> Option<i32> {
    match mint {
        // SOL (wrapped)
        "So11111111111111111111111111111111111111112" => Some(9),
        // USDC mainnet
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => Some(6),
        // USDC devnet
        "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" => Some(6),
        // USDT
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => Some(6),
        // mSOL
        "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So" => Some(9),
        // ETH (Wormhole)
        "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs" => Some(8),
        // BONK
        "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" => Some(5),
        _ => None,
    }
}

/// POST /trade/swap
pub async fn trade_swap_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SwapRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        let sessions = state.inner().hosted_sessions.read().await;
        if let Some(session) = sessions.get(&token) {
            session.signing_key.clone()
        } else {
            return err_resp(StatusCode::UNAUTHORIZED, "invalid or expired token".into());
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    };

    let signer = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes());

    // ── Input validation ──────────────────────────────────────────────────
    if !is_valid_pubkey(&req.input_mint) || !is_valid_pubkey(&req.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid mint".into());
    }
    if req.input_mint == req.output_mint {
        return err_resp(StatusCode::BAD_REQUEST, "mints must differ".into());
    }
    if !is_whitelisted(&req.input_mint) {
        return err_resp(StatusCode::BAD_REQUEST, format!("input_mint {} is not in the swap whitelist", req.input_mint));
    }
    if !is_whitelisted(&req.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, format!("output_mint {} is not in the swap whitelist", req.output_mint));
    }
    if req.amount == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "amount must be > 0".into());
    }

    let slippage = req.slippage_bps.unwrap_or(50);
    if slippage > 1_000 {
        return err_resp(StatusCode::BAD_REQUEST, "slippage_bps cannot exceed 1000 (10%)".into());
    }

    let input_decimals = mint_decimals(&req.input_mint).unwrap_or(6);
    let output_decimals = mint_decimals(&req.output_mint).unwrap_or(6);

    tracing::info!("Swap: {} - {} to {} amount {}", signer, req.input_mint, req.output_mint, req.amount);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    // 1. Get Jupiter Quote
    let quote_url = format!(
        "https://quote-api.jup.ag/v6/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        req.input_mint, req.output_mint, req.amount, slippage
    );

    let quote_res = match client.get(&quote_url).send().await {
        Ok(res) => res,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Quote fail: {e}")),
    };

    if !quote_res.status().is_success() {
        return err_resp(StatusCode::BAD_GATEWAY, "Jupiter Quote returned error".into());
    }

    let quote_json: serde_json::Value = match quote_res.json().await {
        Ok(j) => j,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse quote: {e}")),
    };

    let out_amount_str = quote_json.get("outAmount").and_then(|v| v.as_str()).unwrap_or("0");
    let out_amount: u64 = out_amount_str.parse().unwrap_or(0);

    let kora_fee_payer_opt = if let Some(ref kora) = state.inner().kora {
        match kora.get_fee_payer().await {
            Ok(fp) => Some(fp),
            Err(e) => {
                tracing::warn!("Failed to get Kora fee payer, falling back to signer: {e}");
                None
            }
        }
    } else {
        None
    };

    let swap_req = JupiterSwapRequest {
        user_public_key: signer.to_string(),
        quote_response: quote_json,
        dynamic_compute_unit_limit: true,
        prioritization_fee_lamports: "auto".to_string(),
        fee_account: kora_fee_payer_opt.as_ref().map(|p: &solana_sdk::pubkey::Pubkey| p.to_string()),
    };

    let swap_res = match client.post("https://quote-api.jup.ag/v6/swap").json(&swap_req).send().await {
        Ok(res) => res,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Swap req fail: {e}")),
    };

    if !swap_res.status().is_success() {
        return err_resp(StatusCode::BAD_GATEWAY, "Jupiter Swap returned error".into());
    }

    let swap_data: JupiterSwapResponse = match swap_res.json().await {
        Ok(d) => d,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Invalid JSON from Jupiter".into()),
    };

    let tx_bytes = B64.decode(&swap_data.swap_transaction).unwrap_or_default();
    let mut versioned_tx: VersionedTransaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Invalid tx bytes".into()),
    };

    if kora_fee_payer_opt.is_none() {
        let fee_payer_ok = match &versioned_tx.message {
            solana_sdk::message::VersionedMessage::Legacy(msg) => msg.account_keys.first() == Some(&signer),
            solana_sdk::message::VersionedMessage::V0(msg) => msg.account_keys.first() == Some(&signer),
        };
        if !fee_payer_ok {
            return err_resp(StatusCode::BAD_GATEWAY, "Jupiter returned unexpected fee payer".into());
        }
    }

    let msg_bytes = versioned_tx.message.serialize();
    let sig = signing_key.sign(&msg_bytes);

    let txid = if let Some(ref kora) = state.inner().kora {
        let signer_index = versioned_tx.message.static_account_keys().iter().position(|&k| k == signer);
        if let Some(idx) = signer_index {
            if idx < versioned_tx.signatures.len() {
                versioned_tx.signatures[idx] = solana_sdk::signature::Signature::from(sig.to_bytes());
            } else {
                return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Signer missing from signatures".into());
            }
        }
        
        let tx_b64 = B64.encode(bincode::serialize(&versioned_tx).unwrap());
        match kora.sign_and_send(&tx_b64).await {
            Ok(s) => s, 
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Kora send failed: {e}")),
        }
    } else {
        if !versioned_tx.signatures.is_empty() {
            versioned_tx.signatures[0] = solana_sdk::signature::Signature::from(sig.to_bytes());
        }
        let rpc_client = RpcClient::new(state.inner().rpc_url.clone());
        match rpc_client.send_and_confirm_transaction(&versioned_tx).await {
            Ok(s) => s.to_string(),
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Broadcast failed: {e}")),
        }
    };

    // 5a. Bags fee-sharing: route a cut of the swap output to the Bags distribution wallet.
    #[cfg(feature = "bags")]
    if let Some(bags) = state.inner().bags_config.as_ref() {
        // out_amount is in the output token's native units. Only apply when
        // swapping to USDC so the fee is paid in a stable asset.
        let is_usdc_output = req.output_mint == crate::api::USDC_MINT_MAINNET
            || req.output_mint == crate::api::USDC_MINT_DEVNET;
        if is_usdc_output {
            let fee = ((out_amount as u128 * bags.fee_bps as u128) / 10_000) as u64;
            if fee >= bags.min_fee_micro {
                let bags = bags.clone();
                let sk = state.inner().node_signing_key.clone();
                let rpc = state.inner().rpc_url.clone();
                let client = state.inner().http_client.clone();
                let mainnet = state.inner().is_mainnet;
                let state2 = state.clone();
                tokio::spawn(async move {
                    match crate::bags::distribute_fee(sk, fee, &bags, &rpc, &client, mainnet).await {
                        Ok(txid) => {
                            tracing::info!("Bags swap fee distributed: {txid} ({fee} micro)");
                            state2.record_portfolio_event(PortfolioEvent::BagsFee {
                                amount_usdc: fee as f64 / 1_000_000.0,
                                txid,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            }).await;
                        }
                        Err(e) => tracing::warn!("Bags swap fee failed: {e}"),
                    }
                });
            }
        }
    }

    // 5b. Record swap event in portfolio history
    state.record_portfolio_event(PortfolioEvent::Swap {
        input_mint: req.input_mint.clone(),
        output_mint: req.output_mint.clone(),
        input_amount: req.amount as f64 / 10f64.powi(input_decimals),
        output_amount: out_amount as f64 / 10f64.powi(output_decimals),
        txid: txid.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }).await;

    Json(SwapResponse {
        out_amount,
        txid,
    }).into_response()
}

fn err_resp(code: StatusCode, msg: String) -> Response {
    tracing::warn!("trade_swap_handler error: {}", msg);
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ============================================================================
// Quote API
// ============================================================================

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteQuery {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: u64,
    pub slippage_bps: Option<u16>,
}

/// GET /trade/quote
pub async fn trade_quote_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<QuoteQuery>,
) -> Response {
    if resolve_hosted_token(&headers).is_none() && require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized. require api secret or hosted token" })),
        )
            .into_response();
    }

    if !is_valid_pubkey(&query.input_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid input_mint".into());
    }
    if !is_valid_pubkey(&query.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid output_mint".into());
    }
    if query.amount == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "amount must be > 0".into());
    }

    let slippage = query.slippage_bps.unwrap_or(50);
    let client = reqwest::Client::new();

    let quote_url = format!(
        "https://quote-api.jup.ag/v6/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        query.input_mint, query.output_mint, query.amount, slippage
    );

    let res = match client.get(&quote_url).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Jupiter request failed: {e}")),
    };

    if !res.status().is_success() {
        return err_resp(StatusCode::BAD_GATEWAY, format!("Jupiter Error: {}", res.status()));
    }

    let json: serde_json::Value = match res.json().await {
        Ok(j) => j,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Invalid JSON from Jupiter".into()),
    };

    Json(json).into_response()
}
