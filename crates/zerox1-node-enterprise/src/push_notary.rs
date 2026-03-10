//! Push Notary — FCM token registration and sleeping node coordination.
//!
//! A phone node registers its Firebase Cloud Messaging device token with the
//! aggregator on startup. If the phone goes offline, the aggregator can send a
//! push notification to wake the app when a PROPOSE arrives for that agent.
//!
//! Flow:
//!   1. Node starts → register_fcm_token() + set_sleep_mode(false) + pull_pending_messages()
//!   2. App backgrounds / process ends → set_sleep_mode(true)  [called by app layer]
//!   3. Sender's SDK detects target is sleeping → POST /agents/{id}/pending on aggregator
//!   4. Aggregator sends FCM push → phone wakes, app re-establishes relay reservation
//!   5. Sender retries the bilateral PROPOSE → normal protocol flow resumes

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::net::IpAddr;

// ============================================================================
// Types
// ============================================================================

/// A message the aggregator held for this agent while it was sleeping.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // fields consumed by app layer / SDK, not by node internals
pub struct PendingMessage {
    /// Unique message ID (nanoscecond hex timestamp on the aggregator).
    pub id: String,
    /// Hex-encoded agent_id of the sender.
    pub from: String,
    /// Protocol message type, e.g. "PROPOSE".
    pub msg_type: String,
    /// Base64-encoded raw CBOR envelope bytes.
    pub payload: String,
    /// Unix timestamp (seconds) when the aggregator received it.
    pub ts: u64,
}

// ============================================================================
// Registration
// ============================================================================

/// Register this node's FCM device token with the aggregator.
///
/// Requirement: Must be signed by the agent (HIGH-7).
pub async fn register_fcm_token(
    aggregator_url: &str,
    agent_id_hex: &str,
    fcm_token: &str,
    signing_key: &SigningKey,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let base = validated_aggregator_url(aggregator_url).await?;
    let url = format!("{base}/fcm/register");
    let body = serde_json::json!({
        "agent_id":  agent_id_hex,
        "fcm_token": fcm_token,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let signature = signing_key.sign(&body_bytes);

    let resp = client
        .post(&url)
        .header("X-Signature", hex::encode(signature.to_bytes()))
        .body(body_bytes)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("FCM register returned HTTP {}", resp.status());
    }
    Ok(())
}

// ============================================================================
// Sleep state
// ============================================================================

/// Notify the aggregator that this agent is sleeping (offline) or awake.
///
/// Requirement: Must be signed by the agent (HIGH-7).
pub async fn set_sleep_mode(
    aggregator_url: &str,
    agent_id_hex: &str,
    sleeping: bool,
    signing_key: &SigningKey,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    let base = validated_aggregator_url(aggregator_url).await?;
    let url = format!("{base}/fcm/sleep");
    let body = serde_json::json!({
        "agent_id": agent_id_hex,
        "sleeping": sleeping,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let signature = signing_key.sign(&body_bytes);

    let resp = client
        .post(&url)
        .header("X-Signature", hex::encode(signature.to_bytes()))
        .body(body_bytes)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("FCM sleep update returned HTTP {}", resp.status());
    }
    Ok(())
}

// ============================================================================
// Pending message pull
// ============================================================================

/// Pull messages the aggregator held while this agent was sleeping.
///
/// Requirement: Must be signed by the agent (HIGH-8).
pub async fn pull_pending_messages(
    aggregator_url: &str,
    agent_id_hex: &str,
    signing_key: &SigningKey,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<PendingMessage>> {
    let base = validated_aggregator_url(aggregator_url).await?;
    let url = format!("{base}/agents/{agent_id_hex}/pending");

    // For GET /pending, we sign the path "agents/{id}/pending"
    let msg = format!("agents/{agent_id_hex}/pending");
    let signature = signing_key.sign(msg.as_bytes());

    let resp = client
        .get(&url)
        .header("X-Signature", hex::encode(signature.to_bytes()))
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(vec![]);
    }
    if !resp.status().is_success() {
        anyhow::bail!("Pending pull returned HTTP {}", resp.status());
    }
    let msgs: Vec<PendingMessage> = resp.json().await?;
    Ok(msgs)
}

async fn validated_aggregator_url(raw: &str) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(raw)
        .map_err(|e| anyhow::anyhow!("invalid aggregator URL '{raw}': {e}"))?;

    if parsed.scheme() != "https" {
        anyhow::bail!("aggregator URL must use https://");
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("aggregator URL is missing a host"))?
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        anyhow::bail!("aggregator URL host is local/private");
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_or_local_ip(ip) {
            anyhow::bail!("aggregator URL host is local/private");
        }
    } else {
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("failed to resolve aggregator host '{host}': {e}"))?
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("aggregator host '{host}' resolved to no addresses");
        }
        if addrs.iter().any(|addr| is_private_or_local_ip(addr.ip())) {
            anyhow::bail!("aggregator host '{host}' resolves to local/private IP");
        }
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
        }
    }
}
