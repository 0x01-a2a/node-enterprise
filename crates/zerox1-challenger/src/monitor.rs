//! Per-cycle monitoring logic and agent evidence accumulation.

use std::collections::HashMap;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::signature::Keypair;

use base64::Engine as _;

use crate::submit::{generate_merkle_proof, resolve_challenge_onchain, submit_challenge_onchain};
use crate::Cli;

#[derive(Deserialize)]
struct EnvelopeEntry {
    #[allow(dead_code)]
    seq: i64,
    leaf_hash: String,
    bytes_b64: String,
}

// ============================================================================
// Aggregator response types
// ============================================================================

/// Entry from GET /leaderboard/anomaly
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // fields populated from JSON deserialization; used selectively
pub struct AnomalyEntry {
    pub agent_id: String,
    pub epoch: u64,
    pub anomaly: f64,
    pub ht: Option<f64>,
    pub hb: Option<f64>,
    pub hs: Option<f64>,
    pub hv: Option<f64>,
}

/// Response from GET /entropy/{id}/rolling
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RollingEntropyResult {
    pub agent_id: String,
    pub window_epochs: u32,
    pub epochs_found: u32,
    pub mean_anomaly: f64,
    pub anomaly_variance: f64,
    pub low_variance_flag: bool,
    pub high_anomaly_flag: bool,
}

/// Response from GET /stake/required/{id}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequiredStakeResult {
    pub agent_id: String,
    pub base_stake_usdc: f64,
    pub current_anomaly: f64,
    pub beta_1: f64,
    pub required_stake_usdc: f64,
    pub deficit_usdc: f64,
}

// ============================================================================
// Agent state tracking
// ============================================================================

#[derive(Debug, Clone)]
pub struct AgentState {
    /// How many consecutive cycles has this agent been above the threshold?
    pub consecutive_high: u32,
    /// Latest anomaly score.
    pub latest_anomaly: f64,
    /// Whether we have already emitted a challenge-ready report this cycle.
    pub challenge_ready: bool,
}

pub struct AgentMonitor {
    /// Per-agent tracking state.
    agents: HashMap<String, AgentState>,
    anomaly_threshold: f64,
    consecutive_needed: u32,
}

impl AgentMonitor {
    pub fn new(anomaly_threshold: f64, consecutive_needed: u32) -> Self {
        Self {
            agents: HashMap::new(),
            anomaly_threshold,
            consecutive_needed,
        }
    }

    /// Update state for one agent.  Returns true if newly challenge-ready.
    pub fn update(&mut self, agent_id: &str, anomaly: f64) -> bool {
        let state = self
            .agents
            .entry(agent_id.to_string())
            .or_insert(AgentState {
                consecutive_high: 0,
                latest_anomaly: 0.0,
                challenge_ready: false,
            });

        state.latest_anomaly = anomaly;

        if anomaly >= self.anomaly_threshold {
            state.consecutive_high += 1;
        } else {
            // Reset: agent is below threshold this cycle.
            state.consecutive_high = 0;
            state.challenge_ready = false;
            return false;
        }

        if state.consecutive_high >= self.consecutive_needed && !state.challenge_ready {
            state.challenge_ready = true;
            return true;
        }

        false
    }

    pub fn get(&self, agent_id: &str) -> Option<&AgentState> {
        self.agents.get(agent_id)
    }
}

// ============================================================================
// Evidence report
// ============================================================================

/// Full evidence package for a challenge-ready agent.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceReport {
    pub agent_id: String,
    pub generated_at_unix: u64,
    pub consecutive_cycles: u32,
    pub latest_anomaly: f64,
    pub rolling: Option<RollingEntropyResult>,
    pub required_stake: Option<RequiredStakeResult>,
    pub stake_deficit_usdc: f64,
    pub flags: Vec<String>,
    /// Human-readable summary of why this agent should be challenged.
    pub recommendation: String,
}

// ============================================================================
// One poll cycle
// ============================================================================

pub async fn run_cycle(
    cli: &Cli,
    client: &reqwest::Client,
    mon: &mut AgentMonitor,
    rpc_client: &RpcClient,
    keypair: Option<&Keypair>,
) -> anyhow::Result<()> {
    tracing::debug!("Starting poll cycle");

    // 1. Pull anomaly leaderboard.
    let url = format!(
        "{}/leaderboard/anomaly?limit={}",
        cli.aggregator_url.trim_end_matches('/'),
        cli.leaderboard_limit,
    );
    let resp = fetch_json(client, &url, cli.aggregator_secret.as_deref())
        .await
        .context("fetching anomaly leaderboard")?;

    let entries: Vec<AnomalyEntry> =
        serde_json::from_value(resp).context("parsing anomaly leaderboard")?;

    tracing::info!(
        "Leaderboard: {} agents, {} above threshold {}",
        entries.len(),
        entries
            .iter()
            .filter(|e| e.anomaly >= cli.anomaly_threshold)
            .count(),
        cli.anomaly_threshold,
    );

    // 2. Update monitor state for each agent.
    for entry in &entries {
        let newly_ready = mon.update(&entry.agent_id, entry.anomaly);

        if newly_ready {
            tracing::warn!(
                "Agent {} is CHALLENGE-READY: anomaly={:.3} for {} consecutive cycles",
                &entry.agent_id[..12],
                entry.anomaly,
                cli.consecutive_epochs,
            );

            // 3. Collect extra evidence for challenge-ready agents.
            let report = build_evidence_report(cli, client, entry, mon).await;
            emit_report(cli, &report).await;

            // 4. If auto_submit is enabled, try to submit the challenge on-chain.
            if cli.auto_submit {
                if let Some(kp) = keypair {
                    if let Err(e) = execute_challenge(cli, client, rpc_client, kp, entry).await {
                        tracing::error!("Failed to submit challenge for {}: {}", entry.agent_id, e);
                    }
                }
            }
        } else if let Some(state) = mon.get(&entry.agent_id) {
            if state.consecutive_high > 0 {
                tracing::info!(
                    "Agent {} suspicious: anomaly={:.3} ({}/{} cycles)",
                    &entry.agent_id[..12],
                    entry.anomaly,
                    state.consecutive_high,
                    cli.consecutive_epochs,
                );
            }
        }
    }

    Ok(())
}

async fn build_evidence_report(
    cli: &Cli,
    client: &reqwest::Client,
    entry: &AnomalyEntry,
    mon: &AgentMonitor,
) -> EvidenceReport {
    let base = cli.aggregator_url.trim_end_matches('/');
    let secret = cli.aggregator_secret.as_deref();

    // Rolling entropy.
    let rolling: Option<RollingEntropyResult> = fetch_json(
        client,
        &format!(
            "{}/entropy/{}/rolling?window={}",
            base, entry.agent_id, cli.rolling_window
        ),
        secret,
    )
    .await
    .ok()
    .and_then(|v| serde_json::from_value(v).ok());

    // Required stake.
    let required_stake: Option<RequiredStakeResult> = fetch_json(
        client,
        &format!("{}/stake/required/{}", base, entry.agent_id),
        secret,
    )
    .await
    .ok()
    .and_then(|v| serde_json::from_value(v).ok());

    let state = mon.get(&entry.agent_id);
    let consecutive = state.map(|s| s.consecutive_high).unwrap_or(0);
    let stake_deficit = required_stake
        .as_ref()
        .map(|r| r.deficit_usdc)
        .unwrap_or(0.0);

    let mut flags = vec![];

    if entry.anomaly > 0.80 {
        flags.push(format!("CRITICAL_ANOMALY:{:.3}", entry.anomaly));
    } else if entry.anomaly > 0.55 {
        flags.push(format!("HIGH_ANOMALY:{:.3}", entry.anomaly));
    }

    if let Some(ref r) = rolling {
        if r.low_variance_flag {
            flags.push(format!("PATIENT_CARTEL:variance={:.4}", r.anomaly_variance));
        }
    }

    if stake_deficit > 0.0 {
        flags.push(format!("STAKE_DEFICIT:{:.2}_USDC", stake_deficit));
    }

    if let Some(hv) = entry.hv {
        if hv < 0.5 {
            flags.push(format!("LOW_VERIFIER_ENTROPY:{:.3}", hv));
        }
    }

    let recommendation = if flags.iter().any(|f| f.starts_with("PATIENT_CARTEL")) {
        format!(
            "Agent {} shows low-variance high anomaly over {} epochs — \
             likely patient cartel (GAP-03). Recommend submitting challenge.",
            &entry.agent_id[..16],
            consecutive,
        )
    } else if stake_deficit > 1.0 {
        format!(
            "Agent {} has stake deficit of {:.2} USDC. \
             Recommend calling top_up_stake on-chain.",
            &entry.agent_id[..16],
            stake_deficit,
        )
    } else {
        format!(
            "Agent {} flagged for {} consecutive cycles with anomaly {:.3}. \
             Accumulating evidence.",
            &entry.agent_id[..16],
            consecutive,
            entry.anomaly,
        )
    };

    EvidenceReport {
        agent_id: entry.agent_id.clone(),
        generated_at_unix: unix_now(),
        consecutive_cycles: consecutive,
        latest_anomaly: entry.anomaly,
        rolling,
        required_stake,
        stake_deficit_usdc: stake_deficit,
        flags,
        recommendation,
    }
}

async fn emit_report(cli: &Cli, report: &EvidenceReport) {
    let json = serde_json::to_string_pretty(report).unwrap_or_default();
    println!("{json}");

    if let Some(ref dir) = cli.output_dir {
        let filename = dir.join(format!(
            "evidence_{}_{}.json",
            &report.agent_id[..16],
            report.generated_at_unix,
        ));
        if let Err(e) = std::fs::write(&filename, &json) {
            tracing::warn!("Failed to write evidence file {}: {e}", filename.display());
        } else {
            tracing::info!("Evidence written to {}", filename.display());
        }
    }
}

// ============================================================================
// Auto-submit Challenge
// ============================================================================

async fn execute_challenge(
    cli: &Cli,
    client: &reqwest::Client,
    rpc: &RpcClient,
    signer: &Keypair,
    entry: &AnomalyEntry,
) -> anyhow::Result<()> {
    let base = cli.aggregator_url.trim_end_matches('/');
    let url = format!(
        "{}/epochs/{}/{}/envelopes",
        base, entry.agent_id, entry.epoch
    );

    // Fetch raw envelopes for the epoch.
    let env_resp: Vec<EnvelopeEntry> = fetch_json(client, &url, cli.aggregator_secret.as_deref())
        .await
        .context("fetching epoch envelopes")
        .and_then(|v| serde_json::from_value(v).context("parsing envelopes"))?;

    if env_resp.is_empty() {
        anyhow::bail!(
            "No envelopes found for agent {} epoch {}",
            entry.agent_id,
            entry.epoch
        );
    }

    // Build leaf hash array from hex-encoded hashes (avoids re-hashing).
    let mut leaves = Vec::with_capacity(env_resp.len());
    for e in &env_resp {
        let bytes = hex::decode(&e.leaf_hash).context("hex decode leaf hash")?;
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&bytes);
        leaves.push(leaf);
    }

    // Pick the first envelope as the contradicting entry.
    // In production: select one where aggregator score contradicts the batch.
    let target_idx = 0;
    let raw_entry = base64::engine::general_purpose::STANDARD
        .decode(&env_resp[target_idx].bytes_b64)
        .context("base64 decode envelope bytes")?;

    let proof = generate_merkle_proof(target_idx, &leaves);

    tracing::info!(
        "Submitting on-chain challenge for agent {} epoch {}",
        entry.agent_id,
        entry.epoch
    );

    submit_challenge_onchain(
        rpc,
        signer,
        &entry.agent_id,
        entry.epoch,
        target_idx,
        &raw_entry,
        &proof,
    )
    .await?;

    if !cli.auto_resolve {
        tracing::warn!(
            "Challenge submitted for agent {} epoch {}. Skipping auto-resolve because contradiction proofs still require operator judgment.",
            entry.agent_id,
            entry.epoch
        );
        return Ok(());
    }

    tracing::info!(
        "Resolving on-chain challenge for agent {} epoch {}",
        entry.agent_id,
        entry.epoch
    );

    resolve_challenge_onchain(
        rpc,
        signer,
        &entry.agent_id,
        entry.epoch,
        &raw_entry,
        &proof,
    )
    .await
}

// ============================================================================
// HTTP helpers
// ============================================================================

async fn fetch_json(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
) -> anyhow::Result<Value> {
    let mut req = client.get(url);
    if let Some(s) = secret {
        req = req.header("Authorization", format!("Bearer {s}"));
    }
    let text = req.send().await?.error_for_status()?.text().await?;
    let val: Value = serde_json::from_str(&text)?;
    Ok(val)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
