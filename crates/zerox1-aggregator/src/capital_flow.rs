//! Capital Flow Graph Indexer (GAP-02)
//!
//! Mitigates Sybil attacks at the identity layer by discovering off-chain ownership
//! clusters via on-chain transaction capital flows.
//!
//! How it works:
//! 1. Periodically polls the latest reputation transactions from all known active agents.
//! 2. Pulls historical Solana RPC transactions (`getSignaturesForAddress`).
//! 3. Extracts external wallets that interact with these agents (e.g., funding gas accounts, sweeping profits).
//! 4. Builds an undirected graph linking Agents to External Wallets.
//! 5. Computes Connected Components. Set of agents in a single component are assigned to the same cluster.
//! 6. The `C` (clustering) multiplier is derived from the size of the cluster and applied to required stake.

use petgraph::graph::UnGraph;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, UiMessage, UiTransactionEncoding,
};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::api::AppState;

/// Maximum number of signatures to fetch per agent per cycle.
const MAX_SIGNATURES_PER_POLL: usize = 50;
/// Delay between full polling cycles.
const POLL_INTERVAL_SECS: u64 = 300; // 5 minutes

pub async fn run_indexer(rpc_url: String, state: AppState) {
    let rpc = RpcClient::new(rpc_url);

    loop {
        tracing::debug!("Starting capital flow indexer cycle...");
        if let Err(e) = index_capital_flows(&rpc, &state).await {
            tracing::error!("Capital flow indexer cycle failed: {}", e);
        }

        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

async fn index_capital_flows(rpc: &RpcClient, state: &AppState) -> anyhow::Result<()> {
    // 1. Get all active agents registered in the store
    // This assumes the store has a way to get active agents. If not, we'll need to add it.
    let active_agents = state.store.get_active_agent_pubkeys().await?;

    if active_agents.is_empty() {
        tracing::debug!("No active agents found, skipping indexer cycle.");
        return Ok(());
    }

    tracing::info!(
        "Indexing capital flows for {} active agents",
        active_agents.len()
    );

    let mut agent_to_externals: HashMap<String, HashSet<String>> = HashMap::new();

    // 2. Poll recent transactions for each agent
    // Agent IDs may be hex (legacy SATI) or base58 (8004 registry)
    for agent_pubkey_str in active_agents {
        let pk = if agent_pubkey_str.len() == 64
            && agent_pubkey_str.chars().all(|c| c.is_ascii_hexdigit())
        {
            // Legacy hex: decode 64 hex chars → 32 bytes → Pubkey
            match hex::decode(&agent_pubkey_str) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Pubkey::new_from_array(arr)
                }
                _ => continue,
            }
        } else {
            // 8004 base58: parse directly as Solana Pubkey
            match agent_pubkey_str.parse::<Pubkey>() {
                Ok(p) => p,
                Err(_) => continue,
            }
        };

        let sigs = match rpc.get_signatures_for_address(&pk).await {
            Ok(s) => s
                .into_iter()
                .take(MAX_SIGNATURES_PER_POLL)
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!("Failed to fetch signatures for {}: {}", agent_pubkey_str, e);
                continue;
            }
        };

        for sig_info in sigs {
            let sig = match sig_info.signature.parse::<Signature>() {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Fetch transaction details
            let tx = match rpc.get_transaction(&sig, UiTransactionEncoding::Json).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::trace!("Failed to fetch tx {}: {}", sig, e);
                    continue;
                }
            };

            // Extract external interacting wallets
            extract_external_wallets(&tx, &agent_pubkey_str, &mut agent_to_externals);
        }

        // Slight delay to avoid RPC rate limits
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 3. Build the graph and compute clusters
    let clusters = compute_clusters(&agent_to_externals);

    // 4. Update the state with the new clusters
    state.store.update_capital_flow_clusters(clusters).await?;

    tracing::info!("Capital flow indexing cycle complete.");

    Ok(())
}

/// Simple heuristic: Extract any wallet that is a signer or has balances changed,
/// excluding known system programs and the agent itself.
fn extract_external_wallets(
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    agent_pubkey: &str,
    agent_to_externals: &mut HashMap<String, HashSet<String>>,
) {
    let meta = match &tx.transaction.meta {
        Some(m) => m,
        None => return,
    };

    let message = match &tx.transaction.transaction {
        solana_transaction_status::EncodedTransaction::Json(ui_tx) => &ui_tx.message,
        _ => return, // Only handling JSON encoded for now
    };

    let _accounts = match message {
        UiMessage::Raw(raw) => &raw.account_keys,
        UiMessage::Parsed(_parsed) => {
            // We can extract keys from parsed instructions, but for simplicity we rely on meta
            // or just use pre_balances/post_balances to find real actors.
            &vec![] // Placeholder, better logic needed if parsed is used extensively
        }
    };

    // A very rough extraction: Look for accounts with balance changes
    // that are not the agent itself. This signifies a flow of capital.
    for (i, (pre, post)) in meta
        .pre_balances
        .iter()
        .zip(meta.post_balances.iter())
        .enumerate()
    {
        if pre != post {
            let acc = if let UiMessage::Raw(raw) = message {
                raw.account_keys.get(i).cloned()
            } else {
                // If parsed, we need to extract from account keys list
                None // Fallback
            };

            if let Some(acc_pubkey) = acc {
                if acc_pubkey != agent_pubkey && acc_pubkey != "11111111111111111111111111111111" {
                    agent_to_externals
                        .entry(agent_pubkey.to_string())
                        .or_default()
                        .insert(acc_pubkey);
                }
            }
        }
    }
}

/// Build an undirected bipartite-like graph (Agents <-> Externals) and find connected components.
/// Return lists of grouped agents.
fn compute_clusters(agent_to_externals: &HashMap<String, HashSet<String>>) -> Vec<Vec<String>> {
    let mut graph = UnGraph::<String, ()>::new_undirected();
    let mut node_indices = HashMap::new();

    // Add nodes and edges
    for (agent, externals) in agent_to_externals {
        let agent_idx = *node_indices
            .entry(agent.clone())
            .or_insert_with(|| graph.add_node(agent.clone()));

        for ext in externals {
            let ext_idx = *node_indices
                .entry(ext.clone())
                .or_insert_with(|| graph.add_node(ext.clone()));
            graph.add_edge(agent_idx, ext_idx, ());
        }
    }

    // Find connected components using Tarjan's or simple BFS
    // `petgraph`'s connected_components just returns the *number* of components.
    // To get the actual clusters, we need a simple traversal.

    let mut visited = HashSet::new();
    let mut clusters: Vec<Vec<String>> = Vec::new();

    for start_node in graph.node_indices() {
        if !visited.contains(&start_node) {
            let mut cluster_agents = Vec::new();
            let mut bfs = petgraph::visit::Bfs::new(&graph, start_node);

            while let Some(nx) = bfs.next(&graph) {
                visited.insert(nx);
                let weight = graph.node_weight(nx).unwrap().clone();

                // Only include the Agents in the final cluster output, not the external wallets
                if agent_to_externals.contains_key(&weight) {
                    cluster_agents.push(weight);
                }
            }

            if cluster_agents.len() > 1 {
                clusters.push(cluster_agents);
            }
        }
    }

    clusters
}
