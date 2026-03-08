//! 8004 Solana Agent Registry client for the aggregator.
//!
//! Queries the 8004 GraphQL indexer to check agent registration and ownership.
//! Ported from `zerox1-node/src/registry_8004.rs` — only the read-only client,
//! not the transaction building (that stays in zerox1-node).

use std::time::Duration;

const DEFAULT_INDEXER_URL: &str = "https://8004-indexer-production.up.railway.app/v2/graphql";

/// Client for the 8004 Solana Agent Registry GraphQL API.
///
/// Agents are stored as Metaplex Core NFTs.  The `owner` field equals the
/// agent's Solana pubkey (base58).  We query `agents(where: { owner: $b58 })`
/// to verify registration and resolve ownership.
#[derive(Clone)]
pub struct Registry8004Client {
    pub url: String,
    client: reqwest::Client,
    min_tier: u8,
}

impl Registry8004Client {
    pub fn new(url: Option<&str>, client: reqwest::Client, min_tier: u8) -> Self {
        Self {
            url: url.unwrap_or(DEFAULT_INDEXER_URL).to_string(),
            client,
            min_tier,
        }
    }

    /// Check if an agent (identified by base58 pubkey) is registered in 8004.
    pub async fn is_registered_b58(&self, agent_b58: &str) -> anyhow::Result<bool> {
        let (query, variables) = if self.min_tier > 0 {
            let q =
                "query($o:String!,$t:Int!){agents(first:1,where:{owner:$o,trustTier_gte:$t}){id}}";
            let v = serde_json::json!({ "o": agent_b58, "t": self.min_tier as i32 });
            (q, v)
        } else {
            let q = "query($o:String!){agents(first:1,where:{owner:$o}){id}}";
            let v = serde_json::json!({ "o": agent_b58 });
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

    /// Query 8004 registry for the owner of an agent asset.
    /// Returns the owner pubkey (base58) if the agent exists, None otherwise.
    pub async fn get_owner(&self, agent_b58: &str) -> anyhow::Result<Option<String>> {
        let query = "query($o:String!){agents(first:1,where:{owner:$o}){id owner}}";
        let variables = serde_json::json!({ "o": agent_b58 });
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

        let agents = data
            .get("data")
            .and_then(|d| d.get("agents"))
            .and_then(|a| a.as_array());

        match agents {
            Some(arr) if !arr.is_empty() => {
                let owner = arr[0]
                    .get("owner")
                    .and_then(|o| o.as_str())
                    .map(|s| s.to_string());
                Ok(owner)
            }
            _ => Ok(None),
        }
    }
}
