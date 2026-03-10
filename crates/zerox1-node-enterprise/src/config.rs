use clap::Parser;
use libp2p::Multiaddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "zerox1-node-enterprise", about = "0x01 Enterprise mesh node")]
pub struct Config {
    /// libp2p listen multiaddr.
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    pub listen_addr: Multiaddr,

    /// Bootstrap peer multiaddrs (can repeat).
    /// Enterprise deployments specify their own internal bootstrap nodes.
    #[arg(long)]
    pub bootstrap: Vec<Multiaddr>,

    /// Disable the built-in bootstrap peers (no-op in enterprise — no public fleet).
    #[arg(long, default_value = "false")]
    pub no_default_bootstrap: bool,

    /// Display name for BEACON messages.
    /// If not set, defaults to the first 8 hex characters of the agent ID.
    #[arg(long, default_value = "")]
    pub agent_name: String,

    /// Path to the 32-byte Ed25519 secret key file.
    #[arg(long, default_value = "zerox1-identity.key")]
    pub keypair_path: PathBuf,

    /// Directory for per-epoch CBOR envelope logs.
    #[arg(long, default_value = ".")]
    pub log_dir: PathBuf,

    /// Visualization API listen address (HTTP + WebSocket).
    /// Enables: GET /peers, GET /reputation/:id, GET /batch/:id/:epoch, GET /ws/events
    /// Example: 127.0.0.1:8080
    /// If absent, the API server is not started.
    #[arg(long, env = "ZX01_API_ADDR")]
    pub api_addr: Option<String>,

    /// Master secret bearer token to authenticate the API (e.g. for /envelopes/send).
    /// If absent, the API routes that mutate state will be unauthenticated.
    #[arg(long, env = "ZX01_API_SECRET")]
    pub api_secret: Option<String>,

    /// Comma-separated read-only API keys for the visualization/explorer tier.
    /// These keys grant access to GET endpoints and WebSocket streams
    /// (/ws/events, /peers, /reputation, /batch, /ws/inbox) but NOT to
    /// mutating endpoints like /envelopes/send.
    /// Example: "explorer-abc123,devteam-xyz789"
    #[arg(long, env = "ZX01_API_READ_KEYS", value_delimiter = ',')]
    pub api_read_keys: Vec<String>,

    /// Comma-separated allowed CORS origins for the API server.
    /// Defaults to http://127.0.0.1 and http://localhost when unset.
    /// Set this when serving a web UI from a non-loopback origin.
    /// Example: "https://app.example.com,http://localhost:3000"
    #[arg(long, env = "ZX01_API_CORS_ORIGINS", value_delimiter = ',')]
    pub api_cors_origins: Vec<String>,

    /// Reputation aggregator URL.
    /// When set, FEEDBACK and VERDICT envelopes are pushed to this service.
    /// Example: http://127.0.0.1
    #[arg(long, env = "ZX01_AGGREGATOR_URL")]
    pub aggregator_url: Option<String>,

    /// Shared secret for authenticating pushes to the reputation aggregator.
    /// Must match the aggregator's --ingest-secret.
    #[arg(long, env = "ZX01_AGGREGATOR_SECRET")]
    pub aggregator_secret: Option<String>,

    /// Enable relay server mode.
    /// When set, this node accepts circuit relay reservations from peers so
    /// that NAT-restricted nodes (e.g. mobile phones) can project their
    /// presence through this node. Enable only on always-on infrastructure
    /// nodes — it consumes bandwidth proportional to the number of relayed circuits.
    #[arg(long, env = "ZX01_RELAY_SERVER", default_value = "false")]
    pub relay_server: bool,

    /// Circuit relay multiaddr to listen on.
    /// Used by mobile / NAT-restricted nodes to project their identity
    /// through a relay node.
    /// Format: /p2p/<RELAY_PEER_ID>/p2p-circuit
    #[arg(long, env = "ZX01_RELAY_ADDR")]
    pub relay_addr: Option<Multiaddr>,

    /// Firebase Cloud Messaging device token (for mobile / phone-as-node deployments).
    /// When set, this token is registered with the aggregator so that a push
    /// notification can wake the app when a PROPOSE arrives while offline.
    #[arg(long, env = "ZX01_FCM_TOKEN")]
    pub fcm_token: Option<String>,

    /// Enable hosting mode.
    /// When set, this node registers itself with the aggregator as a hosting
    /// provider and accepts hosted-agent sessions via the /hosted/* API.
    #[arg(long, env = "ZX01_HOSTING", default_value_t = false)]
    pub hosting: bool,

    /// Fee charged to hosted agents in basis points (1 bps = 0.01%).
    /// Only meaningful when --hosting is set.
    #[arg(long, env = "ZX01_HOSTING_FEE_BPS", default_value_t = 0)]
    pub hosting_fee_bps: u32,

    /// Public HTTP listen address for the hosted-agent API (e.g. "0.0.0.0:9091").
    /// Defaults to --api-addr when --hosting is set.
    #[arg(long, env = "ZX01_PUBLIC_API_ADDR")]
    pub public_api_addr: Option<String>,

    /// Public URL advertised in the aggregator so agents know how to reach this node.
    /// Example: "https://host.example.com:9091"
    #[arg(long, env = "ZX01_PUBLIC_API_URL")]
    pub public_api_url: Option<String>,

    /// Geographic region identifier for this node, used as a latency reference point.
    /// When set, the node measures RTT to every connected peer and reports it to the
    /// aggregator so agents' geo claims can be cross-checked.
    /// Intended for always-on infrastructure nodes (bootstrap / genesis fleet).
    /// Suggested values: "us-east", "eu-west". Set ZX01_NODE_REGION on genesis nodes.
    #[arg(long, env = "ZX01_NODE_REGION")]
    pub node_region: Option<String>,

    /// ISO 3166-1 alpha-2 country code advertised to the mesh (e.g. NG, DE, US).
    #[arg(long, env = "ZX01_GEO_COUNTRY")]
    pub geo_country: Option<String>,

    /// City name for geo-tagging (e.g. Lagos). Optional companion to geo_country.
    #[arg(long, env = "ZX01_GEO_CITY")]
    pub geo_city: Option<String>,

    /// Zeroclaw workspace directory. When set, enables POST /skill/write,
    /// POST /skill/install-url, POST /skill/remove, GET /skill/list — the
    /// skill management REST API used by the skill-manager built-in skill.
    #[arg(long, env = "ZX01_SKILL_WORKSPACE")]
    pub skill_workspace: Option<PathBuf>,
}

impl Config {
    /// Return the full bootstrap peer list (user-supplied only).
    /// Enterprise deployments manage their own private bootstrap fleet;
    /// there is no default public 0x01 fleet.
    pub fn all_bootstrap_peers(&self) -> Vec<Multiaddr> {
        self.bootstrap.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn base_config() -> Config {
        Config::try_parse_from(["zerox1-node-enterprise"]).expect("default config parses")
    }

    // --- all_bootstrap_peers ---

    #[test]
    fn bootstrap_empty_by_default() {
        let cfg = base_config();
        assert_eq!(cfg.all_bootstrap_peers().len(), 0);
    }

    #[test]
    fn bootstrap_returns_user_peers() {
        let cfg = Config::try_parse_from([
            "zerox1-node-enterprise",
            "--bootstrap",
            "/ip4/1.2.3.4/tcp/9000",
        ])
        .unwrap();
        assert_eq!(cfg.all_bootstrap_peers().len(), 1);
    }

    #[test]
    fn bootstrap_no_default_bootstrap_still_empty_without_user_peers() {
        let cfg =
            Config::try_parse_from(["zerox1-node-enterprise", "--no-default-bootstrap"]).unwrap();
        assert_eq!(cfg.all_bootstrap_peers().len(), 0);
    }
}
