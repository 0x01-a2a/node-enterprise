use clap::Parser;
use libp2p::Multiaddr;
use solana_sdk::pubkey::Pubkey;
use std::{path::PathBuf, str::FromStr};

// ============================================================================
// 0x01 bootstrap fleet (always-on libp2p nodes for mesh entry)
// ============================================================================
//
// These multiaddrs must be updated when the bootstrap fleet is deployed.
const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[
    // bootstrap-1.0x01.world (US Central)
    "/dns4/bootstrap-1.0x01.world/tcp/9000/p2p/12D3KooWLudabD69eAYzfoZMVRqJb8XHBLDKsQvRn6Q9hTQqvMuY",
    // bootstrap-2.0x01.world (EU West)
    "/dns4/bootstrap-2.0x01.world/tcp/9000/p2p/12D3KooWMXSCZEjjqBnLXhT2TVWde9w6VU2cZixR6D8CxvHeKts2",
    // bootstrap-3.0x01.world (Africa South)
    "/dns4/bootstrap-3.0x01.world/tcp/9000/p2p/12D3KooWAPecZv1ipAGYAZ5bKKNHN6CXdWyLioxbNTXh3y2eBgq3",
    // bootstrap-4.0x01.world (Asia Southeast)
    "/dns4/bootstrap-4.0x01.world/tcp/9000/p2p/12D3KooWCegSAXiTZkCAK7CTFE9oczDRrRBBEBWd4iaHkiRxvraz",
];

#[derive(Parser, Debug)]
#[command(name = "zerox1-node", about = "0x01 mesh node (doc 5, §9)")]
pub struct Config {
    /// libp2p listen multiaddr.
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    pub listen_addr: Multiaddr,

    /// Bootstrap peer multiaddrs (can repeat).
    /// The 0x01 bootstrap fleet is used by default; pass --no-default-bootstrap
    /// if you want to run a fully isolated private mesh.
    #[arg(long)]
    pub bootstrap: Vec<Multiaddr>,

    /// Disable the built-in 0x01 bootstrap peers.
    /// By default, the node connects to the 0x01 always-on bootstrap fleet so
    /// agents can find each other without any manual configuration.
    #[arg(long, default_value = "false")]
    pub no_default_bootstrap: bool,

    /// Solana RPC endpoint for slot queries and batch submission.
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    pub rpc_url: String,

    /// SATI mint address (hex, 32 bytes) = this agent's ID.
    /// If absent, the node runs in dev mode with agent_id = verifying_key bytes.
    #[arg(long, env = "ZX01_SATI_MINT")]
    pub sati_mint: Option<String>,

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

    /// Kora paymaster URL for gasless on-chain transactions (USDC gas payment).
    /// Defaults to the 0x01-hosted Kora instance.
    /// Override with --kora-url to use your own node, or set to "none" to
    /// disable Kora entirely (transactions will require SOL for gas).
    #[arg(long, env = "ZX01_KORA_URL", default_value = "https://kora.0x01.world")]
    pub kora_url: String,

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
    /// Example: "https://app.0x01.world,http://localhost:3000"
    #[arg(long, env = "ZX01_API_CORS_ORIGINS", value_delimiter = ',')]
    pub api_cors_origins: Vec<String>,

    /// USDC SPL token mint address (base58).
    /// Required for inactivity slash enforcement — enables the node to receive
    /// slash bounties into its USDC ATA.
    #[arg(long, env = "ZX01_USDC_MINT")]
    pub usdc_mint: Option<String>,

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
    /// nodes (GCP genesis fleet) — it consumes bandwidth proportional to
    /// the number of relayed circuits.
    #[arg(long, env = "ZX01_RELAY_SERVER", default_value = "false")]
    pub relay_server: bool,

    /// Circuit relay multiaddr to listen on.
    /// Used by mobile / NAT-restricted nodes to project their identity
    /// through a relay node (typically a genesis bootstrap node).
    /// Format: /p2p/<RELAY_PEER_ID>/p2p-circuit
    /// Example: /p2p/12D3KooWLudabD69eAYzfoZMVRqJb8XHBLDKsQvRn6Q9hTQqvMuY/p2p-circuit
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

    /// GraphQL endpoint for the 8004 Solana Agent Registry (primary registration gate).
    ///
    /// Agents registered in the 8004 registry are verified by querying their
    /// owner pubkey (= base58 of their Ed25519 agent_id bytes) against this
    /// indexer — no Solana RPC required.  SATI remains as a legacy fallback.
    ///
    /// Devnet default; set ZX01_REGISTRY_8004_URL to the mainnet endpoint
    /// (https://8004.qnt.sh/v2/graphql) on mainnet deployments.
    #[arg(
        long,
        env = "ZX01_REGISTRY_8004_URL",
        default_value = "https://8004-indexer-production.up.railway.app/v2/graphql"
    )]
    pub registry_8004_url: String,

    /// Disable the 8004 registry check and use SATI-only mode.
    /// Legacy flag for operators who prefer the SATI SPL-mint gate.
    #[arg(long, env = "ZX01_REGISTRY_8004_DISABLED", default_value_t = false)]
    pub registry_8004_disabled: bool,

    /// Minimum 8004 trust tier required for a peer to pass the gate (0–4).
    /// Tier 0 = any registered agent; tier 1+ = at least one confirmed feedback.
    #[arg(long, env = "ZX01_REGISTRY_8004_MIN_TIER", default_value_t = 0u8)]
    pub registry_8004_min_tier: u8,

    /// Base collection address for the 8004 registry (base58 Solana pubkey).
    /// Devnet collection is hardcoded. Set this for mainnet deployments.
    /// Value of `C6W2...` (devnet) is the default and need not be set on devnet.
    #[arg(long, env = "ZX01_REGISTRY_8004_COLLECTION")]
    pub registry_8004_collection: Option<String>,

    /// Agent IDs (hex) that are exempt from lease and registration checks.
    /// Can be specified multiple times or as a comma-separated list. Used for infrastructure bots (like Guardian).
    #[arg(long, env = "ZX01_EXEMPT_AGENTS", value_delimiter = ',')]
    pub exempt_agents: Vec<String>,

    /// Bags fee-sharing: basis points of each swap output / escrow settlement to
    /// route to the Bags distribution contract. 0 = disabled. Max 500 (5%).
    #[cfg(feature = "bags")]
    #[arg(long, env = "ZX01_BAGS_FEE_BPS", default_value_t = 0)]
    pub bags_fee_bps: u16,

    /// Bags distribution wallet (base58 Solana pubkey).
    /// If omitted, the address is resolved from the Bags API at startup.
    #[cfg(feature = "bags")]
    #[arg(long, env = "ZX01_BAGS_WALLET")]
    pub bags_wallet: Option<String>,

    /// Bags API base URL used to resolve the distribution wallet when
    /// --bags-wallet is not set.
    #[cfg(feature = "bags")]
    #[arg(long, env = "ZX01_BAGS_API_URL", default_value = "https://api.bags.fm")]
    pub bags_api_url: String,

    /// Bags.fm API key for the token-launch endpoints.
    /// Required to use POST /bags/launch, POST /bags/claim, GET /bags/positions.
    /// Obtain from bags.fm — free tier allows 1 000 requests/hr.
    #[cfg(feature = "bags")]
    #[arg(long, env = "ZX01_BAGS_API_KEY")]
    pub bags_api_key: Option<String>,

    /// Optional Bags partner key for partner-attributed launches.
    /// When set, the launch client includes partner metadata on token launch
    /// requests and the node skips the legacy post-claim SOL protocol fee skim.
    #[cfg(feature = "bags")]
    #[arg(long, env = "ZX01_BAGS_PARTNER_KEY")]
    pub bags_partner_key: Option<String>,

    /// Solana RPC endpoint for trading operations (Jupiter swaps, Bags fee distribution,
    /// USDC hot-wallet sweep).  Defaults to mainnet so financial operations are always
    /// on the real network regardless of the mesh --rpc-url (which defaults to devnet).
    ///
    /// Override with ZX01_TRADE_RPC_URL to use a paid RPC (Helius, QuickNode, etc.).
    #[arg(
        long,
        env = "ZX01_TRADE_RPC_URL",
        default_value = "https://api.mainnet-beta.solana.com"
    )]
    pub trade_rpc_url: String,

    /// Zeroclaw workspace directory. When set, enables POST /skill/write,
    /// POST /skill/install-url, POST /skill/remove, GET /skill/list — the
    /// skill management REST API used by the skill-manager built-in skill.
    /// On Android this is set to {filesDir}/zw by NodeService.
    #[arg(long, env = "ZX01_SKILL_WORKSPACE")]
    pub skill_workspace: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn base_config() -> Config {
        Config::try_parse_from(["zerox1-node"]).expect("default config parses")
    }

    // --- sati_mint_bytes ---

    #[test]
    fn sati_mint_bytes_none_when_absent() {
        assert!(base_config().sati_mint_bytes().unwrap().is_none());
    }

    #[test]
    fn sati_mint_bytes_parses_base58() {
        // Devnet USDC mint — well-known 32-byte pubkey
        let mut cfg = base_config();
        cfg.sati_mint = Some("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string());
        let bytes = cfg.sati_mint_bytes().unwrap().unwrap();
        assert_eq!(bytes.len(), 32);
        // Round-trip: bytes should match bs58 decode of the same string
        let expected = bs58::decode("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            .into_vec()
            .unwrap();
        assert_eq!(&bytes[..], expected.as_slice());
    }

    #[test]
    fn sati_mint_bytes_parses_64_char_hex() {
        let mut cfg = base_config();
        cfg.sati_mint = Some("aa".repeat(32)); // 64 hex chars = 32 bytes
        let bytes = cfg.sati_mint_bytes().unwrap().unwrap();
        assert_eq!(bytes, [0xaa_u8; 32]);
    }

    #[test]
    fn sati_mint_bytes_parses_0x_prefixed_hex() {
        let mut cfg = base_config();
        cfg.sati_mint = Some(format!("0x{}", "bb".repeat(32)));
        let bytes = cfg.sati_mint_bytes().unwrap().unwrap();
        assert_eq!(bytes, [0xbb_u8; 32]);
    }

    #[test]
    fn sati_mint_bytes_rejects_invalid_base58() {
        let mut cfg = base_config();
        cfg.sati_mint = Some("not!valid@address".to_string());
        assert!(cfg.sati_mint_bytes().is_err());
    }

    #[test]
    fn sati_mint_bytes_rejects_wrong_length_hex() {
        let mut cfg = base_config();
        // 0x-prefix → hex path, but only 16 bytes → should fail try_into
        cfg.sati_mint = Some(format!("0x{}", "aa".repeat(16)));
        assert!(cfg.sati_mint_bytes().is_err());
    }

    #[test]
    fn sati_mint_bytes_whitespace_trimmed() {
        let mut cfg = base_config();
        cfg.sati_mint = Some(format!("  {}  ", "cc".repeat(32)));
        let bytes = cfg.sati_mint_bytes().unwrap().unwrap();
        assert_eq!(bytes, [0xcc_u8; 32]);
    }

    // --- all_bootstrap_peers ---

    #[test]
    fn bootstrap_returns_4_defaults_by_default() {
        let cfg = base_config();
        assert_eq!(cfg.all_bootstrap_peers().len(), 4);
    }

    #[test]
    fn bootstrap_empty_when_no_default_bootstrap() {
        let cfg = Config::try_parse_from(["zerox1-node", "--no-default-bootstrap"]).unwrap();
        assert_eq!(cfg.all_bootstrap_peers().len(), 0);
    }

    #[test]
    fn bootstrap_merges_user_peer_with_defaults() {
        let cfg = Config::try_parse_from([
            "zerox1-node",
            "--bootstrap",
            "/ip4/1.2.3.4/tcp/9000",
        ])
        .unwrap();
        // 1 user peer + 4 defaults
        assert_eq!(cfg.all_bootstrap_peers().len(), 5);
    }

    #[test]
    fn bootstrap_user_peer_only_when_no_defaults() {
        let cfg = Config::try_parse_from([
            "zerox1-node",
            "--no-default-bootstrap",
            "--bootstrap",
            "/ip4/1.2.3.4/tcp/9000",
        ])
        .unwrap();
        assert_eq!(cfg.all_bootstrap_peers().len(), 1);
    }

    // --- usdc_mint_pubkey ---

    #[test]
    fn usdc_mint_pubkey_none_when_absent() {
        assert!(base_config().usdc_mint_pubkey().unwrap().is_none());
    }

    #[test]
    fn usdc_mint_pubkey_parses_devnet_address() {
        let cfg = Config::try_parse_from([
            "zerox1-node",
            "--usdc-mint",
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        ])
        .unwrap();
        let pk = cfg.usdc_mint_pubkey().unwrap().unwrap();
        assert_eq!(pk.to_string(), "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
    }

    #[test]
    fn usdc_mint_pubkey_rejects_garbage() {
        let mut cfg = base_config();
        cfg.usdc_mint = Some("not-a-valid-pubkey!!!".to_string());
        assert!(cfg.usdc_mint_pubkey().is_err());
    }
}

impl Config {
    /// Return the full bootstrap peer list: user-supplied + default fleet
    /// (unless --no-default-bootstrap is set).
    pub fn all_bootstrap_peers(&self) -> Vec<Multiaddr> {
        let mut peers = self.bootstrap.clone();
        if !self.no_default_bootstrap {
            for addr_str in DEFAULT_BOOTSTRAP_PEERS {
                match addr_str.parse::<Multiaddr>() {
                    Ok(addr) => peers.push(addr),
                    Err(e) => tracing::warn!("Invalid default bootstrap addr '{addr_str}': {e}"),
                }
            }
        }
        peers
    }

    /// Parse USDC mint as Pubkey, if provided.
    pub fn usdc_mint_pubkey(&self) -> anyhow::Result<Option<Pubkey>> {
        match &self.usdc_mint {
            None => Ok(None),
            Some(s) => Ok(Some(
                Pubkey::from_str(s).map_err(|e| anyhow::anyhow!("invalid usdc_mint: {e}"))?,
            )),
        }
    }

    /// Parse SATI mint from a Solana address string to bytes32, if provided.
    ///
    /// Accepts both formats:
    ///   - base58  (standard Solana format, what `create-sati-agent publish` outputs)
    ///     e.g. "2LETZxjxSpEZzHM42Fp6RYrcuxtjLytdVUSgGVAbVrqi"
    ///   - hex (legacy / manual usage)
    ///     e.g. "0xabcdef..." or "abcdef..."
    pub fn sati_mint_bytes(&self) -> anyhow::Result<Option<[u8; 32]>> {
        match &self.sati_mint {
            None => Ok(None),
            Some(s) => {
                let s = s.trim();
                // Discriminate by prefix or length:
                //   "0x..."  → explicit hex
                //   64 chars → hex (32 bytes)
                //   anything else → base58 (standard Solana pubkey, 43-44 chars)
                // Length is more reliable than char-set inspection because a
                // base58 address whose characters happen to all be 0-9/a-f
                // would be wrongly decoded as hex if we used char checks.
                let bytes = if s.starts_with("0x") || s.len() == 64 {
                    // Hex path: strip optional "0x" prefix.
                    hex::decode(s.trim_start_matches("0x"))
                        .map_err(|e| anyhow::anyhow!("invalid sati_mint hex: {e}"))?
                } else {
                    // Base58 path: standard Solana pubkey format.
                    bs58::decode(s)
                        .into_vec()
                        .map_err(|e| anyhow::anyhow!("invalid sati_mint base58: {e}"))?
                };
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    anyhow::anyhow!("sati_mint must be 32 bytes (got a wrong-length address)")
                })?;
                Ok(Some(arr))
            }
        }
    }
}
