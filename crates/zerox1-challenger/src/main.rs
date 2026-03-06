//! zerox1-challenger — automated anomaly monitor and evidence accumulator.
//!
//! Polls the aggregator API for high-anomaly agents.  When an agent exceeds
//! the configured anomaly threshold for `--consecutive-epochs` consecutive
//! epochs it is promoted to "challenge-ready" status and a JSON evidence
//! report is written to stdout (and optionally to --output-dir).
//!
//! GAP-07: this daemon closes the loop between off-chain anomaly detection
//! and on-chain enforcement by preparing the evidence packages that a human
//! operator (or future automated signer) can use to submit challenge TXs.

mod monitor;
mod submit;

use clap::Parser;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::signature::{read_keypair_file, Keypair};

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "zerox1-challenger",
    about = "Automated anomaly monitor — accumulates challenge evidence for high-anomaly agents"
)]
pub struct Cli {
    /// URL of the zerox1 aggregator API.
    #[arg(
        long,
        default_value = "https://api.0x01.world",
        env = "ZX01_AGGREGATOR_URL"
    )]
    pub aggregator_url: String,

    /// Bearer token for the aggregator's ingest secret (read-only endpoints don't require it,
    /// but some deployments may require it for all routes).
    #[arg(long, env = "ZX01_AGGREGATOR_SECRET")]
    pub aggregator_secret: Option<String>,

    /// Anomaly score threshold above which an agent is considered suspicious (0.0–1.0).
    #[arg(long, default_value_t = 0.55)]
    pub anomaly_threshold: f64,

    /// Number of consecutive polling cycles an agent must exceed the threshold
    /// before being marked challenge-ready.
    #[arg(long, default_value_t = 3)]
    pub consecutive_epochs: u32,

    /// Rolling entropy window to query (number of epochs).
    #[arg(long, default_value_t = 10)]
    pub rolling_window: u32,

    /// Seconds between polls.
    #[arg(long, default_value_t = 60)]
    pub poll_interval_secs: u64,

    /// Directory to write per-agent evidence JSON files.
    /// If unset, evidence is only printed to stdout.
    #[arg(long)]
    pub output_dir: Option<std::path::PathBuf>,

    /// Maximum agents to pull from the anomaly leaderboard per cycle.
    #[arg(long, default_value_t = 100)]
    pub leaderboard_limit: usize,

    /// RPC URL for submitting challenge transactions.
    #[arg(
        long,
        default_value = "https://api.devnet.solana.com",
        env = "ZX01_RPC_URL"
    )]
    pub rpc_url: String,

    /// Path to the challenger's Solana keypair file for paying gas and staking USDC.
    #[arg(long, env = "ZX01_CHALLENGER_KEYPAIR")]
    pub keypair: Option<std::path::PathBuf>,

    /// Auto-submit on-chain challenges for highly anomalous agents. (Requires --keypair)
    #[arg(long)]
    pub auto_submit: bool,
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_challenger=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    if let Some(ref dir) = cli.output_dir {
        std::fs::create_dir_all(dir)?;
        tracing::info!("Evidence output directory: {}", dir.display());
    }

    tracing::info!(
        "zerox1-challenger starting. Aggregator: {} | threshold: {} | consecutive: {}",
        cli.aggregator_url,
        cli.anomaly_threshold,
        cli.consecutive_epochs,
    );

    let client = reqwest::Client::new();
    let mut mon = monitor::AgentMonitor::new(cli.anomaly_threshold, cli.consecutive_epochs);

    let mut keypair_signer: Option<Keypair> = None;
    if cli.auto_submit {
        match &cli.keypair {
            None => {
                tracing::error!("--auto-submit requires --keypair path");
                std::process::exit(1);
            }
            Some(path) => {
                if !path.exists() {
                    tracing::error!("Keypair file not found: {}", path.display());
                    std::process::exit(1);
                }
                tracing::info!(
                    "Auto-submit enabled. Loading keypair from {}",
                    path.display()
                );
                keypair_signer = Some(
                    read_keypair_file(path)
                        .map_err(|e| anyhow::anyhow!("Failed to read keypair: {}", e))?,
                );
            }
        }
    }

    let rpc_client = RpcClient::new(cli.rpc_url.clone());

    loop {
        if let Err(e) = monitor::run_cycle(
            &cli,
            &client,
            &mut mon,
            &rpc_client,
            keypair_signer.as_ref(),
        )
        .await
        {
            tracing::warn!("Poll cycle failed: {e}");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(cli.poll_interval_secs)).await;
    }
}
