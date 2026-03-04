mod api;
mod capital_flow;
mod registry_8004;
mod store;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use clap::Parser;
use tokio::sync::broadcast;

use api::AppState;
use store::{ActivityEvent, ReputationStore};

#[derive(Parser, Debug)]
#[command(
    name = "zerox1-aggregator",
    about = "0x01 reputation aggregator service"
)]
struct Config {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:80", env = "AGGREGATOR_LISTEN")]
    listen: std::net::SocketAddr,

    /// Shared secret for POST /ingest/envelope.
    /// When set, requests must include `Authorization: Bearer <secret>`.
    /// Omit only in development / closed-network deployments.
    #[arg(long, env = "AGGREGATOR_INGEST_SECRET")]
    ingest_secret: Option<String>,

    /// Path to the SQLite database file for persistent reputation storage.
    /// If absent, data is in-memory only and lost on restart.
    /// Example: /var/lib/zerox1/reputation.db
    #[arg(long, env = "AGGREGATOR_DB_PATH")]
    db_path: Option<std::path::PathBuf>,

    /// Solana RPC URL for Capital Flow Correlation (GAP-02 Sybil deterrence).
    /// Used by the background indexer to fetch funding/sweep graphs.
    #[arg(long, env = "ZX01_SOLANA_RPC")]
    solana_rpc: Option<String>,

    /// Firebase Cloud Messaging server key for sending push notifications to
    /// sleeping phone nodes. Obtain from the Firebase project console under
    /// Project Settings → Cloud Messaging → Server key.
    /// When absent, the FCM push feature is disabled (token registration and
    /// sleep-state tracking still work, but no pushes are sent).
    #[arg(long, env = "FCM_SERVER_KEY")]
    fcm_server_key: Option<String>,

    /// Shared secret for POST /hosting/register.
    /// Host nodes must include `Authorization: Bearer <secret>` in their
    /// heartbeat requests. When absent, the endpoint is unauthenticated
    /// (dev/local only — always set this in production).
    #[arg(long, env = "AGGREGATOR_HOSTING_SECRET")]
    hosting_secret: Option<String>,

    /// Path to a directory for storing large media blobs.
    /// If absent, blob uploads are disabled.
    #[arg(long, env = "AGGREGATOR_BLOB_DIR")]
    blob_dir: Option<std::path::PathBuf>,

    /// 8004 Agent Registry GraphQL indexer URL.
    /// Defaults to the production indexer at Railway.
    #[arg(long, env = "ZX01_REGISTRY_8004_URL")]
    registry_8004_url: Option<String>,

    /// Minimum trust tier for 8004 registry checks (0-4).
    /// Agents below this tier are treated as unregistered.
    #[arg(long, default_value = "0", env = "ZX01_REGISTRY_8004_MIN_TIER")]
    registry_8004_min_tier: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_aggregator=info".parse().unwrap()),
        )
        .init();

    let config = Config::parse();

    if config.ingest_secret.is_none() {
        tracing::warn!(
            "No --ingest-secret set. POST /ingest/envelope is unauthenticated. \
             Set AGGREGATOR_INGEST_SECRET in production."
        );
    }

    let store = match config.db_path.as_ref() {
        Some(path) => ReputationStore::with_db(path)?,
        None => {
            tracing::warn!(
                "No --db-path set. Reputation data is in-memory only and \
                 will be lost on restart. Set AGGREGATOR_DB_PATH in production."
            );
            ReputationStore::new()
        }
    };

    if config.fcm_server_key.is_none() {
        tracing::info!(
            "No --fcm-server-key set. FCM push notifications are disabled. \
             Token registration and sleep-state tracking still work."
        );
    }

    if config.hosting_secret.is_none() {
        tracing::warn!(
            "No --hosting-secret set. POST /hosting/register is unauthenticated. \
             Set AGGREGATOR_HOSTING_SECRET in production."
        );
    }

    let (activity_tx, _) = broadcast::channel::<ActivityEvent>(512);

    let http_client = reqwest::Client::new();
    let registry = registry_8004::Registry8004Client::new(
        config.registry_8004_url.as_deref(),
        http_client.clone(),
        config.registry_8004_min_tier,
    );

    tracing::info!(
        "8004 registry client configured: url={} min_tier={}",
        registry.url,
        config.registry_8004_min_tier,
    );

    let state = AppState {
        store,
        ingest_secret: config.ingest_secret,
        hosting_secret: config.hosting_secret,
        blob_dir: config.blob_dir,
        fcm_server_key: config.fcm_server_key,
        http_client,
        activity_tx,
        registry,
    };

    if let Some(rpc_url) = config.solana_rpc {
        tracing::info!(
            "Starting Capital Flow indexer (GAP-02) using RPC: {}",
            rpc_url
        );
        let indexer_state = state.clone();
        tokio::spawn(async move {
            capital_flow::run_indexer(rpc_url, indexer_state).await;
        });
    } else {
        tracing::info!("No --solana-rpc provided - Capital Flow analysis (GAP-02) disabled.");
    }

    let app = Router::new()
        .route("/health", get(api::health))
        .route("/version", get(api::get_version))
        .route("/stats/network", get(api::get_network_stats))
        .route("/ingest/envelope", post(api::ingest_envelope))
        .route("/reputation/{agent_id}", get(api::get_reputation))
        .route("/leaderboard", get(api::get_leaderboard))
        .route("/agents", get(api::get_agents))
        .route("/leaderboard/anomaly", get(api::get_anomaly_leaderboard))
        .route("/interactions", get(api::get_interactions))
        .route("/stats/timeseries", get(api::get_timeseries))
        .route("/entropy/{agent_id}", get(api::get_entropy))
        .route("/entropy/{agent_id}/history", get(api::get_entropy_history))
        .route("/entropy/{agent_id}/rolling", get(api::get_rolling_entropy))
        .route(
            "/leaderboard/verifier-concentration",
            get(api::get_verifier_concentration),
        )
        .route(
            "/leaderboard/ownership-clusters",
            get(api::get_ownership_clusters),
        )
        .route("/params/calibrated", get(api::get_calibrated_params))
        .route("/system/sri", get(api::get_sri_status))
        .route("/stake/required/{agent_id}", get(api::get_required_stake))
        .route("/graph/flow", get(api::get_flow_graph))
        .route("/graph/clusters", get(api::get_flow_clusters))
        .route("/graph/agent/{agent_id}", get(api::get_agent_flow))
        .route(
            "/epochs/{agent_id}/{epoch}/envelopes",
            get(api::get_epoch_envelopes),
        )
        .route("/agents/search", get(api::search_agents))
        .route("/agents/search/name", get(api::search_agents_by_name))
        .route("/agents/{agent_id}/profile", get(api::get_agent_profile))
        .route("/interactions/by/{agent_id}", get(api::get_interactions_by))
        .route("/disputes/{agent_id}", get(api::get_disputes))
        .route("/registry", get(api::get_registry))
        .route("/fcm/register", post(api::fcm_register))
        .route("/fcm/sleep", post(api::fcm_sleep))
        .route("/agents/{agent_id}/sleeping", get(api::get_sleep_status))
        .route(
            "/agents/{agent_id}/pending",
            get(api::get_pending).post(api::post_pending),
        )
        .route("/activity", get(api::get_activity))
        .route("/ws/activity", get(api::ws_activity))
        .route("/hosting/register", post(api::post_hosting_register))
        .route("/hosting/nodes", get(api::get_hosting_nodes))
        .route(
            "/agents/{agent_id}/propose-owner",
            post(api::post_propose_owner),
        )
        .route(
            "/agents/{agent_id}/claim-owner",
            post(api::post_claim_owner),
        )
        .route("/agents/{agent_id}/owner", get(api::get_agent_owner))
        // Blob routes carry a hard body cap so the tier check never has to
        // buffer a multi-GB payload before rejecting it.  Max tier is 10 MB.
        .route(
            "/blobs",
            post(api::post_blob).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/blobs/{cid}", get(api::get_blob))
        // INFO-2: Allow any origin but deny credential sharing (no allow_credentials).
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        )
        .with_state(state);

    tracing::info!("zerox1-aggregator listening on {}", config.listen);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
