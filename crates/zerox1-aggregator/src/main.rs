mod api;
mod store;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
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

    /// Maximum blob upload size in bytes.
    /// On a local enterprise network this can be set much higher than the public default.
    /// Default: 104857600 (100 MiB).
    #[arg(long, env = "AGGREGATOR_MAX_BLOB_SIZE", default_value_t = 100 * 1024 * 1024)]
    max_blob_size: usize,

    /// Comma-separated API keys for gating read endpoints.
    /// When set, all GET endpoints (reputation, leaderboard, agents, entropy,
    /// interactions, etc.) require `Authorization: Bearer <key>`.
    /// /health, /version, and internal POST endpoints (ingest, hosting) are exempt.
    /// When absent, all read endpoints are public (dev/local mode).
    /// Example: "explorer-abc123,devteam-xyz789,paid-client-001"
    #[arg(long, env = "AGGREGATOR_API_KEYS", value_delimiter = ',')]
    api_keys: Vec<String>,
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

    if config.hosting_secret.is_none() {
        tracing::warn!(
            "No --hosting-secret set. POST /hosting/register is unauthenticated. \
             Set AGGREGATOR_HOSTING_SECRET in production."
        );
    }

    let (activity_tx, _) = broadcast::channel::<ActivityEvent>(512);

    let max_blob_size = config.max_blob_size;

    let state = AppState {
        store,
        ingest_secret: config.ingest_secret,
        hosting_secret: config.hosting_secret,
        blob_dir: config.blob_dir,
        max_blob_size,
        activity_tx,
        api_keys: config.api_keys,
    };

    // ── Public routes (no API key required) ──────────────────────────────
    let public_routes = Router::new()
        .route("/health", get(api::health))
        .route("/version", get(api::get_version))
        // Internal push endpoints — use their own secrets
        .route("/ingest/envelope", post(api::ingest_envelope))
        .route("/hosting/register", post(api::post_hosting_register))
        // High-level public stats for the landing page
        .route("/stats/network", get(api::get_network_stats))
        .route("/agents", get(api::get_agents))
        // Mobile app read endpoints — must be public (mobile has no API key)
        .route("/agents/{agent_id}/profile", get(api::get_agent_profile))
        .route("/activity", get(api::get_activity))
        .route("/ws/activity", get(api::ws_activity))
        .route("/hosting/nodes", get(api::get_hosting_nodes))
        .route("/blobs/{cid}", get(api::get_blob))
        .route("/blobs/{cid}/meta", get(api::get_blob_meta))
        // Blob upload — Ed25519-authenticated, no API key required.
        // Body limit is set from --max-blob-size (default 100 MiB).
        .route(
            "/blobs",
            post(api::post_blob).layer(DefaultBodyLimit::max(max_blob_size)),
        );

    // ── API-key gated routes (read endpoints for explorer / dev team / paid clients) ──
    let gated_routes = Router::new()
        .route("/reputation/{agent_id}", get(api::get_reputation))
        .route("/leaderboard", get(api::get_leaderboard))
        .route("/interactions", get(api::get_interactions))
        .route("/stats/timeseries", get(api::get_timeseries))
        .route("/agents/search", get(api::search_agents))
        .route("/agents/search/name", get(api::search_agents_by_name))
        .route("/interactions/by/{agent_id}", get(api::get_interactions_by))
        .route("/registry", get(api::get_registry))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::api_key_middleware,
        ));

    let app = public_routes
        .merge(gated_routes)
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
