mod api;
mod batch;
mod config;
mod identity;
mod logger;
mod network;
mod node;
mod peer_state;
mod reputation;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_node_enterprise=info,libp2p=warn".parse().unwrap()),
        )
        .init();

    let config = config::Config::parse();
    let identity = identity::AgentIdentity::load_or_generate(&config.keypair_path)?;

    tracing::info!(
        agent_id = %hex::encode(identity.agent_id),
        "0x01 enterprise node starting",
    );

    let bootstrap_peers = config.all_bootstrap_peers();
    let mut swarm = network::build_swarm(
        identity.libp2p_keypair.clone(),
        config.listen_addr.clone(),
        &bootstrap_peers,
        config.relay_server,
    )?;

    // Mobile / NAT-restricted mode: listen on a circuit relay address so that
    // peers can reach this node through the relay even from behind CGNAT.
    if let Some(ref relay_addr) = config.relay_addr {
        match swarm.listen_on(relay_addr.clone()) {
            Ok(_) => tracing::info!("Listening on relay circuit: {relay_addr}"),
            Err(e) => tracing::warn!("Failed to listen on relay circuit {relay_addr}: {e}"),
        }
    }

    // Log the full multiaddr so operators can copy it into config.
    tracing::info!(
        peer_id = %swarm.local_peer_id(),
        listen  = %config.listen_addr,
        "0x01 enterprise bootstrap multiaddr: {}/p2p/{}",
        config.listen_addr,
        swarm.local_peer_id(),
    );

    // Explicitly dial bootstrap peers so the node joins the mesh immediately
    // rather than waiting for an inbound connection.
    for addr in &bootstrap_peers {
        if let Err(e) = swarm.dial(addr.clone()) {
            tracing::warn!("Failed to dial bootstrap peer {addr}: {e}");
        }
    }

    let mut node = node::Zx01Node::new(config, identity, bootstrap_peers).await?;
    node.run(&mut swarm).await
}
