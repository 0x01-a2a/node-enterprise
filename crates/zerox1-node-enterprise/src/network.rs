use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, noise, ping, relay, request_response,
    swarm::NetworkBehaviour, tcp, yamux, StreamProtocol,
};
use std::io;
use std::time::Duration;
use zerox1_protocol::constants::MAX_MESSAGE_SIZE;

/// libp2p protocol string for bilateral 0x01 envelopes.
pub const BILATERAL_PROTOCOL: &str = "/0x01/bilateral/1.0.0";

// ============================================================================
// Combined behaviour
// ============================================================================

#[derive(NetworkBehaviour)]
pub struct Zx01Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub request_response: request_response::Behaviour<Zx01Codec>,
    /// Relay server — lets other nodes use this node as a relay.
    /// Active (max_reservations > 0) only when --relay-server is set.
    /// On regular nodes the limits are zeroed so no circuits are accepted.
    pub relay_server: relay::Behaviour,
    /// Relay client — lets this node project its presence through a relay.
    /// Always active; used by mobile nodes to receive connections via relay.
    pub relay_client: relay::client::Behaviour,
    /// Direct Connection Upgrade Through Relay — upgrades relay connections
    /// to direct connections when both peers are reachable via hole-punching.
    pub dcutr: dcutr::Behaviour,
    /// AutoNAT — probes external reachability; helps classify the node as
    /// publicly reachable, behind NAT, or unknown.
    pub autonat: autonat::Behaviour,
    /// Ping — measures round-trip latency to each connected peer.
    /// Used by reference nodes (--node-region) to report latency to the
    /// aggregator for geo plausibility checks.
    pub ping: ping::Behaviour,
}

// ============================================================================
// Length-prefixed request-response codec for bilateral envelopes
// ============================================================================

/// Simple 4-byte LE length prefix codec.
/// Request  = CBOR-encoded 0x01 envelope (Vec<u8>)
/// Response = 3-byte ACK b"ACK"
#[derive(Clone, Default)]
pub struct Zx01Codec;

#[async_trait]
impl request_response::Codec for Zx01Codec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_framed(io, MAX_MESSAGE_SIZE).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_framed(io, 64).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_framed(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_framed(io, &res).await
    }
}

async fn read_framed<T: AsyncRead + Unpin>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds limit",
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed<T: AsyncWrite + Unpin>(io: &mut T, data: &[u8]) -> io::Result<()> {
    io.write_all(&(data.len() as u32).to_le_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await
}

// ============================================================================
// Swarm builder
// ============================================================================

/// Build the libp2p swarm.
///
/// `is_relay_server` — when true (genesis/GCP nodes), this node accepts
/// circuit relay reservations from peers. When false (regular and mobile
/// nodes), the relay server limits are set to zero so no circuits are relayed,
/// but the relay client is still active for outbound relay use.
pub fn build_swarm(
    keypair: libp2p::identity::Keypair,
    listen_addr: libp2p::Multiaddr,
    bootstrap_peers: &[libp2p::Multiaddr],
    is_relay_server: bool,
) -> anyhow::Result<libp2p::Swarm<Zx01Behaviour>> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        // Android has no /etc/resolv.conf; fall back to Cloudflare DNS.
        // with_dns() reads the system resolver config and fails on Android with
        // "io error: No such file or directory".  with_dns_config() uses an
        // explicit resolver config and never touches the filesystem.
        .with_dns_config(
            libp2p::dns::ResolverConfig::cloudflare(),
            libp2p::dns::ResolverOpts::default(),
        )
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let peer_id = key.public().to_peer_id();

            let gossip_cfg = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(MAX_MESSAGE_SIZE)
                .build()
                .expect("static gossipsub config is valid");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossip_cfg,
            )
            .expect("gossipsub init");

            let mut kademlia = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
            kademlia.set_mode(Some(kad::Mode::Server));

            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>)?;

            let identify = identify::Behaviour::new(identify::Config::new(
                "/0x01/identify/1.0.0".to_string(),
                key.public(),
            ));

            let request_response = request_response::Behaviour::<Zx01Codec>::new(
                [(
                    StreamProtocol::new(BILATERAL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            // Relay server: active on genesis/GCP nodes; disabled elsewhere.
            let relay_cfg = if is_relay_server {
                relay::Config::default()
            } else {
                relay::Config {
                    max_reservations: 0,
                    max_circuits: 0,
                    ..Default::default()
                }
            };
            let relay_server = relay::Behaviour::new(peer_id, relay_cfg);

            let dcutr = dcutr::Behaviour::new(peer_id);
            let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
            let ping = ping::Behaviour::new(ping::Config::new());

            Ok(Zx01Behaviour {
                gossipsub,
                kademlia,
                mdns,
                identify,
                request_response,
                relay_server,
                relay_client,
                dcutr,
                autonat,
                ping,
            })
        })?
        .build();

    // Subscribe to all 0x01 pubsub topics.
    for topic_str in [
        zerox1_protocol::constants::TOPIC_BROADCAST,
        zerox1_protocol::constants::TOPIC_NOTARY,
        zerox1_protocol::constants::TOPIC_REPUTATION,
    ] {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(topic_str))?;
    }

    // Add bootstrap peers to Kademlia.
    for addr in bootstrap_peers {
        if let Some(peer_id) = addr.iter().find_map(|p| {
            if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                Some(pid)
            } else {
                None
            }
        }) {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, addr.clone());
        }
    }

    // Listen on TCP.
    swarm.listen_on(listen_addr.clone())?;

    // Also listen on QUIC (same IP, same port, UDP).
    // TCP and UDP can share the same port number without conflict.
    if let Some(quic_addr) = to_quic_addr(&listen_addr) {
        match swarm.listen_on(quic_addr.clone()) {
            Ok(_) => tracing::info!("Also listening on QUIC: {quic_addr}"),
            Err(e) => tracing::warn!("QUIC listen failed for {quic_addr}: {e}"),
        }
    }

    Ok(swarm)
}

/// Derive a QUIC listen address from a TCP listen address.
///
/// /ip4/X.X.X.X/tcp/PORT → /ip4/X.X.X.X/udp/PORT/quic-v1
/// Returns None if the address contains no /tcp component.
fn to_quic_addr(tcp_addr: &libp2p::Multiaddr) -> Option<libp2p::Multiaddr> {
    use libp2p::multiaddr::Protocol;
    let mut new_addr = libp2p::Multiaddr::empty();
    let mut found = false;
    for proto in tcp_addr.iter() {
        match proto {
            Protocol::Tcp(port) => {
                new_addr.push(Protocol::Udp(port));
                new_addr.push(Protocol::QuicV1);
                found = true;
            }
            other => new_addr.push(other),
        }
    }
    if found {
        Some(new_addr)
    } else {
        None
    }
}
