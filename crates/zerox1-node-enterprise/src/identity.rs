use ed25519_dalek::{SigningKey, VerifyingKey};
use libp2p::identity;
use rand::rngs::OsRng;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Agent identity: Ed25519 signing key.
///
/// The same Ed25519 secret drives both 0x01 envelope signing
/// and the libp2p peer identity (doc 5 §4.1).
///
/// In enterprise mode the agent_id is always the Ed25519 verifying key bytes —
/// no on-chain registration required.
pub struct AgentIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    /// Agent ID = verifying_key bytes (Ed25519 public key, 32 bytes).
    pub agent_id: [u8; 32],
    /// libp2p keypair derived from the same Ed25519 secret.
    pub libp2p_keypair: identity::Keypair,
}

impl AgentIdentity {
    #[allow(dead_code)]
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let agent_id = verifying_key.to_bytes();
        let libp2p_keypair = to_libp2p_keypair(&signing_key);
        Self {
            signing_key,
            verifying_key,
            agent_id,
            libp2p_keypair,
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        // mode 0o600: owner read/write only — private key must never be world-readable.
        #[cfg(unix)]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&self.signing_key.to_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key file: expected 32 bytes"))?;
        Ok(Self::from_signing_key(SigningKey::from_bytes(&arr)))
    }

    pub fn load_or_generate(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let id = Self::load(path)?;
            tracing::info!(
                peer_id = %id.libp2p_keypair.public().to_peer_id(),
                agent_id = %hex::encode(id.agent_id),
                "Loaded identity from {:?}", path,
            );
            Ok(id)
        } else {
            let id = Self::from_signing_key(SigningKey::generate(&mut OsRng));
            id.save(path)?;
            tracing::info!(
                peer_id = %id.libp2p_keypair.public().to_peer_id(),
                agent_id = %hex::encode(id.agent_id),
                "Generated new identity, saved to {:?}", path,
            );
            Ok(id)
        }
    }

    #[allow(dead_code)]
    pub fn peer_id(&self) -> libp2p::PeerId {
        self.libp2p_keypair.public().to_peer_id()
    }
}

fn to_libp2p_keypair(signing_key: &SigningKey) -> identity::Keypair {
    let mut bytes = signing_key.to_bytes();
    let secret = identity::ed25519::SecretKey::try_from_bytes(&mut bytes)
        .expect("valid 32-byte ed25519 secret");
    identity::Keypair::from(identity::ed25519::Keypair::from(secret))
}
