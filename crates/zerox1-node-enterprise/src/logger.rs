use anyhow::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
use zerox1_protocol::{envelope::Envelope, hash::hash_merkle_leaf};

/// Append-only per-epoch CBOR envelope log (doc 5, §8.1).
///
/// Each entry is length-prefixed (4-byte LE u32) followed by CBOR envelope bytes.
/// At epoch end: flush to `zerox1-epoch-{N:06}.cbor`, return leaf hashes for merkle tree.
///
/// Leaf hash for each entry = keccak256(0x00 || CBOR bytes), used to build the merkle tree
/// that yields `log_merkle_root` in the BehaviorBatch.
pub struct EnvelopeLogger {
    log_dir: PathBuf,
    epoch: u64,
    leaf_hashes: Vec<[u8; 32]>,
    buffer: Vec<u8>,
    msg_count: u32,
}

impl EnvelopeLogger {
    pub fn new(log_dir: PathBuf, epoch: u64) -> Self {
        Self {
            log_dir,
            epoch,
            leaf_hashes: Vec::new(),
            buffer: Vec::new(),
            msg_count: 0,
        }
    }

    /// Log a validated envelope. Returns keccak256(0x00 || CBOR) = leaf hash.
    pub fn log(&mut self, env: &Envelope) -> Result<[u8; 32]> {
        let cbor = env.to_cbor()?;
        let leaf = hash_merkle_leaf(&cbor);

        let len = (cbor.len() as u32).to_le_bytes();
        self.buffer.extend_from_slice(&len);
        self.buffer.extend_from_slice(&cbor);
        self.leaf_hashes.push(leaf);
        self.msg_count += 1;

        Ok(leaf)
    }

    /// Flush in-memory buffer to disk.
    pub fn flush(&self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.log_dir)?;
        let path = self.epoch_path(self.epoch);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(&self.buffer)?;
        Ok(())
    }

    /// Flush current epoch to disk and reset for the next epoch.
    /// Returns the leaf hashes for merkle root computation.
    pub fn advance_epoch(&mut self, new_epoch: u64) -> Result<Vec<[u8; 32]>> {
        self.flush()?;
        let leaves = std::mem::take(&mut self.leaf_hashes);
        self.buffer.clear();
        self.epoch = new_epoch;
        self.msg_count = 0;
        Ok(leaves)
    }

    #[allow(dead_code)]
    pub fn leaf_hashes(&self) -> &[[u8; 32]] {
        &self.leaf_hashes
    }
    #[allow(dead_code)]
    pub fn message_count(&self) -> u32 {
        self.msg_count
    }
    #[allow(dead_code)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn epoch_path(&self, epoch: u64) -> PathBuf {
        self.log_dir.join(format!("zerox1-epoch-{epoch:06}.cbor"))
    }

    /// Read the log file for a past epoch and return all CBOR buffers.
    #[allow(dead_code)]
    pub fn read_epoch_log(log_dir: &Path, epoch: u64) -> Result<Vec<Vec<u8>>> {
        let path = log_dir.join(format!("zerox1-epoch-{epoch:06}.cbor"));
        let data = std::fs::read(&path)?;
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > data.len() {
                break;
            }
            entries.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        Ok(entries)
    }
}
