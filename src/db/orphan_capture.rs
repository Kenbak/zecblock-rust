//! Experimental durable capture of node-validated non-finalized blocks.
//!
//! This journal never reads or writes PostgreSQL. It is not an orphan-rate
//! source yet: "non-canonical at check" is a reversible observation. Full
//! consensus verification is the serving node's responsibility; decoding and
//! hash checks here establish payload integrity, not independent validity.

use super::grpc::proto::{indexer_client::IndexerClient, Empty, NonFinalizedStateChangeRequest};
use super::ZebraRpc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic::transport::Endpoint;
use zakura_chain::block::{Block, MAX_BLOCK_BYTES};
use zakura_chain::serialization::ZcashDeserialize;

const MAX_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const QUEUE_BLOCKS: usize = 8;
const MAX_META_BYTES: usize = 4096;
const MAGIC: &[u8; 8] = b"CSCAP001";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub hash: String,
    pub parent: String,
    pub height: u32,
    pub header_time: i64,
    pub received_at_ms: u64,
    pub raw_bytes: usize,
    pub receipt_session: Option<String>,
    pub receipt_order: Option<u64>,
}

fn decode(
    message: &super::grpc::proto::BlockAndHash,
    received_at_ms: u64,
    session: Option<String>,
) -> Result<Evidence, String> {
    if message.hash.len() != 32
        || message.data.is_empty()
        || message.data.len() > MAX_BLOCK_BYTES as usize
    {
        return Err("invalid capture payload bounds".into());
    }
    let mut reader = std::io::Cursor::new(message.data.as_slice());
    let block =
        Block::zcash_deserialize(&mut reader).map_err(|_| "capture block decoding failed")?;
    if reader.position() != message.data.len() as u64
        || block.hash().to_string() != hex::encode(&message.hash)
    {
        return Err("capture payload hash/length mismatch".into());
    }
    Ok(Evidence {
        hash: block.hash().to_string(),
        parent: block.header.previous_block_hash.to_string(),
        height: block
            .coinbase_height()
            .ok_or("capture missing coinbase height")?
            .0,
        header_time: block.header.time.timestamp(),
        received_at_ms,
        raw_bytes: message.data.len(),
        receipt_session: session,
        receipt_order: message.receipt_order,
    })
}

#[derive(Default, Serialize, Deserialize)]
struct Health {
    network: String,
    started_at_ms: u64,
    updated_at_ms: u64,
    connected: bool,
    // A retained replay is not proof that all blocks during an outage survived.
    coverage: String,
    gaps: u64,
    last_gap: Option<String>,
    last_gap_at_ms: Option<u64>,
    connections: u64,
    heads: Vec<String>,
    receipt_session: Option<String>,
}

struct Journal {
    directory: PathBuf,
    _lock: std::fs::File,
    health: Health,
    records: HashMap<String, Evidence>,
    bytes: u64,
    max_bytes: u64,
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|e| format!("capture file open: {e}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("capture file sync: {e}"))?;
        std::fs::rename(&temporary, path).map_err(|e| format!("capture rename: {e}"))?;
        std::fs::File::open(path.parent().ok_or("capture path has no directory")?)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("capture directory sync: {e}"))
    })();
    if result.is_err() {
        // A failed write must not accumulate unaccounted temporary payloads.
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

impl Journal {
    fn open(directory: &Path, network: &str, max_bytes: u64) -> Result<Self, String> {
        std::fs::create_dir_all(directory).map_err(|e| format!("capture directory: {e}"))?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("collector.lock"))
            .map_err(|e| format!("capture lock: {e}"))?;
        lock.try_lock()
            .map_err(|_| "capture journal already in use")?;
        let health_path = directory.join("health.json");
        let mut health = if health_path.exists() {
            if std::fs::metadata(&health_path)
                .map_err(|e| e.to_string())?
                .len()
                > 65536
            {
                return Err("capture health oversized".into());
            }
            let bytes = std::fs::read(&health_path).map_err(|e| format!("capture health: {e}"))?;
            if bytes.len() > 65536 {
                return Err("capture health oversized".into());
            }
            let health: Health =
                serde_json::from_slice(&bytes).map_err(|_| "capture health corrupt")?;
            if health.network != network {
                return Err("capture journal network mismatch".into());
            }
            health
        } else {
            Health {
                network: network.into(),
                started_at_ms: now_ms(),
                coverage: "unverified".into(),
                ..Health::default()
            }
        };
        health.connected = false;
        let mut records = HashMap::new();
        let mut bytes = 0;
        for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().extension().is_some_and(|e| e == "tmp") {
                let name = entry.file_name();
                let stem = entry
                    .path()
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .map(str::to_owned)
                    .unwrap_or_default();
                if stem == "health"
                    || (stem.len() == 64 && stem.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    std::fs::remove_file(entry.path())
                        .map_err(|_| "capture partial file cleanup failed")?;
                } else {
                    return Err(format!("unrecognized capture temporary file: {name:?}"));
                }
                continue;
            }
            if entry.path().extension().is_none_or(|e| e != "capture") {
                continue;
            }
            if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
                return Err("capture record is not a file".into());
            }
            let size = entry.metadata().map_err(|e| e.to_string())?.len();
            bytes += size;
            if size > MAX_BLOCK_BYTES + MAX_META_BYTES as u64 + 12
                || bytes > max_bytes
                || records.len() >= MAX_RECORDS
            {
                return Err("capture journal exceeds configured bounds".into());
            }
            let mut f = std::fs::File::open(entry.path()).map_err(|e| e.to_string())?;
            let mut header = [0; 12];
            f.read_exact(&mut header)
                .map_err(|_| "capture record truncated")?;
            let meta_len = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
            if &header[..8] != MAGIC || meta_len > MAX_META_BYTES {
                return Err("capture record header corrupt".into());
            }
            let mut meta = vec![0; meta_len];
            f.read_exact(&mut meta)
                .map_err(|_| "capture metadata truncated")?;
            let evidence: Evidence =
                serde_json::from_slice(&meta).map_err(|_| "capture metadata corrupt")?;
            if evidence.raw_bytes > MAX_BLOCK_BYTES as usize {
                return Err("capture recorded payload oversized".into());
            }
            if size != 12 + meta_len as u64 + evidence.raw_bytes as u64
                || entry.file_name().to_str() != Some(&format!("{}.capture", evidence.hash))
            {
                return Err("capture record identity/size mismatch".into());
            }
            // Verify previously committed raw data too; a corrupt file is not a resume checkpoint.
            let mut raw = Vec::with_capacity(evidence.raw_bytes);
            f.read_to_end(&mut raw).map_err(|e| e.to_string())?;
            let message = super::grpc::proto::BlockAndHash {
                hash: hex::decode(&evidence.hash).map_err(|_| "capture hash corrupt")?,
                data: raw,
                receipt_order: evidence.receipt_order,
            };
            let decoded = decode(
                &message,
                evidence.received_at_ms,
                evidence.receipt_session.clone(),
            )?;
            if decoded.parent != evidence.parent
                || decoded.height != evidence.height
                || decoded.header_time != evidence.header_time
            {
                return Err("capture metadata/payload mismatch".into());
            }
            records.insert(evidence.hash.clone(), evidence);
        }
        let mut journal = Self {
            directory: directory.into(),
            _lock: lock,
            health,
            records,
            bytes,
            max_bytes,
        };
        // Files may have committed before a crash prevented checkpoint persistence.
        let recovered: Vec<_> = journal.records.values().cloned().collect();
        for evidence in recovered {
            journal.advance_head(&evidence);
        }
        journal.gap("startup: historical and interrupted collection coverage unverified")?;
        Ok(journal)
    }

    fn save_health(&mut self) -> Result<(), String> {
        self.health.updated_at_ms = now_ms();
        let bytes = serde_json::to_vec_pretty(&self.health).map_err(|e| e.to_string())?;
        if bytes.len() > 65536 {
            return Err("capture health exceeds capacity".into());
        }
        atomic_write(&self.directory.join("health.json"), &bytes)
    }

    fn gap(&mut self, reason: &str) -> Result<(), String> {
        self.health.gaps += 1;
        self.health.last_gap = Some(reason.chars().take(256).collect());
        self.health.last_gap_at_ms = Some(now_ms());
        self.save_health()
    }

    fn advance_head(&mut self, evidence: &Evidence) {
        self.health
            .heads
            .retain(|hash| hash != &evidence.parent && hash != &evidence.hash);
        if !self
            .records
            .values()
            .any(|record| record.parent == evidence.hash)
        {
            self.health.heads.push(evidence.hash.clone());
        }
        // Refuse excess heads at subscription time; never silently discard a fork.
    }

    fn store(&mut self, evidence: Evidence, raw: &[u8]) -> Result<bool, String> {
        if self.records.contains_key(&evidence.hash) {
            return Ok(false);
        }
        let metadata = serde_json::to_vec(&evidence).map_err(|e| e.to_string())?;
        if metadata.len() > MAX_META_BYTES {
            return Err("capture metadata too large".into());
        }
        let size = 12 + metadata.len() as u64 + raw.len() as u64;
        if self.bytes + size > self.max_bytes || self.records.len() >= MAX_RECORDS {
            self.gap("journal capacity reached: collector stopped without deleting evidence")?;
            return Err("capture journal full".into());
        }
        let mut bytes = Vec::with_capacity(size as usize);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&metadata);
        bytes.extend_from_slice(raw);
        atomic_write(
            &self.directory.join(format!("{}.capture", evidence.hash)),
            &bytes,
        )?;
        self.bytes += size;
        self.advance_head(&evidence);
        self.records.insert(evidence.hash.clone(), evidence);
        if self.health.heads.len() > zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS {
            self.gap("capture resume heads exceed node fork limit")?;
            return Err("capture resume heads exceed node fork limit".into());
        }
        self.save_health()?;
        Ok(true)
    }
}

#[derive(Serialize)]
pub struct Summary {
    pub new_blocks: u64,
    pub total_records: usize,
    pub journal_bytes: u64,
    pub reconnects: u64,
    pub gaps: u64,
    pub coverage: &'static str,
    pub database_accessed: bool,
    pub elapsed_seconds: f64,
    pub persist_max_ms: f64,
    pub canonical_at_check: usize,
    pub non_canonical_at_check: usize,
    pub unresolved_at_check: usize,
}

/// Filesystem-only collector. All live integration is opt-in. Captures never
/// enter orphaned_blocks or rate calculations without a separate release.
pub async fn run_capture(
    url: &str,
    directory: &Path,
    network: &str,
    duration: Option<Duration>,
    reconnect_after: Option<u64>,
) -> Result<Summary, String> {
    let rpc = ZebraRpc::from_env()?;
    let info = rpc.get_blockchain_info().await?;
    if info.get("chain").and_then(|v| v.as_str())
        != Some(if network == "mainnet" { "main" } else { "test" })
    {
        return Err("capture RPC network mismatch".into());
    }
    let journal_directory = directory.to_owned();
    let journal_network = network.to_owned();
    let mut journal = tokio::task::spawn_blocking(move || {
        Journal::open(&journal_directory, &journal_network, MAX_JOURNAL_BYTES)
    })
    .await
    .map_err(|_| "capture journal worker failed")??;
    let started = Instant::now();
    let deadline = duration.map(|d| tokio::time::Instant::now() + d);
    let mut new_blocks = 0;
    let mut reconnects = 0;
    let mut forced_reconnect = false;
    let mut persist_max_ms: f64 = 0.0;
    loop {
        if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
            break;
        }
        let session = async {
            let endpoint = Endpoint::from_shared(url.to_owned())
                .map_err(|_| "invalid capture gRPC URL")?
                .connect_timeout(Duration::from_secs(5))
                .tcp_keepalive(Some(Duration::from_secs(30)));
            let mut client = IndexerClient::new(
                endpoint
                    .connect()
                    .await
                    .map_err(|_| "capture gRPC connect failed")?,
            )
            .max_decoding_message_size(MAX_BLOCK_BYTES as usize + 1024);
            let mut check = client
                .chain_tip_change(Empty {})
                .await
                .map_err(|_| "capture node identity subscribe failed")?
                .into_inner();
            let tip = tokio::time::timeout(Duration::from_secs(10), check.message())
                .await
                .map_err(|_| "capture node identity timed out")?
                .map_err(|_| "capture node identity failed")?
                .ok_or("capture node identity ended")?;
            if tip.hash.len() != 32
                || rpc.get_block_hash(tip.height as u64).await? != hex::encode(&tip.hash)
            {
                return Err(
                    "capture gRPC/RPC tip mismatch; retrying without saving payloads".into(),
                );
            }
            drop(check);
            if journal.health.heads.is_empty() {
                // Explicit initial baseline, not an assertion of past capture.
                let mut tips = rpc.get_fork_tip_hashes().await?;
                let mut stream = client
                    .chain_tip_change(Empty {})
                    .await
                    .map_err(|_| "capture initial tip subscribe failed")?
                    .into_inner();
                let tip = tokio::time::timeout(Duration::from_secs(10), stream.message())
                    .await
                    .map_err(|_| "capture initial tip timed out")?
                    .map_err(|_| "capture initial tip failed")?
                    .ok_or("capture initial tip ended")?;
                if tip.hash.len() != 32 {
                    return Err("capture initial tip malformed".into());
                }
                if !tips.contains(&tip.hash) {
                    tips.push(tip.hash);
                }
                journal.health.heads = tips.into_iter().map(hex::encode).collect();
            }
            if journal.health.heads.len() > zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS
            {
                return Err("capture resume heads exceed node fork limit".into());
            }
            let heads = journal
                .health
                .heads
                .iter()
                .map(hex::decode)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "capture checkpoint hash malformed")?;
            let response = client
                .non_finalized_state_change(NonFinalizedStateChangeRequest {
                    chain_tip_hashes: heads,
                    receipt_session: journal.health.receipt_session.clone(),
                })
                .await
                .map_err(|_| "capture subscription failed")?;
            let receipt_session = response
                .metadata()
                .get("x-zakura-receipt-session")
                .and_then(|s| s.to_str().ok())
                .filter(|s| s.len() <= 128)
                .map(str::to_owned);
            if journal.health.receipt_session.is_some()
                && journal.health.receipt_session != receipt_session
            {
                journal.gap(
                    "node receipt session changed; retained replay cannot certify outage coverage",
                )?;
            }
            journal.health.receipt_session = receipt_session.clone();
            journal.health.connections += 1;
            journal.health.connected = true;
            tokio::task::block_in_place(|| journal.save_health())?;
            let mut stream = response.into_inner();
            let (sender, mut receiver) = tokio::sync::mpsc::channel(QUEUE_BLOCKS);
            // Reader drains the stream independently of decoding/fsync. Its queue
            // is bounded to eight <=2MB blocks; overflow is a visible gap.
            let reader = tokio::spawn(async move {
                loop {
                    let message = stream
                        .message()
                        .await
                        .map_err(|_| "capture stream error")?
                        .ok_or("capture stream closed")?;
                    let received = now_ms();
                    tokio::time::timeout(
                        Duration::from_millis(250),
                        sender.send((message, received)),
                    )
                    .await
                    .map_err(|_| "capture queue backpressure timeout")?
                    .map_err(|_| "capture worker stopped")?;
                }
                #[allow(unreachable_code)]
                Ok::<(), String>(())
            });
            // Abort the read task on every exit, including worker errors.
            struct Abort(tokio::task::AbortHandle);
            impl Drop for Abort {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let _abort = Abort(reader.abort_handle());
            let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
            enum CaptureEvent {
                Block(super::grpc::proto::BlockAndHash, u64),
                Heartbeat,
                Closed,
            }
            loop {
                let event = tokio::select! {
                    message = receiver.recv() => message
                        .map(|(message, received)| CaptureEvent::Block(message, received))
                        .unwrap_or(CaptureEvent::Closed),
                    _ = heartbeat.tick() => CaptureEvent::Heartbeat,
                };
                let (message, received) = match event {
                    CaptureEvent::Block(message, received) => (message, received),
                    CaptureEvent::Heartbeat => {
                        tokio::task::block_in_place(|| journal.save_health())?;
                        continue;
                    }
                    CaptureEvent::Closed => break,
                };
                let evidence = decode(&message, received, receipt_session.clone())?;
                let write_started = Instant::now();
                if tokio::task::block_in_place(|| journal.store(evidence, &message.data))? {
                    new_blocks += 1;
                }
                persist_max_ms = persist_max_ms.max(write_started.elapsed().as_secs_f64() * 1000.0);
                if !forced_reconnect && reconnect_after.is_some_and(|n| new_blocks >= n) {
                    forced_reconnect = true;
                    return Err(
                        "intentional shadow reconnect; replay coverage remains unverified".into(),
                    );
                }
            }
            reader.await.map_err(|_| "capture reader task failed")?
        };
        let result = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(deadline, session).await {
                Ok(result) => result,
                Err(_) => break,
            }
        } else {
            session.await
        };
        journal.health.connected = false;
        if let Err(error) = result {
            tokio::task::block_in_place(|| journal.gap(&error))?;
            if error == "capture journal full"
                || error.contains("fork limit")
                || error.starts_with("capture file")
                || error.starts_with("capture rename")
                || error.starts_with("capture directory sync")
                || error.starts_with("capture health")
            {
                // Retry transport faults; stop on storage faults so a partially
                // committed record cannot grow an unaccounted retry journal.
                return Err(error);
            }
            reconnects += 1;
            tracing::warn!(%error, "candidate capture disconnected; retrying independently");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    journal.health.connected = false;
    journal.save_health()?;
    // Bounded end-of-trial classification. A losing branch can become canonical
    // again, so this is a point-in-time comparison, not permanent orphan status.
    let mut canonical = 0;
    let mut competing = 0;
    let mut unresolved = 0;
    for evidence in journal.records.values().take(128) {
        match tokio::time::timeout(
            Duration::from_secs(2),
            rpc.get_block_hash(evidence.height as u64),
        )
        .await
        {
            Ok(Ok(hash)) if hash == evidence.hash => canonical += 1,
            Ok(Ok(_)) => competing += 1,
            _ => unresolved += 1,
        }
    }
    unresolved += journal.records.len().saturating_sub(128);
    Ok(Summary {
        new_blocks,
        total_records: journal.records.len(),
        journal_bytes: journal.bytes,
        reconnects,
        gaps: journal.health.gaps,
        coverage: "unverified",
        database_accessed: false,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        persist_max_ms,
        canonical_at_check: canonical,
        non_canonical_at_check: competing,
        unresolved_at_check: unresolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> super::super::grpc::proto::BlockAndHash {
        let rows: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/parser-blocks.json")).unwrap();
        let row = &rows[0];
        super::super::grpc::proto::BlockAndHash {
            hash: hex::decode(row["hash"].as_str().unwrap()).unwrap(),
            data: hex::decode(row["hex"].as_str().unwrap()).unwrap(),
            receipt_order: Some(1),
        }
    }
    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!(
            "capture-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn failed_atomic_write_does_not_accumulate_temp_payloads() {
        let path = directory();
        std::fs::create_dir_all(path.join("blocked")).unwrap();
        assert!(atomic_write(&path.join("blocked"), b"payload").is_err());
        assert!(!path.join("blocked.tmp").exists());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn durable_dedup_resume_and_exclusive_lock() {
        let path = directory();
        let message = fixture();
        let evidence = decode(&message, 123, Some("node-session".into())).unwrap();
        let mut journal = Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).unwrap();
        assert!(Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).is_err());
        assert!(journal.store(evidence.clone(), &message.data).unwrap());
        assert!(!journal.store(evidence.clone(), &message.data).unwrap());
        assert_eq!(journal.records.len(), 1);
        drop(journal);
        let resumed = Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).unwrap();
        assert_eq!(resumed.records[&evidence.hash].received_at_ms, 123);
        assert!(resumed.health.heads.contains(&evidence.hash));
        drop(resumed);
        assert!(Journal::open(&path, "testnet", MAX_JOURNAL_BYTES).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn capacity_failure_preserves_evidence_and_records_gap() {
        let path = directory();
        let message = fixture();
        let evidence = decode(&message, 123, None).unwrap();
        let mut journal = Journal::open(&path, "mainnet", 12).unwrap();
        assert!(journal
            .store(evidence, &message.data)
            .unwrap_err()
            .contains("full"));
        assert_eq!(journal.records.len(), 0);
        assert_eq!(journal.health.gaps, 2);
        assert!(journal
            .health
            .last_gap
            .as_deref()
            .unwrap()
            .contains("capacity"));
        drop(journal);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corrupt_payloads_and_corrupt_restart_are_rejected() {
        let path = directory();
        let mut message = fixture();
        let evidence = decode(&message, 123, None).unwrap();
        let mut journal = Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).unwrap();
        journal.store(evidence.clone(), &message.data).unwrap();
        drop(journal);
        message.hash[0] ^= 1;
        assert!(decode(&message, 123, None).is_err());
        message = fixture();
        message.data.push(0);
        assert!(decode(&message, 123, None).is_err());
        message.data.truncate(20);
        assert!(decode(&message, 123, None).is_err());
        std::fs::write(path.join(format!("{}.capture", evidence.hash)), b"corrupt").unwrap();
        assert!(Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
