//! Experimental durable capture of node-validated non-finalized blocks.
//!
//! Shadow mode uses only the journal. Continuous mode delivers it to PostgreSQL
//! and removes files only after acknowledgement. Canonical status is compared
//! by readers against the current indexed chain, never permanently assigned here.
//! Consensus authority is the serving node; decoding/hash checks establish integrity.

use super::grpc::proto::{indexer_client::IndexerClient, Empty, NonFinalizedStateChangeRequest};
use super::ZebraRpc;
use crate::{config::Network, indexer::TransactionParser};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
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
    #[serde(default)]
    head_heights: HashMap<String, u32>,
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
        self.health.head_heights.remove(&evidence.parent);
        self.health
            .head_heights
            .insert(evidence.hash.clone(), evidence.height);
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
        self.health
            .head_heights
            .retain(|hash, _| self.health.heads.contains(hash));
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
    run_capture_inner(url, directory, network, duration, reconnect_after, None).await
}

/// Continuous collector: durable file buffer, transactional database delivery,
/// then acknowledged-file removal. Never writes canonical chain/accounting tables.
pub async fn run_live_capture(
    url: &str,
    directory: &Path,
    network: &str,
    database_url: &str,
    observer: &str,
) -> Result<Summary, String> {
    let sink = DatabaseSink::new(database_url, observer, network)?;
    run_capture_inner(url, directory, network, None, None, Some(sink)).await
}

async fn run_capture_inner(
    url: &str,
    directory: &Path,
    network: &str,
    duration: Option<Duration>,
    reconnect_after: Option<u64>,
    sink: Option<DatabaseSink>,
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
    if let Some(sink) = &sink {
        // Recover committed files before reconnecting or accepting more blocks.
        sink.try_flush(&mut journal).await?;
    }
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
            if sink.is_some() {
                // Only retire heads far behind the serving node, never recent forks.
                // A reconnect after this horizon remains explicitly incomplete.
                let floor = tip.height.saturating_sub(500);
                let stale: Vec<_> = journal
                    .health
                    .head_heights
                    .iter()
                    .filter(|(_, height)| **height < floor)
                    .map(|(hash, _)| hash.clone())
                    .collect();
                for hash in stale {
                    journal.health.heads.retain(|head| head != &hash);
                    journal.health.head_heights.remove(&hash);
                }
            }
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
                        if let Some(sink) = &sink {
                            sink.try_flush(&mut journal).await?;
                        }
                        continue;
                    }
                    CaptureEvent::Closed => break,
                };
                let evidence = decode(&message, received, receipt_session.clone())?;
                let write_started = Instant::now();
                if tokio::task::block_in_place(|| journal.store(evidence, &message.data))? {
                    new_blocks += 1;
                }
                if let Some(sink) = &sink {
                    sink.try_flush(&mut journal).await?;
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

/// One connection, bounded statements and batches keep this separate from canonical ingestion.
struct DatabaseSink {
    pool: PgPool,
    observer: String,
    network: String,
}

impl DatabaseSink {
    fn new(url: &str, observer: &str, network: &str) -> Result<Self, String> {
        if observer.is_empty()
            || observer.len() > 80
            || !observer
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err("invalid capture observer name".into());
        }
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect_lazy(url)
            .map_err(|_| "invalid capture database configuration")?;
        Ok(Self {
            pool,
            observer: observer.into(),
            network: network.into(),
        })
    }

    async fn try_flush(&self, journal: &mut Journal) -> Result<(), String> {
        match tokio::time::timeout(Duration::from_secs(5), self.flush(journal)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error))
                if error.starts_with("capture file")
                    || error.starts_with("capture health")
                    || error == "capture database network mismatch" =>
            {
                Err(error)
            }
            _ => {
                // Keep every unacknowledged file. Do not expose connection strings in logs.
                tracing::warn!("capture database unavailable; retained blocks will be retried");
                Ok(())
            }
        }
    }

    async fn flush(&self, journal: &mut Journal) -> Result<(), String> {
        let records: Vec<_> = journal.records.values().take(32).cloned().collect();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| "capture database unavailable")?;
        sqlx::query("SET LOCAL statement_timeout = '3s'")
            .execute(&mut *tx)
            .await
            .map_err(|_| "capture database setup")?;
        sqlx::query("SET LOCAL lock_timeout = '500ms'")
            .execute(&mut *tx)
            .await
            .map_err(|_| "capture database setup")?;
        // Prevent accidentally delivering one network's evidence into the other's DB.
        // Existing canonical genesis is the authority; an empty DB is not accepted.
        let genesis: Option<String> =
            sqlx::query_scalar("SELECT hash FROM blocks WHERE height = 0")
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| "capture database identity")?;
        let expected = if self.network == "mainnet" {
            "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
        } else {
            "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
        };
        if genesis.as_deref() != Some(expected) {
            return Err("capture database network mismatch".into());
        }
        sqlx::query("INSERT INTO block_capture_observers (observer,network,stream_connected,gaps,pending_records,last_gap,last_gap_at) VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7::double precision / 1000)) ON CONFLICT(observer) DO UPDATE SET heartbeat_at=now(),stream_connected=EXCLUDED.stream_connected,gaps=EXCLUDED.gaps,pending_records=EXCLUDED.pending_records,last_gap=EXCLUDED.last_gap,last_gap_at=EXCLUDED.last_gap_at WHERE block_capture_observers.network=EXCLUDED.network")
            .bind(&self.observer).bind(&self.network).bind(journal.health.connected)
            .bind(journal.health.gaps as i64).bind((journal.records.len()-records.len()) as i32)
            .bind(&journal.health.last_gap).bind(journal.health.last_gap_at_ms.map(|v|v as f64))
            .execute(&mut *tx).await.map_err(|_| "capture database observer")?;
        for evidence in &records {
            let path = journal.directory.join(format!("{}.capture", evidence.hash));
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|_| "capture file read failed")?;
            if bytes.len() < evidence.raw_bytes + 12 || &bytes[..8] != MAGIC {
                return Err("capture file truncated or corrupt".into());
            }
            let raw = &bytes[bytes.len() - evidence.raw_bytes..];
            let verified = decode(
                &super::grpc::proto::BlockAndHash {
                    hash: hex::decode(&evidence.hash).map_err(|_| "capture file hash invalid")?,
                    data: raw.to_vec(),
                    receipt_order: evidence.receipt_order,
                },
                evidence.received_at_ms,
                evidence.receipt_session.clone(),
            )?;
            if verified.height != evidence.height
                || verified.parent != evidence.parent
                || verified.header_time != evidence.header_time
            {
                return Err("capture file metadata mismatch".into());
            }
            let block = Block::zcash_deserialize(&mut std::io::Cursor::new(raw))
                .map_err(|_| "capture file decoding failed")?;
            let network = if self.network == "mainnet" {
                Network::Mainnet
            } else {
                Network::Testnet
            };
            let coinbase = block
                .transactions
                .first()
                .ok_or("capture file missing coinbase")?;
            let parsed = TransactionParser::from_chain_tx(
                (**coinbase).clone(),
                evidence.height,
                &evidence.hash,
                0,
                network,
            )?;
            let miner = super::postgres::miner_address_candidate(
                parsed.vout.first().and_then(|v| v.address.as_deref()),
            );
            let tag = parsed.vin.first().and_then(|v| v.script_sig.as_deref());
            sqlx::query("INSERT INTO captured_blocks (hash,network,height,previous_block_hash,timestamp,first_seen_at,miner_address,coinbase_hex,raw_block) VALUES ($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000),$7,$8,$9) ON CONFLICT(hash) DO UPDATE SET first_seen_at=LEAST(captured_blocks.first_seen_at,EXCLUDED.first_seen_at)")
                .bind(&evidence.hash).bind(&self.network).bind(evidence.height as i64).bind(&evidence.parent)
                .bind(evidence.header_time).bind(evidence.received_at_ms as f64).bind(miner).bind(tag).bind(raw)
                .execute(&mut *tx).await.map_err(|_| "capture database block")?;
            sqlx::query("INSERT INTO block_capture_receipts (observer,hash,received_at,receipt_session,receipt_order) VALUES ($1,$2,to_timestamp($3::double precision/1000),$4,$5) ON CONFLICT(observer,hash) DO NOTHING")
                .bind(&self.observer).bind(&evidence.hash).bind(evidence.received_at_ms as f64)
                .bind(&evidence.receipt_session).bind(evidence.receipt_order.and_then(|v| i64::try_from(v).ok()))
                .execute(&mut *tx).await.map_err(|_| "capture database receipt")?;
        }
        // Keep metadata and all losing-branch bodies. Drop only redundant canonical
        // bodies beyond the indexer's 500-block automatic reorg horizon, 64 per pass.
        sqlx::query("WITH prune AS (SELECT c.hash FROM captured_blocks c JOIN blocks b ON b.height=c.height AND b.hash=c.hash WHERE c.raw_block IS NOT NULL AND c.height < (SELECT max(height)-500 FROM blocks) ORDER BY c.height LIMIT 64) UPDATE captured_blocks SET raw_block=NULL,raw_pruned=true FROM prune WHERE captured_blocks.hash=prune.hash")
            .execute(&mut *tx).await.map_err(|_| "capture database retention")?;
        tx.commit().await.map_err(|_| "capture database commit")?;
        // The saved resume heads precede file deletion. Crash replay is harmless:
        // primary keys preserve the original block and per-observer receipt.
        tokio::task::block_in_place(|| journal.save_health())?;
        for evidence in records {
            let path = journal.directory.join(format!("{}.capture", evidence.hash));
            let size = std::fs::metadata(&path)
                .map_err(|_| "capture file metadata failed")?
                .len();
            std::fs::remove_file(path).map_err(|_| "capture file acknowledgement failed")?;
            journal.bytes = journal.bytes.saturating_sub(size);
            journal.records.remove(&evidence.hash);
        }
        std::fs::File::open(&journal.directory)
            .and_then(|d| d.sync_all())
            .map_err(|_| "capture file directory sync failed")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn database_delivery_recovers_deduplicates_and_reclaims_only_acknowledged_files() {
        let url = std::env::var("DATABASE_URL").expect("disposable DATABASE_URL required");
        let path = directory();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE blocks(height bigint PRIMARY KEY, hash text UNIQUE);
            CREATE TEMP TABLE captured_blocks(hash text PRIMARY KEY,network text,height bigint,previous_block_hash text,timestamp bigint,first_seen_at timestamptz,miner_address text,coinbase_hex text,raw_block bytea,raw_pruned boolean DEFAULT false);
            CREATE TEMP TABLE block_capture_observers(observer text PRIMARY KEY,network text,collection_started_at timestamptz DEFAULT now(),heartbeat_at timestamptz DEFAULT now(),stream_connected boolean,gaps bigint,pending_records integer,last_gap text,last_gap_at timestamptz);
            CREATE TEMP TABLE block_capture_receipts(observer text, hash text REFERENCES captured_blocks(hash),received_at timestamptz,receipt_session text,receipt_order bigint,PRIMARY KEY(observer,hash));
            INSERT INTO blocks VALUES (0,'00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08')")
            .execute(&pool).await.unwrap();
        let sink = DatabaseSink {
            pool,
            observer: "test-observer".into(),
            network: "mainnet".into(),
        };
        let message = fixture();
        let evidence = decode(&message, 1000, Some("session-one".into())).unwrap();
        let mut journal = Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).unwrap();
        journal.store(evidence.clone(), &message.data).unwrap();
        // A failed delivery retains the durable buffer (simulated database write rejection).
        sqlx::query("ALTER TABLE captured_blocks ADD CONSTRAINT simulate_unavailable CHECK (false) NOT VALID")
            .execute(&sink.pool)
            .await
            .unwrap();
        assert!(sink.flush(&mut journal).await.is_err());
        assert_eq!(journal.records.len(), 1);
        drop(journal);
        let mut journal = Journal::open(&path, "mainnet", MAX_JOURNAL_BYTES).unwrap();
        sqlx::query("ALTER TABLE captured_blocks DROP CONSTRAINT simulate_unavailable")
            .execute(&sink.pool)
            .await
            .unwrap();
        sink.flush(&mut journal).await.unwrap();
        assert!(journal.records.is_empty());
        assert_eq!(journal.bytes, 0);
        // Replay after acknowledgement/receipt-session change does not duplicate or overwrite first receipt.
        let mut replay = evidence.clone();
        replay.received_at_ms = 9000;
        replay.receipt_session = Some("session-two".into());
        journal.store(replay, &message.data).unwrap();
        sink.flush(&mut journal).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM captured_blocks")
            .fetch_one(&sink.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let receipt: String =
            sqlx::query_scalar("SELECT receipt_session FROM block_capture_receipts")
                .fetch_one(&sink.pool)
                .await
                .unwrap();
        assert_eq!(receipt, "session-one");
        let mut competing = message.clone();
        competing.data[108] ^= 1;
        competing.hash = hex::decode(
            Block::zcash_deserialize(&mut std::io::Cursor::new(&competing.data))
                .unwrap()
                .hash()
                .to_string(),
        )
        .unwrap();
        let competing_evidence = decode(&competing, 2000, None).unwrap();
        journal
            .store(competing_evidence.clone(), &competing.data)
            .unwrap();
        sink.flush(&mut journal).await.unwrap();
        // Losing blocks keep bodies; only an old canonical match can release its redundant body.
        sqlx::query("INSERT INTO blocks VALUES ($1,$2),($3,'later-tip')")
            .bind(evidence.height as i64)
            .bind(&evidence.hash)
            .bind(evidence.height as i64 + 501)
            .execute(&sink.pool)
            .await
            .unwrap();
        sink.flush(&mut journal).await.unwrap();
        let pruned: bool = sqlx::query_scalar(
            "SELECT raw_pruned AND raw_block IS NULL FROM captured_blocks WHERE hash=$1",
        )
        .bind(&evidence.hash)
        .fetch_one(&sink.pool)
        .await
        .unwrap();
        assert!(pruned);
        let retained: bool = sqlx::query_scalar(
            "SELECT raw_block IS NOT NULL AND NOT raw_pruned FROM captured_blocks WHERE hash=$1",
        )
        .bind(&competing_evidence.hash)
        .fetch_one(&sink.pool)
        .await
        .unwrap();
        assert!(
            retained,
            "competing block bodies must never be pruned as canonical"
        );
        // Metadata survives body retention, preserving future status/rate comparisons.
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM captured_blocks")
                .fetch_one(&sink.pool)
                .await
                .unwrap(),
            2
        );
        sink.pool.close().await;
        std::fs::remove_dir_all(path).unwrap();
    }

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
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "capture-test-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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
