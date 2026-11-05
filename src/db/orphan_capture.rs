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
use zakura_chain::block::{Block, MAX_BLOCK_BYTES};
use zakura_chain::serialization::ZcashDeserialize;

// Pending (undelivered) journal budget. At NU7's 25-second spacing, 1 GiB holds
// about 3.5 hours of maximum-size 2 MB blocks while PostgreSQL is unavailable.
const DEFAULT_JOURNAL_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_BYTES_LIMIT: u64 = 16 * 1024 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const MAX_RECENT_GAPS: usize = 32;
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

/// Configured pending-journal budget (`CAPTURE_JOURNAL_MAX_BYTES`), clamped.
fn journal_max_bytes() -> u64 {
    parse_journal_max_bytes(std::env::var("CAPTURE_JOURNAL_MAX_BYTES").ok().as_deref())
}

fn parse_journal_max_bytes(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|v| v.clamp(MIN_JOURNAL_BYTES, MAX_JOURNAL_BYTES_LIMIT))
        .unwrap_or(DEFAULT_JOURNAL_BYTES)
}

/// A closed interval during which this collector was not streaming.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct GapInterval {
    start_ms: u64,
    end_ms: u64,
    reason: String,
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
    // Total closed not-streaming time, and the open interval if any. Replay can
    // still recover retained blocks, so this bounds unverified time only.
    #[serde(default)]
    unobserved_ms: u64,
    #[serde(default)]
    outage_since_ms: Option<u64>,
    #[serde(default)]
    outage_reason: Option<String>,
    #[serde(default)]
    recent_gaps: Vec<GapInterval>,
}

struct Journal {
    directory: PathBuf,
    _lock: std::fs::File,
    health: Health,
    records: HashMap<String, Evidence>,
    bytes: u64,
    max_bytes: u64,
}

/// Parent hash of a block still pending in the journal, from its metadata only.
/// `hash` must already be validated lowercase hex; anything unreadable is "absent".
pub(crate) fn read_journal_parent(directory: &Path, hash: &str) -> Option<String> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut file = std::fs::File::open(directory.join(format!("{hash}.capture"))).ok()?;
    let mut header = [0; 12];
    file.read_exact(&mut header).ok()?;
    let meta_len = u32::from_be_bytes(header[8..].try_into().ok()?) as usize;
    if &header[..8] != MAGIC || meta_len > MAX_META_BYTES {
        return None;
    }
    let mut meta = vec![0; meta_len];
    file.read_exact(&mut meta).ok()?;
    let evidence: Evidence = serde_json::from_slice(&meta).ok()?;
    (evidence.hash == hash).then_some(evidence.parent)
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
        if health.outage_since_ms.is_none() && health.updated_at_ms > 0 {
            // Heartbeats persist every 15s, so this is at most ~15s optimistic.
            health.outage_since_ms = Some(health.updated_at_ms);
            health.outage_reason = Some("collector not running".into());
        }
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
        journal.compact_resume_heads();
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

    /// Opens a not-streaming interval unless one is already open.
    fn mark_disconnected(&mut self, reason: &str, at_ms: u64) {
        if self.health.outage_since_ms.is_none() {
            self.health.outage_since_ms = Some(at_ms);
            self.health.outage_reason = Some(reason.chars().take(256).collect());
        }
    }

    /// Closes the open not-streaming interval, if any.
    fn mark_connected(&mut self, at_ms: u64) {
        if let Some(start_ms) = self.health.outage_since_ms.take() {
            let end_ms = at_ms.max(start_ms);
            self.health.unobserved_ms = self.health.unobserved_ms.saturating_add(end_ms - start_ms);
            self.health.recent_gaps.push(GapInterval {
                start_ms,
                end_ms,
                reason: self.health.outage_reason.take().unwrap_or_default(),
            });
            let excess = self
                .health
                .recent_gaps
                .len()
                .saturating_sub(MAX_RECENT_GAPS);
            self.health.recent_gaps.drain(..excess);
        }
        self.health.outage_reason = None;
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
        self.compact_resume_heads();
    }

    fn compact_resume_heads(&mut self) {
        // These hashes are replay-suppression hints, not retained block evidence.
        // The node can retain fewer forks than we have observed over time. Omitting
        // an old hint makes it replay more retained blocks on reconnect; database
        // and journal hash keys deduplicate them. Never stop capture for this.
        let excess = self
            .health
            .heads
            .len()
            .saturating_sub(zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS);
        self.health.heads.drain(..excess);
        self.health
            .head_heights
            .retain(|hash, _| self.health.heads.contains(hash));
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
        let half = self.max_bytes / 2;
        if self.bytes <= half && self.bytes + size > half {
            tracing::warn!(
                pending_bytes = self.bytes + size,
                max_bytes = self.max_bytes,
                "capture journal over half full; database delivery is falling behind"
            );
        }
        self.bytes += size;
        self.advance_head(&evidence);
        self.records.insert(evidence.hash.clone(), evidence);
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
    // The coverage audit gets its own connection and task so it can never
    // delay stream draining or journal delivery.
    let audit_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect_lazy(database_url)
        .map_err(|_| "invalid capture database configuration")?;
    let audit = tokio::spawn(super::capture_audit::run_audit_loop(
        ZebraRpc::from_env()?,
        audit_pool,
        directory.to_owned(),
        observer.to_owned(),
        network.to_owned(),
    ));
    let result = run_capture_inner(url, directory, network, None, None, Some(sink)).await;
    audit.abort();
    result
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
        Journal::open(&journal_directory, &journal_network, journal_max_bytes())
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
            let endpoint = super::grpc_tls::GrpcTls::from_env()
                .endpoint(url)
                .map_err(|_| "invalid capture gRPC URL or TLS configuration")?
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
            // Keep even old resume hints: unrecognized hashes cause retained
            // history to replay. Clearing them and taking a fresh baseline here
            // would instead skip blocks the node can still recover after an outage.
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
            journal.mark_connected(now_ms());
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
        journal.mark_disconnected(
            result
                .as_ref()
                .err()
                .map_or("capture stream ended", String::as_str),
            now_ms(),
        );
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

/// True when migration 042's observer coverage columns exist on the relation the
/// unqualified name resolves to (search path, so test temp schemas apply too).
pub(crate) const COVERAGE_COLUMNS_SQL: &str = "SELECT count(*) = 6 FROM pg_attribute WHERE attrelid = to_regclass('block_capture_observers') AND NOT attisdropped AND attname IN ('coverage_since','unobserved_ms','outage_since','recent_gaps','pending_bytes','journal_max_bytes')";

/// One connection, bounded statements and batches keep this separate from canonical ingestion.
struct DatabaseSink {
    pool: PgPool,
    observer: String,
    network: String,
    // 0 = not yet checked, 1 = migration 042 present, 2 = absent (pre-042 schema).
    coverage_schema: std::sync::atomic::AtomicU8,
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
            coverage_schema: Default::default(),
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

    /// Migration 042 adds coverage columns; older schemas keep the 035 contract.
    async fn has_coverage_schema(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<bool, String> {
        use std::sync::atomic::Ordering;
        match self.coverage_schema.load(Ordering::Relaxed) {
            1 => return Ok(true),
            2 => return Ok(false),
            _ => {}
        }
        // Check the exact columns the UPDATE writes, on the relation it resolves to.
        let present: bool = sqlx::query_scalar(COVERAGE_COLUMNS_SQL)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| "capture database identity")?;
        self.coverage_schema
            .store(if present { 1 } else { 2 }, Ordering::Relaxed);
        Ok(present)
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
        if self.has_coverage_schema(&mut tx).await? {
            let gaps = serde_json::to_string(&journal.health.recent_gaps)
                .map_err(|_| "capture health encoding")?;
            sqlx::query("UPDATE block_capture_observers SET coverage_since=COALESCE(coverage_since, now()), unobserved_ms=$2, outage_since=to_timestamp($3::double precision/1000), recent_gaps=$4::jsonb, pending_bytes=$5, journal_max_bytes=$6 WHERE observer=$1")
                .bind(&self.observer)
                .bind(i64::try_from(journal.health.unobserved_ms).unwrap_or(i64::MAX))
                .bind(journal.health.outage_since_ms.map(|v| v as f64))
                .bind(gaps)
                .bind(i64::try_from(journal.bytes).unwrap_or(i64::MAX))
                .bind(i64::try_from(journal.max_bytes).unwrap_or(i64::MAX))
                .execute(&mut *tx).await.map_err(|_| "capture database observer coverage")?;
        }
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
            coverage_schema: Default::default(),
        };
        let message = fixture();
        let evidence = decode(&message, 1000, Some("session-one".into())).unwrap();
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        journal.store(evidence.clone(), &message.data).unwrap();
        // A failed delivery retains the durable buffer (simulated database write rejection).
        sqlx::query("ALTER TABLE captured_blocks ADD CONSTRAINT simulate_unavailable CHECK (false) NOT VALID")
            .execute(&sink.pool)
            .await
            .unwrap();
        assert!(sink.flush(&mut journal).await.is_err());
        assert_eq!(journal.records.len(), 1);
        drop(journal);
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
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

    #[test]
    fn journal_budget_is_configurable_and_clamped() {
        assert_eq!(parse_journal_max_bytes(None), DEFAULT_JOURNAL_BYTES);
        assert_eq!(parse_journal_max_bytes(Some("junk")), DEFAULT_JOURNAL_BYTES);
        assert_eq!(parse_journal_max_bytes(Some("1")), MIN_JOURNAL_BYTES);
        assert_eq!(
            parse_journal_max_bytes(Some("99999999999999")),
            MAX_JOURNAL_BYTES_LIMIT
        );
        assert_eq!(parse_journal_max_bytes(Some(" 2147483648 ")), 2_147_483_648);
        // 1 GiB holds at least 500 maximum-size blocks (~3.5 h at 25 s spacing).
        assert!(DEFAULT_JOURNAL_BYTES / (MAX_BLOCK_BYTES + MAX_META_BYTES as u64 + 12) >= 500);
    }

    #[test]
    fn not_streaming_time_is_recorded_as_closed_intervals_across_restarts() {
        let path = directory();
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        // A brand-new journal has no prior run, so nothing before start is a gap.
        assert_eq!(journal.health.outage_since_ms, None);
        journal.mark_connected(1_000);
        assert!(journal.health.recent_gaps.is_empty());
        journal.mark_disconnected("capture stream error", 5_000);
        journal.mark_disconnected("later error does not move the start", 6_000);
        journal.mark_connected(9_000);
        assert_eq!(journal.health.unobserved_ms, 4_000);
        assert_eq!(
            journal.health.recent_gaps,
            vec![GapInterval {
                start_ms: 5_000,
                end_ms: 9_000,
                reason: "capture stream error".into()
            }]
        );
        journal.save_health().unwrap();
        let last_alive = journal.health.updated_at_ms;
        drop(journal);
        // Restart: the outage starts at the previous run's last durable heartbeat.
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert_eq!(journal.health.outage_since_ms, Some(last_alive));
        assert_eq!(
            journal.health.outage_reason.as_deref(),
            Some("collector not running")
        );
        journal.mark_connected(last_alive + 60_000);
        assert_eq!(journal.health.unobserved_ms, 64_000);
        assert_eq!(journal.health.recent_gaps.len(), 2);
        // A crash while disconnected keeps the original open interval start.
        journal.mark_disconnected("capture gRPC connect failed", last_alive + 70_000);
        journal.save_health().unwrap();
        drop(journal);
        let journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert_eq!(journal.health.outage_since_ms, Some(last_alive + 70_000));
        assert_eq!(
            journal.health.outage_reason.as_deref(),
            Some("capture gRPC connect failed")
        );
        drop(journal);
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        for i in 0..(MAX_RECENT_GAPS as u64 + 5) {
            journal.mark_disconnected("flap", 10_000_000 + i * 10);
            journal.mark_connected(10_000_000 + i * 10 + 5);
        }
        assert_eq!(journal.health.recent_gaps.len(), MAX_RECENT_GAPS);
        assert_eq!(
            journal.health.recent_gaps.last().unwrap().end_ms,
            10_000_000 + (MAX_RECENT_GAPS as u64 + 4) * 10 + 5
        );
        drop(journal);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn pending_journal_parent_lookup_rejects_bad_names_and_mismatches() {
        let path = directory();
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        let message = fixture();
        let evidence = decode(&message, 1000, None).unwrap();
        journal.store(evidence.clone(), &message.data).unwrap();
        assert_eq!(
            read_journal_parent(&path, &evidence.hash),
            Some(evidence.parent.clone())
        );
        assert_eq!(read_journal_parent(&path, "../health"), None);
        assert_eq!(read_journal_parent(&path, &"00".repeat(32)), None);
        // A file whose metadata names another hash is not evidence for this one.
        let other = "11".repeat(32);
        std::fs::copy(
            path.join(format!("{}.capture", evidence.hash)),
            path.join(format!("{other}.capture")),
        )
        .unwrap();
        assert_eq!(read_journal_parent(&path, &other), None);
        drop(journal);
        std::fs::remove_dir_all(path).unwrap();
    }

    const COVERAGE_TABLES: &str = "CREATE TEMP TABLE blocks(height bigint PRIMARY KEY, hash text UNIQUE, timestamp bigint);
        CREATE TEMP TABLE captured_blocks(hash text PRIMARY KEY,network text,height bigint,previous_block_hash text,timestamp bigint,first_seen_at timestamptz,miner_address text,coinbase_hex text,raw_block bytea,raw_pruned boolean DEFAULT false);
        CREATE TEMP TABLE block_capture_observers(observer text PRIMARY KEY,network text,collection_started_at timestamptz DEFAULT now(),heartbeat_at timestamptz DEFAULT now(),stream_connected boolean,gaps bigint,pending_records integer,last_gap text,last_gap_at timestamptz,
            coverage_since timestamptz, unobserved_ms bigint, outage_since timestamptz, recent_gaps jsonb, pending_bytes bigint, journal_max_bytes bigint,
            audit_checked_at timestamptz, audit_status text, audit_fork_tips integer, audit_fork_blocks integer, audit_canonical_checked integer, audit_canonical_missing integer);
        CREATE TEMP TABLE block_capture_receipts(observer text, hash text REFERENCES captured_blocks(hash),received_at timestamptz,receipt_session text,receipt_order bigint,PRIMARY KEY(observer,hash));
        CREATE TEMP TABLE block_capture_audit_misses(observer text NOT NULL, hash text NOT NULL, network text NOT NULL, height bigint NOT NULL, branch_len integer NOT NULL, detected_at timestamptz NOT NULL DEFAULT now(), captured_later_at timestamptz, PRIMARY KEY(observer,hash));
        INSERT INTO blocks VALUES (0,'00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08',0)";

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coverage_fields_are_delivered_once_migration_042_exists() {
        let url = std::env::var("DATABASE_URL").expect("disposable DATABASE_URL required");
        let path = directory();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(COVERAGE_TABLES).execute(&pool).await.unwrap();
        let sink = DatabaseSink {
            pool,
            observer: "cov".into(),
            network: "mainnet".into(),
            coverage_schema: Default::default(),
        };
        let mut journal = Journal::open(&path, "mainnet", 64 * 1024 * 1024).unwrap();
        journal.mark_disconnected("capture stream error", 10_000);
        journal.mark_connected(70_000);
        journal.mark_disconnected("capture gRPC connect failed", 80_000);
        let message = fixture();
        journal
            .store(decode(&message, 1000, None).unwrap(), &message.data)
            .unwrap();
        sink.flush(&mut journal).await.unwrap();
        let (unobserved, outage, gaps, max_bytes): (i64, Option<f64>, String, i64) = sqlx::query_as(
            "SELECT unobserved_ms, extract(epoch FROM outage_since)::float8 * 1000, recent_gaps::text, journal_max_bytes FROM block_capture_observers WHERE observer='cov'")
            .fetch_one(&sink.pool).await.unwrap();
        assert_eq!(unobserved, 60_000);
        assert_eq!(outage, Some(80_000.0));
        assert!(
            gaps.contains("\"start_ms\": 10000") && gaps.contains("capture stream error"),
            "{gaps}"
        );
        assert_eq!(max_bytes, 64 * 1024 * 1024);
        let since: Option<f64> = sqlx::query_scalar("SELECT extract(epoch FROM coverage_since)::float8 FROM block_capture_observers WHERE observer='cov'")
            .fetch_one(&sink.pool).await.unwrap();
        // Set once at the first timed delivery, then preserved.
        sqlx::query("UPDATE block_capture_observers SET heartbeat_at = now()")
            .execute(&sink.pool)
            .await
            .unwrap();
        sink.flush(&mut journal).await.unwrap();
        let again: Option<f64> = sqlx::query_scalar("SELECT extract(epoch FROM coverage_since)::float8 FROM block_capture_observers WHERE observer='cov'")
            .fetch_one(&sink.pool).await.unwrap();
        assert!(since.is_some());
        assert_eq!(since, again);
        sink.pool.close().await;
        std::fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pre_042_schema_keeps_the_original_delivery_contract() {
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
            observer: "old".into(),
            network: "mainnet".into(),
            coverage_schema: Default::default(),
        };
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        let message = fixture();
        journal
            .store(decode(&message, 1000, None).unwrap(), &message.data)
            .unwrap();
        sink.flush(&mut journal).await.unwrap();
        assert!(journal.records.is_empty());
        sink.pool.close().await;
        std::fs::remove_dir_all(path).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_walks_fork_branches_through_journal_and_database_and_counts_stream_drops() {
        use super::super::capture_audit::{
            confirm, record, uncaptured_fork_blocks, ForkTip, Outcome,
        };
        let url = std::env::var("DATABASE_URL").expect("disposable DATABASE_URL required");
        let path = directory();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(COVERAGE_TABLES).execute(&pool).await.unwrap();
        // Branch tip T is still pending in the journal; its parent P was delivered;
        // P's parent Q was never captured. A second fork F is fully captured.
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        let message = fixture();
        let tip = decode(&message, 1000, None).unwrap();
        journal.store(tip.clone(), &message.data).unwrap();
        let q = "ab".repeat(32);
        let f = "cd".repeat(32);
        let f_parent = "ef".repeat(32);
        sqlx::query("INSERT INTO captured_blocks (hash,network,height,previous_block_hash,timestamp,first_seen_at) VALUES ($1,'mainnet',$2,$3,0,now()),($4,'mainnet',500,$5,0,now())")
            .bind(&tip.parent).bind(tip.height as i64 - 1).bind(&q).bind(&f).bind(&f_parent)
            .execute(&pool).await.unwrap();
        let forks = vec![
            ForkTip {
                hash: tip.hash.clone(),
                height: tip.height as u64,
                branch_len: 3,
            },
            ForkTip {
                hash: f.clone(),
                height: 500,
                branch_len: 1,
            },
        ];
        let (checked, missing) = uncaptured_fork_blocks(&pool, &path, &forks).await.unwrap();
        assert_eq!(checked, 4);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].hash, q);
        assert_eq!(missing[0].height, tip.height as u64 - 2);
        // First sighting is only a candidate; the second audit confirms it.
        let mut candidates = Default::default();
        assert!(confirm(&mut candidates, missing.clone()).is_empty());
        let confirmed = confirm(&mut candidates, missing);
        sqlx::query("INSERT INTO block_capture_observers (observer,network,stream_connected,gaps,pending_records,collection_started_at) VALUES ('aud','mainnet',true,0,0,to_timestamp(100))")
            .execute(&pool).await.unwrap();
        record(
            &pool,
            "aud",
            "mainnet",
            &Ok(Outcome {
                fork_tips: 2,
                fork_blocks: 4,
                confirmed,
                canonical_checked: 0,
                canonical_missing: 0,
            }),
        )
        .await
        .unwrap();
        record(
            &pool,
            "aud",
            "mainnet",
            &Ok(Outcome {
                fork_tips: 2,
                fork_blocks: 4,
                confirmed: vec![super::super::capture_audit::Missing {
                    hash: q.clone(),
                    height: 1,
                    branch_len: 3,
                }],
                canonical_checked: 0,
                canonical_missing: 0,
            }),
        )
        .await
        .unwrap();
        let (misses, late): (i64, i64) = sqlx::query_as("SELECT count(*), count(captured_later_at) FROM block_capture_audit_misses WHERE observer='aud'").fetch_one(&pool).await.unwrap();
        assert_eq!((misses, late), (1, 0), "a miss is recorded once");
        // Late delivery (e.g. retained replay) marks it, never deletes it.
        sqlx::query("INSERT INTO captured_blocks (hash,network,height,previous_block_hash,timestamp,first_seen_at) VALUES ($1,'mainnet',1,$2,0,now())")
            .bind(&q).bind("00".repeat(32)).execute(&pool).await.unwrap();
        record(
            &pool,
            "aud",
            "mainnet",
            &Err("capture audit timed out".into()),
        )
        .await
        .unwrap();
        let (misses, late, status, tips): (i64, i64, String, i32) = sqlx::query_as("SELECT (SELECT count(*) FROM block_capture_audit_misses), (SELECT count(captured_later_at) FROM block_capture_audit_misses), audit_status, audit_fork_tips FROM block_capture_observers WHERE observer='aud'").fetch_one(&pool).await.unwrap();
        assert_eq!((misses, late), (1, 1));
        assert_eq!(status, "error: capture audit timed out");
        assert_eq!(tips, 2, "a failed audit keeps the last successful counts");
        // Canonical stream-drop check: since collection start, outside the settle window.
        sqlx::query("INSERT INTO blocks (height,hash,timestamp) VALUES (1,$1,50),(2,$2,200),(3,$3,300),(4,$4,400),(5,$5,500),(6,$6,600),(7,$7,700)")
            .bind("01".repeat(32)).bind(&f).bind("03".repeat(32)).bind(&tip.hash)
            .bind("05".repeat(32)).bind("06".repeat(32)).bind("07".repeat(32))
            .execute(&pool).await.unwrap();
        let (checked, canonical_missing) =
            super::super::capture_audit::canonical_gaps_for_test(&pool, &path, "aud")
                .await
                .unwrap();
        // Heights 2..=4 are settled and after start; 2 captured, 3 missing, 4 pending in journal.
        assert_eq!((checked, canonical_missing), (3, 1));
        drop(journal);
        pool.close().await;
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
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert!(Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).is_err());
        assert!(journal.store(evidence.clone(), &message.data).unwrap());
        assert!(!journal.store(evidence.clone(), &message.data).unwrap());
        assert_eq!(journal.records.len(), 1);
        drop(journal);
        let resumed = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert_eq!(resumed.records[&evidence.hash].received_at_ms, 123);
        assert!(resumed.health.heads.contains(&evidence.hash));
        drop(resumed);
        assert!(Journal::open(&path, "testnet", DEFAULT_JOURNAL_BYTES).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn historical_fork_hints_do_not_stop_durable_capture() {
        let path = directory();
        let message = fixture();
        let evidence = decode(&message, 123, None).unwrap();
        let limit = zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS;
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        journal.health.heads = (0..limit).map(|i| hex::encode([i as u8; 32])).collect();
        let oldest = journal.health.heads[0].clone();
        assert!(journal.store(evidence.clone(), &message.data).unwrap());
        assert_eq!(journal.health.heads.len(), limit);
        assert!(!journal.health.heads.contains(&oldest));
        assert!(journal.health.heads.contains(&evidence.hash));
        assert_eq!(journal.records.len(), 1);
        drop(journal);
        let resumed = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert_eq!(resumed.records[&evidence.hash].received_at_ms, 123);
        assert_eq!(resumed.health.heads.len(), limit);
        drop(resumed);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn restart_repairs_oversized_legacy_checkpoint_without_deleting_evidence() {
        let path = directory();
        let message = fixture();
        let evidence = decode(&message, 123, None).unwrap();
        let limit = zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS;
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        journal.store(evidence.clone(), &message.data).unwrap();
        journal.health.heads = (0..limit + 1).map(|i| hex::encode([i as u8; 32])).collect();
        journal.save_health().unwrap();
        drop(journal);
        let resumed = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert_eq!(resumed.health.heads.len(), limit);
        assert!(resumed.health.heads.contains(&evidence.hash));
        assert_eq!(resumed.records.len(), 1);
        assert!(path.join(format!("{}.capture", evidence.hash)).exists());
        drop(resumed);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn oversized_acknowledged_checkpoint_resumes_without_a_fresh_baseline() {
        let path = directory();
        let limit = zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS;
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        journal.health.heads = (0..limit + 1).map(|i| hex::encode([i as u8; 32])).collect();
        let latest = journal.health.heads.last().unwrap().clone();
        let started = journal.health.started_at_ms;
        journal.save_health().unwrap();
        drop(journal);
        let resumed = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        assert_eq!(resumed.health.heads.len(), limit);
        assert!(resumed.health.heads.contains(&latest));
        assert_eq!(resumed.health.started_at_ms, started);
        assert!(resumed.records.is_empty());
        drop(resumed);
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
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
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
        assert!(Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
