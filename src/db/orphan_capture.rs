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
/// Hashes captured recently, kept after delivery so a reconnect can tell the
/// node exactly which blocks we already have. Covers the non-finalized window
/// (reorg limit 100) and its fork branches with margin.
const MAX_RECENT_HASHES: usize = 512;
/// How far below the best tip resume hints search the main chain.
const RESUME_HINT_WINDOW: u64 = 120;

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
    /// Recently captured block hashes (delivered or not), oldest first.
    #[serde(default)]
    recent: Vec<String>,
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

    fn remember(&mut self, hash: &str) {
        remember_recent(&mut self.health.recent, hash);
    }

    /// Captured by this observer: still journaled, or recently delivered.
    fn has_captured(&self, hash: &str) -> bool {
        self.records.contains_key(hash) || self.health.recent.iter().any(|h| h == hash)
    }

    fn store(&mut self, evidence: Evidence, raw: &[u8]) -> Result<bool, String> {
        // A node replay of a block we already captured adds nothing: its first
        // receipt is journaled or in the database, keyed by (observer, hash).
        // Re-journaling it would only rebuild a delivery backlog.
        if self.has_captured(&evidence.hash) {
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
        self.remember(&evidence.hash);
        self.records.insert(evidence.hash.clone(), evidence);
        self.save_health()?;
        Ok(true)
    }
}

/// Appends `hash` once, keeping the newest `MAX_RECENT_HASHES`.
fn remember_recent(recent: &mut Vec<String>, hash: &str) {
    if !recent.iter().any(|h| h == hash) {
        recent.push(hash.to_owned());
        let excess = recent.len().saturating_sub(MAX_RECENT_HASHES);
        recent.drain(..excess);
    }
}

/// Picks at most one resume hint per node chain so the node resends only
/// blocks we are missing. Zakura stops every chain's replay walk at the first
/// block whose hash is in the one hint set, whichever chain the hint came from,
/// so a hint on the main chain also ends the main chain's walk:
/// - the active chain: the newest captured main-chain block within
///   `RESUME_HINT_WINDOW`, else no hint (the node resends that chain, under
///   100 blocks; a drop part-way still journals a prefix, so the next resume
///   has an active hint);
/// - a chain whose tip we captured: the tip (nothing resent);
/// - a fork whose tip we lack: the main-chain block at its fork point
///   (`height - branchlen`), only when that is at or below the active hint.
///   A higher fork point would also stop the main chain's walk and silently
///   skip the main-chain blocks between the active hint and it. Without one,
///   the fork's walk runs down the shared prefix to the active hint instead.
///
/// Zakura cannot look up fork blocks by hash over RPC, so only main-chain
/// heights are queried. A failed lookup only costs that chain's hint.
async fn resume_hints<F, Fut>(
    tips: &[super::rpc::ChainTip],
    captured: impl Fn(&str) -> bool,
    mut main_hash_at: F,
) -> Vec<String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let Some(best) = tips
        .iter()
        .filter(|t| t.status == "active")
        .map(|t| t.height)
        .max()
    else {
        return Vec::new();
    };
    let floor = best.saturating_sub(RESUME_HINT_WINDOW);
    let mut cache: HashMap<u64, Option<String>> = HashMap::new();
    // The active chain's resume point first: fork-point hints must not sit above it.
    let mut active_hint: Option<(u64, String)> = None;
    if let Some(active) = tips.iter().find(|t| t.status == "active") {
        if captured(&active.hash) {
            active_hint = Some((active.height, active.hash.clone()));
        } else {
            let mut height = active.height;
            while height >= floor {
                match cached_main_hash(&mut cache, &mut main_hash_at, height).await {
                    Some(hash) if captured(&hash) => {
                        active_hint = Some((height, hash));
                        break;
                    }
                    Some(_) if height > 0 => height -= 1,
                    _ => break,
                }
            }
        }
    }
    let mut hints: Vec<String> = Vec::new();
    for tip in tips {
        let hint = if tip.status == "active" {
            active_hint.as_ref().map(|(_, hash)| hash.clone())
        } else if captured(&tip.hash) {
            Some(tip.hash.clone())
        } else {
            let fork_point = tip.height.saturating_sub(tip.branchlen);
            match &active_hint {
                Some((active_height, _)) if fork_point <= *active_height => {
                    cached_main_hash(&mut cache, &mut main_hash_at, fork_point).await
                }
                _ => None,
            }
        };
        if let Some(hint) = hint {
            if !hints.contains(&hint) {
                hints.push(hint);
            }
        }
    }
    hints.truncate(zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS);
    hints
}

async fn cached_main_hash<F, Fut>(
    cache: &mut HashMap<u64, Option<String>>,
    main_hash_at: &mut F,
    height: u64,
) -> Option<String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    if let Some(hash) = cache.get(&height) {
        return hash.clone();
    }
    let hash = main_hash_at(height).await.ok();
    cache.insert(height, hash.clone());
    hash
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
            let baselined = journal.health.heads.is_empty();
            if baselined {
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
            // Tell the node, per chain it holds, the newest block we already have,
            // so it resends only what we are missing. Our own head list names tips
            // only; for a fork whose tip we lack the node would otherwise resend
            // the fork plus the whole main chain below it (~100 blocks), and a few
            // such forks fill its 200-block subscriber queue, which drops us at
            // once and repeats on every reconnect. Fall back to our heads if the
            // node cannot be asked.
            // A fresh baseline is already exactly the node's tips: resume hints would
            // instead replay retained history that this observer never received.
            let hints = if baselined {
                Vec::new()
            } else {
                match rpc.get_chain_tips().await {
                    Ok(tips) => {
                        resume_hints(
                            &tips,
                            // Our own heads count as known: they are the tips we
                            // last stored (or baselined), so a walk may stop there.
                            |hash| {
                                journal.has_captured(hash)
                                    || journal.health.heads.iter().any(|h| h == hash)
                            },
                            |height| rpc.get_block_hash(height),
                        )
                        .await
                    }
                    Err(_) => Vec::new(),
                }
            };
            let hint_list = if hints.is_empty() {
                journal.health.heads.clone()
            } else {
                hints
            };
            let heads = hint_list
                .iter()
                .take(zakura_chain::parameters::MAX_NON_FINALIZED_CHAIN_FORKS)
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
            // First tick after one period: a subscription's replay arrives right
            // away, and a delivery at that moment would stall the reader.
            let mut heartbeat = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(15),
                Duration::from_secs(15),
            );
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
                        // Journal queued blocks first; deliver on a quiet tick.
                        if receiver.is_empty() {
                            if let Some(sink) = &sink {
                                sink.try_flush(&mut journal).await?;
                            }
                        }
                        continue;
                    }
                    CaptureEvent::Closed => break,
                };
                let evidence = decode(&message, received, receipt_session.clone())?;
                let write_started = Instant::now();
                let stored =
                    tokio::task::block_in_place(|| journal.store(evidence, &message.data))?;
                if stored {
                    new_blocks += 1;
                }
                // One delivery is a multi-round-trip transaction (seconds from a
                // distant observer). Deliver only after journaling something new
                // and once queued blocks are journaled, so a burst is read at fsync
                // speed. Anything still pending goes out on the next heartbeat.
                if stored && receiver.is_empty() {
                    if let Some(sink) = &sink {
                        sink.try_flush(&mut journal).await?;
                    }
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
    flush_control: FlushControl,
}

/// The shared row every collector writes for a block. Committed on its own; a
/// conflict only lowers `first_seen_at`, so the row is rewritten only when this
/// observer saw the block earlier.
const CAPTURED_BLOCK_INSERT_SQL: &str = "INSERT INTO captured_blocks (hash,network,height,previous_block_hash,timestamp,first_seen_at,miner_address,coinbase_hex,raw_block) VALUES ($1,$2,$3,$4,$5,to_timestamp($6::double precision/1000),$7,$8,$9) ON CONFLICT(hash) DO UPDATE SET first_seen_at=EXCLUDED.first_seen_at WHERE captured_blocks.first_seen_at > EXCLUDED.first_seen_at";
const CAPTURE_RETENTION_SQL: &str = "WITH prune AS (SELECT c.hash FROM captured_blocks c JOIN blocks b ON b.height=c.height AND b.hash=c.hash WHERE c.raw_block IS NOT NULL AND c.height < (SELECT max(height)-500 FROM blocks) ORDER BY c.height LIMIT 64 FOR UPDATE OF c SKIP LOCKED) UPDATE captured_blocks SET raw_block=NULL,raw_pruned=true FROM prune WHERE captured_blocks.hash=prune.hash";

struct VerifiedBlock {
    miner: Option<String>,
    tag: Option<String>,
    raw: Vec<u8>,
}

/// Largest number of journal records delivered in one transaction.
const MAX_FLUSH_BATCH: usize = 32;
const DEFAULT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// After this many consecutive full batches, retry a size that timed out before:
/// load or latency may have improved. Costs at most one timeout per probe.
const FLUSH_PROBE_AFTER: u32 = 16;

/// Bounds one delivery transaction. Each record costs two round trips on top of
/// about eight fixed ones, so on a distant observer (300+ ms to the primary) a
/// full 32-record batch cannot finish inside the timeout. A fixed batch then
/// never drains a backlog: every attempt times out and rolls back. The batch
/// therefore halves after each timeout (down to one record) and grows again
/// after full batches, but it remembers the smallest size that timed out and
/// only retries it after `FLUSH_PROBE_AFTER` consecutive full batches, instead of
/// alternating between a working and a failing size.
struct FlushControl {
    policy: std::sync::Mutex<FlushPolicy>,
    timeout: Duration,
}

impl Default for FlushControl {
    fn default() -> Self {
        Self {
            policy: std::sync::Mutex::new(FlushPolicy::default()),
            timeout: DEFAULT_FLUSH_TIMEOUT,
        }
    }
}

impl FlushControl {
    fn from_env() -> Self {
        Self {
            timeout: flush_timeout_from(
                std::env::var("CAPTURE_FLUSH_TIMEOUT_SECONDS")
                    .ok()
                    .as_deref(),
            ),
            ..Self::default()
        }
    }

    fn batch(&self) -> usize {
        self.policy.lock().map(|p| p.batch).unwrap_or(1)
    }

    /// Applies one outcome and returns the next batch size.
    fn record(&self, outcome: FlushOutcome) -> usize {
        match self.policy.lock() {
            Ok(mut policy) => policy.record(outcome),
            Err(_) => 1,
        }
    }
}

/// `CAPTURE_FLUSH_TIMEOUT_SECONDS`, clamped to 1..=60; invalid values use the default.
fn flush_timeout_from(value: Option<&str>) -> Duration {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(|secs| Duration::from_secs(secs.min(60)))
        .unwrap_or(DEFAULT_FLUSH_TIMEOUT)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlushOutcome {
    /// Committed `delivered` records out of an allowed batch.
    Delivered(usize),
    TimedOut,
    /// Any other database failure: not evidence that the batch is too large.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlushPolicy {
    batch: usize,
    /// Smallest batch that timed out; `None` when no size is known to fail.
    ceiling: Option<usize>,
    /// Consecutive full batches since the last change.
    streak: u32,
}

impl Default for FlushPolicy {
    fn default() -> Self {
        Self {
            batch: MAX_FLUSH_BATCH,
            ceiling: None,
            streak: 0,
        }
    }
}

impl FlushPolicy {
    fn record(&mut self, outcome: FlushOutcome) -> usize {
        let current = self.batch.clamp(1, MAX_FLUSH_BATCH);
        match outcome {
            FlushOutcome::TimedOut => {
                self.ceiling = Some(self.ceiling.map_or(current, |c| c.min(current)));
                self.batch = (current / 2).max(1);
                self.streak = 0;
            }
            // Only a full batch shows the limit was the constraint; a partial one is the whole backlog.
            FlushOutcome::Delivered(n) if n >= current => {
                self.streak = self.streak.saturating_add(1);
                let larger = (current * 2).min(MAX_FLUSH_BATCH);
                if larger > current {
                    let known_to_fail = self.ceiling.is_some_and(|c| larger >= c);
                    if !known_to_fail {
                        self.batch = larger;
                        self.streak = 0;
                    } else if self.streak >= FLUSH_PROBE_AFTER {
                        self.ceiling = None;
                        self.batch = larger;
                        self.streak = 0;
                    }
                }
            }
            FlushOutcome::Delivered(_) => {}
            FlushOutcome::Failed => self.streak = 0,
        }
        self.batch = self.batch.clamp(1, MAX_FLUSH_BATCH);
        self.batch
    }
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
            flush_control: FlushControl::from_env(),
        })
    }

    async fn try_flush(&self, journal: &mut Journal) -> Result<(), String> {
        let batch = self.flush_control.batch().clamp(1, MAX_FLUSH_BATCH);
        let (result, outcome) = match tokio::time::timeout(
            self.flush_control.timeout,
            self.flush(journal, batch),
        )
        .await
        {
            Ok(Ok(delivered)) => (Ok(()), FlushOutcome::Delivered(delivered)),
            Ok(Err(error))
                if error.starts_with("capture file")
                    || error.starts_with("capture health")
                    || error == "capture database network mismatch" =>
            {
                (Err(error), FlushOutcome::Failed)
            }
            Ok(Err(stage)) => {
                // Keep every unacknowledged file. `stage` is one of this module's
                // static messages; never log driver errors or connection strings.
                tracing::warn!(%stage, "capture database unavailable; retained blocks will be retried");
                (Ok(()), FlushOutcome::Failed)
            }
            Err(_) => (Ok(()), FlushOutcome::TimedOut),
        };
        let next = self.flush_control.record(outcome);
        if outcome == FlushOutcome::TimedOut {
            tracing::warn!(
                batch,
                next_batch = next,
                timeout_ms = self.flush_control.timeout.as_millis() as u64,
                pending = journal.records.len(),
                "capture delivery timed out; retained blocks will be retried in a smaller batch"
            );
        }
        result
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

    /// Reads and re-verifies one journaled block before it is delivered.
    async fn verified_block(
        &self,
        journal: &Journal,
        evidence: &Evidence,
    ) -> Result<VerifiedBlock, String> {
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
        Ok(VerifiedBlock {
            miner,
            tag: tag.map(str::to_owned),
            raw: raw.to_vec(),
        })
    }

    /// Delivers at most `batch` records; returns how many.
    ///
    /// Every collector writes the same `captured_blocks` row for a block, so that
    /// shared write is committed on its own, one block per statement: its row lock
    /// lasts one server-side statement, not a multi-round-trip transaction from a
    /// distant observer (other collectors' 500 ms `lock_timeout` used to expire
    /// behind it). This observer's own rows (observer health, receipts) stay in
    /// one transaction. A failure in between leaves a block row without this
    /// observer's receipt; the retry adds the receipt, and the block insert keeps
    /// the earliest `first_seen_at`.
    async fn flush(&self, journal: &mut Journal, batch: usize) -> Result<usize, String> {
        let records: Vec<_> = journal.records.values().take(batch).cloned().collect();
        let delivered = records.len();
        // Verify every file before writing anything.
        let mut blocks = Vec::with_capacity(records.len());
        for evidence in &records {
            blocks.push(self.verified_block(journal, evidence).await?);
        }
        // Prevent accidentally delivering one network's evidence into the other's DB.
        // Existing canonical genesis is the authority; an empty DB is not accepted.
        let genesis: Option<String> =
            sqlx::query_scalar("SELECT hash FROM blocks WHERE height = 0")
                .fetch_optional(&self.pool)
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
        for (evidence, block) in records.iter().zip(&blocks) {
            sqlx::query(CAPTURED_BLOCK_INSERT_SQL)
                .bind(&evidence.hash)
                .bind(&self.network)
                .bind(evidence.height as i64)
                .bind(&evidence.parent)
                .bind(evidence.header_time)
                .bind(evidence.received_at_ms as f64)
                .bind(&block.miner)
                .bind(&block.tag)
                .bind(&block.raw)
                .execute(&self.pool)
                .await
                .map_err(|_| "capture database block")?;
        }
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
            sqlx::query("INSERT INTO block_capture_receipts (observer,hash,received_at,receipt_session,receipt_order) VALUES ($1,$2,to_timestamp($3::double precision/1000),$4,$5) ON CONFLICT(observer,hash) DO NOTHING")
                .bind(&self.observer).bind(&evidence.hash).bind(evidence.received_at_ms as f64)
                .bind(&evidence.receipt_session).bind(evidence.receipt_order.and_then(|v| i64::try_from(v).ok()))
                .execute(&mut *tx).await.map_err(|_| "capture database receipt")?;
        }
        tx.commit().await.map_err(|_| "capture database commit")?;
        // Keep metadata and all losing-branch bodies. Drop only redundant canonical
        // bodies beyond the indexer's 500-block automatic reorg horizon, 64 per pass.
        // Housekeeping every collector repeats: its own statement, skipping rows
        // another collector is pruning, and never a reason to resend evidence.
        if sqlx::query(CAPTURE_RETENTION_SQL)
            .execute(&self.pool)
            .await
            .is_err()
        {
            tracing::debug!("capture retention pass skipped");
        }
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
        Ok(delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(hash: &str, status: &str, height: u64, branchlen: u64) -> super::super::rpc::ChainTip {
        super::super::rpc::ChainTip {
            hash: hash.into(),
            status: status.into(),
            height,
            branchlen,
        }
    }

    fn main_chain(lo: u64, hi: u64) -> HashMap<u64, String> {
        (lo..=hi).map(|h| (h, format!("main{h}"))).collect()
    }

    #[tokio::test]
    async fn resume_hints_name_the_newest_captured_block_per_chain() {
        // SYD1 2026-11-06: active tip plus fork tips of branchlen 1, most never captured.
        let main = main_chain(3_544_800, 3_544_986);
        let tips = vec![
            tip("main3544986", "active", 3_544_986, 0),
            tip("forkA", "valid-fork", 3_544_912, 1),
            tip("forkB", "valid-fork", 3_544_879, 1),
            tip("forkC", "valid-fork", 3_544_874, 1),
        ];
        // Captured: forkA, and the main chain up to 3_544_984 (missed the last two).
        let captured = |h: &str| {
            h == "forkA"
                || h.strip_prefix("main")
                    .and_then(|n| n.parse::<u64>().ok())
                    .is_some_and(|n| n <= 3_544_984)
        };
        let hints = resume_hints(&tips, captured, |h| {
            std::future::ready(main.get(&h).cloned().ok_or_else(|| "missing".to_string()))
        })
        .await;
        assert_eq!(
            hints,
            vec![
                "main3544984".to_string(), // node resends 3_544_985..986 only
                "forkA".into(),            // tip captured: nothing resent
                "main3544878".into(),      // fork point: only forkB resent
                "main3544873".into(),      // only forkC resent
            ]
        );
    }

    #[tokio::test]
    async fn resume_hints_omit_fork_points_when_the_main_chain_has_no_hint() {
        // Long outage: nothing captured within the window.
        let tips = vec![tip("t", "active", 1_000, 0), tip("f", "valid-fork", 990, 2)];
        let hints = resume_hints(
            &tips,
            |_| false,
            |h| std::future::ready(Ok(format!("m{h}"))),
        )
        .await;
        // Nothing captured on the main chain: no main-chain hint at all, since a
        // fork point would also end the main chain's replay.
        assert!(hints.is_empty());
        // RPC failing below 995: the active chain still finds 995; the fork's lookup fails.
        let hints = resume_hints(
            &tips,
            |h| h == "m995",
            |h| {
                std::future::ready(if h >= 995 {
                    Ok(format!("m{h}"))
                } else {
                    Err("rpc".into())
                })
            },
        )
        .await;
        assert_eq!(hints, vec!["m995".to_string()]);
        // No active tip at all: no hints, the caller falls back to its heads.
        assert!(resume_hints(
            &tips[1..],
            |_| true,
            |_| std::future::ready(Ok(String::new()))
        )
        .await
        .is_empty());
    }

    /// Zakura's first send (zakura-state `NonFinalizedBlocksListener::spawn`):
    /// each chain is walked from its tip down until a hash in the one hint set.
    fn zakura_replay(chains: &[Vec<String>], hints: &[String]) -> Vec<String> {
        chains
            .iter()
            .flat_map(|chain| {
                chain
                    .iter()
                    .rev()
                    .take_while(|h| !hints.contains(h))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[tokio::test]
    async fn resume_hints_never_hide_main_chain_blocks_from_the_replay() {
        // Main chain 900..=1000; we captured main up to `head`. Forks branch off
        // with one block each at various heights, above and below `head`.
        let main = main_chain(900, 1_000);
        let main_hashes: Vec<String> = (900..=1_000).map(|h| format!("main{h}")).collect();
        for head in [940_u64, 990, 999] {
            for fork_points in [vec![994_u64], vec![930, 950, 997], vec![985, 992]] {
                let mut chains = vec![main_hashes.clone()];
                let mut tips = vec![tip("main1000", "active", 1_000, 0)];
                for fp in &fork_points {
                    let mut chain: Vec<String> = (900..=*fp).map(|h| format!("main{h}")).collect();
                    chain.push(format!("fork{fp}"));
                    chains.push(chain);
                    tips.push(tip(&format!("fork{fp}"), "valid-fork", fp + 1, 1));
                }
                let captured = |h: &str| {
                    h.strip_prefix("main")
                        .and_then(|n| n.parse::<u64>().ok())
                        .is_some_and(|n| n <= head)
                };
                let hints = resume_hints(&tips, captured, |h| {
                    std::future::ready(main.get(&h).cloned().ok_or_else(|| "missing".into()))
                })
                .await;
                let replay = zakura_replay(&chains, &hints);
                for chain in &chains {
                    for hash in chain.iter().filter(|h| !captured(h)) {
                        assert!(
                            replay.contains(hash),
                            "head {head}, forks {fork_points:?}: {hash} not replayed (hints {hints:?})"
                        );
                    }
                }
                // Bounded: each chain resends at most its blocks above the head.
                let bound: usize = chains
                    .iter()
                    .map(|c| c.iter().filter(|h| !captured(h)).count())
                    .sum();
                assert!(
                    replay.len() <= bound,
                    "head {head}: replay {}",
                    replay.len()
                );
            }
        }
    }

    #[test]
    fn recent_hashes_suppress_replayed_blocks_and_stay_bounded() {
        let mut health = Health::default();
        for i in 0..(MAX_RECENT_HASHES + 10) {
            remember_recent(&mut health.recent, &format!("{i:064x}"));
            remember_recent(&mut health.recent, &format!("{i:064x}")); // duplicate is a no-op
        }
        assert_eq!(health.recent.len(), MAX_RECENT_HASHES);
        assert_eq!(health.recent[0], format!("{:064x}", 10));
        // Older health files without the field still load.
        let old: Health = serde_json::from_str(r#"{"network":"mainnet","started_at_ms":0,"updated_at_ms":0,"connected":false,"coverage":"","gaps":0,"last_gap":null,"last_gap_at_ms":null,"connections":0,"heads":[],"receipt_session":null}"#).unwrap();
        assert!(old.recent.is_empty());
    }

    #[test]
    fn flush_batch_halves_on_timeout_and_recovers_on_full_batches() {
        use FlushOutcome::*;
        // A 32-record backlog at ~0.3 s per round trip times out; shrink to one record.
        let mut p = FlushPolicy::default();
        let mut seen = vec![p.batch];
        while p.batch > 1 {
            seen.push(p.record(TimedOut));
        }
        assert_eq!(seen, vec![32, 16, 8, 4, 2, 1]);
        assert_eq!(p.record(TimedOut), 1);
        // Other failures (connection refused, role limit) do not change the size.
        let mut p = FlushPolicy {
            batch: 4,
            ceiling: None,
            streak: 0,
        };
        assert_eq!(p.record(Failed), 4);
        // A partial batch delivered the whole backlog: no evidence to grow.
        assert_eq!(p.record(Delivered(1)), 4);
        // With no known failing size, full batches double back to the cap.
        assert_eq!(p.record(Delivered(4)), 8);
        assert_eq!(p.record(Delivered(8)), 16);
        assert_eq!(p.record(Delivered(16)), 32);
        assert_eq!(p.record(Delivered(32)), 32);
        // Out-of-range state is clamped.
        let mut p = FlushPolicy {
            batch: 0,
            ceiling: None,
            streak: 0,
        };
        assert_eq!(p.record(Failed), 1);
        let mut p = FlushPolicy {
            batch: 500,
            ceiling: None,
            streak: 0,
        };
        assert_eq!(p.record(Failed), MAX_FLUSH_BATCH);
    }

    #[test]
    fn flush_batch_does_not_oscillate_into_a_size_that_timed_out() {
        use FlushOutcome::*;
        // SYD1, 2026-11-06: 16 timed out, 8 fit. The old policy went 8 -> 16 -> 8
        // after every success, wasting a 10 s timeout per cycle.
        let mut p = FlushPolicy::default();
        p.record(TimedOut); // 32 -> 16
        p.record(TimedOut); // 16 -> 8, ceiling 16
        assert_eq!((p.batch, p.ceiling), (8, Some(16)));
        for _ in 1..FLUSH_PROBE_AFTER {
            assert_eq!(p.record(Delivered(8)), 8);
        }
        // Then one probe of the failing size.
        assert_eq!(p.record(Delivered(8)), 16);
        assert_eq!(p.ceiling, None);
        // If the probe fails again the ceiling is restored and growth waits again.
        assert_eq!(p.record(TimedOut), 8);
        assert_eq!(p.ceiling, Some(16));
        assert_eq!(p.record(Delivered(8)), 8);
        // Sizes below the ceiling still grow at once (4 -> 8 after a deeper backoff).
        let mut p = FlushPolicy {
            batch: 4,
            ceiling: Some(16),
            streak: 0,
        };
        assert_eq!(p.record(Delivered(4)), 8);
        assert_eq!(p.record(Delivered(8)), 8);
        // A database failure resets the streak towards a probe.
        let mut p = FlushPolicy {
            batch: 8,
            ceiling: Some(16),
            streak: FLUSH_PROBE_AFTER - 1,
        };
        p.record(Failed);
        assert_eq!(p.record(Delivered(8)), 8);
    }

    #[test]
    fn flush_timeout_env_is_bounded() {
        assert_eq!(flush_timeout_from(None), DEFAULT_FLUSH_TIMEOUT);
        assert_eq!(flush_timeout_from(Some("12")), Duration::from_secs(12));
        assert_eq!(flush_timeout_from(Some(" 7 ")), Duration::from_secs(7));
        assert_eq!(flush_timeout_from(Some("600")), Duration::from_secs(60));
        for bad in ["0", "-3", "abc", ""] {
            assert_eq!(
                flush_timeout_from(Some(bad)),
                DEFAULT_FLUSH_TIMEOUT,
                "{bad}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_delivery_does_not_hold_the_shared_block_row() {
        // Live 2026-11-06: nine collectors insert the same captured_blocks row; the
        // first held its lock through a multi-round-trip transaction, and the
        // others' 500 ms lock_timeout expired behind it (114-460 per hour).
        let url = std::env::var("DATABASE_URL").expect("disposable DATABASE_URL required");
        // Real (migrated) tables: the stall needs a second session to see the row.
        // Other database tests use session-local TEMP tables, so nothing else here
        // writes these; everything this test adds is removed at the end.
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let added_genesis: Option<i64> = sqlx::query_scalar("INSERT INTO blocks (height,hash,timestamp) VALUES (0,'00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08',0) ON CONFLICT DO NOTHING RETURNING height")
            .fetch_optional(&admin).await.unwrap();
        let sink = std::sync::Arc::new(DatabaseSink {
            pool: PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .unwrap(),
            observer: "lock-test-distant".into(),
            network: "mainnet".into(),
            coverage_schema: Default::default(),
            flush_control: Default::default(),
        });
        let message = fixture();
        let evidence = decode(&message, 1000, Some("s".into())).unwrap();
        let path = directory();
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        journal.store(evidence.clone(), &message.data).unwrap();

        // Stall this observer's delivery at its receipt write, like a slow link would.
        let mut stall = admin.begin().await.unwrap();
        sqlx::query("LOCK TABLE block_capture_receipts IN SHARE MODE")
            .execute(&mut *stall)
            .await
            .unwrap();
        let delivery = {
            let sink = sink.clone();
            tokio::spawn(async move {
                let result = sink.flush(&mut journal, MAX_FLUSH_BATCH).await;
                (result, journal)
            })
        };
        let mut other = admin.acquire().await.unwrap();
        let started = Instant::now();
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO block_capture_receipts%'")
                .fetch_one(&mut *other).await.unwrap();
            if waiting > 0 {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "delivery never reached its receipts"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Another collector, which saw the block earlier, writes the same row meanwhile.
        sqlx::query("SET lock_timeout = '100ms'")
            .execute(&mut *other)
            .await
            .unwrap();
        sqlx::query(CAPTURED_BLOCK_INSERT_SQL)
            .bind(&evidence.hash)
            .bind("mainnet")
            .bind(evidence.height as i64)
            .bind(&evidence.parent)
            .bind(evidence.header_time)
            .bind(500.0_f64)
            .bind(None::<String>)
            .bind(None::<String>)
            .bind(&message.data)
            .execute(&mut *other)
            .await
            .expect("the shared block row must not stay locked by another observer's delivery");
        stall.rollback().await.unwrap();
        drop(other);

        // Stalled or not, the delivery completes on retry with nothing lost.
        let (_, mut journal) = delivery.await.unwrap();
        if !journal.records.is_empty() {
            sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
        }
        assert!(journal.records.is_empty());
        let (receipts, first_seen): (i64, f64) = sqlx::query_as("SELECT (SELECT count(*) FROM block_capture_receipts WHERE observer='lock-test-distant' AND hash=$1), extract(epoch FROM first_seen_at)::float8 FROM captured_blocks WHERE hash=$1")
            .bind(&evidence.hash)
            .fetch_one(&admin)
            .await
            .unwrap();
        assert_eq!(receipts, 1);
        assert_eq!(first_seen, 0.5, "the earliest sighting wins");
        sqlx::query("DELETE FROM block_capture_receipts WHERE observer='lock-test-distant'")
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("DELETE FROM block_capture_observers WHERE observer='lock-test-distant'")
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("DELETE FROM captured_blocks WHERE hash=$1")
            .bind(&evidence.hash)
            .execute(&admin)
            .await
            .unwrap();
        if added_genesis.is_some() {
            sqlx::query("DELETE FROM blocks WHERE height=0")
                .execute(&admin)
                .await
                .unwrap();
        }
    }

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
            flush_control: Default::default(),
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
        assert!(sink.flush(&mut journal, MAX_FLUSH_BATCH).await.is_err());
        assert_eq!(journal.records.len(), 1);
        drop(journal);
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        sqlx::query("ALTER TABLE captured_blocks DROP CONSTRAINT simulate_unavailable")
            .execute(&sink.pool)
            .await
            .unwrap();
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
        assert!(journal.records.is_empty());
        assert_eq!(journal.bytes, 0);
        // Replay after acknowledgement/receipt-session change does not duplicate or overwrite first receipt.
        let mut replay = evidence.clone();
        replay.received_at_ms = 9000;
        replay.receipt_session = Some("session-two".into());
        // Recently delivered: the node's replay is not journaled again.
        assert!(!journal.store(replay, &message.data).unwrap());
        assert!(journal.records.is_empty());
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
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
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
        // Losing blocks keep bodies; only an old canonical match can release its redundant body.
        sqlx::query("INSERT INTO blocks VALUES ($1,$2),($3,'later-tip')")
            .bind(evidence.height as i64)
            .bind(&evidence.hash)
            .bind(evidence.height as i64 + 501)
            .execute(&sink.pool)
            .await
            .unwrap();
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
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
            flush_control: Default::default(),
        };
        let mut journal = Journal::open(&path, "mainnet", 64 * 1024 * 1024).unwrap();
        journal.mark_disconnected("capture stream error", 10_000);
        journal.mark_connected(70_000);
        journal.mark_disconnected("capture gRPC connect failed", 80_000);
        let message = fixture();
        journal
            .store(decode(&message, 1000, None).unwrap(), &message.data)
            .unwrap();
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
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
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
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
            flush_control: Default::default(),
        };
        let mut journal = Journal::open(&path, "mainnet", DEFAULT_JOURNAL_BYTES).unwrap();
        let message = fixture();
        journal
            .store(decode(&message, 1000, None).unwrap(), &message.data)
            .unwrap();
        sink.flush(&mut journal, MAX_FLUSH_BATCH).await.unwrap();
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
