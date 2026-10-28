use crate::config::Config;
use crate::util::{parse_optional_u32, parse_optional_u64, unix_timestamp_secs};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LiveMetrics {
    height: u32,
    rpc_tip: u32,
    source: String,
    elapsed_ms: u64,
    source_ms: u64,
    processing_ms: u64,
    transaction_count: u32,
    flow_count: u32,
    backlog_blocks: u32,
    queue_depth: usize,
}

/// Show indexer status
#[derive(Debug, Serialize)]
pub(crate) struct FailureState {
    height: Option<u32>,
    mode: Option<String>,
    error: Option<String>,
    timestamp: Option<u64>,
    consecutive_failures: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct IndexerStatus {
    network: String,
    chain_tip: u32,
    chain_tip_source: String,
    block_count: u64,
    last_indexed_height: Option<u32>,
    backfill_height: Option<u32>,
    lag_blocks: Option<u32>,
    last_seen_rpc_tip: Option<u32>,
    last_tip_check_at: Option<u64>,
    last_success_at: Option<u64>,
    pending_work_since: Option<u64>,
    live_metrics: Option<LiveMetrics>,
    failure: FailureState,
}

#[derive(Debug)]
pub(crate) struct HealthAssessment {
    healthy: bool,
    reasons: Vec<String>,
    reason_codes: Vec<&'static str>,
}

fn assess_health(
    status: &IndexerStatus,
    max_lag: u32,
    max_consecutive_failures: u32,
    max_heartbeat_age: u64,
    max_ingest_ms: u64,
    now: u64,
) -> HealthAssessment {
    let mut reasons = Vec::new();
    let mut reason_codes = Vec::new();

    if let Some(lag) = status.lag_blocks {
        if lag > max_lag {
            reasons.push(format!("lag {} exceeds threshold {}", lag, max_lag));
            reason_codes.push("lag_exceeded");
        }
    } else {
        reasons.push("live checkpoint missing".to_string());
        reason_codes.push("checkpoint_missing");
    }

    if let Some(last_indexed) = status.last_indexed_height {
        if last_indexed > status.chain_tip {
            reasons.push(format!(
                "last indexed height {} exceeds chain tip {}",
                last_indexed, status.chain_tip
            ));
            reason_codes.push("checkpoint_ahead");
        }
    }

    if status.chain_tip_source != "rpc" {
        reasons.push(format!(
            "rpc tip unavailable; using {} fallback",
            status.chain_tip_source
        ));
        reason_codes.push("rpc_unavailable");
    }

    match status.last_tip_check_at {
        Some(0) | None => {
            reasons.push("tip heartbeat missing".to_string());
            reason_codes.push("tip_heartbeat_missing");
        }
        Some(timestamp) => {
            if timestamp > now {
                reasons.push("tip heartbeat is in the future".to_string());
                reason_codes.push("tip_heartbeat_future");
            } else {
                let age = now - timestamp;
                if age > max_heartbeat_age {
                    reasons.push(format!(
                        "tip heartbeat age {}s exceeds threshold {}s",
                        age, max_heartbeat_age
                    ));
                    reason_codes.push("tip_heartbeat_stale");
                }
            }
        }
    }

    match status.last_success_at {
        Some(0) | None => {
            reasons.push("success heartbeat missing".to_string());
            reason_codes.push("success_heartbeat_missing");
        }
        Some(timestamp) => {
            if timestamp > now {
                reasons.push("success heartbeat is in the future".to_string());
                reason_codes.push("success_heartbeat_future");
            } else if status.lag_blocks.is_some_and(|lag| lag > 0)
                || status.pending_work_since.is_some()
            {
                // A new block after a long idle period gets a complete grace window.
                // Before the writer observes that block, its last successful idle
                // poll provides the bound. Once observed, a durable pending clock
                // survives repeated retries without masking stalled ingestion.
                let pending_since = status.pending_work_since.or(
                    match (status.last_seen_rpc_tip, status.last_indexed_height) {
                        (Some(seen), Some(indexed)) if seen <= indexed => status.last_tip_check_at,
                        _ => None,
                    },
                );
                match pending_since {
                    Some(0) | None => {
                        reasons.push("pending work clock missing".to_string());
                        reason_codes.push("pending_work_clock_missing");
                    }
                    Some(pending_since) if pending_since > now => {
                        reasons.push("pending work clock is in the future".to_string());
                        reason_codes.push("pending_work_clock_future");
                    }
                    Some(pending_since) => {
                        let age = now - timestamp.max(pending_since);
                        if age > max_heartbeat_age {
                            reasons.push(format!(
                                "ingest progress age {}s exceeds threshold {}s while blocks are pending",
                                age, max_heartbeat_age
                            ));
                            reason_codes.push("ingest_stalled");
                        }
                    }
                }
            }
        }
    }

    if status.failure.consecutive_failures > max_consecutive_failures {
        reasons.push(format!(
            "consecutive failures {} exceeds threshold {}",
            status.failure.consecutive_failures, max_consecutive_failures
        ));
        reason_codes.push("consecutive_failures");
    }
    if let Some(metrics) = status.live_metrics.as_ref() {
        if metrics.elapsed_ms > max_ingest_ms {
            reasons.push(format!(
                "last ingest latency {}ms exceeds threshold {}ms",
                metrics.elapsed_ms, max_ingest_ms
            ));
            reason_codes.push("ingest_latency");
        }
    }

    HealthAssessment {
        healthy: reasons.is_empty(),
        reasons,
        reason_codes,
    }
}

async fn collect_status(config: &Config) -> Result<IndexerStatus, String> {
    let mut last_indexed_height = None;
    let mut backfill_height = None;
    let mut last_seen_rpc_tip = None;
    let mut last_tip_check_at = None;
    let mut last_success_at = None;
    let mut pending_work_since = None;
    let mut live_metrics = None;
    let mut failure = FailureState {
        height: None,
        mode: None,
        error: None,
        timestamp: None,
        consecutive_failures: 0,
    };

    if !config.database_url.is_empty() {
        let postgres = crate::db::PostgresWriter::connect(&config.database_url)
            .await
            .map_err(|e| format!("PostgreSQL status error: {}", e))?;

        let state = postgres
            .get_states(&[
                "last_indexed_height",
                "backfill_height",
                "last_seen_rpc_tip",
                "last_tip_check_at",
                "last_success_at",
                "pending_work_since",
                "last_live_metrics",
                "last_failed_height",
                "last_failed_mode",
                "last_failed_error",
                "last_failed_at",
                "consecutive_failure_count",
            ])
            .await
            .map_err(|e| format!("Status read error: {}", e))?;
        last_indexed_height = parse_optional_u32(state.get("last_indexed_height").cloned());
        backfill_height = parse_optional_u32(state.get("backfill_height").cloned());
        last_seen_rpc_tip = parse_optional_u32(state.get("last_seen_rpc_tip").cloned());
        last_tip_check_at = parse_optional_u64(state.get("last_tip_check_at").cloned());
        last_success_at = parse_optional_u64(state.get("last_success_at").cloned());
        pending_work_since = match state.get("pending_work_since") {
            Some(value) => Some(
                value
                    .parse::<u64>()
                    .map_err(|_| "Invalid pending work clock".to_string())?,
            ),
            None => None,
        };
        live_metrics = state
            .get("last_live_metrics")
            .map(|value| {
                serde_json::from_str(value)
                    .map_err(|e| format!("Invalid live metrics in indexer_state: {e}"))
            })
            .transpose()?;
        failure.height = parse_optional_u32(state.get("last_failed_height").cloned());
        failure.mode = state.get("last_failed_mode").cloned();
        failure.error = state.get("last_failed_error").cloned();
        failure.timestamp = parse_optional_u64(state.get("last_failed_at").cloned());
        failure.consecutive_failures =
            parse_optional_u32(state.get("consecutive_failure_count").cloned()).unwrap_or(0);
    }

    let (chain_tip, chain_tip_source) = match crate::db::ZebraRpc::from_env() {
        Ok(rpc) => match rpc.get_block_count().await {
            Ok(tip) => (tip as u32, "rpc".to_string()),
            Err(_) => match last_seen_rpc_tip {
                Some(tip) => (tip, "state".to_string()),
                None => (
                    last_indexed_height.or(backfill_height).unwrap_or(0),
                    "checkpoint".to_string(),
                ),
            },
        },
        Err(_) => match last_seen_rpc_tip {
            Some(tip) => (tip, "state".to_string()),
            None => (
                last_indexed_height.or(backfill_height).unwrap_or(0),
                "checkpoint".to_string(),
            ),
        },
    };

    let lag_blocks = last_indexed_height.map(|indexed| chain_tip.saturating_sub(indexed));

    Ok(IndexerStatus {
        network: config.network_name().to_string(),
        chain_tip,
        chain_tip_source,
        block_count: chain_tip as u64 + 1,
        last_indexed_height,
        backfill_height,
        lag_blocks,
        last_seen_rpc_tip,
        last_tip_check_at,
        last_success_at,
        pending_work_since,
        live_metrics,
        failure,
    })
}

pub(crate) async fn show_status(config: &Config, json: bool) -> Result<(), String> {
    let status = collect_status(config).await?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status)
                .map_err(|e| format!("Status serialization error: {}", e))?
        );
        return Ok(());
    }

    println!("📊 Indexer Status");
    println!("────────────────────────────────────────────────────────────");
    println!("   Network:           {}", status.network);
    println!("   Chain tip:         {}", status.chain_tip);
    println!("   Tip source:        {}", status.chain_tip_source);
    println!("   Block count:       {}", status.block_count);
    println!(
        "   Last indexed:      {}",
        status
            .last_indexed_height
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "   Backfill checkpoint:{}",
        status
            .backfill_height
            .map(|v| format!(" {}", v))
            .unwrap_or_else(|| " unknown".to_string())
    );
    println!(
        "   Live lag:          {}",
        status
            .lag_blocks
            .map(|v| format!("{} blocks", v))
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "   Last RPC tip:      {}",
        status
            .last_seen_rpc_tip
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "   Last tip check:    {}",
        status
            .last_tip_check_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "   Last success:      {}",
        status
            .last_success_at
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    if let Some(metrics) = status.live_metrics.as_ref() {
        println!(
            "   Last ingest:       {}ms via {} (source {}ms, process {}ms, queue {})",
            metrics.elapsed_ms,
            metrics.source,
            metrics.source_ms,
            metrics.processing_ms,
            metrics.queue_depth
        );
    }
    println!();

    if status.failure.consecutive_failures > 0 {
        println!("⚠️  Active failure");
        println!(
            "   Mode:              {}",
            status
                .failure
                .mode
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "   Height:            {}",
            status
                .failure
                .height
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "   Consecutive fails: {}",
            status.failure.consecutive_failures
        );
        println!(
            "   Last failure at:   {}",
            status
                .failure
                .timestamp
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "   Error:             {}",
            status
                .failure
                .error
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!();
    }

    println!("════════════════════════════════════════════════════════════");

    Ok(())
}

pub(crate) async fn check_health(
    config: &Config,
    max_lag: u32,
    max_consecutive_failures: u32,
    max_heartbeat_age: u64,
    max_ingest_ms: u64,
    json: bool,
) -> Result<(), String> {
    let status = collect_status(config).await?;
    let assessment = assess_health(
        &status,
        max_lag,
        max_consecutive_failures,
        max_heartbeat_age,
        max_ingest_ms,
        unix_timestamp_secs(),
    );

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "healthy": assessment.healthy,
                "reasons": assessment.reasons,
                "reason_codes": assessment.reason_codes,
                "status": status,
            }))
            .map_err(|e| format!("Health serialization error: {}", e))?
        );
    } else if assessment.healthy {
        println!(
            "✅ Healthy | last indexed {} | tip {} | lag {}",
            status
                .last_indexed_height
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            status.chain_tip,
            status
                .lag_blocks
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
    } else {
        println!("❌ Unhealthy");
        for reason in &assessment.reasons {
            println!("   - {}", reason);
        }
    }

    if assessment.healthy {
        Ok(())
    } else {
        Err(format!(
            "Indexer health check failed: {}",
            assessment.reasons.join("; ")
        ))
    }
}

#[cfg(test)]
mod health_tests {
    use super::{assess_health, FailureState, IndexerStatus, LiveMetrics};

    const NOW: u64 = 1_710_000_300;

    fn sample_status(lag_blocks: Option<u32>, consecutive_failures: u32) -> IndexerStatus {
        IndexerStatus {
            network: "mainnet".to_string(),
            chain_tip: 100,
            chain_tip_source: "rpc".to_string(),
            block_count: 101,
            last_indexed_height: Some(100u32.saturating_sub(lag_blocks.unwrap_or(0))),
            backfill_height: Some(100),
            lag_blocks,
            last_seen_rpc_tip: Some(100),
            last_tip_check_at: Some(NOW - 60),
            last_success_at: Some(NOW - 30),
            pending_work_since: lag_blocks.filter(|lag| *lag > 0).map(|_| NOW - 60),
            live_metrics: Some(LiveMetrics {
                height: 100,
                rpc_tip: 100,
                source: "rpc".to_string(),
                elapsed_ms: 100,
                source_ms: 40,
                processing_ms: 60,
                transaction_count: 2,
                flow_count: 1,
                backlog_blocks: 0,
                queue_depth: 0,
            }),
            failure: FailureState {
                height: None,
                mode: None,
                error: None,
                timestamp: None,
                consecutive_failures,
            },
        }
    }

    #[test]
    fn health_passes_when_lag_and_failures_are_within_threshold() {
        let assessment = assess_health(&sample_status(Some(2), 0), 3, 0, 600, 5_000, NOW);
        assert!(assessment.healthy);
        assert!(assessment.reasons.is_empty());
    }

    #[test]
    fn health_fails_when_lag_exceeds_threshold() {
        let assessment = assess_health(&sample_status(Some(5), 0), 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("lag")));
    }

    #[test]
    fn health_fails_when_failure_count_exceeds_threshold() {
        let assessment = assess_health(&sample_status(Some(1), 2), 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("consecutive failures")));
    }

    #[test]
    fn health_fails_when_indexed_height_exceeds_tip() {
        let mut status = sample_status(Some(0), 0);
        status.chain_tip = 90;
        status.last_indexed_height = Some(100);
        status.lag_blocks = Some(0);

        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("exceeds chain tip")));
    }

    #[test]
    fn health_fails_when_rpc_tip_is_unavailable() {
        let mut status = sample_status(Some(0), 0);
        status.chain_tip_source = "state".to_string();

        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("rpc tip unavailable")));
    }

    #[test]
    fn health_fails_when_tip_heartbeat_is_stale() {
        let mut status = sample_status(Some(0), 0);
        status.last_tip_check_at = Some(NOW - 601);

        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("tip heartbeat age")));
    }

    #[test]
    fn health_fails_when_ingestion_stops_with_pending_blocks() {
        let mut status = sample_status(Some(1), 0);
        status.last_success_at = Some(NOW - 601);
        status.pending_work_since = Some(NOW - 601);

        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("ingest progress age")));
    }

    #[test]
    fn caught_up_indexer_can_wait_indefinitely_with_fresh_tip_polls() {
        let mut status = sample_status(Some(0), 0);
        status.last_success_at = Some(NOW - 86_400);
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(assessment.healthy, "{:?}", assessment.reasons);
    }

    #[test]
    fn stopped_idle_indexer_is_unhealthy_even_when_node_has_no_new_block() {
        let mut status = sample_status(Some(0), 0);
        status.last_success_at = Some(NOW - 86_400);
        status.last_tip_check_at = Some(NOW - 601);
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert_eq!(assessment.reason_codes, ["tip_heartbeat_stale"]);
    }

    #[test]
    fn missing_or_future_heartbeat_cannot_certify_a_live_indexer() {
        for timestamp in [None, Some(NOW + 1)] {
            let mut status = sample_status(Some(0), 0);
            status.last_tip_check_at = timestamp;
            let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
            assert!(!assessment.healthy);
        }
        let mut status = sample_status(Some(0), 0);
        status.last_success_at = Some(NOW + 1);
        assert!(!assess_health(&status, 3, 0, 600, 5_000, NOW).healthy);
    }

    #[test]
    fn zero_clocks_never_certify_liveness_or_progress() {
        let mut status = sample_status(Some(0), 0);
        status.last_tip_check_at = Some(0);
        assert_eq!(
            assess_health(&status, 3, 0, 600, 5_000, NOW).reason_codes,
            ["tip_heartbeat_missing"]
        );
        status.last_tip_check_at = Some(NOW);
        status.last_success_at = Some(0);
        assert_eq!(
            assess_health(&status, 3, 0, 600, 5_000, NOW).reason_codes,
            ["success_heartbeat_missing"]
        );
        status.last_success_at = Some(NOW);
        status.pending_work_since = Some(0);
        assert_eq!(
            assess_health(&status, 3, 0, 600, 5_000, NOW).reason_codes,
            ["pending_work_clock_missing"]
        );
    }

    #[test]
    fn heartbeat_threshold_is_inclusive_and_missing_success_stays_unhealthy() {
        let mut status = sample_status(Some(1), 0);
        status.last_success_at = Some(NOW - 600);
        status.last_tip_check_at = Some(NOW - 600);
        status.pending_work_since = Some(NOW - 600);
        assert!(assess_health(&status, 3, 0, 600, 5_000, NOW).healthy);
        status.last_success_at = None;
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert_eq!(assessment.reason_codes, ["success_heartbeat_missing"]);
    }

    #[test]
    fn new_block_after_long_idle_receives_a_full_ingestion_grace_period() {
        let mut status = sample_status(Some(1), 0);
        status.last_success_at = Some(NOW - 86_400);
        status.pending_work_since = Some(NOW - 1);
        assert!(assess_health(&status, 3, 0, 600, 5_000, NOW).healthy);
        status.pending_work_since = Some(NOW - 600);
        assert!(assess_health(&status, 3, 0, 600, 5_000, NOW).healthy);
        status.pending_work_since = Some(NOW - 601);
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert_eq!(assessment.reason_codes, ["ingest_stalled"]);
    }

    #[test]
    fn repeated_same_height_reorg_failures_cannot_hide_behind_fresh_polling() {
        let mut status = sample_status(Some(0), 0);
        status.last_success_at = Some(NOW - 86_400);
        status.pending_work_since = Some(NOW - 601);
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert_eq!(assessment.reason_codes, ["ingest_stalled"]);
    }

    #[test]
    fn fresh_success_extends_progress_window_for_a_remaining_backlog() {
        let mut status = sample_status(Some(1), 0);
        status.pending_work_since = Some(NOW - 86_400);
        assert!(assess_health(&status, 3, 0, 600, 5_000, NOW).healthy);
    }

    #[test]
    fn missing_pending_clock_only_gets_grace_until_writer_observes_new_work() {
        let mut status = sample_status(Some(1), 0);
        status.last_success_at = Some(NOW - 86_400);
        status.pending_work_since = None;
        status.last_seen_rpc_tip = status.last_indexed_height;
        assert!(assess_health(&status, 3, 0, 600, 5_000, NOW).healthy);
        status.last_seen_rpc_tip = Some(status.chain_tip);
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert_eq!(assessment.reason_codes, ["pending_work_clock_missing"]);
        status.pending_work_since = Some(NOW + 1);
        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert_eq!(assessment.reason_codes, ["pending_work_clock_future"]);
    }

    #[test]
    fn health_fails_when_last_ingest_exceeds_latency_budget() {
        let mut status = sample_status(Some(0), 0);
        status
            .live_metrics
            .as_mut()
            .expect("sample metrics")
            .elapsed_ms = 5_001;

        let assessment = assess_health(&status, 3, 0, 600, 5_000, NOW);
        assert!(!assessment.healthy);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("ingest latency")));
    }
}
