use crate::config::Config;
use clap::ValueEnum;
use sqlx::{PgPool, Postgres, Row, Transaction};

const BLOCK_WRITE_LOCK: i64 = 0x4349_5048_4552;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum IntegrityPhase {
    Audit,
    Repair,
}

#[derive(Debug, Default, Clone, Copy)]
struct AuditReport {
    missing_exposures: i64,
    addressed_direct_scripts: i64,
    unresolved_prevouts: i64,
    prevout_mismatches: i64,
    spent_mismatches: i64,
    negative_summaries: i64,
    algebra_mismatches: i64,
}

impl AuditReport {
    fn total(self) -> i64 {
        self.missing_exposures
            + self.addressed_direct_scripts
            + self.unresolved_prevouts
            + self.prevout_mismatches
            + self.spent_mismatches
            + self.negative_summaries
            + self.algebra_mismatches
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    config: &Config,
    phase: IntegrityPhase,
    from: u32,
    to: u32,
    repair_range_summaries: bool,
    dry_run: bool,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> Result<(), String> {
    if config.database_url.is_empty() {
        return Err("DATABASE_URL not configured".into());
    }
    if from > to {
        return Err("invalid height range".into());
    }

    let writer = crate::db::PostgresWriter::connect(&config.database_url)
        .await
        .map_err(|error| format!("PostgreSQL error: {error}"))?;
    let pool = writer.pool();

    match phase {
        IntegrityPhase::Audit => {
            let report = audit(pool, from, to, lock_timeout_ms, statement_timeout_ms).await?;
            print_report(from, to, report);
            if report.total() != 0 {
                return Err(format!(
                    "address integrity audit found {} mismatches",
                    report.total()
                ));
            }
            Ok(())
        }
        IntegrityPhase::Repair => {
            if dry_run {
                let report = audit(pool, from, to, lock_timeout_ms, statement_timeout_ms).await?;
                print_report(from, to, report);
                println!(
                    "dry-run: would repair direct scripts, mismatched prevouts, spent metadata, \
                     negative summaries{}",
                    if repair_range_summaries {
                        ", and summaries touched by the selected range"
                    } else {
                        ""
                    }
                );
                return Ok(());
            }

            repair(
                pool,
                from,
                to,
                repair_range_summaries,
                lock_timeout_ms,
                statement_timeout_ms,
            )
            .await?;

            let report = audit(pool, from, to, lock_timeout_ms, statement_timeout_ms).await?;
            print_report(from, to, report);
            if report.total() != 0 {
                return Err(format!(
                    "post-repair integrity audit found {} mismatches",
                    report.total()
                ));
            }
            Ok(())
        }
    }
}

async fn audit(
    pool: &PgPool,
    from: u32,
    to: u32,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> Result<AuditReport, String> {
    let mut tx = pool.begin().await.map_err(|error| error.to_string())?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("read-only audit setup failed: {error}"))?;
    set_timeouts(&mut tx, lock_timeout_ms, statement_timeout_ms).await?;

    let script = sqlx::query(
        r#"
        SELECT
          COUNT(*) FILTER (
            WHERE NOT EXISTS (
              SELECT 1 FROM transparent_key_exposures exposure
              WHERE exposure.txid=output.txid AND exposure.vout_index=output.vout_index
            )
          ) AS missing_exposures,
          COUNT(*) FILTER (WHERE output.address IS NOT NULL) AS addressed_direct_scripts
        FROM transaction_outputs output
        WHERE output.script_type IN ('pubkey','multisig')
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("script audit failed: {error}"))?;

    let prevouts = sqlx::query(
        r#"
        SELECT
          COUNT(*) FILTER (WHERE previous.txid IS NULL OR input.value IS NULL)
            AS unresolved_prevouts,
          COUNT(*) FILTER (
            WHERE previous.txid IS NOT NULL
              AND (input.value IS DISTINCT FROM previous.value
                OR input.address IS DISTINCT FROM previous.address)
          ) AS prevout_mismatches,
          COUNT(*) FILTER (
            WHERE previous.txid IS NOT NULL
              AND (previous.spent IS DISTINCT FROM TRUE
                OR previous.spent_txid IS DISTINCT FROM input.txid
                OR previous.spent_at IS DISTINCT FROM
                   (to_timestamp(spender.block_time) AT TIME ZONE 'UTC'))
          ) AS spent_mismatches
        FROM transactions spender
        JOIN transaction_inputs input ON input.txid=spender.txid
        LEFT JOIN transaction_outputs previous
          ON previous.txid=input.prev_txid AND previous.vout_index=input.prev_vout
        WHERE spender.block_height BETWEEN $1 AND $2
        "#,
    )
    .bind(from as i64)
    .bind(to as i64)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("prevout audit failed: {error}"))?;

    let summaries = sqlx::query(
        r#"
        SELECT
          COUNT(*) FILTER (WHERE balance < 0) AS negative_summaries,
          COUNT(*) FILTER (
            WHERE balance IS DISTINCT FROM total_received-total_sent
          ) AS algebra_mismatches
        FROM addresses
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("summary audit failed: {error}"))?;

    let report = AuditReport {
        missing_exposures: script.get("missing_exposures"),
        addressed_direct_scripts: script.get("addressed_direct_scripts"),
        unresolved_prevouts: prevouts.get("unresolved_prevouts"),
        prevout_mismatches: prevouts.get("prevout_mismatches"),
        spent_mismatches: prevouts.get("spent_mismatches"),
        negative_summaries: summaries.get("negative_summaries"),
        algebra_mismatches: summaries.get("algebra_mismatches"),
    };
    tx.commit().await.map_err(|error| error.to_string())?;
    Ok(report)
}

fn print_report(from: u32, to: u32, report: AuditReport) {
    println!(
        "integrity range={from}..={to} missing_exposures={} addressed_direct_scripts={} \
         unresolved_prevouts={} prevout_mismatches={} spent_mismatches={} \
         negative_summaries={} algebra_mismatches={}",
        report.missing_exposures,
        report.addressed_direct_scripts,
        report.unresolved_prevouts,
        report.prevout_mismatches,
        report.spent_mismatches,
        report.negative_summaries,
        report.algebra_mismatches,
    );
}

async fn repair(
    pool: &PgPool,
    from: u32,
    to: u32,
    repair_range_summaries: bool,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|error| error.to_string())?;
    set_timeouts(&mut tx, lock_timeout_ms, statement_timeout_ms).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BLOCK_WRITE_LOCK)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("indexer lock failed: {error}"))?;

    let missing_exposures: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM transaction_outputs output
        WHERE output.script_type IN ('pubkey','multisig')
          AND NOT EXISTS (
            SELECT 1 FROM transparent_key_exposures exposure
            WHERE exposure.txid=output.txid AND exposure.vout_index=output.vout_index
          )
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("exposure preflight failed: {error}"))?;
    if missing_exposures != 0 {
        return Err(format!(
            "{missing_exposures} direct-script outputs require backfill-scripts first"
        ));
    }

    sqlx::query(
        r#"CREATE TEMP TABLE integrity_affected_txids(
          txid text PRIMARY KEY
        ) ON COMMIT DROP"#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("affected transaction table failed: {error}"))?;
    sqlx::query(
        r#"CREATE TEMP TABLE integrity_value_mismatch_txids(
          txid text PRIMARY KEY
        ) ON COMMIT DROP"#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("value mismatch table failed: {error}"))?;
    sqlx::query(
        r#"CREATE TEMP TABLE integrity_touched_addresses(
          address text PRIMARY KEY
        ) ON COMMIT DROP"#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("touched address table failed: {error}"))?;

    // Direct scripts need canonical addressless ownership on both receive and
    // spend sides. Exact-value mismatches are limited to the requested range.
    sqlx::query(
        r#"
        INSERT INTO integrity_value_mismatch_txids
        SELECT DISTINCT input.txid
        FROM transaction_inputs input
        JOIN transactions spender ON spender.txid=input.txid
        JOIN transaction_outputs previous
          ON previous.txid=input.prev_txid AND previous.vout_index=input.prev_vout
        WHERE spender.block_height BETWEEN $1 AND $2
          AND (input.value IS DISTINCT FROM previous.value
            OR input.address IS DISTINCT FROM previous.address)
        "#,
    )
    .bind(from as i64)
    .bind(to as i64)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("value mismatch scan failed: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO integrity_affected_txids
        SELECT txid FROM transaction_outputs WHERE script_type IN ('pubkey','multisig')
        UNION
        SELECT input.txid
        FROM transaction_inputs input
        JOIN transaction_outputs previous
          ON previous.txid=input.prev_txid AND previous.vout_index=input.prev_vout
        WHERE previous.script_type IN ('pubkey','multisig')
        UNION
        SELECT txid FROM integrity_value_mismatch_txids
        ON CONFLICT DO NOTHING
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("affected transaction scan failed: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO integrity_touched_addresses
        SELECT address FROM address_transactions
        WHERE txid IN (SELECT txid FROM integrity_affected_txids)
        UNION
        SELECT address FROM transaction_outputs
        WHERE script_type IN ('pubkey','multisig') AND address IS NOT NULL
        UNION
        SELECT address FROM addresses WHERE balance < 0
        ON CONFLICT DO NOTHING
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("affected address scan failed: {error}"))?;

    if repair_range_summaries {
        sqlx::query(
            r#"
            INSERT INTO integrity_touched_addresses
            SELECT DISTINCT address FROM address_transactions
            WHERE block_height BETWEEN $1 AND $2
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(from as i32)
        .bind(to as i32)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("summary range scan failed: {error}"))?;
    }

    sqlx::query(
        "UPDATE transaction_outputs SET address=NULL \
         WHERE script_type IN ('pubkey','multisig') AND address IS NOT NULL",
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("direct-script correction failed: {error}"))?;

    sqlx::query(
        r#"
        UPDATE transaction_inputs input
        SET prev_txid=previous.txid, prev_vout=previous.vout_index,
            value=previous.value, address=previous.address
        FROM transaction_outputs previous
        WHERE input.txid IN (SELECT txid FROM integrity_affected_txids)
          AND previous.txid=input.prev_txid AND previous.vout_index=input.prev_vout
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("prevout correction failed: {error}"))?;

    sqlx::query(
        r#"
        UPDATE transactions chain_tx
        SET total_input=totals.total_input,
            -- value_balance excludes Sprout; an unknown Sprout balance or a
            -- negative result leaves the fee unknown (NULL), never zero.
            fee=CASE WHEN totals.total_input + chain_tx.value_balance
                          + chain_tx.value_balance_sprout - chain_tx.total_output >= 0
                     THEN totals.total_input + chain_tx.value_balance
                          + chain_tx.value_balance_sprout - chain_tx.total_output
                END
        FROM (
          SELECT input.txid,SUM(input.value) total_input
          FROM transaction_inputs input
          WHERE input.txid IN (SELECT txid FROM integrity_value_mismatch_txids)
          GROUP BY input.txid
        ) totals
        WHERE chain_tx.txid=totals.txid AND chain_tx.is_coinbase=FALSE
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("transaction total correction failed: {error}"))?;

    sqlx::query(
        "DELETE FROM address_transactions \
         WHERE txid IN (SELECT txid FROM integrity_affected_txids)",
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("activity reset failed: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO address_transactions
          (address,txid,block_height,tx_index,block_time,is_input,is_output,value_in,value_out)
        SELECT address,txid,block_height,tx_index,block_time,
               SUM(value_in)>0,SUM(value_out)>0,SUM(value_in),SUM(value_out)
        FROM (
          SELECT input.address,input.txid,chain_tx.block_height,chain_tx.tx_index,
                 chain_tx.block_time,input.value value_in,0::bigint value_out
          FROM transaction_inputs input
          JOIN transactions chain_tx ON chain_tx.txid=input.txid
          WHERE input.txid IN (SELECT txid FROM integrity_affected_txids)
            AND input.address IS NOT NULL
          UNION ALL
          SELECT output.address,output.txid,chain_tx.block_height,chain_tx.tx_index,
                 chain_tx.block_time,0::bigint,output.value
          FROM transaction_outputs output
          JOIN transactions chain_tx ON chain_tx.txid=output.txid
          WHERE output.txid IN (SELECT txid FROM integrity_affected_txids)
            AND output.address IS NOT NULL
        ) movement
        GROUP BY address,txid,block_height,tx_index,block_time
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("activity rebuild failed: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO integrity_touched_addresses
        SELECT DISTINCT address FROM address_transactions
        WHERE txid IN (SELECT txid FROM integrity_affected_txids)
        ON CONFLICT DO NOTHING
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("rebuilt address scan failed: {error}"))?;

    sqlx::query(
        r#"
        INSERT INTO addresses
          (address,balance,total_received,total_sent,tx_count,first_seen,last_seen,address_type,updated_at)
        SELECT activity.address,SUM(value_out)-SUM(value_in),SUM(value_out),SUM(value_in),
               COUNT(DISTINCT txid),MIN(block_time),MAX(block_time),'transparent',NOW()
        FROM address_transactions activity
        JOIN integrity_touched_addresses touched USING(address)
        GROUP BY activity.address
        ON CONFLICT(address) DO UPDATE SET
          balance=EXCLUDED.balance,total_received=EXCLUDED.total_received,
          total_sent=EXCLUDED.total_sent,tx_count=EXCLUDED.tx_count,
          first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,updated_at=NOW()
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("summary recompute failed: {error}"))?;

    sqlx::query(
        r#"
        DELETE FROM addresses summary
        USING integrity_touched_addresses touched
        WHERE summary.address=touched.address
          AND NOT EXISTS (
            SELECT 1 FROM address_transactions activity
            WHERE activity.address=summary.address
          )
        "#,
    )
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("removed summary cleanup failed: {error}"))?;

    sqlx::query(
        r#"
        UPDATE transaction_outputs previous
        SET spent=TRUE,spent_txid=input.txid,
            spent_at=to_timestamp(spender.block_time) AT TIME ZONE 'UTC'
        FROM transaction_inputs input
        JOIN transactions spender ON spender.txid=input.txid
        WHERE spender.block_height BETWEEN $1 AND $2
          AND previous.txid=input.prev_txid AND previous.vout_index=input.prev_vout
        "#,
    )
    .bind(from as i64)
    .bind(to as i64)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("spent metadata correction failed: {error}"))?;

    let activity_mismatches: i64 = sqlx::query_scalar(
        r#"
        WITH expected AS (
          SELECT address,txid,SUM(value_in) value_in,SUM(value_out) value_out
          FROM (
            SELECT input.address,input.txid,input.value value_in,0::bigint value_out
            FROM transaction_inputs input
            WHERE input.txid IN (SELECT txid FROM integrity_affected_txids)
              AND input.address IS NOT NULL
            UNION ALL
            SELECT output.address,output.txid,0::bigint,output.value
            FROM transaction_outputs output
            WHERE output.txid IN (SELECT txid FROM integrity_affected_txids)
              AND output.address IS NOT NULL
          ) movement GROUP BY address,txid
        ), actual AS (
          SELECT address,txid,value_in,value_out FROM address_transactions
          WHERE txid IN (SELECT txid FROM integrity_affected_txids)
        )
        SELECT
          (SELECT COUNT(*) FROM (SELECT * FROM expected EXCEPT SELECT * FROM actual) missing)
          + (SELECT COUNT(*) FROM (SELECT * FROM actual EXCEPT SELECT * FROM expected) extra)
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("activity verification failed: {error}"))?;

    let summary_mismatches: i64 = sqlx::query_scalar(
        r#"
        WITH expected AS (
          SELECT activity.address,SUM(value_out)-SUM(value_in) balance,
                 SUM(value_out) received,SUM(value_in) sent,
                 COUNT(DISTINCT txid)::bigint tx_count,
                 MIN(block_time) first_seen,MAX(block_time) last_seen
          FROM address_transactions activity
          JOIN integrity_touched_addresses touched USING(address)
          GROUP BY activity.address
        )
        SELECT COUNT(*) FROM expected
        JOIN addresses summary USING(address)
        WHERE summary.balance IS DISTINCT FROM expected.balance
           OR summary.total_received IS DISTINCT FROM expected.received
           OR summary.total_sent IS DISTINCT FROM expected.sent
           OR summary.tx_count::bigint IS DISTINCT FROM expected.tx_count
           OR summary.first_seen IS DISTINCT FROM expected.first_seen
           OR summary.last_seen IS DISTINCT FROM expected.last_seen
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("summary verification failed: {error}"))?;

    if activity_mismatches != 0 || summary_mismatches != 0 {
        return Err(format!(
            "targeted repair verification failed: activity={activity_mismatches}, \
             summaries={summary_mismatches}"
        ));
    }

    tx.commit().await.map_err(|error| error.to_string())
}

async fn set_timeouts(
    tx: &mut Transaction<'_, Postgres>,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> Result<(), String> {
    sqlx::query(
        "SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)",
    )
    .bind(format!("{lock_timeout_ms}ms"))
    .bind(format!("{statement_timeout_ms}ms"))
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("timeout setup failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuditReport, IntegrityPhase};

    #[test]
    fn any_mismatch_fails_the_audit() {
        assert_eq!(AuditReport::default().total(), 0);
        assert_eq!(
            AuditReport {
                prevout_mismatches: 1,
                ..AuditReport::default()
            }
            .total(),
            1
        );
    }

    #[test]
    fn only_targeted_phases_are_exposed() {
        assert_ne!(IntegrityPhase::Audit, IntegrityPhase::Repair);
    }
}
