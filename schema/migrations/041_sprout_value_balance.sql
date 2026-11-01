-- Sprout JoinSplit value balance per transaction.
--
-- value_balance_sprout = sum(vpub_new) - sum(vpub_old) over every JoinSplit of
-- a v2-v4 transaction, in integer zatoshis. Positive = value leaving Sprout into
-- the transaction's transparent value pool (same sign as the Sapling, Orchard
-- and Ironwood value balances). The fee is
--   total_input + value_balance_sprout + value_balance_sapling
--   + value_balance_orchard + value_balance_ironwood - total_output.
--
-- The temporary DEFAULT 0 is a metadata-only fast default (PostgreSQL >= 11):
-- every existing row reads 0, which is exact for transactions without
-- JoinSplits. Existing Sprout rows remain wrong, exactly like their stored fee,
-- until `repair-sprout-fees` rewrites them; the column is not authoritative for
-- historical Sprout transactions below indexer_state.sprout_fee_repair_height.
-- Dropping the default afterwards makes any writer that omits the column store
-- NULL (unknown) instead of a false zero. The indexer always writes it.
--
-- transactions.value_balance keeps its existing meaning (Sapling + Orchard +
-- Ironwood) so current readers are unchanged.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '30s';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS value_balance_sprout bigint DEFAULT 0;
ALTER TABLE transactions ALTER COLUMN value_balance_sprout DROP DEFAULT;
ALTER TABLE orphaned_transactions ADD COLUMN IF NOT EXISTS value_balance_sprout bigint DEFAULT 0;
ALTER TABLE orphaned_transactions ALTER COLUMN value_balance_sprout DROP DEFAULT;
COMMENT ON COLUMN transactions.value_balance_sprout IS 'Sprout JoinSplit sum(vpub_new) - sum(vpub_old) in zatoshis; positive leaves Sprout. Historical Sprout rows are authoritative only after repair-sprout-fees covers their height (indexer_state.sprout_fee_repair_height). NULL = unknown.';
COMMENT ON COLUMN transactions.fee IS 'Consensus fee in zatoshis including Sprout, Sapling, Orchard and Ironwood value balances. NULL = unknown or coinbase; never a substitute zero.';
COMMENT ON COLUMN blocks.total_fees IS 'Sum of non-coinbase transaction fees in zatoshis; NULL when any non-coinbase fee in the block is unknown.';
COMMENT ON COLUMN orphaned_transactions.value_balance_sprout IS 'Copied from transactions.value_balance_sprout when the block was orphaned.';
COMMIT;
