-- 035: Durable node-validated competing-block observations, independent of canonical writes.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '120s';
CREATE TABLE IF NOT EXISTS public.captured_blocks (
    hash text PRIMARY KEY CHECK (hash ~ '^[0-9a-f]{64}$'),
    network text NOT NULL CHECK (network IN ('mainnet', 'testnet')),
    height bigint NOT NULL CHECK (height >= 0),
    previous_block_hash text NOT NULL CHECK (previous_block_hash ~ '^[0-9a-f]{64}$'),
    timestamp bigint NOT NULL,
    first_seen_at timestamptz NOT NULL,
    miner_address text,
    coinbase_hex text,
    raw_block bytea,
    raw_pruned boolean NOT NULL DEFAULT false,
    CHECK ((raw_block IS NULL) = raw_pruned)
);
CREATE TABLE IF NOT EXISTS public.block_capture_observers (
    observer text PRIMARY KEY,
    network text NOT NULL CHECK (network IN ('mainnet', 'testnet')),
    collection_started_at timestamptz NOT NULL DEFAULT now(),
    heartbeat_at timestamptz NOT NULL DEFAULT now(),
    stream_connected boolean NOT NULL,
    gaps bigint NOT NULL CHECK (gaps >= 0),
    pending_records integer NOT NULL CHECK (pending_records >= 0),
    last_gap text,
    last_gap_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.block_capture_receipts (
    observer text NOT NULL REFERENCES public.block_capture_observers(observer),
    hash text NOT NULL REFERENCES public.captured_blocks(hash),
    received_at timestamptz NOT NULL,
    receipt_session text,
    receipt_order bigint,
    PRIMARY KEY (observer, hash)
);
REVOKE ALL ON public.captured_blocks, public.block_capture_observers, public.block_capture_receipts FROM PUBLIC;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT DISTINCT grantee FROM information_schema.role_table_grants
    WHERE table_schema='public' AND table_name='blocks' AND grantee <> 'PUBLIC'
  LOOP
    IF has_table_privilege(r.grantee,'public.blocks','SELECT') THEN
      EXECUTE format('GRANT SELECT ON public.captured_blocks, public.block_capture_observers, public.block_capture_receipts TO %I', r.grantee);
    END IF;
    IF has_table_privilege(r.grantee,'public.blocks','INSERT') THEN
      EXECUTE format('GRANT INSERT, UPDATE ON public.captured_blocks, public.block_capture_observers, public.block_capture_receipts TO %I', r.grantee);
    END IF;
  END LOOP;
END $$;
COMMIT;
CREATE INDEX CONCURRENTLY IF NOT EXISTS captured_blocks_timestamp_idx ON public.captured_blocks(timestamp);
CREATE INDEX CONCURRENTLY IF NOT EXISTS captured_blocks_retained_height_idx ON public.captured_blocks(height) WHERE raw_block IS NOT NULL;
