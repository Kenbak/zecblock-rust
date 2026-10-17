-- Deterministic historical subsidy allocations, separate from real tip samples.
-- Readers must match network, height AND canonical hash. Orphan records may remain.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '120s';
CREATE TABLE IF NOT EXISTS public.block_subsidy_allocations (
    hash text PRIMARY KEY CHECK (hash ~ '^[0-9a-f]{64}$'),
    height bigint NOT NULL CHECK (height BETWEEN 0 AND 499999999),
    chain text NOT NULL CHECK (chain IN ('main', 'test')),
    founders_zat bigint NOT NULL CHECK (founders_zat BETWEEN 0 AND 2100000000000000),
    funding_streams_zat bigint NOT NULL CHECK (funding_streams_zat BETWEEN 0 AND 2100000000000000),
    miner_zat bigint CHECK (miner_zat BETWEEN 0 AND 2100000000000000),
    retrieved_at timestamptz NOT NULL DEFAULT now(),
    source text NOT NULL CHECK (source = 'getblocksubsidy')
);
COMMENT ON TABLE public.block_subsidy_allocations IS
'Historical getblocksubsidy allocations in exact zatoshis. No NSM, pool or supply snapshot is inferred. Canonical hash, height and network must match when reading.';
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT DISTINCT grantee FROM information_schema.role_table_grants
    WHERE table_schema='public' AND table_name='blocks' AND grantee <> 'PUBLIC'
  LOOP
    IF has_table_privilege(r.grantee,'public.blocks','SELECT') THEN
      EXECUTE format('GRANT SELECT ON public.block_subsidy_allocations TO %I', r.grantee);
    END IF;
    IF has_table_privilege(r.grantee,'public.blocks','INSERT') THEN
      EXECUTE format('GRANT INSERT ON public.block_subsidy_allocations TO %I', r.grantee);
    END IF;
  END LOOP;
END $$;
COMMIT;
