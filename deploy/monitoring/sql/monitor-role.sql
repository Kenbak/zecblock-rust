-- Read-only role for zecblock-capture-exporter.py on the primary.
-- Run as the database owner/superuser in EACH explorer database it reads, e.g.
--   sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d zcash_explorer_mainnet -f monitor-role.sql
-- Idempotent. No password: the exporter connects over the local Unix socket as
-- OS user zecblock-monitor with peer authentication, so no secret exists.
-- pg_ident.conf needs:   zecblock_monitor  zecblock-monitor  zecblock_monitor
-- pg_hba.conf needs (reload only, no restart), above any broader local rule:
--   local  zcash_explorer_mainnet  zecblock_monitor  peer map=zecblock_monitor
--
-- Grants are table-level SELECT on exactly the tables the exporter reads.
-- Deliberately NOT granted: nodes, nodes_crawl, topology_gossip_edges and any
-- table holding IP addresses/endpoints, pg_monitor / pg_read_all_stats (they
-- expose other sessions' query text).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zecblock_monitor') THEN
    CREATE ROLE zecblock_monitor LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 2;
  END IF;
END $$;
ALTER ROLE zecblock_monitor SET default_transaction_read_only = on;
ALTER ROLE zecblock_monitor SET statement_timeout = '10s';
ALTER ROLE zecblock_monitor SET lock_timeout = '1s';
ALTER ROLE zecblock_monitor SET idle_in_transaction_session_timeout = '15s';

DO $$
DECLARE
  db text := current_database();
  t text;
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO zecblock_monitor', db);
  GRANT USAGE ON SCHEMA public TO zecblock_monitor;
  FOREACH t IN ARRAY ARRAY['block_capture_observers', 'block_capture_receipts', 'block_capture_audit_misses',
                           'topology_gossip_snapshots', 'node_snapshots']
  LOOP
    -- Tables a database has not migrated to yet are skipped; re-run after migrating.
    IF to_regclass('public.' || t) IS NOT NULL THEN
      EXECUTE format('GRANT SELECT ON public.%I TO zecblock_monitor', t);
    END IF;
  END LOOP;
END $$;
