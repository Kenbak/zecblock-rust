#!/usr/bin/env python3
"""Orphan-collector observer health and node-census freshness as Prometheus text.

Runs on the PRIMARY (where the explorer databases live) every 30 s from
zecblock-capture-exporter@<network>.timer, as OS user `zecblock-monitor`
connecting over the local Unix socket with peer authentication to the
read-only role `zecblock_monitor` (sql/monitor-role.sql). It writes
<dir>/zecblock_capture_<network>.prom for node_exporter's textfile collector,
so the monitor scrapes it over WireGuard with the host metrics. No new port.

Read: block_capture_observers (heartbeat, stream_connected, pending, gaps and
the migration-042 coverage/audit columns), block_capture_audit_misses counts,
latest block_capture_receipts time, topology_gossip_snapshots (per
collector_source) and node_snapshots (per census_version). Only per-observer /
per-source aggregates are exported. Never node IPs, endpoints or edges.

Ages are computed with database now(), so they do not depend on this host's
clock. Missing tables/columns are reported as *_schema_present 0 instead of
failing, because the same script runs against databases at different
migration levels.

Usage: zecblock-capture-exporter.py --network mainnet --database zcash_explorer_mainnet
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

DEFAULT_DIR = '/var/lib/prometheus/node-exporter'
COVERAGE_042_COLUMNS = (
    'coverage_since', 'unobserved_ms', 'outage_since', 'recent_gaps', 'pending_bytes',
    'journal_max_bytes', 'audit_checked_at', 'audit_status', 'audit_fork_tips',
    'audit_fork_blocks', 'audit_canonical_checked', 'audit_canonical_missing',
)

PROBE_SQL = """SELECT json_build_object(
  'observers', to_regclass('public.block_capture_observers') IS NOT NULL,
  'receipts', to_regclass('public.block_capture_receipts') IS NOT NULL,
  'misses', to_regclass('public.block_capture_audit_misses') IS NOT NULL,
  'coverage_042', (SELECT count(*) = %d FROM pg_attribute
     WHERE attrelid = to_regclass('public.block_capture_observers') AND NOT attisdropped
       AND attname IN (%s)),
  'gossip', to_regclass('public.topology_gossip_snapshots') IS NOT NULL,
  'snapshots', to_regclass('public.node_snapshots') IS NOT NULL,
  'census_version', EXISTS (SELECT 1 FROM pg_attribute
     WHERE attrelid = to_regclass('public.node_snapshots') AND attname = 'census_version' AND NOT attisdropped)
)""" % (len(COVERAGE_042_COLUMNS), ', '.join("'%s'" % c for c in COVERAGE_042_COLUMNS))


def age(expr):
    return f'extract(epoch FROM now() - {expr})::float8'


def build_query(probe):
    """Build one SELECT returning a JSON document, from constant fragments only."""
    parts = []
    if probe.get('observers'):
        cols = [
            'b.observer', 'b.network', 'b.stream_connected', 'b.gaps', 'b.pending_records',
            f"{age('b.heartbeat_at')} AS heartbeat_age",
            f"{age('b.collection_started_at')} AS collection_age",
            f"{age('b.last_gap_at')} AS last_gap_age",
        ]
        if probe.get('coverage_042'):
            cols += [
                f"{age('b.coverage_since')} AS coverage_age",
                'b.unobserved_ms', 'b.pending_bytes', 'b.journal_max_bytes',
                f"CASE WHEN b.outage_since IS NULL THEN 0 ELSE {age('b.outage_since')} END AS outage_age",
                f"{age('b.audit_checked_at')} AS audit_age",
                "(b.audit_status = 'ok') AS audit_ok",
                'b.audit_fork_tips', 'b.audit_fork_blocks',
                'b.audit_canonical_checked', 'b.audit_canonical_missing',
            ]
        if probe.get('misses'):
            cols += [
                '(SELECT count(*) FROM public.block_capture_audit_misses m '
                'WHERE m.observer = b.observer AND m.captured_later_at IS NULL) AS misses_open',
                "(SELECT count(*) FROM public.block_capture_audit_misses m "
                "WHERE m.observer = b.observer AND m.detected_at > now() - interval '24 hours') AS misses_24h",
            ]
        if probe.get('receipts'):
            cols.append(
                "(SELECT extract(epoch FROM now() - max(r.received_at))::float8 "
                "FROM public.block_capture_receipts r WHERE r.observer = b.observer "
                "AND r.received_at > now() - interval '1 day') AS last_receipt_age")
        parts.append(
            "'observers', (SELECT coalesce(json_agg(row_to_json(o) ORDER BY o.observer), '[]'::json) FROM ("
            f"SELECT {', '.join(cols)} FROM public.block_capture_observers b) o)")
    if probe.get('gossip'):
        parts.append(
            "'gossip', (SELECT coalesce(json_agg(json_build_object('source', g.collector_source, "
            f"'age', {age('g.generated_at')}, 'edges', g.edge_count, 'truncated', g.truncated) "
            "ORDER BY g.collector_source), '[]'::json) FROM public.topology_gossip_snapshots g)")
    if probe.get('snapshots'):
        # A function call, not a literal: ORDER BY/DISTINCT ON treat integer literals as positions.
        version = 's.census_version' if probe.get('census_version') else 'coalesce(NULL::int, -1)'
        parts.append(
            "'snapshots', (SELECT coalesce(json_agg(json_build_object('census_version', v.census_version, "
            "'age', v.age, 'active_nodes', v.active_nodes) ORDER BY v.census_version), '[]'::json) FROM ("
            f"SELECT DISTINCT ON ({version}) {version} AS census_version, "
            f"{age('s.snapshot_time')} AS age, s.active_nodes FROM public.node_snapshots s "
            "WHERE s.snapshot_time > now() - interval '7 days' "
            f"ORDER BY {version}, s.snapshot_time DESC) v)")
    if not parts:
        return None
    return 'SELECT json_build_object(' + ', '.join(parts) + ')'


def escape_label(value):
    return str(value).replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')


class Metrics:
    def __init__(self):
        self._order, self._meta, self._samples = [], {}, {}

    def add(self, name, value, help_text, labels, mtype='gauge'):
        if name not in self._meta:
            self._order.append(name)
            self._meta[name] = (help_text, mtype)
            self._samples[name] = []
        if value is None:
            return
        if isinstance(value, bool):
            value = int(value)
        text = '{' + ','.join(f'{k}="{escape_label(v)}"' for k, v in sorted(labels.items())) + '}'
        self._samples[name].append(f'{name}{text} {value if isinstance(value, int) else repr(float(value))}')

    def render(self):
        out = []
        for name in self._order:
            help_text, mtype = self._meta[name]
            out += [f'# HELP {name} {help_text}', f'# TYPE {name} {mtype}'] + self._samples[name]
        return '\n'.join(out) + '\n'


OBSERVER_METRICS = [
    # (json key, metric suffix, help, type, scale)
    ('heartbeat_age', 'heartbeat_age_seconds', 'Seconds since the observer last wrote its heartbeat (collector heartbeats every 15 s).', 'gauge', 1),
    ('stream_connected', 'stream_connected', 'The collector reports its block stream connected (1) or not (0).', 'gauge', 1),
    ('pending_records', 'pending_records', 'Captured records still in the local journal, not yet in PostgreSQL.', 'gauge', 1),
    ('gaps', 'gaps_total', 'Stream gaps recorded by the collector since collection started.', 'counter', 1),
    ('last_gap_age', 'last_gap_age_seconds', 'Seconds since the last recorded gap.', 'gauge', 1),
    ('collection_age', 'collection_age_seconds', 'Seconds since collection_started_at.', 'gauge', 1),
    ('coverage_age', 'coverage_age_seconds', 'Seconds since coverage_since (first timed-gap delivery, migration 042).', 'gauge', 1),
    ('unobserved_ms', 'unobserved_seconds', 'Timed seconds the collector was not streaming since coverage_since (bounds unverified time, not missed blocks).', 'gauge', 0.001),
    ('outage_age', 'outage_seconds', 'Seconds the current outage has lasted (0 when streaming).', 'gauge', 1),
    ('pending_bytes', 'pending_bytes', 'Bytes held in the local journal.', 'gauge', 1),
    ('journal_max_bytes', 'journal_max_bytes', 'Configured journal capacity in bytes.', 'gauge', 1),
    ('audit_age', 'audit_age_seconds', 'Seconds since the last getchaintips coverage audit (default interval 300 s).', 'gauge', 1),
    ('audit_ok', 'audit_ok', 'The last coverage audit finished with status ok.', 'gauge', 1),
    ('audit_fork_tips', 'audit_fork_tips', 'valid-fork chain tips seen by the last audit.', 'gauge', 1),
    ('audit_fork_blocks', 'audit_fork_blocks', 'Fork-branch blocks checked by the last audit.', 'gauge', 1),
    ('audit_canonical_checked', 'audit_canonical_checked', 'Recent canonical blocks checked against captured_blocks by the last audit.', 'gauge', 1),
    ('audit_canonical_missing', 'audit_canonical_missing', 'Recent canonical blocks missing from captured_blocks at the last audit.', 'gauge', 1),
    ('misses_open', 'audit_misses_open', 'Audit misses (fork blocks uncaptured on two audits) not yet captured later.', 'gauge', 1),
    ('misses_24h', 'audit_misses_24h', 'Audit misses detected in the last 24 hours.', 'gauge', 1),
    ('last_receipt_age', 'last_receipt_age_seconds', 'Seconds since this observer\'s newest block_capture_receipts row (absent if none in 24 h).', 'gauge', 1),
]


def render(network, probe, doc, *, up=True, duration=None, now=None):
    m = Metrics()
    base = {'network': network}
    m.add('zecblock_capture_exporter_up', up, 'The last capture/census query succeeded.', base)
    for key, label in (('observers', 'block_capture_observers'), ('coverage_042', 'migration_042_coverage'),
                       ('misses', 'block_capture_audit_misses'), ('gossip', 'topology_gossip_snapshots'),
                       ('snapshots', 'node_snapshots')):
        if probe is not None:
            m.add('zecblock_capture_schema_present', bool(probe.get(key)),
                  'Database object used by this exporter exists.', dict(base, object=label))
    doc = doc or {}
    for row in doc.get('observers') or []:
        labels = {'network': row.get('network') or network, 'observer': row['observer']}
        for key, suffix, help_text, mtype, scale in OBSERVER_METRICS:
            value = row.get(key)
            if value is not None and scale != 1:
                value = float(value) * scale
            m.add('zecblock_capture_observer_' + suffix, value, help_text, labels, mtype)
    for row in doc.get('gossip') or []:
        labels = dict(base, collector_source=row['source'])
        m.add('zecblock_census_gossip_age_seconds', row.get('age'),
              'Seconds since the qualified-gossip snapshot for this collector source was generated.', labels)
        m.add('zecblock_census_gossip_edges', row.get('edges'), 'Accepted edges in the current gossip snapshot.', labels)
        m.add('zecblock_census_gossip_truncated', row.get('truncated'), 'The current gossip snapshot was truncated.', labels)
    for row in doc.get('snapshots') or []:
        labels = dict(base, census_version=str(row['census_version']))
        m.add('zecblock_census_snapshot_age_seconds', row.get('age'),
              'Seconds since the newest node_snapshots row of this census_version (last 7 days only).', labels)
        m.add('zecblock_census_snapshot_active_nodes', row.get('active_nodes'),
              'active_nodes in that newest snapshot.', labels)
    if duration is not None:
        m.add('zecblock_capture_exporter_duration_seconds', round(duration, 6), 'Query run time.', base)
    m.add('zecblock_capture_exporter_last_run_timestamp_seconds', round(now or time.time(), 3),
          'Exporter finish time (host clock).', base)
    return m.render()


def psql_json(database, sql, timeout=20):
    env = dict(os.environ)
    env['PGAPPNAME'] = 'zecblock-capture-exporter'
    env['PGOPTIONS'] = '-c statement_timeout=10000 -c default_transaction_read_only=on -c lock_timeout=1000'
    env.setdefault('PGCONNECT_TIMEOUT', '5')
    res = subprocess.run(
        ['psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', sql],
        capture_output=True, text=True, timeout=timeout, env=env, check=False)
    if res.returncode != 0:
        # stderr can contain connection details; keep only the first line, never the DSN.
        raise RuntimeError((res.stderr.strip().splitlines() or ['psql failed'])[0][:200])
    return json.loads(res.stdout.strip())


def write_atomic(directory, name, text):
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + name + '.', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(directory, name))
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--network', required=True, choices=['mainnet', 'testnet'])
    ap.add_argument('--database', required=True, help='database name or libpq connection string')
    ap.add_argument('--dir', default=DEFAULT_DIR)
    ap.add_argument('--stdout', action='store_true')
    args = ap.parse_args(argv)
    started = time.time()
    probe, doc, up = None, None, True
    try:
        probe = psql_json(args.database, PROBE_SQL)
        query = build_query(probe)
        doc = psql_json(args.database, query) if query else {}
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        up = False
        print(f'zecblock-capture-exporter: {exc}', file=sys.stderr)
    text = render(args.network, probe, doc, up=up, duration=time.time() - started)
    if args.stdout:
        sys.stdout.write(text)
    else:
        write_atomic(args.dir, f'zecblock_capture_{args.network}.prom', text)
    # Exit 0 even when the database failed: the file now says up=0, and the unit's
    # ExecStartPost must still publish it so CaptureExporterDown fires.
    return 0


if __name__ == '__main__':
    sys.exit(main())
