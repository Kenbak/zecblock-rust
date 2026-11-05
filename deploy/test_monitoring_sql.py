"""Run the capture/census exporter's real SQL against a migrated database.

CI sets MONITOR_TEST_DATABASE_URL to the disposable database after
deploy/apply-migrations.sh; elsewhere these tests are skipped.
"""
import importlib.util
import os
import pathlib
import subprocess
import unittest

URL = os.environ.get('MONITOR_TEST_DATABASE_URL')
spec = importlib.util.spec_from_file_location(
    'zecblock_capture_exporter', pathlib.Path(__file__).with_name('monitoring') / 'exporters/zecblock-capture-exporter.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)

OBSERVER = 'monitor-sql-test'


def psql(sql):
    subprocess.run(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-d', URL, '-c', sql], check=True)


@unittest.skipUnless(URL, 'MONITOR_TEST_DATABASE_URL not set')
class CaptureExporterSqlTests(unittest.TestCase):
    def setUp(self):
        psql(f"DELETE FROM block_capture_observers WHERE observer = '{OBSERVER}'")
        psql("INSERT INTO block_capture_observers (observer, network, stream_connected, gaps, pending_records, "
             "heartbeat_at, coverage_since, unobserved_ms, pending_bytes, journal_max_bytes, audit_checked_at, "
             "audit_status, audit_fork_tips, audit_fork_blocks, audit_canonical_checked, audit_canonical_missing) "
             f"VALUES ('{OBSERVER}', 'mainnet', true, 2, 0, now() - interval '5 seconds', now() - interval '1 hour', "
             "1500, 0, 268435456, now() - interval '2 minutes', 'ok', 1, 3, 100, 0)")
        psql("INSERT INTO block_capture_audit_misses (observer, hash, network, height, branch_len) "
             f"VALUES ('{OBSERVER}', repeat('ab', 32), 'mainnet', 3000000, 1)")

    def tearDown(self):
        psql(f"DELETE FROM block_capture_audit_misses WHERE observer = '{OBSERVER}'")
        psql(f"DELETE FROM block_capture_observers WHERE observer = '{OBSERVER}'")

    def test_probe_and_query_run_read_only(self):
        probe = capture.psql_json(URL, capture.PROBE_SQL)
        for key in ('observers', 'receipts', 'misses', 'coverage_042', 'snapshots', 'census_version'):
            self.assertTrue(probe[key], key)
        doc = capture.psql_json(URL, capture.build_query(probe))
        row = next(r for r in doc['observers'] if r['observer'] == OBSERVER)
        self.assertGreaterEqual(row['heartbeat_age'], 4)
        self.assertLess(row['heartbeat_age'], 120)
        self.assertTrue(row['audit_ok'])
        self.assertEqual(row['misses_open'], 1)
        self.assertEqual(row['outage_age'], 0)
        self.assertIsNone(row['last_receipt_age'])
        text = capture.render('mainnet', probe, doc)
        self.assertIn(f'zecblock_capture_observer_audit_misses_open{{network="mainnet",observer="{OBSERVER}"}} 1\n', text)
        self.assertIn(f'zecblock_capture_observer_unobserved_seconds{{network="mainnet",observer="{OBSERVER}"}} 1.5\n', text)

    def test_query_without_optional_objects(self):
        # Simulates an older database: only the 035 columns are referenced.
        doc = capture.psql_json(URL, capture.build_query({'observers': True, 'snapshots': True}))
        row = next(r for r in doc['observers'] if r['observer'] == OBSERVER)
        self.assertNotIn('coverage_age', row)
        self.assertIsInstance(doc['snapshots'], list)

    def test_monitor_role_sql_applies_and_is_idempotent(self):
        sql = pathlib.Path(__file__).with_name('monitoring') / 'sql/monitor-role.sql'
        for _ in range(2):
            subprocess.run(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-d', URL, '-f', str(sql)], check=True)
        out = subprocess.run(
            ['psql', '-X', '-A', '-t', '-d', URL, '-c',
             "SELECT has_table_privilege('zecblock_monitor', 'public.block_capture_observers', 'SELECT'),"
             " has_table_privilege('zecblock_monitor', 'public.block_capture_observers', 'UPDATE'),"
             " has_table_privilege('zecblock_monitor', 'public.nodes', 'SELECT'),"
             " (SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = 'zecblock_monitor')"],
            capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(out, 't|f|f|f')


if __name__ == '__main__':
    unittest.main()
