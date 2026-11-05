"""Unit and consistency tests for deploy/monitoring (no network, no root, no YAML library)."""
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent / 'monitoring'


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load('zecblock_host_textfile', 'exporters/zecblock-host-textfile.py')
capture = load('zecblock_capture_exporter', 'exporters/zecblock-capture-exporter.py')
render_am = load('render_alertmanager', 'alertmanager/render-alertmanager.py')
install = load('monitoring_install', 'install.py')

NFT_JSON = json.dumps({'nftables': [
    {'metainfo': {'version': '1.0.9', 'json_schema_version': 1}},
    {'table': {'family': 'ip', 'name': 'cve_2026_98432', 'handle': 7}},
    {'chain': {'family': 'ip', 'table': 'cve_2026_98432', 'name': 'prerouting', 'handle': 1,
               'type': 'filter', 'hook': 'prerouting', 'prio': -300, 'policy': 'accept'}},
    {'rule': {'family': 'ip', 'table': 'cve_2026_98432', 'chain': 'prerouting', 'handle': 2, 'expr': [
        {'match': {'op': '==', 'left': {'meta': {'key': 'l4proto'}}, 'right': 'tcp'}},
        {'match': {'op': '!=', 'left': {'payload': {'protocol': 'ip', 'field': 'hdrlength'}}, 'right': 5}},
        {'counter': {'packets': 12, 'bytes': 720}},
        {'drop': None}]}},
]})
CHRONY = 'A9FEA97B,169.254.169.123,3,1762300000.123456789,-0.000012345,0.000001234,0.000020000,-12.345,0.001,0.010,0.000500,0.000250,64.2,Normal\n'


class Result:
    def __init__(self, returncode, stdout=''):
        self.returncode, self.stdout = returncode, stdout


class HostTextfileTests(unittest.TestCase):
    def test_parse_nft_counts_drop_rule(self):
        self.assertEqual(host.parse_nft(NFT_JSON), (True, 12, 720, 1))

    def test_rule_without_drop_is_not_protection(self):
        doc = json.loads(NFT_JSON)
        doc['nftables'][3]['rule']['expr'].pop()
        present, _, _, rules = host.parse_nft(json.dumps(doc))
        self.assertTrue(present)
        self.assertEqual(rules, 0)

    def test_parse_chrony(self):
        t = host.parse_chrony(CHRONY)
        self.assertEqual(t['stratum'], 3)
        self.assertAlmostEqual(t['system_time'], -0.000012345)
        self.assertTrue(t['synchronised'])
        unsynced = host.parse_chrony('00000000,,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,Not synchronised')
        self.assertFalse(unsynced['synchronised'])
        with self.assertRaises(ValueError):
            host.parse_chrony('a,b,c')

    def test_kernel_sort_is_numeric(self):
        self.assertEqual(max(['6.8.0-99-generic', '6.8.0-147-generic', '6.8.0-149-generic'],
                             key=host.kernel_sort_key), '6.8.0-149-generic')

    def collect(self, nft=Result(0, NFT_JSON), chrony=Result(0, CHRONY), reboot=True):
        with tempfile.TemporaryDirectory() as root:
            r = pathlib.Path(root)
            (r / 'proc/sys/net/mptcp').mkdir(parents=True)
            (r / 'proc/sys/net/mptcp/enabled').write_text('0\n')
            (r / 'boot').mkdir()
            for k in ('6.8.0-147-generic', '6.8.0-149-generic'):
                (r / 'boot' / f'vmlinuz-{k}').write_text('')
            (r / 'run').mkdir()
            if reboot:
                (r / 'run/reboot-required').write_text('*** System restart required ***\n')
                (r / 'run/reboot-required.pkgs').write_text('linux-base\nlinux-image-6.8.0-149-generic\nlinux-base\n')
            m = host.Metrics()
            host.collect(m, nft_runner=lambda: nft, chrony_runner=lambda: chrony, root=root)
            return m.render()

    def test_collect_renders_expected_series(self):
        text = self.collect()
        for line in ('zecblock_cve_2026_98432_nft_table_present 1',
                     'zecblock_cve_2026_98432_nft_dropped_packets_total 12',
                     'zecblock_mptcp_enabled 0',
                     'zecblock_reboot_required 1',
                     'zecblock_reboot_required_packages 2',
                     'zecblock_kernel_newer_installed 1',
                     'zecblock_chrony_up 1',
                     'zecblock_chrony_synchronised 1',
                     'zecblock_chrony_stratum 3'):
            self.assertIn(line + '\n', text)
        self.assertIn('newest_installed="6.8.0-149-generic"', text)
        self.assertIn('# TYPE zecblock_cve_2026_98432_nft_dropped_packets_total counter', text)

    def test_missing_table_and_chrony(self):
        text = self.collect(nft=Result(1), chrony=Result(1), reboot=False)
        self.assertIn('zecblock_cve_2026_98432_nft_table_present 0\n', text)
        self.assertNotRegex(text, r'(?m)^zecblock_cve_2026_98432_nft_dropped_packets_total ')
        self.assertIn('zecblock_chrony_up 0\n', text)
        self.assertIn('zecblock_reboot_required 0\n', text)
        self.assertNotRegex(text, r'(?m)^zecblock_reboot_required_since_timestamp_seconds ')

    def test_label_escaping(self):
        m = host.Metrics()
        m.add('x', 1, 'h', labels={'a': 'q"\\\n'})
        self.assertIn('x{a="q\\"\\\\\\n"} 1', m.render())

    def test_atomic_write(self):
        with tempfile.TemporaryDirectory() as d:
            host.write_atomic(d, 'zecblock_host.prom', 'a 1\n')
            self.assertEqual(os.listdir(d), ['zecblock_host.prom'])


FULL_PROBE = {'observers': True, 'receipts': True, 'misses': True, 'coverage_042': True,
              'gossip': True, 'snapshots': True, 'census_version': True}


class CaptureExporterTests(unittest.TestCase):
    def test_query_only_references_probed_objects(self):
        q = capture.build_query({'observers': True})
        self.assertIn('block_capture_observers', q)
        for absent in ('coverage_since', 'block_capture_audit_misses', 'block_capture_receipts',
                       'topology_gossip_snapshots', 'node_snapshots'):
            self.assertNotIn(absent, q)
        self.assertIsNone(capture.build_query({}))
        full = capture.build_query(FULL_PROBE)
        for present in ('coverage_since', 'audit_canonical_missing', 'block_capture_audit_misses',
                        'topology_gossip_snapshots', 'census_version'):
            self.assertIn(present, full)

    def test_query_never_reads_ip_tables(self):
        full = capture.build_query(FULL_PROBE) + capture.PROBE_SQL
        for table in ('public.nodes ', 'nodes_crawl', 'topology_gossip_edges', 'pg_stat_activity'):
            self.assertNotIn(table, full)

    def test_render(self):
        doc = {
            'observers': [{'observer': 'do-nyc3', 'network': 'mainnet', 'stream_connected': True, 'gaps': 3,
                           'pending_records': 0, 'heartbeat_age': 4.5, 'collection_age': 100.0,
                           'last_gap_age': None, 'coverage_age': 3600.0, 'unobserved_ms': 1500,
                           'pending_bytes': 0, 'journal_max_bytes': 268435456, 'outage_age': 0,
                           'audit_age': 120.0, 'audit_ok': True, 'audit_fork_tips': 1, 'audit_fork_blocks': 2,
                           'audit_canonical_checked': 100, 'audit_canonical_missing': 0,
                           'misses_open': 0, 'misses_24h': 0, 'last_receipt_age': 60.0}],
            'gossip': [{'source': 'direct', 'age': 30.0, 'edges': 1200, 'truncated': False}],
            'snapshots': [{'census_version': 3, 'age': 600.0, 'active_nodes': 250}],
        }
        text = capture.render('mainnet', FULL_PROBE, doc, duration=0.01, now=1.0)
        obs = '{network="mainnet",observer="do-nyc3"}'
        for line in (f'zecblock_capture_observer_heartbeat_age_seconds{obs} 4.5',
                     f'zecblock_capture_observer_stream_connected{obs} 1',
                     f'zecblock_capture_observer_gaps_total{obs} 3',
                     f'zecblock_capture_observer_unobserved_seconds{obs} 1.5',
                     f'zecblock_capture_observer_audit_ok{obs} 1',
                     'zecblock_census_gossip_age_seconds{collector_source="direct",network="mainnet"} 30.0',
                     'zecblock_census_gossip_truncated{collector_source="direct",network="mainnet"} 0',
                     'zecblock_census_snapshot_age_seconds{census_version="3",network="mainnet"} 600.0',
                     'zecblock_capture_exporter_up{network="mainnet"} 1',
                     'zecblock_capture_schema_present{network="mainnet",object="migration_042_coverage"} 1'):
            self.assertIn(line + '\n', text)
        self.assertNotIn('last_gap_age_seconds{', text)

    def test_down_render(self):
        text = capture.render('testnet', None, None, up=False)
        self.assertIn('zecblock_capture_exporter_up{network="testnet"} 0\n', text)
        self.assertNotIn('zecblock_capture_schema_present{', text)


class AlertmanagerRenderTests(unittest.TestCase):
    TEMPLATE = (ROOT / 'alertmanager/alertmanager.yml.tmpl').read_text()

    def render(self, **kw):
        args = dict(chat_id='-100123', secrets_dir='/etc/zecblock-monitor',
                    templates_dir='/etc/zecblock-monitor/alertmanager', heartbeat=False)
        args.update(kw)
        return render_am.render(self.TEMPLATE, **args)

    def test_no_placeholder_left_and_chat_id_is_integer(self):
        out = self.render()
        self.assertNotIn('${', out)
        self.assertIn('chat_id: -100123\n', out)
        self.assertIn('bot_token_file: /etc/zecblock-monitor/telegram-bot-token', out)

    def test_heartbeat_toggle(self):
        off = self.render()
        self.assertNotIn('name: heartbeat', off)
        self.assertIn('receiver: blackhole', off)
        on = self.render(heartbeat=True)
        self.assertIn('name: heartbeat', on)
        self.assertIn('url_file: /etc/zecblock-monitor/heartbeat-url', on)
        self.assertNotIn('HEARTBEAT-', on)

    def test_rejects_bad_values(self):
        for bad in ('', '12a', '1; rm', '-'):
            with self.assertRaises(ValueError):
                self.render(chat_id=bad)
        with self.assertRaises(ValueError):
            self.render(secrets_dir='relative/path')

    def test_env_file_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'telegram.env'
            p.write_text('# comment\nTELEGRAM_CHAT_ID="-42"\nTELEGRAM_BOT_TOKEN=unused\n')
            self.assertEqual(render_am.read_env_file(p)['TELEGRAM_CHAT_ID'], '-42')
            p.write_text('not an assignment\n')
            with self.assertRaises(ValueError):
                render_am.read_env_file(p)


class InstallerTests(unittest.TestCase):
    def test_wg_ip_validation(self):
        self.assertEqual(install.validate_wg_ip('10.77.0.11'), '10.77.0.11')
        for bad in ('10.77.1.5', '10.77.0.0', '10.77.0.255', '10.77.0.2', '0.0.0.0'):
            with self.assertRaises(ValueError):
                install.validate_wg_ip(bad)

    def test_node_exporter_never_binds_wildcard(self):
        args = install.node_exporter_args('10.77.0.3:9100')
        self.assertIn('--web.listen-address=10.77.0.3:9100', args)
        self.assertNotIn('0.0.0.0', args)

    def test_versions_are_pinned(self):
        v = install.read_versions()
        for key in ('PROMETHEUS', 'ALERTMANAGER', 'GRAFANA'):
            self.assertRegex(v[f'{key}_SHA256'], r'^[0-9a-f]{64}$')
            self.assertTrue(v[f'{key}_URL'].startswith('https://'))
            self.assertIn(v[f'{key}_VERSION'], v[f'{key}_URL'])

    def test_dry_run_monitor_does_not_need_root(self):
        out = subprocess.run(['python3', str(ROOT / 'install.py'), 'host', '--wg-ip', '10.77.0.11', '--dry-run'],
                             capture_output=True, text=True, check=True).stdout
        self.assertIn('ufw allow in on wg0 from 10.77.0.2 to 10.77.0.11 port 9100', out)


def kit_files():
    return [p for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts]


class ConsistencyTests(unittest.TestCase):
    RULES = (ROOT / 'prometheus/rules/fleet.rules.yml').read_text()
    DASHBOARD = json.loads((ROOT / 'grafana/dashboards/zecblock-fleet.json').read_text())
    EXPORTER_SOURCES = ((ROOT / 'exporters/zecblock-host-textfile.py').read_text()
                        + (ROOT / 'exporters/zecblock-capture-exporter.py').read_text())

    def exported(self, name):
        if name in self.EXPORTER_SOURCES:
            return True
        if name.startswith('zecblock_capture_observer_'):
            suffix = name[len('zecblock_capture_observer_'):]
            return any(m[1] == suffix for m in capture.OBSERVER_METRICS)
        return False

    def test_every_zecblock_metric_used_is_exported(self):
        exprs = self.RULES + json.dumps(self.DASHBOARD)
        used = set(re.findall(r'\bzecblock_[a-z0-9_]+\b(?!\.prom)', exprs))
        self.assertTrue(used)
        missing = sorted(n for n in used if not self.exported(n))
        self.assertEqual(missing, [])

    def test_recorded_series_used_are_defined(self):
        recorded = set(re.findall(r'record: (zecblock:[a-z_]+)', self.RULES))
        used = set(re.findall(r'zecblock:[a-z_]+', self.RULES + json.dumps(self.DASHBOARD)))
        self.assertEqual(used - recorded, set())

    def test_alerts_have_severity_and_summary(self):
        blocks = re.split(r'\n      - alert: ', self.RULES)[1:]
        names = [b.split('\n', 1)[0] for b in blocks]
        self.assertEqual(len(names), len(set(names)))
        for name, block in zip(names, blocks):
            with self.subTest(alert=name):
                self.assertRegex(block, r'labels: \{severity: (critical|warning|info|none)\}')
                self.assertIn('summary:', block)

    def test_promtool_tests_reference_real_alerts(self):
        tests = (ROOT / 'prometheus/tests/fleet.test.yml').read_text()
        alerts = set(re.findall(r'- alert: (\w+)', self.RULES))
        tested = set(re.findall(r'alertname: (\w+)', tests))
        self.assertTrue(tested)
        self.assertEqual(tested - alerts, set())

    def test_targets_are_wireguard_only_and_unique(self):
        net = ipaddress.ip_network('10.77.0.0/24')
        hosts = {}
        for name in ('node', 'zakura'):
            text = (ROOT / f'prometheus/targets/{name}.yml').read_text()
            entries = re.findall(r"targets: \['([0-9.]+):(\d+)'\]\n\s+labels: \{host: ([a-z0-9-]+),", text)
            self.assertTrue(entries)
            seen = set()
            for ip, port, h in entries:
                self.assertIn(ipaddress.ip_address(ip), net)
                self.assertNotEqual(ip, '10.77.0.2')
                self.assertNotIn(h, seen)
                seen.add(h)
                hosts.setdefault(h, set()).add(ip)
        for h, ips in hosts.items():
            self.assertEqual(len(ips), 1, f'{h} has different wg addresses across target files')

    def test_no_public_ipv4_or_secrets_in_kit(self):
        allowed = {ipaddress.ip_network(n) for n in ('10.77.0.0/24', '127.0.0.0/8', '0.0.0.0/32', '169.254.0.0/16')}
        for path in kit_files():
            text = path.read_text(errors='replace')
            for ip in re.findall(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])', text):
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                with self.subTest(path=str(path.relative_to(ROOT)), ip=ip):
                    self.assertTrue(any(addr in n for n in allowed), 'public address in public repo')
            with self.subTest(path=str(path.relative_to(ROOT))):
                for pattern in (r'\b\d{8,10}:[A-Za-z0-9_-]{30,}\b',            # Telegram bot token
                                r'(?i)(password|passwd)\s*=\s*[^\s<]\S{5,}'):  # literal password, not <placeholder>
                    found = re.search(pattern, text)
                    self.assertIsNone(found, found and found.group(0)[:12] + '...')

    def test_services_listen_on_loopback_or_wg(self):
        units = ''.join(p.read_text() for p in (ROOT / 'systemd').iterdir())
        for addr in re.findall(r'listen-address=([^\s\\]*)', units):
            if addr:
                self.assertTrue(addr.startswith('127.0.0.1:'), addr)
        self.assertIn('http_addr = 127.0.0.1', (ROOT / 'grafana/grafana.ini').read_text())

    def test_dashboard_panels_have_unique_ids_and_datasource(self):
        ids = [p['id'] for p in self.DASHBOARD['panels']]
        self.assertEqual(len(ids), len(set(ids)))
        for p in self.DASHBOARD['panels']:
            for t in p.get('targets', []):
                self.assertEqual(t['datasource']['uid'], 'zecblock-prometheus')


if __name__ == '__main__':
    unittest.main()
