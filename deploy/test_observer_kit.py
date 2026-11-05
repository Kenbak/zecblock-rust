import importlib.util, pathlib, unittest

HERE = pathlib.Path(__file__).resolve().parent / 'observer'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


role = load('create-observer-db-role')
install = load('install-observer')
remote = load('add-remote-node')
PW = 'a' * 64


class ObserverKitTest(unittest.TestCase):
    def test_role_names_are_safe_and_scoped(self):
        self.assertEqual(role.validate('mainnet', 'do-nyc3', '10.77.0.2'),
                         ('zecblock_capture_do_nyc3', 'zcash_explorer_mainnet', '10.77.0.2'))
        for bad in ("x';drop", 'local-node', '', 'a' * 41, 'do nyc'):
            with self.assertRaises(ValueError):
                role.validate('mainnet', bad, '10.77.0.2')

    def test_rejects_non_peer_addresses(self):
        for ip in ('10.77.0.1', '10.78.0.2', '37.27.61.34'):
            with self.assertRaises(ValueError):
                role.validate('mainnet', 'do-nyc3', ip)

    def test_sql_grants_only_capture_tables(self):
        sql = role.role_sql('zecblock_capture_do_nyc3', 'zcash_explorer_mainnet', PW)
        self.assertIn('NOSUPERUSER', sql)
        self.assertIn('ON captured_blocks, block_capture_observers, block_capture_receipts, block_capture_audit_misses', sql)
        self.assertNotIn('transactions', sql)

    def test_env_points_at_wireguard_hub_and_loopback_node(self):
        env = install.build_env('mainnet', 'do-sgp1', PW)
        self.assertIn('OBSERVER="do-sgp1"', env)
        self.assertIn('@10.77.0.1:5432/zcash_explorer_mainnet"', env)
        self.assertIn('ZEBRA_RPC_URL="http://127.0.0.1:8232"', env)
        with self.assertRaises(ValueError):
            install.build_env('mainnet', 'do-sgp1', 'short')

    def test_collector_unit_uses_observer_name(self):
        unit = (HERE / 'cipherscan-observer-collector.service').read_text()
        self.assertIn('--observer ${OBSERVER}', unit)
        self.assertIn('Requires=wg-quick@wg0.service', unit)
        self.assertIn('User=zakura', unit)

    def test_cloud_init_security_baseline(self):
        ci = (HERE / 'cloud-init.yaml').read_text()
        self.assertTrue(ci.startswith('#cloud-config'))
        self.assertIn('meta l4proto tcp ip hdrlength != 5 counter drop', ci)
        self.assertIn('[systemctl, enable, --now, cve-2026-98432-nft.service]', ci)
        self.assertIn('net.mptcp.enabled = 0', ci)
        self.assertIn('PasswordAuthentication no', ci)
        self.assertIn('Automatic-Reboot "true"', ci)
        self.assertIn('package_reboot_if_required: true', ci)
        self.assertNotIn('  - fail2ban', ci)
        # cloud-init ignores `home:`; a /home path breaks ProtectHome=yes in the node unit.
        self.assertIn('homedir: /var/lib/zakura', ci)

    def remote_args(self, **kw):
        import argparse
        base = dict(instance='node1', observer='ext-op1-node1', node_ip='1.1.1.1',
                    tls_domain='node1.example', db_role='zecblock_capture_ext_op1',
                    rpc_user=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_remote_node_env_uses_mtls_and_wireguard_db(self):
        env = remote.build_env(self.remote_args(), PW)
        self.assertIn('ZEBRA_GRPC_URL="https://1.1.1.1:8230"', env)
        self.assertIn('ZEBRA_RPC_URL="http://1.1.1.1:8232"', env)
        self.assertIn('ZEBRA_GRPC_TLS_CA_FILE="/etc/cipherscan/grpc-tls/node1-server-ca.pem"', env)
        self.assertIn('ZEBRA_GRPC_TLS_DOMAIN="node1.example"', env)
        self.assertIn('@10.77.0.1:5432/zcash_explorer_mainnet"', env)
        self.assertNotIn('ZEBRA_RPC_PASS', env)
        self.assertNotIn('ZEBRA_RPC_TLS_CA_FILE', env)
        tls = remote.build_env(self.remote_args(rpc_https=True), PW)
        self.assertIn('ZEBRA_RPC_URL="https://1.1.1.1:8232"', tls)
        self.assertIn('ZEBRA_RPC_TLS_CA_FILE="/etc/cipherscan/grpc-tls/node1-server-ca.pem"', tls)

    def test_remote_node_rejects_bad_input(self):
        for kw in ({'node_ip': '10.0.0.5'}, {'node_ip': '::1'}, {'observer': 'do-nyc3'},
                   {'observer': 'local-node'}, {'instance': 'Node One'}, {'tls_domain': 'a b'}):
            with self.assertRaises(ValueError):
                remote.build_env(self.remote_args(**kw), PW)
        with self.assertRaises(ValueError):
            remote.build_env(self.remote_args(rpc_user='zec'), PW)

    def test_remote_env_file_is_never_readable_by_others(self):
        import os, stat, tempfile
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / 'op1.env'
            remote.write_private(path, 'PGPASSWORD=x\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            path.chmod(0o644)  # a pre-existing, too-open file is tightened on rewrite
            remote.write_private(path, 'PGPASSWORD=y\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), 'PGPASSWORD=y\n')

    def test_remote_unit_is_a_template_with_its_own_journal(self):
        unit = (HERE / 'cipherscan-remote-collector@.service').read_text()
        self.assertIn('EnvironmentFile=/etc/cipherscan/remote/%i.env', unit)
        self.assertIn('--journal /var/lib/cipherscan-remote-collector/%i', unit)
        self.assertIn('User=zakura', unit)
        self.assertNotIn('zakurad-observer.service', unit)


if __name__ == '__main__':
    unittest.main()
