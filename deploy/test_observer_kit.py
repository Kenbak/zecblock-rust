import importlib.util, pathlib, unittest

HERE = pathlib.Path(__file__).resolve().parent / 'observer'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


role = load('create-observer-db-role')
install = load('install-observer')
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
        self.assertIn('ON captured_blocks, block_capture_observers, block_capture_receipts', sql)
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


if __name__ == '__main__':
    unittest.main()
