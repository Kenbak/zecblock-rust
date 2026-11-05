"""Run on a regional OBSERVER after Zakura is synced and WireGuard is up.

Usage: install-observer.py <network> <observer> <artifact> <sha256> <password-file>

Verifies the collector artifact, writes /etc/cipherscan/orphan-collector.env
(0600, never printed) and enables cipherscan-observer-collector.service.
Refuses to replace an existing environment file.
"""
import hashlib, os, pathlib, re, subprocess, sys

HUB = '10.77.0.1'
SERVICE = 'cipherscan-observer-collector'
HERE = pathlib.Path(__file__).resolve().parent


def quote(v):
    if '\n' in v or '\r' in v:
        raise ValueError('newline in environment value')
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'


def build_env(network, observer, password):
    if network not in ('mainnet', 'testnet'):
        raise ValueError('network must be mainnet or testnet')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', observer) or observer == 'local-node':
        raise ValueError('invalid or reserved observer name')
    if not re.fullmatch(r'[0-9a-f]{64}', password):
        raise ValueError('unexpected password format')
    role = 'zecblock_capture_' + observer.lower().replace('-', '_')
    env = {
        'NETWORK': network,
        'OBSERVER': observer,
        'ZEBRA_RPC_URL': 'http://127.0.0.1:8232',
        'ZEBRA_GRPC_URL': 'http://127.0.0.1:8230',
        'ZEBRA_RPC_COOKIE_FILE': '/var/lib/zakura/.cache/zakura/.cookie',
        'DATABASE_URL': f'postgresql://{role}:{password}@{HUB}:5432/zcash_explorer_{network}',
    }
    return ''.join(k + '=' + quote(v) + '\n' for k, v in env.items())


def main(argv):
    network, observer, artifact, expected, password_file = argv
    if hashlib.sha256(pathlib.Path(artifact).read_bytes()).hexdigest() != expected:
        raise SystemExit('artifact hash mismatch')
    envpath = pathlib.Path('/etc/cipherscan/orphan-collector.env')
    if envpath.exists():
        raise SystemExit('collector environment already exists; inspect before replacement')
    content = build_env(network, observer, pathlib.Path(password_file).read_text().strip())
    envpath.parent.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(envpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    pathlib.Path(password_file).unlink()
    release = pathlib.Path('/opt/cipherscan-orphan-collector')
    release.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(['install', '-m', '0755', artifact, str(release / 'cipherscan-indexer')], check=True)
    subprocess.run(['install', '-m', '0644', str(HERE / f'{SERVICE}.service'),
                    f'/etc/systemd/system/{SERVICE}.service'], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', SERVICE], check=True)
    print('observer collector installed:', network, observer, expected)


if __name__ == '__main__':
    main(sys.argv[1:])
