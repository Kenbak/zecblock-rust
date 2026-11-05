"""Run on an OBSERVER. Adds one third-party Zakura node as a remote capture source.

Usage:
  add-remote-node.py --instance <short-name> --observer <public-observer-name>
                     --node-ip <ipv4> --server-ca <pem> --tls-domain <name-in-server-cert>
                     --db-role <role> --db-password-file <file>
                     [--rpc-user <user> --rpc-password-file <file>]

Writes /etc/cipherscan/remote/<instance>.env (0600 root) and enables
cipherscan-remote-collector@<instance>. The collector connects to
https://<node-ip>:8230 with our client certificate (mutual TLS) and to the
node's JSON-RPC at http://<node-ip>:8232, and writes receipts to the primary
over WireGuard. Secrets are read from files, never from argv, and never printed.
"""
import argparse, ipaddress, pathlib, re, shutil, subprocess, sys

NAME = re.compile(r'^[a-z0-9][a-z0-9-]{0,30}$')
OBSERVER = re.compile(r'^[A-Za-z0-9_-]{1,80}$')
ROLE = re.compile(r'^[a-z0-9_]{1,63}$')
DOMAIN = re.compile(r'^[A-Za-z0-9.-]{1,253}$')
HUB = '10.77.0.1'
TLS_DIR = pathlib.Path('/etc/cipherscan/grpc-tls')
REMOTE_DIR = pathlib.Path('/etc/cipherscan/remote')


def quote(v):
    if '\n' in v or '\r' in v:
        raise ValueError('newline in value')
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'


def build_env(a, db_password, rpc_password=None, server_ca_path=None):
    if not NAME.match(a.instance):
        raise ValueError('instance must be lowercase letters, digits and dashes')
    if not OBSERVER.match(a.observer) or a.observer in ('local-node',) or a.observer.startswith('do-'):
        raise ValueError('invalid or reserved observer name')
    ip = ipaddress.ip_address(a.node_ip)
    if ip.version != 4 or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError('node IP must be a public IPv4 address')
    if not DOMAIN.match(a.tls_domain):
        raise ValueError('invalid TLS domain')
    if not ROLE.match(a.db_role):
        raise ValueError('invalid DB role')
    if not re.fullmatch(r'[0-9a-f]{64}', db_password):
        raise ValueError('unexpected DB password format')
    env = {
        'NETWORK': 'mainnet',
        'OBSERVER': a.observer,
        'ZEBRA_RPC_URL': f'http://{ip}:8232',
        'ZEBRA_GRPC_URL': f'https://{ip}:8230',
        'ZEBRA_GRPC_TLS_CA_FILE': str(server_ca_path or TLS_DIR / f'{a.instance}-server-ca.pem'),
        'ZEBRA_GRPC_TLS_CERT_FILE': str(TLS_DIR / 'client.pem'),
        'ZEBRA_GRPC_TLS_KEY_FILE': str(TLS_DIR / 'client.key'),
        'ZEBRA_GRPC_TLS_DOMAIN': a.tls_domain,
        'DATABASE_URL': f'postgresql://{a.db_role}:{db_password}@{HUB}:5432/zcash_explorer_mainnet',
    }
    if a.rpc_user:
        if rpc_password is None:
            raise ValueError('--rpc-user needs --rpc-password-file')
        env['ZEBRA_RPC_USER'] = a.rpc_user
        env['ZEBRA_RPC_PASS'] = rpc_password
    return ''.join(f'{k}={quote(v)}\n' for k, v in env.items())


def main(argv):
    p = argparse.ArgumentParser()
    for flag in ('--instance', '--observer', '--node-ip', '--server-ca', '--tls-domain', '--db-role', '--db-password-file'):
        p.add_argument(flag, required=True)
    p.add_argument('--rpc-user')
    p.add_argument('--rpc-password-file')
    a = p.parse_args(argv)
    ca_text = pathlib.Path(a.server_ca).read_text()
    if '-----BEGIN CERTIFICATE-----' not in ca_text or 'PRIVATE KEY' in ca_text:
        raise SystemExit('server CA must be a PEM certificate (and never a private key)')
    rpc_password = pathlib.Path(a.rpc_password_file).read_text().strip() if a.rpc_password_file else None
    content = build_env(a, pathlib.Path(a.db_password_file).read_text().strip(), rpc_password)
    ca_dest = TLS_DIR / f'{a.instance}-server-ca.pem'
    shutil.copyfile(a.server_ca, ca_dest)
    ca_dest.chmod(0o644)
    REMOTE_DIR.mkdir(mode=0o700, exist_ok=True)
    env_path = REMOTE_DIR / f'{a.instance}.env'
    env_path.write_text(content)
    env_path.chmod(0o600)
    unit = f'cipherscan-remote-collector@{a.instance}'
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', unit], check=True)
    print(f'{unit} enabled for observer {a.observer} ({a.node_ip})')


if __name__ == '__main__':
    main(sys.argv[1:])
