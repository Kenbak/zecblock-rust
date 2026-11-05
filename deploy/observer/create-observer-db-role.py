"""Run on the PRIMARY. Creates one restricted capture login per regional observer.

Usage: create-observer-db-role.py <network> <observer> <wireguard-ip>

Grants mirror the primary's zecblock_capture login as measured 2026-11-05
(including migration 042's block_capture_audit_misses). The password is written to a
0600 file, never printed; move it to the observer over SSH and delete it here.
The pg_hba line is printed for review; this script does not edit pg_hba.conf.
"""
import ipaddress, os, pathlib, re, secrets, subprocess, sys

OBSERVER_RE = re.compile(r'^[A-Za-z0-9_-]{1,40}$')  # collector allows 80; role names cap at 63


def validate(network, observer, wg_ip):
    if network not in ('mainnet', 'testnet'):
        raise ValueError('network must be mainnet or testnet')
    if not OBSERVER_RE.match(observer) or observer == 'local-node':
        raise ValueError('invalid or reserved observer name')
    ip = ipaddress.ip_address(wg_ip)
    if ip not in ipaddress.ip_network('10.77.0.0/24') or str(ip) == '10.77.0.1':
        raise ValueError('observer address must be a 10.77.0.0/24 WireGuard peer, not the hub')
    role = 'zecblock_capture_' + observer.lower().replace('-', '_')
    return role, 'zcash_explorer_' + network, str(ip)


def role_sql(role, db, password):
    # role/db come only from validate(); the password is hex.
    assert re.fullmatch(r'[a-z0-9_]{1,63}', role) and re.fullmatch(r'[0-9a-f]{64}', password)
    return f"""DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} LOGIN; END IF; END $$;
ALTER ROLE {role} WITH PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 2;
GRANT CONNECT ON DATABASE {db} TO {role};
GRANT USAGE ON SCHEMA public TO {role};
GRANT SELECT ON blocks, block_subsidy_allocations TO {role};
GRANT SELECT, INSERT, UPDATE ON captured_blocks, block_capture_observers, block_capture_receipts, block_capture_audit_misses TO {role};
ALTER ROLE {role} SET statement_timeout='5s';
ALTER ROLE {role} SET lock_timeout='500ms';
"""


def main(argv):
    network, observer, wg_ip = argv
    role, db, ip = validate(network, observer, wg_ip)
    out = pathlib.Path('/root') / f'{role}.password'
    if out.exists():
        raise SystemExit(f'{out} already exists; inspect before replacement')
    password = secrets.token_hex(32)
    r = subprocess.run(['sudo', '-u', 'postgres', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', db],
                       input=role_sql(role, db, password), text=True, capture_output=True)
    if r.returncode:
        raise SystemExit('role setup failed; inspect locally (output withheld)')
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(password + '\n')
    print(f'role {role} ready; password file {out}')
    print(f'review, add to pg_hba.conf, then reload:\nhost {db} {role} {ip}/32 scram-sha-256')


if __name__ == '__main__':
    main(sys.argv[1:])
