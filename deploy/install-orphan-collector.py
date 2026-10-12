"""Run on the serving host after migration 035 and artifact verification. Never prints secrets."""
import os, pathlib, secrets, subprocess, sys
network, artifact, expected = sys.argv[1:]
assert network in ('mainnet','testnet')
import hashlib
assert hashlib.sha256(pathlib.Path(artifact).read_bytes()).hexdigest() == expected
service = 'cipherscan-orphan-collector'
db = 'zcash_explorer_'+network
release = pathlib.Path('/opt/cipherscan-orphan-collector')
release.mkdir(mode=0o755,exist_ok=True)
envdir=pathlib.Path('/etc/cipherscan');envdir.mkdir(mode=0o700,exist_ok=True)
envpath=envdir/'orphan-collector.env'
# Refuse changing an existing deployment with this first-install script.
assert not envpath.exists(), 'collector environment already exists; inspect before replacement'
source={}
for line in pathlib.Path('/root/cipherscan-rust/.env').read_text().splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        k,v=line.split('=',1); source[k.strip()]=v.strip().strip('"').strip("'")
allowed=('ZEBRA_RPC_URL','ZEBRA_GRPC_URL','ZEBRA_RPC_COOKIE_FILE','ZEBRA_RPC_USER','ZEBRA_RPC_PASS')
env={k:source[k] for k in allowed if k in source}
assert env.get('ZEBRA_RPC_URL') and env.get('ZEBRA_GRPC_URL'), 'node endpoints missing'
if not (env.get('ZEBRA_RPC_COOKIE_FILE') or (env.get('ZEBRA_RPC_USER') and env.get('ZEBRA_RPC_PASS'))):
    # Some serving nodes deliberately expose unauthenticated RPC on loopback.
    # Match that existing configuration, but never allow an unauthenticated remote endpoint.
    from urllib.parse import urlparse
    import ipaddress
    endpoint = urlparse(env['ZEBRA_RPC_URL'])
    assert endpoint.scheme in ('http', 'https') and endpoint.hostname, 'invalid RPC endpoint'
    assert endpoint.hostname == 'localhost' or ipaddress.ip_address(endpoint.hostname).is_loopback, 'remote node auth missing'
pw=secrets.token_hex(32)
sql=f"""DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='zecblock_capture') THEN CREATE ROLE zecblock_capture LOGIN; END IF; END $$;
ALTER ROLE zecblock_capture WITH PASSWORD '{pw}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 2;
GRANT CONNECT ON DATABASE {db} TO zecblock_capture;
GRANT USAGE ON SCHEMA public TO zecblock_capture;
GRANT SELECT ON blocks TO zecblock_capture;
GRANT SELECT, INSERT, UPDATE ON captured_blocks, block_capture_observers, block_capture_receipts TO zecblock_capture;
ALTER ROLE zecblock_capture SET statement_timeout='3s';
ALTER ROLE zecblock_capture SET lock_timeout='500ms';
"""
r=subprocess.run(['sudo','-u','postgres','psql','-X','-v','ON_ERROR_STOP=1','-d',db],input=sql,text=True,capture_output=True)
if r.returncode: raise RuntimeError('collector database role setup failed; inspect locally')
env['NETWORK']=network
env['DATABASE_URL']=f'postgresql://zecblock_capture:{pw}@127.0.0.1:5432/{db}'
# Systemd environment files: quote and escape; only known keys are copied.
def quote(v):
    assert '\n' not in v and '\r' not in v
    return '"'+v.replace('\\','\\\\').replace('"','\\"')+'"'
fd=os.open(envpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f: f.write(''.join(k+'='+quote(v)+'\n' for k,v in env.items()))
subprocess.run(['install','-m','0755',artifact,str(release/'cipherscan-indexer')],check=True)
subprocess.run(['install','-m','0644','/tmp/cipherscan-orphan-collector.service','/etc/systemd/system/'+service+'.service'],check=True)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now',service],check=True)
print('collector installed:',network,expected)
