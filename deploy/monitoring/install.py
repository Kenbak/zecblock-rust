#!/usr/bin/env python3
"""Install the ZecBlock private monitoring pieces. Run as root from a checkout.

  install.py monitor [--dry-run]
      On the monitor droplet: pinned Prometheus/Alertmanager/Grafana (SHA-256
      verified), configs under /etc/zecblock-monitor, loopback-only services.
      Alertmanager is enabled only once its secret files exist.

  install.py host --wg-ip 10.77.0.N [--dry-run]
      On any fleet host whose WireGuard peer to the monitor is up: Ubuntu's
      prometheus-node-exporter bound to the wg address, the host textfile
      collector timer, and a UFW rule allowing 9100 only from the monitor on wg0.

  install.py primary-capture --network mainnet [--dry-run]
      On the primary, after `host`: the capture/census exporter timer as OS user
      zecblock-monitor. It does NOT touch PostgreSQL; the role SQL and the
      pg_hba line are printed for an owner-approved manual step.

Nothing here restarts PostgreSQL, Zakura, the indexer or the collectors.
"""
import argparse
import hashlib
import ipaddress
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
WG_NET = ipaddress.ip_network('10.77.0.0/24')
MONITOR_WG = ipaddress.ip_address('10.77.0.10')
OPT = pathlib.Path('/opt/zecblock-monitor')
ETC = pathlib.Path('/etc/zecblock-monitor')
TEXTFILE_DIR = '/var/lib/prometheus/node-exporter'


class Plan:
    def __init__(self, dry_run):
        self.dry_run = dry_run

    def run(self, *cmd, check=True):
        print('+ ' + ' '.join(str(c) for c in cmd))
        if not self.dry_run:
            return subprocess.run([str(c) for c in cmd], check=check)
        return None

    def copy(self, src, dst, mode=0o644):
        print(f'+ install -m {mode:o} {src} {dst}')
        if not self.dry_run:
            pathlib.Path(dst).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            os.chmod(dst, mode)

    def write(self, dst, text, mode=0o644):
        print(f'+ write {dst} ({mode:o})')
        if not self.dry_run:
            pathlib.Path(dst).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(dst).write_text(text)
            os.chmod(dst, mode)


def read_versions(path=HERE / 'versions.env'):
    out = {}
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            k, _, v = line.partition('=')
            out[k] = v
    return out


def validate_wg_ip(value):
    ip = ipaddress.ip_address(value)
    if ip not in WG_NET or ip == WG_NET.network_address or ip == WG_NET.broadcast_address:
        raise ValueError(f'{value} is not a host address in {WG_NET}')
    if ip == MONITOR_WG:
        raise ValueError('10.77.0.10 is the monitor itself; use `install.py monitor`')
    return str(ip)


def node_exporter_args(listen):
    # Only collectors the dashboard/rules need beyond the defaults; no per-process data.
    return (f'ARGS="--web.listen-address={listen} '
            f'--collector.textfile.directory={TEXTFILE_DIR} '
            '--collector.filesystem.mount-points-exclude=^/(dev|proc|run|sys|snap|var/lib/docker/.+)($|/)"\n')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def fetch_verified(url, expected, dest_dir):
    if not url.startswith('https://'):
        raise ValueError('refusing non-HTTPS artifact URL')
    dest = pathlib.Path(dest_dir) / url.rsplit('/', 1)[1]
    with urllib.request.urlopen(url, timeout=120) as r, open(dest, 'wb') as f:
        shutil.copyfileobj(r, f)
    actual = sha256_file(dest)
    if actual != expected:
        dest.unlink()
        raise SystemExit(f'SHA-256 mismatch for {dest.name}: expected {expected}, got {actual}')
    return dest


def safe_extract(tar_path, dest):
    with tarfile.open(tar_path) as tf:
        base = pathlib.Path(dest).resolve()
        for m in tf.getmembers():
            target = (base / m.name).resolve()
            if base not in target.parents and target != base:
                raise SystemExit(f'unsafe path in archive: {m.name}')
            if m.issym() or m.islnk():
                raise SystemExit(f'link in archive: {m.name}')
        tf.extractall(base)


def ensure_user(plan, name, home='/nonexistent'):
    if subprocess.run(['id', '-u', name], capture_output=True).returncode != 0:
        plan.run('useradd', '--system', '--no-create-home', '--home-dir', home,
                 '--shell', '/usr/sbin/nologin', name)


def install_monitor(plan):
    v = read_versions()
    for user in ('zecblock-prometheus', 'zecblock-alertmanager'):
        ensure_user(plan, user)
    plan.run('apt-get', 'install', '-y', 'prometheus-node-exporter', 'python3')
    plan.write('/etc/default/prometheus-node-exporter', node_exporter_args('127.0.0.1:9100'))
    if not plan.dry_run:
        work = pathlib.Path(tempfile.mkdtemp(prefix='zecblock-monitor-'))
        for key in ('PROMETHEUS', 'ALERTMANAGER'):
            tar = fetch_verified(v[f'{key}_URL'], v[f'{key}_SHA256'], work)
            safe_extract(tar, OPT)
            name = tar.name[:-len('.tar.gz')]
            link = OPT / key.lower()
            tmp_link = OPT / f'.{key.lower()}.new'
            if tmp_link.exists() or tmp_link.is_symlink():
                tmp_link.unlink()
            tmp_link.symlink_to(OPT / name)
            os.replace(tmp_link, link)
        deb = fetch_verified(v['GRAFANA_URL'], v['GRAFANA_SHA256'], work)
        plan.run('apt-get', 'install', '-y', str(deb))
        shutil.rmtree(work)
    else:
        print(f"+ fetch+verify {v['PROMETHEUS_URL']}\n+ fetch+verify {v['ALERTMANAGER_URL']}\n+ fetch+verify+apt {v['GRAFANA_URL']}")

    # Configs (no secrets in any of these files).
    plan.copy(HERE / 'prometheus/prometheus.yml', ETC / 'prometheus/prometheus.yml')
    for p in sorted((HERE / 'prometheus/rules').glob('*.yml')):
        plan.copy(p, ETC / 'prometheus/rules' / p.name)
    for p in sorted((HERE / 'prometheus/targets').glob('*.yml')):
        plan.copy(p, ETC / 'prometheus/targets' / p.name)
    plan.copy(HERE / 'alertmanager/alertmanager.yml.tmpl', ETC / 'alertmanager/alertmanager.yml.tmpl')
    plan.copy(HERE / 'alertmanager/telegram.tmpl', ETC / 'alertmanager/telegram.tmpl')
    plan.copy(HERE / 'alertmanager/render-alertmanager.py', OPT / 'bin/render-alertmanager.py', 0o755)
    plan.copy(HERE / 'exporters/zecblock-host-textfile.py', OPT / 'bin/zecblock-host-textfile.py', 0o755)
    for p in sorted((HERE / 'grafana/provisioning/datasources').glob('*.yml')):
        plan.copy(p, ETC / 'grafana/provisioning/datasources' / p.name)
    for p in sorted((HERE / 'grafana/provisioning/dashboards').glob('*.yml')):
        plan.copy(p, ETC / 'grafana/provisioning/dashboards' / p.name)
    plan.copy(HERE / 'grafana/dashboards/zecblock-fleet.json', ETC / 'grafana/dashboards/zecblock-fleet.json')
    plan.copy(HERE / 'grafana/grafana.ini', '/etc/grafana/grafana.ini', 0o640)
    plan.run('chgrp', 'grafana', '/etc/grafana/grafana.ini')

    units = HERE / 'systemd'
    for name in ('zecblock-prometheus.service', 'zecblock-alertmanager.service',
                 'zecblock-host-textfile.service', 'zecblock-host-textfile.timer'):
        plan.copy(units / name, f'/etc/systemd/system/{name}')
    plan.copy(units / 'grafana-server.zecblock.conf', '/etc/systemd/system/grafana-server.service.d/zecblock.conf')
    plan.run('systemctl', 'daemon-reload')
    plan.run(OPT / 'prometheus/promtool', 'check', 'config', ETC / 'prometheus/prometheus.yml')
    plan.run('systemctl', 'enable', '--now', 'prometheus-node-exporter', 'zecblock-prometheus',
             'zecblock-host-textfile.timer')

    missing = [n for n in ('telegram.env', 'telegram-bot-token', 'grafana.env') if not (ETC / n).is_file()]
    if missing:
        print('NOT enabling Alertmanager/Grafana yet; create (README "Secrets"): ' + ', '.join(missing))
        return
    plan.run('systemctl', 'enable', '--now', 'zecblock-alertmanager', 'grafana-server')


def install_host(plan, wg_ip):
    wg_ip = validate_wg_ip(wg_ip)
    if not plan.dry_run:
        addrs = subprocess.run(['ip', '-o', 'addr', 'show', 'dev', 'wg0'], capture_output=True, text=True)
    if not plan.dry_run and f'inet {wg_ip}/' not in addrs.stdout:
        raise SystemExit(f'{wg_ip} is not configured on wg0; bring the monitor WireGuard peer up first')
    plan.run('apt-get', 'install', '-y', 'prometheus-node-exporter', 'python3')
    plan.write('/etc/default/prometheus-node-exporter', node_exporter_args(f'{wg_ip}:9100'))
    units = HERE / 'systemd'
    plan.copy(units / 'prometheus-node-exporter.zecblock.conf',
              '/etc/systemd/system/prometheus-node-exporter.service.d/zecblock.conf')
    plan.copy(HERE / 'exporters/zecblock-host-textfile.py', OPT / 'bin/zecblock-host-textfile.py', 0o755)
    for name in ('zecblock-host-textfile.service', 'zecblock-host-textfile.timer'):
        plan.copy(units / name, f'/etc/systemd/system/{name}')
    plan.run('install', '-d', '-m', '0755', TEXTFILE_DIR)
    plan.run('systemctl', 'daemon-reload')
    plan.run('systemctl', 'restart', 'prometheus-node-exporter')
    plan.run('systemctl', 'enable', '--now', 'zecblock-host-textfile.timer')
    # Allow only the monitor, only on wg0. Does not change any other UFW rule.
    plan.run('ufw', 'allow', 'in', 'on', 'wg0', 'from', str(MONITOR_WG), 'to', wg_ip,
             'port', '9100', 'proto', 'tcp', 'comment', 'zecblock-monitor node_exporter')


def install_primary_capture(plan, network):
    ensure_user(plan, 'zecblock-monitor')
    plan.run('apt-get', 'install', '-y', 'postgresql-client')
    plan.copy(HERE / 'exporters/zecblock-capture-exporter.py', OPT / 'bin/zecblock-capture-exporter.py', 0o755)
    units = HERE / 'systemd'
    for name in ('zecblock-capture-exporter@.service', 'zecblock-capture-exporter@.timer'):
        plan.copy(units / name, f'/etc/systemd/system/{name}')
    plan.run('systemctl', 'daemon-reload')
    db = f'zcash_explorer_{network}'
    print('\nOwner-approved manual PostgreSQL step (reload only, no restart):\n'
          f'  sudo -u postgres psql -X -v ON_ERROR_STOP=1 -d {db} -f {HERE / "sql/monitor-role.sql"}\n'
          f'  add to pg_hba.conf above broader local rules:  local  {db}  zecblock_monitor  peer\n'
          '  sudo systemctl reload postgresql\n'
          f'  sudo -u zecblock-monitor psql -X -d {db} -c "select 1"\n'
          f'Then: systemctl enable --now zecblock-capture-exporter@{network}.timer')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name in ('monitor', 'host', 'primary-capture'):
        p = sub.add_parser(name)
        p.add_argument('--dry-run', action='store_true')
        if name == 'host':
            p.add_argument('--wg-ip', required=True)
        if name == 'primary-capture':
            p.add_argument('--network', required=True, choices=['mainnet', 'testnet'])
    args = ap.parse_args(argv)
    if not args.dry_run and os.geteuid() != 0:
        raise SystemExit('run as root (or use --dry-run)')
    plan = Plan(args.dry_run)
    if args.cmd == 'monitor':
        install_monitor(plan)
    elif args.cmd == 'host':
        install_host(plan, args.wg_ip)
    else:
        install_primary_capture(plan, args.network)


if __name__ == '__main__':
    main()
