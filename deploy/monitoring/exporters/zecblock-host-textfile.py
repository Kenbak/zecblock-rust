#!/usr/bin/env python3
"""Host security/clock state for the node_exporter textfile collector.

Runs as root every minute (zecblock-host-textfile.timer) on every fleet host and
atomically writes <dir>/zecblock_host.prom. It reads local state only and
exports aggregate gauges/counters. No addresses, peers or packet contents.

  - CVE-2026-98432 stopgap: presence of `table ip cve_2026_98432` and its drop
    counter (packets/bytes of IPv4 TCP with IP options dropped at raw prerouting).
  - net.mptcp.enabled.
  - Pending reboot (/run/reboot-required) and running vs newest installed kernel.
  - chrony tracking: offset, stratum, root delay/dispersion, leap status.

Usage: zecblock-host-textfile.py [--dir /var/lib/prometheus/node-exporter]
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import time

NFT_TABLE = 'cve_2026_98432'
DEFAULT_DIR = '/var/lib/prometheus/node-exporter'
OUTPUT = 'zecblock_host.prom'


def escape_label(value):
    return str(value).replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')


class Metrics:
    def __init__(self):
        self._order = []
        self._meta = {}
        self._samples = {}

    def add(self, name, value, help_text, mtype='gauge', labels=None):
        if name not in self._meta:
            self._order.append(name)
            self._meta[name] = (help_text, mtype)
            self._samples[name] = []
        if value is None:
            return
        if isinstance(value, bool):
            value = int(value)
        label_text = ''
        if labels:
            label_text = '{' + ','.join(f'{k}="{escape_label(v)}"' for k, v in sorted(labels.items())) + '}'
        self._samples[name].append(f'{name}{label_text} {format_value(value)}')

    def render(self):
        lines = []
        for name in self._order:
            help_text, mtype = self._meta[name]
            lines.append(f'# HELP {name} {help_text}')
            lines.append(f'# TYPE {name} {mtype}')
            lines.extend(self._samples[name])
        return '\n'.join(lines) + '\n'


def format_value(value):
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


def parse_nft(json_text):
    """Return (present, dropped_packets, dropped_bytes, drop_rules) from `nft -j list table`."""
    doc = json.loads(json_text)
    present = False
    packets = 0
    nbytes = 0
    rules = 0
    for item in doc.get('nftables', []):
        table = item.get('table')
        if table and table.get('family') == 'ip' and table.get('name') == NFT_TABLE:
            present = True
        rule = item.get('rule')
        if not rule or rule.get('table') != NFT_TABLE or rule.get('family') != 'ip':
            continue
        exprs = rule.get('expr', [])
        if not any(isinstance(e, dict) and 'drop' in e for e in exprs):
            continue
        for e in exprs:
            if isinstance(e, dict) and isinstance(e.get('counter'), dict):
                rules += 1
                packets += int(e['counter'].get('packets', 0))
                nbytes += int(e['counter'].get('bytes', 0))
    return present, packets, nbytes, rules


CHRONY_FIELDS = [
    'ref_id', 'ref_name', 'stratum', 'ref_time', 'system_time', 'last_offset',
    'rms_offset', 'frequency_ppm', 'residual_frequency_ppm', 'skew_ppm',
    'root_delay', 'root_dispersion', 'update_interval', 'leap_status',
]


def parse_chrony(csv_line):
    """Parse one `chronyc -c tracking` line into a dict, or raise ValueError."""
    parts = csv_line.strip().split(',')
    if len(parts) != len(CHRONY_FIELDS):
        raise ValueError(f'unexpected chronyc field count {len(parts)}')
    row = dict(zip(CHRONY_FIELDS, parts))
    out = {'leap_status': row['leap_status'], 'ref_id': row['ref_id']}
    for key in ('stratum',):
        out[key] = int(row[key])
    for key in ('ref_time', 'system_time', 'last_offset', 'rms_offset', 'frequency_ppm',
                'residual_frequency_ppm', 'skew_ppm', 'root_delay', 'root_dispersion', 'update_interval'):
        out[key] = float(row[key])
    out['synchronised'] = (row['leap_status'] != 'Not synchronised'
                           and 1 <= out['stratum'] <= 15
                           and row['ref_id'].strip('0') != '')
    return out


def kernel_sort_key(release):
    return [int(p) if p.isdigit() else p for p in re.split(r'(\d+)', release)]


def newest_installed_kernel(boot_dir='/boot'):
    releases = [os.path.basename(p)[len('vmlinuz-'):] for p in glob.glob(os.path.join(boot_dir, 'vmlinuz-*'))]
    releases = [r for r in releases if r and not r.endswith('.old')]
    return max(releases, key=kernel_sort_key) if releases else None


def run(cmd, timeout=10):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def collect(m, *, nft_runner=None, chrony_runner=None, root='/'):
    nft_runner = nft_runner or (lambda: run(['nft', '-j', 'list', 'table', 'ip', NFT_TABLE]))
    chrony_runner = chrony_runner or (lambda: run(['chronyc', '-c', '-n', 'tracking']))

    # CVE-2026-98432 nftables stopgap.
    present, packets, nbytes, rules = False, None, None, 0
    try:
        res = nft_runner()
        if res.returncode == 0:
            present, packets, nbytes, rules = parse_nft(res.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        present = False
    present = present and rules > 0
    m.add('zecblock_cve_2026_98432_nft_table_present', present,
          'CVE-2026-98432 stopgap nftables table with a counted drop rule is loaded (1) or not (0).')
    m.add('zecblock_cve_2026_98432_nft_drop_rules', rules if present else 0,
          'Counted drop rules in table ip cve_2026_98432.')
    m.add('zecblock_cve_2026_98432_nft_dropped_packets_total', packets if present else None,
          'IPv4 TCP packets with IP options dropped by the stopgap since the table was loaded.', 'counter')
    m.add('zecblock_cve_2026_98432_nft_dropped_bytes_total', nbytes if present else None,
          'Bytes of IPv4 TCP packets with IP options dropped since the table was loaded.', 'counter')

    mptcp = read_int(os.path.join(root, 'proc/sys/net/mptcp/enabled'))
    m.add('zecblock_mptcp_enabled', mptcp, 'net.mptcp.enabled sysctl (expected 0 on every host).')

    # Pending reboot and kernel.
    flag = os.path.join(root, 'run/reboot-required')
    required = os.path.exists(flag)
    m.add('zecblock_reboot_required', required, 'The /run/reboot-required marker exists.')
    m.add('zecblock_reboot_required_since_timestamp_seconds', os.stat(flag).st_mtime if required else None,
          'Modification time of /run/reboot-required.')
    pkgs = os.path.join(root, 'run/reboot-required.pkgs')
    count = None
    if required and os.path.exists(pkgs):
        with open(pkgs, encoding='utf-8', errors='replace') as f:
            count = len({line.strip() for line in f if line.strip()})
    m.add('zecblock_reboot_required_packages', count, 'Distinct packages listed in /run/reboot-required.pkgs.')
    running = os.uname().release
    newest = newest_installed_kernel(os.path.join(root, 'boot'))
    m.add('zecblock_kernel_info', 1, 'Running and newest installed kernel release.',
          labels={'running': running, 'newest_installed': newest or 'unknown'})
    m.add('zecblock_kernel_newer_installed', int(newest is not None and newest != running),
          'A newer kernel than the running one is installed (reboot needed to use it).')

    # chrony.
    tracking = None
    try:
        res = chrony_runner()
        if res.returncode == 0:
            tracking = parse_chrony(res.stdout.splitlines()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        tracking = None
    m.add('zecblock_chrony_up', tracking is not None, 'chronyc tracking answered and parsed.')
    if tracking:
        m.add('zecblock_chrony_synchronised', tracking['synchronised'],
              'chrony has a selected reference, stratum 1-15 and leap status is not "Not synchronised".')
        m.add('zecblock_chrony_leap_normal', tracking['leap_status'] == 'Normal', 'chrony leap status is Normal.')
        m.add('zecblock_chrony_stratum', tracking['stratum'], 'chrony stratum.')
        m.add('zecblock_chrony_system_time_offset_seconds', tracking['system_time'],
              'chronyc -c tracking "System time": current offset of the system clock from chrony\'s estimate of true time (sign as reported by chronyc).')
        m.add('zecblock_chrony_last_offset_seconds', tracking['last_offset'], 'Offset measured at the last clock update.')
        m.add('zecblock_chrony_rms_offset_seconds', tracking['rms_offset'], 'Long-term RMS offset.')
        m.add('zecblock_chrony_root_delay_seconds', tracking['root_delay'], 'Root delay to the stratum-1 source.')
        m.add('zecblock_chrony_root_dispersion_seconds', tracking['root_dispersion'], 'Root dispersion.')
        m.add('zecblock_chrony_frequency_ppm', tracking['frequency_ppm'], 'Clock frequency error in ppm.')
        m.add('zecblock_chrony_last_update_age_seconds', max(0.0, time.time() - tracking['ref_time'])
              if tracking['ref_time'] > 0 else None, 'Seconds since chrony last updated the clock.')


def read_int(path):
    try:
        with open(path, encoding='ascii') as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


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
    ap.add_argument('--dir', default=DEFAULT_DIR)
    ap.add_argument('--stdout', action='store_true', help='print instead of writing the textfile')
    args = ap.parse_args(argv)
    m = Metrics()
    started = time.time()
    collect(m)
    m.add('zecblock_host_textfile_duration_seconds', round(time.time() - started, 6), 'Collector run time.')
    m.add('zecblock_host_textfile_last_run_timestamp_seconds', round(time.time(), 3), 'Collector finish time.')
    text = m.render()
    if args.stdout:
        sys.stdout.write(text)
    else:
        write_atomic(args.dir, OUTPUT, text)


if __name__ == '__main__':
    main()
