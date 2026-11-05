# Private fleet monitoring (Prometheus + Alertmanager + Grafana)

Config-as-code for one small **monitor droplet** that scrapes every ZecBlock
host over WireGuard and sends alerts to the existing Telegram alert channel.
**Nothing here is ordered or deployed.** Every production-host step below
needs owner approval first.

It adds a fleet view next to the per-host timers, Telegram scripts and
BetterStack uptime checks. It does not replace them: keep those running until
this stack has run for at least a week with tuned thresholds.

## What it watches

| Area | Source | Exported by |
|---|---|---|
| CPU, memory, disk, network, OOM, kernel clock | node_exporter (Ubuntu package) | every host, `wg-ip:9100` |
| CVE-2026-98432 stopgap: `table ip cve_2026_98432` present, drop counter (packets/bytes), `net.mptcp.enabled` | `nft -j list table`, `/proc/sys` | `zecblock-host-textfile.py` (root, 1/min) |
| Pending reboot, running vs newest installed kernel | `/run/reboot-required[.pkgs]`, `/boot/vmlinuz-*` | same |
| chrony offset, stratum, sync, root delay/dispersion | `chronyc -c -n tracking` | same |
| Zakura tip height, peers, lag vs best fleet node | Zakura `[metrics]` endpoint (**unverified**, below) | each node, `wg-ip:9999` |
| Orphan-collector observers: heartbeat age, `stream_connected`, `pending_records`, gaps, journal fill, last receipt | `block_capture_observers`, `block_capture_receipts` (035) | `zecblock-capture-exporter.py` on the primary |
| Migration 042 coverage: `coverage_since`, `unobserved_ms`, outage, audit age/status, fork tips/blocks, canonical checked/missing, open/24 h audit misses | `block_capture_observers` (042 columns), `block_capture_audit_misses` | same |
| Census freshness per source: qualified-gossip snapshot age/edges/truncated per `collector_source`; newest `node_snapshots` per `census_version` | `topology_gossip_snapshots` (039), `node_snapshots` (029) | same |
| The monitor itself | Prometheus/Alertmanager self-metrics, Watchdog | monitor |

The capture exporter is a database-backed exporter, not a Grafana SQL panel:
the monitor never holds a database credential. Ages use database `now()`.
Missing tables/columns (an older database) appear as
`zecblock_capture_schema_present{object=...} 0`, not as a failure.
`unobserved_seconds` bounds unverified time, not missed blocks (retained
replay may still recover blocks), and the dashboard says so.

Per-observer coverage stays **internal** (owner decision 2026-11-05). This
dashboard is private; nothing here feeds a public page.

## Privacy rules

- Aggregates only. No request logs, client IPs, RPC/PIR queries, addresses,
  node IPs, gossip endpoints or edges are exported.
- The monitor database role has `SELECT` on exactly five tables
  (`sql/monitor-role.sql`) and no `pg_monitor`/`pg_read_all_stats` (those
  expose other sessions' query text). It has no password: Unix-socket peer auth.
- Scrapes go over WireGuard only. node_exporter binds the host's wg address;
  UFW allows 9100 only from `10.77.0.10` on `wg0`. Prometheus, Alertmanager,
  Grafana and the monitor's own node_exporter bind `127.0.0.1`.
- This repository is public. It holds no public host addresses, keys, chat
  ids or tokens. A test fails if a public IPv4 address or a bot-token-shaped
  string appears under `deploy/monitoring/`.

## Address plan

The hub `10.77.0.1` (primary) and the observers `.2–.4` are live (2026-11-05).
The monitor takes `.10` and existing production hosts `.20–.26`; record each
in the wiki host table when configured. Never reuse an address or host name.

| wg address | host | role |
|---|---|---|
| 10.77.0.1 | primary | mainnet primary, observer `local-node`, PostgreSQL hub |
| 10.77.0.10 | monitor | this stack |
| 10.77.0.20 | standby | passive standby |
| 10.77.0.21 | testnet | testnet |
| 10.77.0.22 | analytics | analytics |
| 10.77.0.23 | crosslink | Crosslink |
| 10.77.0.24 | cipherpay-mainnet | CipherPay |
| 10.77.0.25 | cipherpay-testnet | CipherPay testnet |
| 10.77.0.26 | shopify | Shopify worker |
| 10.77.0.2–4 | do-nyc3, do-sgp1, do-syd1 | regional observers (live since 2026-11-05) |
| 10.77.0.5–6 | vultr-sao, vultr-jnb | reserved (pending owner OK) |

Topology: the monitor peers **directly** with every host (`/32` AllowedIPs
both ways, see `wireguard/`), so it keeps working when the primary is down.
Observers keep their primary peer; the monitor's `/32` peer is added beside it
(WireGuard picks the longest prefix). The eight existing hosts are not on
WireGuard today; each needs a `wg0` before it can be scraped.

## Monitor placement and size

- **Provider/region (recommendation):** DigitalOcean **FRA1**. Different
  provider and region from the HEL1 primary/standby/testnet/analytics, and not
  co-located with any observer (NYC3/SGP1/SYD1). Open decision in the wiki
  scaling plan; the owner chooses.
- **Size (estimate):** 1 vCPU / 2 GB / 50 GB (`s-1vcpu-2gb`). About 15
  targets at 30 s is a few tens of thousands of series; 90-day retention is
  capped at 30 GB. Check the price at order time; it is not verified here.
- Ubuntu 24.04 with `cloud-init/monitor.yaml` as user data: same CVE-2026-98432
  nft stopgap, MPTCP off, key-only SSH, UFW (22 limited, 51820/udp), no
  Fail2ban, unattended upgrades with 04:00 UTC reboots.

## Pinned versions

`versions.env` pins Prometheus 3.15.1, Alertmanager 0.34.2 and Grafana OSS
13.2.5 with SHA-256 from the upstream checksum lists (2026-11-05). The
installer refuses mismatches. 0.34.2 and 13.2.5 are security releases.
Fleet hosts use Ubuntu's `prometheus-node-exporter` package.

## Rollout

Each step has a check; stop on failure.

1. **Order the droplet** (owner purchase) with `cloud-init/monitor.yaml`.
   Accept: `cloud-init status` done and rebooted; `nft list table ip
   cve_2026_98432` present; `sysctl net.mptcp.enabled` = 0; `ufw status` shows
   only 22 (limit) and 51820/udp; `ss -tlnp` shows nothing public but sshd.
2. **Install the stack**: copy this directory to the droplet, then
   `sudo python3 install.py monitor` (try `--dry-run` first). Prometheus,
   node_exporter and the host textfile timer start; Alertmanager and Grafana wait
   for secrets.
3. **Secrets** (on the droplet, typed or copied over SSH, never into git):
   ```
   sudo install -m 0640 -o root -g zecblock-alertmanager /dev/null /etc/zecblock-monitor/telegram.env
   sudo install -m 0640 -o root -g zecblock-alertmanager /dev/null /etc/zecblock-monitor/telegram-bot-token
   sudo install -m 0640 -o root -g grafana /dev/null /etc/zecblock-monitor/grafana.env
   sudoedit /etc/zecblock-monitor/telegram.env          # TELEGRAM_CHAT_ID=<integer>
   sudoedit /etc/zecblock-monitor/telegram-bot-token    # token only, one line
   sudoedit /etc/zecblock-monitor/grafana.env           # GF_SECURITY_ADMIN_PASSWORD=<generated>
   ```
   Use the **same bot and chat** as the existing health alerts
   (`TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` in the Rust health env file); copy
   the values without printing them. Optional dead-man switch:
   `/etc/zecblock-monitor/heartbeat-url` (0640 root:zecblock-alertmanager) with a
   BetterStack heartbeat URL; Watchdog then pings it every minute and BetterStack
   alerts if the monitor or its Alertmanager goes silent. Without it Watchdog
   goes nowhere and a dead monitor is silent. Then
   `sudo systemctl enable --now zecblock-alertmanager grafana-server`.
4. **WireGuard per host** (owner approval per production host): add the
   host's `wg0` (if missing) and the monitor peer (`wireguard/host-peer.conf.example`),
   and the host peer on the monitor (`wireguard/monitor-wg0.conf.example`).
   Accept: `wg show` handshake on both sides, `ping 10.77.0.N` from the monitor.
   This touches only WireGuard and one UFW rule; no service restarts.
5. **Exporters per host**: copy this directory, then
   `sudo python3 install.py host --wg-ip 10.77.0.N`. It installs/rebinds
   node_exporter to the wg address, the textfile timer, and
   `ufw allow in on wg0 from 10.77.0.10 to 10.77.0.N port 9100`. Accept: from
   the monitor `curl -s 10.77.0.N:9100/metrics | grep zecblock_cve_2026_98432_nft_table_present`
   returns 1; `ss -tlnp` on the host shows 9100 only on the wg address.
   Uncomment/keep the host in `prometheus/targets/node.yml`.
6. **Capture exporter (primary only)**: `sudo python3 install.py
   primary-capture --network mainnet`. Then the owner-approved database step it
   prints: run `sql/monitor-role.sql` as postgres in `zcash_explorer_mainnet`,
   add `zecblock_monitor zecblock-monitor zecblock_monitor` to `pg_ident.conf` (the OS
   user has a hyphen, the role an underscore) and
   `local zcash_explorer_mainnet zecblock_monitor peer map=zecblock_monitor` above broader local
   rules in `pg_hba.conf`, and **reload** (not restart) PostgreSQL. Check
   `sudo -u zecblock-monitor psql -X -d zcash_explorer_mainnet -c 'select 1'`,
   then `systemctl enable --now zecblock-capture-exporter@mainnet.timer`. Repeat
   for testnet only where that database lives. Accept:
   `zecblock_capture_exporter_up{network="mainnet"} 1` and one series per
   `block_capture_observers` row. Writer, API and replication must be unchanged.
7. **Zakura metrics** (unverified, owner approval: it restarts a node): confirm
   the production Zakura build serves Prometheus metrics, set `[metrics]
   endpoint_addr = "10.77.0.N:9999"` (never `0.0.0.0`), restart that node in a
   maintenance window (standby first, primary last), allow
   `ufw allow in on wg0 from 10.77.0.10 to 10.77.0.N port 9999 proto tcp`. Check
   the metric names against `zecblock:zakura_tip_height`/`zecblock:zakura_peers`
   in `prometheus/rules/fleet.rules.yml`; fix them there only. Until then keep
   the node's line in `targets/zakura.yml` commented out (an unreachable target
   raises `ZakuraMetricsDown`).
8. **Accept the stack**: Grafana "ZecBlock fleet" shows every host; force one
   test alert (e.g. stop `zecblock-host-textfile.timer` on the monitor for 20 m
   and watch `HostTextfileStale` reach Telegram and resolve). Record the date,
   droplet, versions and accepted hosts in the wiki.

### Access

Grafana and Prometheus are on loopback. Use an SSH tunnel:
`ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 <monitor>`, then open
`http://localhost:3000`. Do not expose either port publicly.

### Changing config

Edit here, run `deploy/monitoring/validate.sh` (CI runs it with the pinned
promtool/amtool) and `python3 -m unittest deploy/test_monitoring.py`, merge,
then re-run `install.py monitor` and `systemctl reload zecblock-prometheus`
(`restart zecblock-alertmanager` re-renders its config).

### Rollback

Per host: `systemctl disable --now zecblock-host-textfile.timer`, delete the
UFW 9100 rule, restore `/etc/default/prometheus-node-exporter`, remove the
monitor WireGuard peer. Primary: disable the capture timer, remove the
`pg_hba` line (reload), `DROP OWNED BY zecblock_monitor; DROP ROLE
zecblock_monitor;` in each database. Monitor: destroy the droplet. No
production data is written by any part of this stack.

## Alerts

Severities: **critical** (page now, repeat 2 h), **warning** (repeat 12 h),
**info** (grouped, 24 h). Inhibitions: `HostDown` mutes that host's other
alerts; `CaptureExporterDown` mutes capture/census alerts for that network;
`CaptureNoHealthyObserver` mutes per-observer heartbeat/stream pages.

- Hosts: `HostDown`, `HostTextfileStale`/`Missing`/`ScrapeError`,
  `DiskSpaceLow`/`Critical`, `DiskFillsWithin24h`, `MemoryLow`, `OomKill`.
- Security: `Cve202698432StopgapMissing` (critical), `MptcpEnabled`
  (critical), `Cve202698432PacketsDropped` (info), `RebootPending` (info),
  `RebootPendingStale` (> 3 days, warning). Observers reboot themselves at
  04:00; production reboots stay owner-approved.
- Clock: `ClockOffsetHigh` (|offset| > 10 ms, the observer gate),
  `ClockUnsynchronised`, `ChronyDown`, `KernelClockUnsynchronised`.
- Zakura: `ZakuraMetricsDown`, `ZakuraTipBehind` (> 3 blocks), `ZakuraTipStalled`
  (45 m), `ZakuraFewPeers` (< 8).
- Capture: `CaptureExporterDown`, `CaptureObserverHeartbeatStale` (> 45 s,
  the acceptance bound), `CaptureObserverStreamDisconnected`,
  `CaptureNoHealthyObserver`, pending/journal/gaps/receipts, 042 coverage and
  audit alerts, `CaptureCanonicalBlocksMissing` (critical).
  Silence a retired observer's row: its heartbeat stays old forever.
- Census: `CensusGossipStale` (> 20 m per source), `CensusGossipTruncated`,
  `CensusSnapshotStale`/`Missing` (v3).
- Monitor: `Watchdog`, `PrometheusRuleFailures`, `AlertmanagerNotificationsFailing`.

Thresholds marked "initial" in the rules (receipt, gossip and snapshot
cadences) are first guesses; tune them after a week of real data.

## Not covered yet

- PostgreSQL replication/pool (`postgres_exporter`) and backup age.
- External probes (`blackbox_exporter` from 2–3 regions); BetterStack covers
  public uptime today.
- Vultr South America/Africa observers (targets reserved, not listed).
- A public status page (later, separate).
