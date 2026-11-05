# Regional block observers

A regional observer is a small single-purpose VM that runs:

1. a **pruned Zakura mainnet node** with public P2P (8233) and loopback-only
   RPC (8232) and indexer gRPC (8230);
2. the existing **`orphan-collect`** mode of this binary, with a unique
   `--observer` name, writing to the primary PostgreSQL over WireGuard;
3. **chrony** (receipt times from different machines are compared, so clock
   error directly distorts "first seen") and **node_exporter** on the WireGuard
   address only.

Nothing else. No indexer writer, API, lightwalletd or PIR. The schema already
supports many observers: `captured_blocks.first_seen_at` keeps the earliest
receipt (`LEAST`), `block_capture_receipts` keeps one row per observer and
migration 042 keeps per-observer coverage. More observers improve what we see,
never prove complete network coverage.

## Fleet (proposed 2026-11-05, not ordered)

| Observer name | Provider / region | Continent |
|---|---|---|
| `local-node` (existing) | Hetzner HEL1 primary | Europe |
| `do-nyc3` | DigitalOcean NYC3 | North America |
| `do-sgp1` | DigitalOcean SGP1 | Asia |
| `do-syd1` | DigitalOcean SYD1 | Oceania |
| `vultr-sao` | Vultr São Paulo (neither DO nor Hetzner has South America) | South America |
| `vultr-jnb` | Vultr Johannesburg (neither DO nor Hetzner has Africa) | Africa |

Names must match `[A-Za-z0-9_-]{1,80}` (enforced by the collector) and must
never be reused for a different host: receipts are attributed by name.

Size per box (estimate; qualify on the first box): 4 vCPU, 8 GB RAM, 160 GB SSD.
Pruned Zakura state measured 13 GB on the standby; the rest is headroom for
upgrade snapshots and the 256 MiB collector journal. Archive mode (~261 GB+)
is only needed if a box later serves lightwalletd/Zaino.

## Network

```
observer (wg 10.77.0.N) ──WireGuard UDP 51820──▶ primary (wg 10.77.0.1)
                                                  └─ PostgreSQL on 10.77.0.1:5432
                                                     pg_hba: one role per observer,
                                                     scram-sha-256, from its /32 only
```

Public firewall on observers: 22/tcp key-only behind fail2ban (narrow to an
admin allowlist after setup), 8233/tcp
open (Zcash P2P), 51820/udp from the primary only. Everything else denied.
RPC, gRPC and metrics are never public.

On the primary, PostgreSQL must also listen on `10.77.0.1`. Adding an address to
`listen_addresses` requires a **PostgreSQL restart**: schedule it with owner
approval, keep the standby streaming, and verify writer, API and replication
afterwards. This is the only change on a production host besides WireGuard,
UFW and one `pg_hba.conf` line per observer (reload only).

## Rollout per observer

Each step has a check; stop on failure.

1. **Create the VM** (owner purchase): Ubuntu 24.04, the size above, SSH key
   only, with `cloud-init.yaml` as user data. Record IP, region and order ID in
   the wiki's `server-infrastructure.md` host table.
2. **Install Zakura**: the same verified release artifact (SHA-256) as the
   primary/standby, to `/usr/local/bin/zakurad`. Write
   `/etc/zakura/zakura.toml` from `zakura-observer.toml`, then **diff it
   against the standby's `/root/.config/zakura.toml`**. The template's key
   names are not yet verified against a running Zakura config.
3. **Bootstrap state**: either checkpoint-sync from scratch (slow, no
   production impact) or copy a stopped pruned snapshot. Never stop the
   standby node for this without owner approval. Accept only when
   `getblockchaininfo` matches the primary's best hash at the same height.
4. **WireGuard**: add the observer peer on the primary and the primary peer on
   the observer; check `wg show` handshakes and that 5432 is reachable only
   through wg.
5. **Database role** (on the primary): `create-observer-db-role.py <observer>
   <wg-ip>`. It creates `zecblock_capture_<observer>` with the existing
   collector grants and writes the password to a 0600 file. Move that file to the
   observer over SSH, then delete it from the primary.
6. **Collector** (on the observer): `install-observer.py <observer> <artifact>
   <sha256> <password-file>`. It verifies the artifact, writes the protected
   env file and enables `cipherscan-observer-collector.service`.
7. **Accept**: on the primary, a `block_capture_observers` row for the
   observer, connected, `pending_records = 0`, heartbeat <45 s old, and fresh
   `block_capture_receipts` rows. `chronyc tracking` offset must stay below
   10 ms. Canonical writer health and standby passivity must be unchanged.

Rollback: stop the collector, revoke and drop the role's login, remove the
pg_hba line and WireGuard peer. Captured rows and receipts are evidence and
remain.

## Effect on public numbers

- `firstSeenAt` becomes the earliest receipt across all observers. This is a
  real semantic change: document it on the reorg page copy and in the wiki
  before the first remote observer goes live.
- Orphan-rate `observers` / `healthyObservers` count every observer; `status`
  stays `collecting` while at least one is healthy. Per-observer coverage
  (migration 042) stays internal per the 2026-11-05 owner decision.
- `capture.startedAt` is the minimum across observers, so it does not move.
