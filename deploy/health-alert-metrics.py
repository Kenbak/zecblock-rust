#!/usr/bin/env python3
"""Prometheus textfile metrics for check-indexer-health.sh.

Usage: health-alert-metrics.py <service_status> <health_rc> <unix_now>  < health output

Exports only categories, never heights, clocks, hostnames or raw output, so a
series changes only when the failure reason changes:
  zecblock_indexer_service_active 0|1
  zecblock_indexer_healthy{reasons="lag_exceeded,ingest_stalled"} 0|1
  zecblock_indexer_health_last_run_timestamp_seconds <unix>
"""
import json
import re
import sys

_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def reasons(service_status, health_rc, output):
    """Sorted failure categories; [] when healthy. Mirrors the alert fingerprint."""
    if service_status != "active":
        return ["service_inactive"]
    if health_rc == 0:
        return []
    if health_rc in (124, 137):
        return ["health_command_timeout"]
    for offset, char in enumerate(output):
        if char != "{":
            continue
        try:
            assessment, _ = json.JSONDecoder().raw_decode(output[offset:])
        except ValueError:
            continue
        if not isinstance(assessment, dict) or assessment.get("healthy") is not False:
            continue
        codes = assessment.get("reason_codes")
        if isinstance(codes, list) and codes and all(isinstance(c, str) and _CODE.match(c) for c in codes):
            return sorted(set(codes))
        break
    return ["health_command_failed"]


def render(service_status, health_rc, now, output):
    codes = reasons(service_status, health_rc, output)
    return "".join([
        "# HELP zecblock_indexer_service_active 1 if the indexer systemd unit is active.\n",
        "# TYPE zecblock_indexer_service_active gauge\n",
        f"zecblock_indexer_service_active {1 if service_status == 'active' else 0}\n",
        "# HELP zecblock_indexer_healthy 1 if `cipherscan-indexer health` passed; reasons lists failure codes.\n",
        "# TYPE zecblock_indexer_healthy gauge\n",
        f'zecblock_indexer_healthy{{reasons="{",".join(codes)}"}} {0 if codes else 1}\n',
        "# HELP zecblock_indexer_health_last_run_timestamp_seconds Unix time of the last health check run.\n",
        "# TYPE zecblock_indexer_health_last_run_timestamp_seconds gauge\n",
        f"zecblock_indexer_health_last_run_timestamp_seconds {int(now)}\n",
    ])


if __name__ == "__main__":
    sys.stdout.write(render(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.stdin.read()))
