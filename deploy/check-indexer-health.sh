#!/usr/bin/env bash
set -euo pipefail

INDEXER_BIN="${INDEXER_BIN:-/root/cipherscan-rust/target/release/cipherscan-indexer}"
STATE_DIR="${INDEXER_MONITOR_STATE_DIR:-/var/lib/cipherscan-rust-monitor}"
STATE_FILE="${STATE_DIR}/health-alert-state.env"
MAX_LAG="${INDEXER_MAX_LAG:-3}"
MAX_CONSECUTIVE_FAILURES="${INDEXER_MAX_CONSECUTIVE_FAILURES:-0}"
MAX_HEARTBEAT_AGE_SECONDS="${INDEXER_MAX_HEARTBEAT_AGE_SECONDS:-600}"
ALERT_COOLDOWN_SECONDS="${INDEXER_ALERT_COOLDOWN_SECONDS:-1800}"
HEALTH_TIMEOUT_SECONDS="${INDEXER_HEALTH_TIMEOUT_SECONDS:-45}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INDEXER_SERVICE_NAME="${INDEXER_SERVICE_NAME:-cipherscan-rust.service}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
TELEGRAM_API_BASE="${TELEGRAM_API_BASE:-https://api.telegram.org}"
# "off" once the fleet monitor (deploy/monitoring) alerts from the metrics below.
TELEGRAM_ALERTS="${INDEXER_TELEGRAM_ALERTS:-on}"
# node_exporter textfile collector directory; empty disables metrics.
METRICS_DIR="${INDEXER_METRICS_DIR-/var/lib/prometheus/node-exporter}"
HOST_LABEL="$(hostname -f 2>/dev/null || hostname)"

mkdir -p "${STATE_DIR}"

previous_status="unknown"
previous_fingerprint=""
previous_alert_at=0

if [[ -f "${STATE_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${STATE_FILE}"
fi

if [[ "${TELEGRAM_ALERTS}" != "on" && "${TELEGRAM_ALERTS}" != "off" ]]; then
  echo "INDEXER_TELEGRAM_ALERTS must be on or off" >&2
  exit 2
fi
if [[ "${TELEGRAM_ALERTS}" == "on" && ( -z "${TELEGRAM_BOT_TOKEN}" || -z "${TELEGRAM_CHAT_ID}" ) ]]; then
  echo "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set (or INDEXER_TELEGRAM_ALERTS=off)" >&2
  exit 2
fi

if [[ ! -x "${INDEXER_BIN}" ]]; then
  echo "Indexer binary is not executable: ${INDEXER_BIN}" >&2
  exit 2
fi

send_telegram() {
  local message="$1"
  [[ "${TELEGRAM_ALERTS}" == "on" ]] || return 0

  curl -fsS -X POST \
    "${TELEGRAM_API_BASE}/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${message}" \
    --data-urlencode "parse_mode=HTML" \
    --data-urlencode "disable_web_page_preview=true" \
    >/dev/null
}

persist_state() {
  local current_status="$1"
  local current_fingerprint="$2"
  local current_alert_at="$3"

  cat > "${STATE_FILE}" <<EOF
previous_status=${current_status}
previous_fingerprint=${current_fingerprint}
previous_alert_at=${current_alert_at}
EOF
}

now="$(date +%s)"
timestamp="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

service_status="$(systemctl is-active "${INDEXER_SERVICE_NAME}" 2>&1 || true)"

if [[ "${service_status}" == "active" ]]; then
  health_output="$(timeout --kill-after=5s "${HEALTH_TIMEOUT_SECONDS}s" "${INDEXER_BIN}" health --max-lag "${MAX_LAG}" --max-consecutive-failures "${MAX_CONSECUTIVE_FAILURES}" --max-heartbeat-age "${MAX_HEARTBEAT_AGE_SECONDS}" --json 2>&1)" || health_rc=$?
  health_rc="${health_rc:-0}"
else
  health_output="service ${INDEXER_SERVICE_NAME} is not active: ${service_status}"
  health_rc=1
fi

combined_output="$(printf 'service=%s\nhealth rc=%s\n%s\n' "${service_status}" "${health_rc}" "${health_output}")"

# Metrics for the fleet monitor: health, reason codes (no heights, clocks or
# hostnames), service state and run time. Written atomically; never fatal.
write_metrics() {
  [[ -n "${METRICS_DIR}" && -d "${METRICS_DIR}" ]] || return 0
  local tmp="${METRICS_DIR}/.zecblock_indexer_health.prom.$$"
  {
    printf '%s' "${health_output}" | python3 "${SCRIPT_DIR}/health-alert-metrics.py" \
      "${service_status}" "${health_rc}" "${now}"
  } > "${tmp}" 2>/dev/null && mv -f "${tmp}" "${METRICS_DIR}/zecblock_indexer_health.prom" || rm -f "${tmp}"
}
write_metrics
fingerprint="$(printf '%s' "${health_output}" | python3 "${SCRIPT_DIR}/health-alert-fingerprint.py" "${service_status}" "${health_rc}")"
summary="$(printf '%s' "${combined_output}" | tail -n 40 | cut -c1-3500)"

if [[ "${health_rc}" -eq 0 ]]; then
  if [[ "${previous_status}" == "unhealthy" ]]; then
    send_telegram "$(cat <<EOF
✅ <b>Fixed: Indexer having problems</b>
📍 ${HOST_LABEL}
The indexer is running and keeping up with the chain again (${timestamp}). Nothing to do.
EOF
)"
  fi

  persist_state "healthy" "${fingerprint}" "${now}"
  exit 0
fi

should_alert=0
if [[ "${previous_status}" != "unhealthy" ]]; then
  should_alert=1
elif [[ "${previous_fingerprint}" != "${fingerprint}" ]]; then
  should_alert=1
elif (( now - previous_alert_at >= ALERT_COOLDOWN_SECONDS )); then
  should_alert=1
fi

if (( should_alert == 1 )); then
  if [[ "${service_status}" != "active" ]]; then
    happening="The indexer is not running (service state: ${service_status})."
    todo="Start it: <code>systemctl restart ${INDEXER_SERVICE_NAME}</code>, then check it stays up with <code>journalctl -u ${INDEXER_SERVICE_NAME} -n 100</code>."
  else
    happening="The indexer is running but failing its health check: it is more than ${MAX_LAG} blocks behind, has failed ${MAX_CONSECUTIVE_FAILURES}+ times in a row, or has not made progress for ${MAX_HEARTBEAT_AGE_SECONDS}s."
    todo="Look at its logs: <code>journalctl -u ${INDEXER_SERVICE_NAME} -n 100</code>. If the Zcash node is fine, a restart (<code>systemctl restart ${INDEXER_SERVICE_NAME}</code>) often fixes it."
  fi
  details="$(printf '%s' "${summary}" | tail -n 15 | cut -c1-1500 | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')"
  send_telegram "$(cat <<EOF
🔴 <b>Indexer having problems</b>
📍 ${HOST_LABEL}

<b>What’s happening:</b> ${happening}
<b>Why it matters:</b> The indexer copies new blocks into our database, so new blocks and transactions may not appear on the website.
<b>What to do:</b> ${todo}

Technical details:
<pre>${details}</pre>
<i>Urgent, look now · ${timestamp} · repeats while it lasts</i>
EOF
)"
  persist_state "unhealthy" "${fingerprint}" "${now}"
else
  persist_state "unhealthy" "${previous_fingerprint}" "${previous_alert_at}"
fi

exit 1
