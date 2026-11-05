#!/usr/bin/env bash
# Validate the monitoring kit with the real tools.
# Usage: PROMTOOL=/path/promtool AMTOOL=/path/amtool deploy/monitoring/validate.sh
# CI downloads the versions pinned in versions.env and verifies their SHA-256.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
promtool="${PROMTOOL:-promtool}"
amtool="${AMTOOL:-amtool}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Stage the tree as it is installed, with /etc/zecblock-monitor -> $work/etc.
mkdir -p "$work/etc/prometheus" "$work/etc/alertmanager" "$work/secrets"
cp -R "$here/prometheus/rules" "$here/prometheus/targets" "$work/etc/prometheus/"
sed "s#/etc/zecblock-monitor#$work/etc#g" "$here/prometheus/prometheus.yml" > "$work/etc/prometheus/prometheus.yml"
cp "$here/alertmanager/telegram.tmpl" "$work/etc/alertmanager/"

echo "== promtool check config"
"$promtool" check config "$work/etc/prometheus/prometheus.yml"
echo "== promtool check rules"
"$promtool" check rules "$here"/prometheus/rules/*.yml
echo "== promtool test rules"
"$promtool" test rules "$here"/prometheus/tests/*.test.yml

# Dummy secrets: a fake bot token and chat id, never real values.
printf 'TELEGRAM_CHAT_ID=-1000000000001\n' > "$work/secrets/telegram.env"
printf '000000:dummy-token-for-validation\n' > "$work/secrets/telegram-bot-token"
for heartbeat in off on; do
  if [[ $heartbeat == on ]]; then printf 'https://example.invalid/heartbeat\n' > "$work/secrets/heartbeat-url"; fi
  echo "== render + amtool check-config (heartbeat $heartbeat)"
  python3 "$here/alertmanager/render-alertmanager.py" \
    --template "$here/alertmanager/alertmanager.yml.tmpl" \
    --secrets-dir "$work/secrets" --templates-dir "$work/etc/alertmanager" \
    --out "$work/alertmanager-$heartbeat.yml"
  "$amtool" check-config "$work/alertmanager-$heartbeat.yml"
done

echo "== amtool config routes test"
cfg="$work/alertmanager-on.yml"
expect_route() {
  local want="$1"; shift
  local got
  got="$("$amtool" config routes test --config.file="$cfg" "$@" | tr -d '[:space:]')"
  [[ "$got" == "$want" ]] || { echo "route for $* = $got, want $want" >&2; exit 1; }
  echo "ok  $* -> $got"
}
expect_route heartbeat alertname=Watchdog severity=none
expect_route telegram alertname=HostDown severity=critical host=primary
expect_route telegram alertname=ClockOffsetHigh severity=warning host=do-sgp1
expect_route telegram-quiet alertname=RebootPending severity=info host=analytics

echo "== telegram template renders (fixtures)"
for data in "$here"/alertmanager/fixtures/*.json; do
  want="${data%.json}.expected"
  got="$("$amtool" template render --template.glob="$here/alertmanager/telegram.tmpl" \
    --template.data="$data" --template.text='{{ template "zecblock.telegram.message" . }}')"
  if [[ "$(printf '%s' "$got" | sed -e '/^$/d')" != "$(sed -e '/^$/d' "$want")" ]]; then
    echo "template render mismatch for $(basename "$data")" >&2
    diff <(printf '%s\n' "$got" | sed -e '/^$/d') <(sed -e '/^$/d' "$want") >&2 || true
    exit 1
  fi
  echo "ok  $(basename "$data")"
done

echo "== grafana dashboard JSON"
python3 -m json.tool "$here/grafana/dashboards/zecblock-fleet.json" > /dev/null
echo "all monitoring checks passed"
