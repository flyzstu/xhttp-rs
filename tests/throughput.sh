#!/usr/bin/env bash
# Real-network throughput test that BYPASSES the local xhttp-box TUN device.
#
# Why this exists: xhttp-box installs an ip policy rule
#   "32768: not from all fwmark 0x2024 lookup 2022"
# so every non-bypassed packet is captured into table 2022 -> tun0.
# Anything you measure (curl/iperf3/xhttp-rs outbound) otherwise traverses
# the TUN and the measurement is not representative.
#
# The bypass used here is a transient ip rule sending traffic to the test
# target straight to the main table (physical NIC), skipping lookup 2022.
# It is removed by the EXIT trap, so the running proxy stack is untouched.
#
# Usage:
#   TARGET_IP=47.236.121.24 IPERF_PORT=18110 tests/throughput.sh direct
#   TARGET_IP=47.236.121.24 SOCKS_PORT=7890 tests/throughput.sh socks
#
# On the remote host:  iperf3 -s -p 18110
set -euo pipefail

mode=${1:-direct}
target=${TARGET_IP:?set TARGET_IP to the iperf3 server address}
port=${IPERF_PORT:-18110}
duration=${DURATION:-5}
parallel=${PARALLEL:-4}
rule="to ${target}/32 lookup main priority 999"

cleanup() {
  ip rule del $rule 2>/dev/null || true
  if [[ -n ${socat_pid:-} ]]; then kill "$socat_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

echo "=== mode=$mode target=$target:$port duration=${duration}s parallel=$parallel ==="

# Add the bypass rule and prove the route no longer points at tun0.
ip rule add $rule
echo "bypass rule: $(ip rule show | grep 999)"
route_line=$(ip route get "$target" | head -1)
echo "route: $route_line"
if echo "$route_line" | grep -q 'tun0'; then
  echo "ERROR: target still routed via tun0" >&2
  exit 1
fi

tun_rx_before=$(ip -s link show tun0 2>/dev/null | awk '/RX:/{getline;print $2}' || echo 0)
tun_tx_before=$(ip -s link show tun0 2>/dev/null | awk '/TX:/{getline;print $2}' || echo 0)

if [[ $mode == direct ]]; then
  endpoint=$target
else
  # socat bridges a local TCP port through the SOCKS proxy to the target.
  local_port=${LOCAL_PORT:-19110}
  socat "TCP-LISTEN:${local_port},reuseaddr,fork" \
    "SOCKS5-CONNECT:127.0.0.1:${SOCKS_PORT:-7890}:${target}:${port}" \
    >/dev/null 2>&1 &
  socat_pid=$!
  sleep 1
  endpoint=127.0.0.1
  port=$local_port
fi

echo "=== iperf3 $endpoint:$port ==="
iperf3 -c "$endpoint" -p "$port" -t "$duration" -P "$parallel" --json 2>/dev/null \
  | python3 -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d:
    print("iperf3 error:", d["error"]); raise SystemExit(1)
s = d["end"]["sum_sent"]; r = d["end"]["sum_received"]
send = s["bits_per_second"] / 1e6
recv = r["bits_per_second"] / 1e6
print("TCP send %.2f Mbit/s  recv %.2f Mbit/s  retrans %s" % (send, recv, s.get("retransmits")))
'

tun_rx_after=$(ip -s link show tun0 2>/dev/null | awk '/RX:/{getline;print $2}' || echo 0)
tun_tx_after=$(ip -s link show tun0 2>/dev/null | awk '/TX:/{getline;print $2}' || echo 0)
echo "tun0 delta during test: RX=$((tun_rx_after - tun_rx_before)) TX=$((tun_tx_after - tun_tx_before)) (should be ~0 = bypassed)"
