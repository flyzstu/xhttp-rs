#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "skip: Linux only"
  exit 0
fi
if [[ "$(id -u)" != 0 ]]; then
  echo "skip: network namespace test requires root"
  exit 0
fi
for command in ip nft socat python3 curl ping; do
  command -v "$command" >/dev/null || {
    echo "skip: missing $command"
    exit 0
  }
done

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
client_ns="xhttp-tun-client"
gateway_ns="xhttp-tun-gateway"
server_ns="xhttp-tun-server"
work_dir="$(mktemp -d)"
route_set_path="/tmp/xhttp-rs-tun-route-set.json"
xhttp_pid=""
tcp_pid=""
udp_pid=""
udp2_pid=""
tcp6_pid=""
udp6_pid=""

cleanup() {
  for pid in "$xhttp_pid" "$tcp_pid" "$udp_pid" "$udp2_pid" "$tcp6_pid" "$udp6_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  ip netns del "$client_ns" 2>/dev/null || true
  ip netns del "$gateway_ns" 2>/dev/null || true
  ip netns del "$server_ns" 2>/dev/null || true
  rm -r "$work_dir"
  rm -f "$route_set_path" "$route_set_path.next"
}
trap cleanup EXIT

ip netns del "$client_ns" 2>/dev/null || true
ip netns del "$gateway_ns" 2>/dev/null || true
ip netns del "$server_ns" 2>/dev/null || true
cp "$repo_dir/tests/tun-route-set.json" "$route_set_path"

ip netns add "$client_ns"
ip netns add "$gateway_ns"
ip netns add "$server_ns"
ip link add xh-c0 type veth peer name xh-client
ip link set xh-c0 netns "$client_ns"
ip link set xh-client netns "$gateway_ns"
ip link add xh-uplink type veth peer name xh-s0
ip link set xh-uplink netns "$gateway_ns"
ip link set xh-s0 netns "$server_ns"

ip -n "$client_ns" link set lo up
ip -n "$client_ns" addr add 192.0.2.2/24 dev xh-c0
ip -n "$client_ns" -6 addr add 2001:db8:1::2/64 dev xh-c0 nodad
ip -n "$client_ns" link set xh-c0 up
ip -n "$client_ns" route add default via 192.0.2.1
ip -n "$client_ns" -6 route add default via 2001:db8:1::1

ip -n "$gateway_ns" link set lo up
ip -n "$gateway_ns" addr add 192.0.2.1/24 dev xh-client
ip -n "$gateway_ns" -6 addr add 2001:db8:1::1/64 dev xh-client nodad
ip -n "$gateway_ns" link set xh-client up
ip -n "$gateway_ns" addr add 198.18.0.1/30 dev xh-uplink
ip -n "$gateway_ns" -6 addr add 2001:db8:2::1/64 dev xh-uplink nodad
ip -n "$gateway_ns" link set xh-uplink up
ip -n "$gateway_ns" route add 203.0.113.2/32 via 198.18.0.2
ip -n "$gateway_ns" -6 route add 2001:db8:3::2/128 via 2001:db8:2::2

ip -n "$server_ns" link set lo up
ip -n "$server_ns" addr add 198.18.0.2/30 dev xh-s0
ip -n "$server_ns" -6 addr add 2001:db8:2::2/64 dev xh-s0 nodad
ip -n "$server_ns" link set xh-s0 up
ip -n "$server_ns" addr add 203.0.113.2/32 dev lo
ip -n "$server_ns" -6 addr add 2001:db8:3::2/128 dev lo nodad

initial_v4_forward="$(ip netns exec "$gateway_ns" cat /proc/sys/net/ipv4/ip_forward)"
initial_v6_forward="$(ip netns exec "$gateway_ns" cat /proc/sys/net/ipv6/conf/all/forwarding)"

ip netns exec "$server_ns" python3 -m http.server 18080 --bind 203.0.113.2 \
  >"$work_dir/http.log" 2>&1 &
tcp_pid=$!
ip netns exec "$server_ns" python3 "$repo_dir/tests/udp_peer_echo.py" 203.0.113.2 15353 \
  >"$work_dir/udp.log" 2>&1 &
udp_pid=$!
ip netns exec "$server_ns" python3 "$repo_dir/tests/udp_peer_echo.py" 203.0.113.2 15355 \
  >"$work_dir/udp2.log" 2>&1 &
udp2_pid=$!
ip netns exec "$server_ns" python3 -m http.server 18081 --bind 2001:db8:3::2 \
  >"$work_dir/http6.log" 2>&1 &
tcp6_pid=$!
ip netns exec "$server_ns" socat UDP6-RECVFROM:15354,bind='[2001:db8:3::2]',fork EXEC:/bin/cat \
  >"$work_dir/udp6.log" 2>&1 &
udp6_pid=$!

ip netns exec "$gateway_ns" "$repo_dir/target/debug/xhttp" run \
  -c "$repo_dir/tests/tun-router-linux.json" >"$work_dir/xhttp.log" 2>&1 &
xhttp_pid=$!

for _ in $(seq 1 100); do
  if ip netns exec "$gateway_ns" nft list table inet xhttp_xh_tun >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$xhttp_pid" 2>/dev/null; then
    cat "$work_dir/xhttp.log"
    exit 1
  fi
  sleep 0.05
done
ip netns exec "$gateway_ns" nft list table inet xhttp_xh_tun >/dev/null

ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  --output "$work_dir/http.body" http://203.0.113.2:18080/
grep -q "Directory listing" "$work_dir/http.body"
ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  --output "$work_dir/http6.body" 'http://[2001:db8:3::2]:18081/'
grep -q "Directory listing" "$work_dir/http6.body"

ip netns exec "$client_ns" ping -c 1 -W 2 203.0.113.2 >/dev/null
ip netns exec "$client_ns" ping -6 -c 1 -W 2 2001:db8:3::2 >/dev/null

ip netns exec "$client_ns" python3 "$repo_dir/tests/tun_udp_nat_probe.py" \
  >"$work_dir/udp-nat.log"
echo -n router-udp6 | ip netns exec "$client_ns" socat -T5 - 'UDP6:[2001:db8:3::2]:15354' \
  >"$work_dir/udp6.body"
grep -qx router-udp6 "$work_dir/udp6.body"

nft_rules="$(ip netns exec "$gateway_ns" nft list table inet xhttp_xh_tun)"
grep -q 'iifname != "xh-client" return' <<<"$nft_rules"
grep -q 'meta mark set ct mark' <<<"$nft_rules"
grep -Eq 'counter packets [1-9][0-9]* bytes [1-9][0-9]*' <<<"$nft_rules"
ip netns exec "$gateway_ns" ip -4 rule show | grep -q 'fwmark 0x2223 lookup 22023'
ip netns exec "$gateway_ns" ip -6 rule show | grep -q 'fwmark 0x2223 lookup 22023'

cp "$repo_dir/tests/tun-route-set-updated.json" "$route_set_path.next"
mv "$route_set_path.next" "$route_set_path"
for _ in $(seq 1 50); do
  if ! ip netns exec "$gateway_ns" nft list set inet xhttp_xh_tun route4 \
    | grep -q '203.0.113.2'; then
    break
  fi
  sleep 0.1
done
if ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --max-time 1 \
  http://203.0.113.2:18080/ >/dev/null 2>&1; then
  echo "route_address_set removal did not stop TUN capture"
  exit 1
fi
cp "$repo_dir/tests/tun-route-set.json" "$route_set_path.next"
mv "$route_set_path.next" "$route_set_path"
for _ in $(seq 1 50); do
  if ip netns exec "$gateway_ns" nft list set inet xhttp_xh_tun route4 \
    | grep -q '203.0.113.2'; then
    break
  fi
  sleep 0.1
done
ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  --output "$work_dir/http-restored.body" http://203.0.113.2:18080/

# A hard kill leaves kernel-owned policy state behind. The next process must
# remove that exact stale plan before installing a fresh one.
kill -KILL "$xhttp_pid"
wait "$xhttp_pid" 2>/dev/null || true
xhttp_pid=""
ip netns exec "$gateway_ns" nft list table inet xhttp_xh_tun >/dev/null
ip netns exec "$gateway_ns" ip -4 rule show | grep -q 'lookup 22023'

ip netns exec "$gateway_ns" "$repo_dir/target/debug/xhttp" run \
  -c "$repo_dir/tests/tun-router-linux.json" >"$work_dir/xhttp-restart.log" 2>&1 &
xhttp_pid=$!
for _ in $(seq 1 100); do
  if ip netns exec "$gateway_ns" ip link show xh-tun >/dev/null 2>&1 \
    && kill -0 "$xhttp_pid" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
ip netns exec "$client_ns" curl --noproxy '*' --fail --silent --show-error --max-time 5 \
  --output "$work_dir/http-restart.body" http://203.0.113.2:18080/

kill "$xhttp_pid"
wait "$xhttp_pid" || true
xhttp_pid=""
if ip netns exec "$gateway_ns" nft list table inet xhttp_xh_tun >/dev/null 2>&1; then
  echo "nftables table remained after shutdown"
  exit 1
fi
if ip netns exec "$gateway_ns" ip link show xh-tun >/dev/null 2>&1; then
  echo "TUN interface remained after shutdown"
  exit 1
fi
if ip netns exec "$gateway_ns" ip -4 rule show | grep -q 'lookup 22023'; then
  echo "policy rule remained after shutdown"
  exit 1
fi
test "$(ip netns exec "$gateway_ns" cat /proc/sys/net/ipv4/ip_forward)" = "$initial_v4_forward"
test "$(ip netns exec "$gateway_ns" cat /proc/sys/net/ipv6/conf/all/forwarding)" = "$initial_v6_forward"

echo "Linux TUN router topology passed (dual-stack flows, SIGKILL recovery, cleanup)"
