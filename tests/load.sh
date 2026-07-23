#!/usr/bin/env bash
set -euo pipefail

duration=${1:-10}
concurrency=${2:-16}
project_dir=$(cd "$(dirname "$0")/.." && pwd)
tmp_dir=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cd "$project_dir"
cargo build --release --quiet
python3 -m http.server 19091 --bind 127.0.0.1 >"$tmp_dir/http.log" 2>&1 & pids+=("$!")
python3 tests/udp_echo.py >"$tmp_dir/udp.log" 2>&1 & pids+=("$!")
./target/release/xhttp run -c tests/interop-rust-server.json >"$tmp_dir/server.log" 2>&1 & server_pid=$!; pids+=("$server_pid")
jq '.outbounds[0].server_port=19080' tests/interop-rust-client.json >"$tmp_dir/client.json"
./target/release/xhttp run -c "$tmp_dir/client.json" >"$tmp_dir/client.log" 2>&1 & client_pid=$!; pids+=("$client_pid")

ready=0
for _ in $(seq 1 50); do
  if curl --fail --silent --max-time 2 --socks5-hostname 127.0.0.1:11081 \
    http://127.0.0.1:19091/Cargo.toml >/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [[ $ready != 1 ]]; then
  echo "load test proxy did not become ready" >&2
  exit 1
fi

python3 tests/load_probe.py 11081 "$duration" "$concurrency"
for item in "server:$server_pid" "client:$client_pid"; do
  name=${item%%:*}
  pid=${item##*:}
  rss=$(awk '/VmHWM:/{print $2 " " $3}' "/proc/$pid/status")
  echo "$name peak_rss=$rss"
done
