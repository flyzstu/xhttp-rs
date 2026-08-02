#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "$0")/.." && pwd)
workspace_dir=$(cd "$project_dir/.." && pwd)
tmp_dir=$(mktemp -d)
pids=()
cleanup_run() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; pids=(); }
cleanup() {
  cleanup_run
  if [[ ${KEEP_INTEROP_TMP:-0} == 1 ]]; then
    echo "interop artifacts kept at $tmp_dir"
  else
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT

cd "$project_dir"
cargo build --quiet
(cd "$workspace_dir/xhttp-box" && go build -tags with_quic -o "$tmp_dir/sing-box" ./cmd/sing-box)
(cd "$workspace_dir/Xray-core" && go build -o "$tmp_dir/xray" ./main)

python3 -m http.server 19091 --bind 127.0.0.1 >"$tmp_dir/http.log" 2>&1 &
http_pid=$!
pids+=("$http_pid")
python3 tests/udp_echo.py >"$tmp_dir/udp.log" 2>&1 &
pids+=("$!")

request() {
  local port=$1
  for _ in $(seq 1 20); do
    if curl --fail --silent --max-time 2 --socks5-hostname "127.0.0.1:$port" \
      http://127.0.0.1:19091/Cargo.toml | rg -q 'name = "xhttp-rs"'; then return 0; fi
    sleep 0.1
  done
  return 1
}

udp_request() {
  local port=$1
  for _ in $(seq 1 20); do
    if python3 tests/socks_udp_probe.py "$port" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  python3 tests/socks_udp_probe.py "$port"
}

request_must_fail() {
  local port=$1
  local ready=0
  for _ in $(seq 1 20); do
    if python3 - "$port" <<'PY'
import socket, sys
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close()
except OSError:
    raise SystemExit(1)
PY
    then ready=1; break; fi
    sleep 0.1
  done
  if [[ $ready != 1 ]]; then
    echo "proxy on port $port did not become ready" >&2
    return 1
  fi
  if curl --fail --silent --max-time 2 --socks5-hostname "127.0.0.1:$port" \
    http://127.0.0.1:19091/Cargo.toml >/dev/null 2>&1; then
    echo "request unexpectedly succeeded through port $port" >&2
    return 1
  fi
}

for mode in stream-one stream-up packet-up; do
  echo "testing sing-box -> Rust: $mode"
  jq --arg mode "$mode" '.inbounds[0].transport.mode=$mode' tests/interop-rust-server.json >"$tmp_dir/rust-server.json"
  jq --arg mode "$mode" '.outbounds[0].transport.mode=$mode' tests/interop-singbox-client.json >"$tmp_dir/sing-client.json"
  ./target/debug/xhttp run -c "$tmp_dir/rust-server.json" >"$tmp_dir/rust-server-$mode.log" 2>&1 & pids+=("$!")
  "$tmp_dir/sing-box" run -c "$tmp_dir/sing-client.json" >"$tmp_dir/sing-client-$mode.log" 2>&1 & pids+=("$!")
  request 11080
  udp_request 11080
  kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
  unset 'pids[-1]' 'pids[-1]'

  echo "testing Rust -> sing-box: $mode"
  jq --arg mode "$mode" '.inbounds[0].transport.mode=$mode' tests/interop-singbox-server.json >"$tmp_dir/sing-server.json"
  jq --arg mode "$mode" '.outbounds[0].transport.mode=$mode' tests/interop-rust-client.json >"$tmp_dir/rust-client.json"
  "$tmp_dir/sing-box" run -c "$tmp_dir/sing-server.json" >"$tmp_dir/sing-server-$mode.log" 2>&1 & pids+=("$!")
  ./target/debug/xhttp run -c "$tmp_dir/rust-client.json" >"$tmp_dir/rust-client-$mode.log" 2>&1 & pids+=("$!")
  request 11081
  udp_request 11081
  kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
  unset 'pids[-1]' 'pids[-1]'
done

for mode in stream-one stream-up packet-up; do
  echo "testing Xray -> Rust: $mode"
  jq --arg mode "$mode" '.inbounds[0].transport.mode=$mode' tests/interop-rust-server.json >"$tmp_dir/rust-server.json"
  jq --arg mode "$mode" '.outbounds[0].streamSettings.xhttpSettings.mode=$mode' tests/interop-xray-client.json >"$tmp_dir/xray-client.json"
  ./target/debug/xhttp run -c "$tmp_dir/rust-server.json" >"$tmp_dir/rust-server-xray-$mode.log" 2>&1 & pids+=("$!")
  "$tmp_dir/xray" run -config "$tmp_dir/xray-client.json" >"$tmp_dir/xray-client-$mode.log" 2>&1 & pids+=("$!")
  request 11082
  udp_request 11082
  kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
  unset 'pids[-1]' 'pids[-1]'

  echo "testing Rust -> Xray: $mode"
  jq --arg mode "$mode" '.inbounds[0].streamSettings.xhttpSettings.mode=$mode' tests/interop-xray-server.json >"$tmp_dir/xray-server.json"
  jq --arg mode "$mode" '.outbounds[0].transport.mode=$mode' tests/interop-rust-xray-client.json >"$tmp_dir/rust-xray-client.json"
  "$tmp_dir/xray" run -config "$tmp_dir/xray-server.json" >"$tmp_dir/xray-server-$mode.log" 2>&1 & pids+=("$!")
  ./target/debug/xhttp run -c "$tmp_dir/rust-xray-client.json" >"$tmp_dir/rust-xray-client-$mode.log" 2>&1 & pids+=("$!")
  request 11083
  udp_request 11083
  kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
  unset 'pids[-1]' 'pids[-1]'
done

custom_options='{"path":"/xhttp?fixed=value","mode":"packet-up","x_padding_obfs_mode":true,"x_padding_placement":"header","x_padding_header":"X-Test-Padding","x_padding_method":"tokenish","session_id_placement":"cookie","session_id_key":"test_session","seq_placement":"header","seq_key":"X-Test-Seq","uplink_data_placement":"cookie","uplink_data_key":"test_data","uplink_http_method":"PUT"}'
echo "testing non-default XHTTP placements and obfuscation"
jq --argjson options "$custom_options" '.inbounds[0].transport += $options' tests/interop-rust-server.json >"$tmp_dir/rust-custom-server.json"
jq --argjson options "$custom_options" '.outbounds[0].transport += $options' tests/interop-singbox-client.json >"$tmp_dir/sing-custom-client.json"
./target/debug/xhttp run -c "$tmp_dir/rust-custom-server.json" >"$tmp_dir/rust-custom-server.log" 2>&1 & pids+=("$!")
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-custom-client.json" >"$tmp_dir/sing-custom-client.log" 2>&1 & pids+=("$!")
request 11080
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq --argjson options "$custom_options" '.inbounds[0].transport += $options' tests/interop-singbox-server.json >"$tmp_dir/sing-custom-server.json"
jq --argjson options "$custom_options" '.outbounds[0].transport += $options' tests/interop-rust-client.json >"$tmp_dir/rust-custom-client.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-custom-server.json" >"$tmp_dir/sing-custom-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-custom-client.json" >"$tmp_dir/rust-custom-client.log" 2>&1 & pids+=("$!")
request 11081
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "testing XHTTP XMUX under concurrent logical connections"
jq '.outbounds[0].transport.xmux={"max_connections":{"from":2,"to":2},"c_max_reuse_times":{"from":32,"to":32},"h_max_request_times":{"from":256,"to":256}}' \
  tests/interop-rust-client.json >"$tmp_dir/rust-xmux-client.json"
"$tmp_dir/sing-box" run -c tests/interop-singbox-server.json >"$tmp_dir/sing-xmux-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-xmux-client.json" >"$tmp_dir/rust-xmux-client.log" 2>&1 & pids+=("$!")
xmux_jobs=()
for _ in $(seq 1 12); do request 11081 & xmux_jobs+=("$!"); done
for pid in "${xmux_jobs[@]}"; do wait "$pid"; done
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "testing TLS, inline PEM and separate server_name"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost' -addext 'basicConstraints=critical,CA:FALSE' \
  -keyout "$tmp_dir/key.pem" -out "$tmp_dir/cert.pem" >/dev/null 2>&1
cert_pin=$(openssl x509 -in "$tmp_dir/cert.pem" -outform DER | sha256sum | cut -d' ' -f1)
jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" '.inbounds[0].tls={"enabled":true,"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' tests/interop-rust-server.json >"$tmp_dir/rust-tls-server.json"
jq '.outbounds[0].tls={"enabled":true,"insecure":true,"server_name":"localhost"}' tests/interop-singbox-client.json >"$tmp_dir/sing-tls-client.json"
./target/debug/xhttp run -c "$tmp_dir/rust-tls-server.json" >"$tmp_dir/rust-tls-server.log" 2>&1 & pids+=("$!")
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-tls-client.json" >"$tmp_dir/sing-tls-client.log" 2>&1 & pids+=("$!")
request 11080
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" '.inbounds[0].tls={"enabled":true,"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' tests/interop-singbox-server.json >"$tmp_dir/sing-tls-server.json"
jq '.outbounds[0].tls={"enabled":true,"insecure":true,"server_name":"localhost"}' tests/interop-rust-client.json >"$tmp_dir/rust-tls-client.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-tls-server.json" >"$tmp_dir/sing-tls-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-tls-client.json" >"$tmp_dir/rust-tls-client.log" 2>&1 & pids+=("$!")
request 11081
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "testing TLS trust, hostname and ALPN failures"
jq --rawfile cert "$tmp_dir/cert.pem" '.outbounds[0].tls={"enabled":true,"server_name":"wrong.invalid","certificate":($cert|split("\n")|map(select(length>0)))}' \
  tests/interop-rust-client.json >"$tmp_dir/rust-wrong-host-client.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-tls-server.json" >"$tmp_dir/sing-wrong-host-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-wrong-host-client.json" >"$tmp_dir/rust-wrong-host-client.log" 2>&1 & pids+=("$!")
request_must_fail 11081
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq '.outbounds[0].tls={"enabled":true,"server_name":"localhost"}' \
  tests/interop-rust-client.json >"$tmp_dir/rust-untrusted-client.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-tls-server.json" >"$tmp_dir/sing-untrusted-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-untrusted-client.json" >"$tmp_dir/rust-untrusted-client.log" 2>&1 & pids+=("$!")
request_must_fail 11081
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" \
  '.inbounds[0].tls={"enabled":true,"alpn":["unsupported-test-alpn"],"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' \
  tests/interop-singbox-server.json >"$tmp_dir/sing-alpn-mismatch-server.json"
jq --rawfile cert "$tmp_dir/cert.pem" \
  '.outbounds[0].tls={"enabled":true,"server_name":"localhost","certificate":($cert|split("\n")|map(select(length>0)))}' \
  tests/interop-rust-client.json >"$tmp_dir/rust-alpn-mismatch-client.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-alpn-mismatch-server.json" >"$tmp_dir/sing-alpn-mismatch-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-alpn-mismatch-client.json" >"$tmp_dir/rust-alpn-mismatch-client.log" 2>&1 & pids+=("$!")
request_must_fail 11081
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "testing client ECH over HTTP/1.1, HTTP/2 and HTTP/3"
"$tmp_dir/sing-box" generate ech-keypair localhost >"$tmp_dir/ech-pair.pem"
awk '/BEGIN ECH CONFIGS/{copy=1} copy{print} /END ECH CONFIGS/{copy=0}' "$tmp_dir/ech-pair.pem" >"$tmp_dir/ech-config.pem"
awk '/BEGIN ECH KEYS/{copy=1} copy{print} /END ECH KEYS/{copy=0}' "$tmp_dir/ech-pair.pem" >"$tmp_dir/ech-key.pem"
for alpn in http/1.1 h2 h3; do
  label=${alpn//\//-}
  jq --arg alpn "$alpn" --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" --rawfile ech_key "$tmp_dir/ech-key.pem" \
    '.inbounds[0].tls={"enabled":true,"alpn":[$alpn],"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0))),"ech":{"enabled":true,"key":($ech_key|split("\n")|map(select(length>0)))}}' \
    tests/interop-singbox-server.json >"$tmp_dir/sing-ech-server-$label.json"
  jq --arg alpn "$alpn" --rawfile cert "$tmp_dir/cert.pem" --rawfile ech_config "$tmp_dir/ech-config.pem" \
    '.outbounds[0].tls={"enabled":true,"alpn":[$alpn],"server_name":"localhost","certificate":($cert|split("\n")|map(select(length>0))),"ech":{"enabled":true,"config":($ech_config|split("\n")|map(select(length>0)))}}' \
    tests/interop-rust-client.json >"$tmp_dir/rust-ech-client-$label.json"
  "$tmp_dir/sing-box" run -c "$tmp_dir/sing-ech-server-$label.json" >"$tmp_dir/sing-ech-server-$label.log" 2>&1 & pids+=("$!")
  ./target/debug/xhttp run -c "$tmp_dir/rust-ech-client-$label.json" >"$tmp_dir/rust-ech-client-$label.log" 2>&1 & pids+=("$!")
  request 11081
  kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
  unset 'pids[-1]' 'pids[-1]'
done

echo "testing HTTP/3 in both directions"
jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" '.inbounds[0].tls={"enabled":true,"alpn":["h3"],"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' tests/interop-rust-server.json >"$tmp_dir/rust-h3-server.json"
jq '.outbounds[0].tls={"enabled":true,"alpn":["h3"],"insecure":true,"server_name":"localhost"}' tests/interop-singbox-client.json >"$tmp_dir/sing-h3-client.json"
./target/debug/xhttp run -c "$tmp_dir/rust-h3-server.json" >"$tmp_dir/rust-h3-server.log" 2>&1 & pids+=("$!")
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-h3-client.json" >"$tmp_dir/sing-h3-client.log" 2>&1 & pids+=("$!")
request 11080
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" '.inbounds[0].tls={"enabled":true,"alpn":["h3"],"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' tests/interop-singbox-server.json >"$tmp_dir/sing-h3-server.json"
jq '.outbounds[0].tls={"enabled":true,"alpn":["h3"],"insecure":true,"server_name":"localhost"}' tests/interop-rust-client.json >"$tmp_dir/rust-h3-client.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-h3-server.json" >"$tmp_dir/sing-h3-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-h3-client.json" >"$tmp_dir/rust-h3-client.log" 2>&1 & pids+=("$!")
request 11081
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" '.inbounds[0].tls={"enabled":true,"alpn":["h3"],"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' tests/interop-rust-server.json >"$tmp_dir/rust-h3-server.json"
jq --arg pin "$cert_pin" '.outbounds[0].streamSettings.security="tls" | .outbounds[0].streamSettings.tlsSettings={"serverName":"localhost","pinnedPeerCertSha256":$pin,"alpn":["h3"]}' tests/interop-xray-client.json >"$tmp_dir/xray-h3-client.json"
./target/debug/xhttp run -c "$tmp_dir/rust-h3-server.json" >"$tmp_dir/rust-h3-xray-server.log" 2>&1 & pids+=("$!")
"$tmp_dir/xray" run -config "$tmp_dir/xray-h3-client.json" >"$tmp_dir/xray-h3-client.log" 2>&1 & pids+=("$!")
request 11082
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

jq --arg cert "$tmp_dir/cert.pem" --arg key "$tmp_dir/key.pem" '.inbounds[0].streamSettings.security="tls" | .inbounds[0].streamSettings.tlsSettings={"alpn":["h3"],"certificates":[{"certificateFile":$cert,"keyFile":$key}]}' tests/interop-xray-server.json >"$tmp_dir/xray-h3-server.json"
jq '.outbounds[0].tls={"enabled":true,"alpn":["h3"],"insecure":true,"server_name":"localhost"}' tests/interop-rust-xray-client.json >"$tmp_dir/rust-xray-h3-client.json"
"$tmp_dir/xray" run -config "$tmp_dir/xray-h3-server.json" >"$tmp_dir/xray-h3-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c "$tmp_dir/rust-xray-h3-client.json" >"$tmp_dir/rust-xray-h3-client.log" 2>&1 & pids+=("$!")
request 11083
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "testing sing-box AnyTLS client -> Rust AnyTLS server"
jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" \
  '.inbounds[0].tls={"enabled":true,"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' \
  tests/interop-rust-anytls-server.json >"$tmp_dir/rust-anytls-server.json"
./target/debug/xhttp run -c "$tmp_dir/rust-anytls-server.json" >"$tmp_dir/rust-anytls-server.log" 2>&1 & pids+=("$!")
"$tmp_dir/sing-box" run -c tests/interop-singbox-anytls-client.json >"$tmp_dir/sing-anytls-client.log" 2>&1 & pids+=("$!")
request 11084
udp_request 11084
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "testing Rust AnyTLS client -> sing-box AnyTLS server"
jq --rawfile cert "$tmp_dir/cert.pem" --rawfile key "$tmp_dir/key.pem" \
  '.inbounds[0].tls={"enabled":true,"certificate":($cert|split("\n")|map(select(length>0))),"key":($key|split("\n")|map(select(length>0)))}' \
  tests/interop-singbox-anytls-server.json >"$tmp_dir/sing-anytls-server.json"
"$tmp_dir/sing-box" run -c "$tmp_dir/sing-anytls-server.json" >"$tmp_dir/sing-anytls-server.log" 2>&1 & pids+=("$!")
./target/debug/xhttp run -c tests/interop-rust-anytls-client.json >"$tmp_dir/rust-anytls-client.log" 2>&1 & pids+=("$!")
request 11085
udp_request 11085
kill "${pids[-1]}" "${pids[-2]}" 2>/dev/null || true
unset 'pids[-1]' 'pids[-1]'

echo "sing-box, Xray and AnyTLS TCP/UDP interoperability passed in both directions"
