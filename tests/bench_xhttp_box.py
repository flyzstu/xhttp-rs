#!/usr/bin/env python3
"""Real-link benchmark for deployed xhttp-box servers.

Measures download throughput and time-to-first-byte (TTFB) through:
  * direct         - raw link, no tunnel (TUN bypassed) - the control baseline
  * xhttp-<mode>   - xhttp-rs SOCKS -> xhttp-box XHTTP inbound. The deployed
                     inbound is hardcoded to packet-up (server.json.j2:52),
                     so only xhttp-packet-up connects.
  * anytls         - xhttp-rs SOCKS -> xhttp-box AnyTLS inbound

The download target is each host's own nginx /__down?file=100mb, so the
server->nginx leg is local. The client->server leg is the real Internet link,
which is exactly what the tunnel adds overhead to. Comparing tunnel modes
against the direct baseline isolates tunnel cost from link variance.

Hosts and credentials come from ansible/hosts + ansible/{sing_box.yml,
server.json.j2}. The TUN-capture bypass is the transient ip rule used by
throughput.sh; it is removed in a finally block.

Usage (credentials are sourced from local ansible vars, never committed):
  export XHTTP_TOKEN=$(awk '/xhttp_token:/{print $2}' ../ansible/sing_box.yml)
  export ANYTLS_PASSWORD=$(awk '/anytls_password:/{print $2}' ../ansible/sing_box.yml)
  XHTTP_BENCH_CLIENT=../target/release/xhttp \
  python3 tests/bench_xhttp_box.py --hosts sin,lax2 --modes direct,xhttp-packet-up,anytls \
      --size-mb 20 --samples 2 --json-out /tmp/xhbox-bench/results.json
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

# Origin IPs from ansible/hosts. XHTTP connects to the origin IP:443 and lets
# nginx SNI-route <host>.piccdn.click to the xhttp-box vless inbound.
HOSTS = {
    "hkg": "183.87.147.66",
    "iad": "47.251.71.9",
    "sin": "47.236.121.24",
    "lax": "96.44.174.145",
    "lax2": "23.251.34.192",
}
UUID = "e07c0f3b-5ff4-4fd7-833b-df2f4cc90963"
XHTTP_PATH = "/assets/7d91f0c2a8e54b6f/manifest"
# Credentials are intentionally NOT hardcoded: read them from the local ansible
# vars at run time, e.g.
#   export XHTTP_TOKEN=$(awk '/xhttp_token:/{print $2}' ../ansible/sing_box.yml)
#   export ANYTLS_PASSWORD=$(awk '/anytls_password:/{print $2}' ../ansible/sing_box.yml)
XHTTP_TOKEN = os.environ.get("XHTTP_TOKEN", "")
ANYTLS_PASSWORD = os.environ.get("ANYTLS_PASSWORD", "")
SOCKS_PORT = 11150
BENCH_RULE_PRIORITY = 999

CLIENT = os.environ.get(
    "XHTTP_BENCH_CLIENT",
    str(Path(__file__).resolve().parent.parent / "target/release/xhttp"),
)


def run(cmd, **kw):
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def tun_bypass(ip):
    rule = f"to {ip}/32 lookup main priority {BENCH_RULE_PRIORITY}"
    run(["ip", "rule", "add", rule])
    route = run(["ip", "route", "get", ip]).stdout.strip().splitlines()[0]
    if "tun0" in route:
        raise RuntimeError(f"TUN bypass failed for {ip}: {route}")
    return rule


def tun_unbypass(ip):
    run([
        "ip", "rule", "del",
        f"to {ip}/32 lookup main priority {BENCH_RULE_PRIORITY}",
    ])


def write_config(path, mode, host):
    ip = HOSTS[host]
    if mode.startswith("xhttp"):
        xmode = mode.split("-", 1)[1]
        # Connect to the origin IP:443; nginx SNI-routes <host>.piccdn.click
        # to the xhttp-box vless inbound. This is the validated path.
        cfg = {
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1",
                          "listen_port": SOCKS_PORT}],
            "outbounds": [{
                "type": "vless", "tag": "out",
                "server": ip, "server_port": 443,
                "uuid": UUID,
                "tls": {"enabled": True, "server_name": f"{host}.piccdn.click", "alpn": "h2"},
                "transport": {"type": "xhttp", "host": f"{host}.piccdn.click",
                              "path": f"{XHTTP_PATH}?k={XHTTP_TOKEN}", "mode": xmode},
            }],
            "route": {"final": "out"},
        }
    elif mode == "anytls":
        cfg = {
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1",
                          "listen_port": SOCKS_PORT}],
            "outbounds": [{
                "type": "anytls", "tag": "out",
                "server": ip, "server_port": 443,
                "password": ANYTLS_PASSWORD,
                "idle_session_check_interval": "20s",
                "idle_session_timeout": "2m",
                "min_idle_session": 5,
                "tls": {"enabled": True, "insecure": True,
                        "server_name": "gateway.icloud.com", "alpn": "h2"},
            }],
            "route": {"final": "out"},
        }
    else:
        raise ValueError(mode)
    path.write_text(json.dumps(cfg))


def port_open(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def start_client(config):
    proc = subprocess.Popen(
        [CLIENT, "run", "-c", str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"client exited with {proc.returncode}")
        if port_open(SOCKS_PORT):
            return proc
        time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("client SOCKS did not become ready")


def curl_download(mode, ip, size_mb, timeout):
    url = f"https://{ip}/__down?file=100mb"
    cmd = ["curl", "-k", "-sS", "-o", os.devnull]
    if mode != "direct":
        cmd += ["--socks5", f"127.0.0.1:{SOCKS_PORT}"]
    cmd += [
        "--max-time", str(timeout), "-r", f"0-{size_mb * 1024 * 1024 - 1}",
        "-w",
        "%{http_code} %{speed_download} %{time_starttransfer} %{time_total}",
        url,
    ]
    result = run(cmd, timeout=timeout + 5)
    if result.returncode != 0:
        return {"ok": False, "error": result.stderr.strip()[:200]}
    parts = result.stdout.strip().split()
    if len(parts) != 4 or parts[0] != "206":
        return {"ok": False, "error": f"bad result: {result.stdout.strip()[:120]}"}
    return {
        "ok": True,
        "mbps": round(float(parts[1]) / 1e6, 2),
        "ttfb_s": round(float(parts[2]), 3),
        "total_s": round(float(parts[3]), 3),
    }


def bench(host, mode, size_mb, samples, timeout, tmp):
    ip = HOSTS[host]
    rule = tun_bypass(ip)
    proc = None
    try:
        if mode != "direct":
            cfg = tmp / f"{host}-{mode}.json"
            write_config(cfg, mode, host)
            proc = start_client(cfg)
        results = []
        for _ in range(samples):
            results.append(curl_download(mode, ip, size_mb, timeout))
        good = [r for r in results if r["ok"]]
        out = {
            "host": host, "mode": mode, "samples": samples,
            "ok_samples": len(good), "size_mb": size_mb,
        }
        if good:
            out["mbps_median"] = round(statistics.median(r["mbps"] for r in good), 2)
            out["mbps_all"] = [r["mbps"] for r in good]
            out["ttfb_s_median"] = round(statistics.median(r["ttfb_s"] for r in good), 3)
            out["total_s_median"] = round(statistics.median(r["total_s"] for r in good), 3)
        else:
            out["errors"] = [r["error"] for r in results]
        return out
    finally:
        if proc is not None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        tun_unbypass(ip)
        del rule


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", default=",".join(HOSTS))
    ap.add_argument("--modes", default="direct,xhttp-packet-up,anytls")
    ap.add_argument("--size-mb", type=int, default=20)
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--json-out")
    args = ap.parse_args()

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    for h in hosts:
        if h not in HOSTS:
            ap.error(f"unknown host {h}; choose from {', '.join(HOSTS)}")

    if not Path(CLIENT).exists():
        ap.error(f"xhttp client not found: {CLIENT} (set XHTTP_BENCH_CLIENT)")
    if any(m.startswith("xhttp") for m in modes) and not XHTTP_TOKEN:
        ap.error("XHTTP_TOKEN is required for xhttp modes "
                 "(source it from ansible/sing_box.yml; see module header)")
    if "anytls" in modes and not ANYTLS_PASSWORD:
        ap.error("ANYTLS_PASSWORD is required for anytls mode "
                 "(source it from ansible/sing_box.yml; see module header)")
    results = []
    with tempfile.TemporaryDirectory(prefix="xhbox-bench-") as td:
        tmp = Path(td)
        for host in hosts:
            for mode in modes:
                print(f"[bench] {host:5} {mode:18} {args.size_mb}MB x{args.samples}", flush=True)
                try:
                    result = bench(host, mode, args.size_mb, args.samples, args.timeout, tmp)
                except Exception as exc:  # keep the rest of the matrix running
                    result = {"host": host, "mode": mode, "ok": False, "error": str(exc)}
                results.append(result)
                mbps = result.get("mbps_median")
                print(f"        -> {mbps if mbps is not None else 'FAIL'} MB/s "
                      f"({result.get('ok_samples', 0)}/{args.samples} ok)", flush=True)

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "client": CLIENT,
        "size_mb": args.size_mb,
        "samples": args.samples,
        "target": "xhttp-box (ansible sing_box.yml, image 0.3.0)",
        "results": results,
    }
    text = json.dumps(payload, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(text)
        print(f"[bench] wrote {args.json_out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
