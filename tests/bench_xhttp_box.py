#!/usr/bin/env python3
"""Real-link benchmark for deployed xhttp-box servers.

Measures download and upload throughput through:
  * direct             - raw link, no tunnel (TUN bypassed) - the control
  * xhttp-<mode>       - xhttp-rs SOCKS -> xhttp-box XHTTP inbound. The
                         deployed inbound is packet-up (server.json.j2:52).
  * anytls             - xhttp-rs SOCKS -> xhttp-box AnyTLS inbound
  * upload-<mode>      - upload direction: POST a sparse payload to a
                         temporary discard receiver on the origin host.
                         The 4 client-side knobs (packet interval, chunk
                         size, coalescing, xmux connections) affect uploads,
                         so upload mode is required to measure their effect.
  * <mode>+tuned       - A/B variant with client-only tunables applied:
                         packet_interval_ms=0, h1_coalesce_delay_ms=10,
                         xmux.max_connections=4. max_packet_size is left at
                         1e6: the Go server rejects larger posts.

Downloads use each host's nginx /__down?file=100mb; uploads use a temporary
python discard receiver deployed via SSH. The client->server leg is the real
Internet link; comparing tunnel modes against direct isolates tunnel cost.
Interleave baseline and +tuned within a host to cancel link variance.

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
    tuned = mode.endswith("+tuned")
    base = mode.removesuffix("+tuned")
    transport_mode = base.removeprefix("upload-")
    if transport_mode.startswith("xhttp"):
        xmode = transport_mode.split("-", 1)[1]
        # Connect to the origin IP:443; nginx SNI-routes <host>.piccdn.click
        # to the xhttp-box vless inbound. This is the validated path.
        transport = {"type": "xhttp", "host": f"{host}.piccdn.click",
                     "path": f"{XHTTP_PATH}?k={XHTTP_TOKEN}", "mode": xmode}
        if tuned:
            # Client-only knobs; the deployed Go server needs no change.
            # Config is parsed by SingBoxConfig (main.rs:103), so use the
            # sing-box field name sc_min_posts_interval_ms, NOT the native
            # packet_interval_ms (which would be silently ignored).
            # max_packet_size is left at 1e6: the Go server rejects larger
            # posts (scMaxPost=1e6), so the default is the hard ceiling.
            transport.update({
                "sc_min_posts_interval_ms": {"from": 0, "to": 0},
                "h1_coalesce_delay_ms": 10,
                "xmux": {"max_connections": {"from": 4, "to": 4}},
            })
        cfg = {
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1",
                          "listen_port": SOCKS_PORT}],
            "outbounds": [{
                "type": "vless", "tag": "out",
                "server": ip, "server_port": 443,
                "uuid": UUID,
                "tls": {"enabled": True, "server_name": f"{host}.piccdn.click", "alpn": "h2"},
                "transport": transport,
            }],
            "route": {"final": "out"},
        }
    elif transport_mode == "anytls":
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

UPLOAD_PORT = 18190
RECEIVER_REMOTE = "/tmp/xhbench-recv.py"
RECEIVER_PID = "/tmp/xhbench-recv.pid"


def ssh_cmd(ip, script, timeout=15):
    return run([
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes", f"root@{ip}", script,
    ], timeout=timeout)


def deploy_receiver(ip):
    content = (Path(__file__).resolve().parent / "upload_receiver.py").read_text()
    subprocess.run([
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
        "-o", "BatchMode=yes", f"root@{ip}", f"cat > {RECEIVER_REMOTE}",
    ], input=content, text=True, capture_output=True, timeout=20, check=True)
    # Kill by recorded PID only; pkill -f would match the SSH shell itself.
    ssh_cmd(ip, f"[ -f {RECEIVER_PID} ] && kill $(cat {RECEIVER_PID}) 2>/dev/null || true; "
                f"nohup python3 {RECEIVER_REMOTE} </dev/null >/dev/null 2>&1 & "
                f"echo $! > {RECEIVER_PID}; sleep 0.5")


def remove_receiver(ip):
    ssh_cmd(ip, f"[ -f {RECEIVER_PID} ] && kill $(cat {RECEIVER_PID}) 2>/dev/null || true; "
                f"rm -f {RECEIVER_PID} {RECEIVER_REMOTE}")


def make_payload(size_mb, tmp):
    payload = tmp / f"upload-{size_mb}mb.bin"
    if not payload.exists():
        with open(payload, "wb") as handle:
            handle.truncate(size_mb * 1024 * 1024)  # sparse
    return payload


def curl_upload(ip, size_mb, timeout, payload, mode):
    url = f"http://{ip}:{UPLOAD_PORT}/upload"
    cmd = ["curl", "-sS", "-o", os.devnull]
    if mode != "upload-direct":
        cmd += ["--socks5", f"127.0.0.1:{SOCKS_PORT}"]
    cmd += [
        "--max-time", str(timeout), "-X", "POST", "--data-binary", f"@{payload}",
        "-w", "%{http_code} %{speed_upload} %{time_total}", url,
    ]
    result = run(cmd, timeout=timeout + 5)
    if result.returncode != 0:
        return {"ok": False, "error": result.stderr.strip()[:200]}
    parts = result.stdout.strip().split()
    if len(parts) != 3 or parts[0] != "200":
        return {"ok": False, "error": f"bad result: {result.stdout.strip()[:120]}"}
    return {"ok": True, "mbps": round(float(parts[1]) / 1e6, 2),
            "total_s": round(float(parts[2]), 3)}


def bench(host, mode, size_mb, samples, timeout, tmp):
    ip = HOSTS[host]
    is_upload = mode.startswith("upload-")
    transport_mode = mode.removeprefix("upload-")
    rule = tun_bypass(ip)
    proc = None
    payload = None
    try:
        if is_upload:
            deploy_receiver(ip)
            payload = make_payload(size_mb, tmp)
        if transport_mode != "direct":
            cfg = tmp / f"{host}-{mode}.json"
            write_config(cfg, mode, host)
            proc = start_client(cfg)
        results = []
        for _ in range(samples):
            if is_upload:
                results.append(curl_upload(ip, size_mb, timeout, payload, mode))
            else:
                results.append(curl_download(mode, ip, size_mb, timeout))
        good = [r for r in results if r["ok"]]
        out = {
            "host": host, "mode": mode, "samples": samples,
            "ok_samples": len(good), "size_mb": size_mb,
        }
        if good:
            out["mbps_median"] = round(statistics.median(r["mbps"] for r in good), 2)
            out["mbps_all"] = [r["mbps"] for r in good]
            if not is_upload:
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
        if is_upload:
            remove_receiver(ip)
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
    transport_modes = [m.removeprefix("upload-") for m in modes]
    if any(m.startswith("xhttp") for m in transport_modes) and not XHTTP_TOKEN:
        ap.error("XHTTP_TOKEN is required for xhttp modes "
                 "(source it from ansible/sing_box.yml; see module header)")
    if "anytls" in transport_modes and not ANYTLS_PASSWORD:
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
