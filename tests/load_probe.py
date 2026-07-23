#!/usr/bin/env python3
import concurrent.futures
import json
import socket
import struct
import sys
import threading
import time

proxy_port = int(sys.argv[1])
duration = float(sys.argv[2])
concurrency = int(sys.argv[3])
deadline = time.monotonic() + duration
lock = threading.Lock()
totals = {"tcp_requests": 0, "tcp_bytes": 0, "udp_packets": 0, "errors": 0}


def recv_exact(sock, length):
    output = bytearray()
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise EOFError("unexpected EOF")
        output.extend(chunk)
    return bytes(output)


def socks_connect():
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS method failed")
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 19091))
    reply = recv_exact(sock, 4)
    if reply[1] != 0:
        raise RuntimeError("SOCKS connect failed")
    lengths = {1: 6, 4: 18}
    if reply[3] == 3:
        recv_exact(sock, recv_exact(sock, 1)[0] + 2)
    else:
        recv_exact(sock, lengths[reply[3]])
    return sock


def tcp_worker():
    local = {"tcp_requests": 0, "tcp_bytes": 0, "errors": 0}
    while time.monotonic() < deadline:
        try:
            with socks_connect() as sock:
                sock.sendall(
                    b"GET /Cargo.toml HTTP/1.1\r\nHost: 127.0.0.1:19091\r\nConnection: close\r\n\r\n"
                )
                response = bytearray()
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
                if b'name = "xhttp-rs"' not in response:
                    raise RuntimeError("unexpected HTTP response")
                local["tcp_requests"] += 1
                local["tcp_bytes"] += len(response)
        except Exception:
            local["errors"] += 1
    with lock:
        for key, value in local.items():
            totals[key] += value


def udp_worker():
    local_packets = 0
    local_errors = 0
    try:
        control = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
        control.sendall(b"\x05\x01\x00")
        recv_exact(control, 2)
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = recv_exact(control, 4)
        if reply[3] != 1:
            raise RuntimeError("load probe requires an IPv4 UDP relay")
        address = socket.inet_ntoa(recv_exact(control, 4))
        port = struct.unpack("!H", recv_exact(control, 2))[0]
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(3)
        sequence = 0
        while time.monotonic() < deadline:
            payload = struct.pack("!Q", sequence)
            packet = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 19092) + payload
            udp.sendto(packet, (address, port))
            response, _ = udp.recvfrom(2048)
            if not response.endswith(payload):
                raise RuntimeError("unexpected UDP response")
            local_packets += 1
            sequence += 1
        control.close()
        udp.close()
    except Exception:
        local_errors += 1
    with lock:
        totals["udp_packets"] += local_packets
        totals["errors"] += local_errors


started = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency + 1) as executor:
    jobs = [executor.submit(tcp_worker) for _ in range(concurrency)]
    jobs.append(executor.submit(udp_worker))
    for job in jobs:
        job.result()
elapsed = time.monotonic() - started
totals["elapsed_seconds"] = round(elapsed, 3)
totals["tcp_requests_per_second"] = round(totals["tcp_requests"] / elapsed, 2)
totals["tcp_mebibytes_per_second"] = round(totals["tcp_bytes"] / elapsed / 1048576, 2)
totals["udp_packets_per_second"] = round(totals["udp_packets"] / elapsed, 2)
print(json.dumps(totals, sort_keys=True))
