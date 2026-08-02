#!/usr/bin/env python3
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.0.2.2", 0))
sock.settimeout(5)
observed = []
for port in (15353, 15355):
    payload = f"destination-{port}".encode()
    sock.sendto(payload, ("203.0.113.2", port))
    response, peer = sock.recvfrom(65535)
    body, source_port = response.rsplit(b"|", 1)
    if body != payload or peer != ("203.0.113.2", port):
        raise RuntimeError(f"unexpected UDP response from {peer}: {response!r}")
    observed.append(int(source_port))
if observed[0] != observed[1]:
    raise RuntimeError(f"endpoint-independent mapping used different ports: {observed}")
print(f"endpoint-independent mapping reused gateway UDP port {observed[0]}")
