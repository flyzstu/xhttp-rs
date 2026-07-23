import socket
import struct
import sys


def exact(sock, length):
    output = b""
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise RuntimeError("SOCKS control connection closed")
        output += chunk
    return output


proxy_port = int(sys.argv[1])
control = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
control.sendall(b"\x05\x01\x00")
assert exact(control, 2) == b"\x05\x00"
control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
reply = exact(control, 4)
assert reply[:3] == b"\x05\x00\x00"
if reply[3] == 1:
    host = socket.inet_ntop(socket.AF_INET, exact(control, 4))
elif reply[3] == 4:
    host = socket.inet_ntop(socket.AF_INET6, exact(control, 16))
elif reply[3] == 3:
    host = exact(control, exact(control, 1)[0]).decode()
else:
    raise RuntimeError("invalid SOCKS relay address")
port = struct.unpack("!H", exact(control, 2))[0]
if host in ("0.0.0.0", "::"):
    host = "127.0.0.1"

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(3)
payload = b"xhttp-vless-udp"
packet = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 19092) + payload
udp.sendto(packet, (host, port))
response, _ = udp.recvfrom(65535)
assert response[3] == 1 and response[10:] == payload
