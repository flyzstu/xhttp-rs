#!/usr/bin/env python3
import socket
import sys

address = sys.argv[1]
port = int(sys.argv[2])
family = socket.AF_INET6 if ":" in address else socket.AF_INET
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.bind((address, port))
while True:
    payload, peer = sock.recvfrom(65535)
    sock.sendto(payload + b"|" + str(peer[1]).encode(), peer)
