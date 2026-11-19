#!/usr/bin/env python3
"""Discard upload bodies for throughput benchmarks.

Deployed to each remote host by bench_xhttp_box.py for upload-direction
tests. Binds 0.0.0.0 so the xhttp proxy can dial the origin IP locally.
The body is drained without buffering, so throughput measures the tunnel,
not disk or memory.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 18190


class Handler(BaseHTTPRequestHandler):
    def _drain(self) -> None:
        remaining = int(self.headers.get("Content-Length", 0))
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 16))
            if not chunk:
                break
            remaining -= len(chunk)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = _drain
    do_PUT = _drain

    def log_message(self, *_args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
