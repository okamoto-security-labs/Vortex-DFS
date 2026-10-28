#!/usr/bin/env python3
"""Loopback HTTP MCP-like test fixture with independent tool-call receipt counter.
Not a production MCP server. Python standard library only.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

count = 0
lock = Lock()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            issuer = os.environ.get("VORTEX_TEST_ISSUER")
            if not issuer:
                self.send_error(404)
            else:
                self.reply(200, {"issuer": issuer, "jwks_uri": "http://127.0.0.1:%s/.well-known/jwks.json" % self.server.server_port})
            return
        if self.path == "/.well-known/jwks.json":
            jwks_file = os.environ.get("VORTEX_TEST_JWKS_FILE")
            if jwks_file:
                try:
                    with open(jwks_file, "r", encoding="utf-8") as f:
                        jwks = f.read()
                except OSError:
                    jwks = None
            else:
                jwks = os.environ.get("VORTEX_TEST_JWKS")
            if jwks is None:
                self.send_error(404)
            else:
                self.reply(200, json.loads(jwks))
            return
        if self.path != "/_count":
            self.send_error(404)
            return
        with lock:
            n = count
        self.reply(200, {"received_tool_calls": n})

    def do_POST(self):
        global count
        if self.path != "/mcp":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            self.send_error(413)
            return
        try:
            req = json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            self.send_error(400)
            return
        if req.get("method") != "tools/call":
            self.reply(200, {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "Unsupported"}})
            return
        with lock:
            count += 1
        self.reply(200, {"jsonrpc": "2.0", "id": req.get("id"),
                         "result": {"content": [{"type": "text", "text": "Fixture accepted"}]}})

    def reply(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

if __name__ == "__main__":
    port = int(os.environ.get("VORTEX_MCP_FIXTURE_PORT", "8790"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
