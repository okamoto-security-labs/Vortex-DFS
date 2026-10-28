#!/usr/bin/env python3
"""Isolated external MCP stdio server fixture. Python standard library only."""
import json
import sys

TOOLS = [{"name": "crm_export", "description": "Record a test export (no customer data)",
          "inputSchema": {"type": "object", "properties": {"customer_group": {"type": "string"}},
                          "required": ["customer_group"]}}]

def respond(req):
    method = req.get("method")
    if method == "initialize":
        return {"protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vortex-isolated-crm-fixture", "version": "0.1.0"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = req.get("params") or {}
        if params.get("name") != "crm_export" or not isinstance((params.get("arguments") or {}).get("customer_group"), str):
            return {"isError": True, "content": [{"type": "text", "text": "Invalid tool call"}]}
        # Side effect occurs only in this separate process; stdout stays MCP JSON-RPC only.
        sys.stderr.write("EXECUTED crm_export\n")
        sys.stderr.flush()
        return {"content": [{"type": "text", "text": "Isolated export fixture accepted"}]}
    return None

for line in sys.stdin:
    try:
        req = json.loads(line)
        if not isinstance(req, dict):
            continue
        result = respond(req)
        if "id" not in req:
            continue
        if result is None:
            msg = {"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": "Method not found"}}
        else:
            msg = {"jsonrpc": "2.0", "id": req["id"], "result": result}
        sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except (ValueError, TypeError):
        continue
