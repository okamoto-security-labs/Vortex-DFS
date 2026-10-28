#!/usr/bin/env python3
"""Independent Python MCP JSON-RPC HTTP client probe (stdlib only).
Exercises initialize, notification, tools/list and tools/call.
Not a certification or official MCP SDK conformance suite.
"""
import json
import sys
import urllib.error
import urllib.request

def send(endpoint, token, request, session=None):
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": "2025-06-18"}
    if session:
        headers["Mcp-Session-Id"] = session
    payload = json.dumps(request).encode("utf-8")
    req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            return response.status, dict(response.headers.items()), json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        raw = err.read()
        return err.code, dict(err.headers.items()), json.loads(raw) if raw else None

def run(endpoint, token, expected):
    status, headers, response = send(endpoint, token, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "vortex-independent-python-probe", "version": "1"}}})
    assert status == 200 and response["result"]["protocolVersion"] == "2025-06-18", response
    session = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
    assert session, "missing MCP session ID"
    status, _, _ = send(endpoint, token, {
        "jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    assert status == 202, status
    status, _, response = send(endpoint, token, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session)
    assert status == 200 and response["result"]["tools"][0]["name"] == "crm_export", response
    status, _, response = send(endpoint, token, {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "crm_export", "arguments": {"customer_group": "test"}}}, session)
    assert status == 200, response
    if expected == "ALLOW":
        assert response["result"]["content"][0]["text"] == "Fixture accepted", response
    else:
        assert response["error"]["data"]["reason_code"] == "SCOPE_DENIED", response
    print(json.dumps({"client": "python-stdlib", "protocol": "2025-06-18",
                      "expected": expected, "verified": True, "tool": "crm_export"}))

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[3] not in ("ALLOW", "REJECT"):
        sys.exit("usage: mcp_client_probe.py URL JWT ALLOW|REJECT")
    run(*sys.argv[1:])
