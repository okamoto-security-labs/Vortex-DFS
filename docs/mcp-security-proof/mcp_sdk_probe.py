#!/usr/bin/env python3
"""Official Python MCP SDK Streamable HTTP interoperability probe.

Runs against the isolated Vortex gateway. Requires pip package 'mcp'.
A failure is meaningful: this is a genuine SDK client, not the stdlib fixture.
"""
import asyncio
import json
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def probe(endpoint: str, token: str, expected: str) -> None:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(10.0),
        follow_redirects=False,
    ) as http_client:
        async with streamablehttp_client(endpoint, http_client=http_client) as streams:
            read, write, _session_id = streams
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert initialized.protocolVersion, "MCP initialize did not negotiate a version"
                tools = await session.list_tools()
                assert any(tool.name == "crm_export" for tool in tools.tools)
                if expected == "ALLOW":
                    result = await session.call_tool("crm_export", {"customer_group": "test"})
                    assert any(getattr(item, "text", "") == "Fixture accepted" for item in result.content), result
                else:
                    try:
                        await session.call_tool("crm_export", {"customer_group": "test"})
                    except Exception as exc:
                        assert "SCOPE_DENIED" in str(exc) or "Vortex policy rejected" in str(exc), str(exc)
                    else:
                        raise AssertionError("read-only token unexpectedly executed tool")
    print(json.dumps({"client": "official-python-mcp-sdk", "expected": expected, "verified": True}))


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[3] not in ("ALLOW", "REJECT"):
        sys.exit("usage: mcp_sdk_probe.py URL JWT ALLOW|REJECT")
    asyncio.run(probe(*sys.argv[1:]))
