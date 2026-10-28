# Vortex DFS — reproducible MCP enforcement demonstration

**Audience:** prospective pilot reviewers. **Status:** controlled loopback proof, not a production-ready or Internet-hosted gateway.

## What is independently verified

The Rust gateway runs as a separate process from the Python HTTP MCP fixture. An RSA key pair is generated during the test. The fixture exposes OIDC discovery metadata and JWKS. The gateway validates signed RS256 tokens, binds session identity, checks `crm:export` scope using the Vortex DFS runtime, persists policy decisions before forwarding, and denies calls without the scope. A second independent Python stdlib MCP HTTP client performs initialize, notifications/initialized, tools/list and tools/call. The fixture's independent counter tracks the actual number of received tool calls.

The integration test rotates the JWKS from one RSA public key to another, checks that the old token is no longer accepted, and confirms a newly signed token works. No customer data or customer credentials are used.

## Run the demo

Requirements: Rust stable, Python 3, OpenSSL development libraries and the backend's locked Rust dependencies.

From the repository root on the isolated branch:

```sh
cargo test --manifest-path backend/Cargo.toml --locked --test mcp_oidc_http_gateway -- --nocapture
```

The test starts all local services, generates temporary keys, runs both clients, validates audit records and upstream receipt counts, and terminates its child processes. It does **not** deploy a remote service. A passing CI run for the same commit is the reproducible reference.

## What to show a buyer

1. **Identity** — a signed token for Alice (`crm:export`) initializes an MCP session; Bob (`crm:read`) cannot reuse it.
2. **Authorization** — Bob's valid but insufficiently scoped token returns `SCOPE_DENIED`.
3. **Independent side effect** — the fixture's counter increases only when an authorized tool call is forwarded.
4. **Key rotation** — JWKS changes; old signing key stops working, new signing key works.
5. **Audit before execution** — JSONL records principal, tool, reason code and decision. The separate failure-injection test demonstrates that a broken audit sink prevents forwarding.

## Evidence checklist

- CI green for exact commit and test name
- Logs for `mcp_oidc_http_gateway`, `mcp_http_gateway` and audit-failure injection
- Independently observed upstream receipt count
- Source diff in isolated branch, no changes to main or customer systems

## Explicit limitations and remaining release gates

- The independent client is a Python **stdlib protocol probe**, not an official MCP SDK. Official SDK interoperability is **not yet validated**.
- The gateway implements a narrow MCP JSON-RPC subset; it is not a complete Streamable HTTP implementation (SSE, DELETE session termination, resumability, streaming and protocol-version negotiation remain incomplete).
- OIDC discovery is limited to same-origin JWKS with HTTPS outside loopback. No real third-party IdP integration or enterprise OAuth authorization flow has been tested.
- JWKS refresh is periodic and fails closed on refresh error, but it has no resilient last-known-good policy, managed key lifecycle, or IdP availability strategy.
- Audit uses local JSONL and is not tamper-evident or centralized; malformed requests and early authentication failures are not comprehensively audited.
- Gateway and upstream are loopback-bound. TLS termination, deployment, monitoring, external security review and load tests are pending.

**Commercial wording:** "Reproducible pre-execution MCP authorization proof with independently observed upstream receipt counts." Do not describe this artifact as production certified or a fully compliant MCP gateway.
