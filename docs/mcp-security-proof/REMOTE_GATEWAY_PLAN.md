# Vortex DFS Remote MCP Enforcement Gateway — implementation and release gates

Status: engineering plan, **not** a production-readiness claim. Isolated branch only. Existing stdio test is not remote HTTP interoperability.

## Security boundary

MCP client → TLS reverse proxy → MCP gateway → policy evaluator → upstream MCP server.

The gateway MUST be the only network path to upstream. A direct client-to-upstream path invalidates the enforcement claim. Upstream credentials are held server-side, never supplied by agent tool arguments. No production secrets in tests.

## Milestone 1 — interoperable remote gateway

- Rust service exposes MCP Streamable HTTP endpoint; supports JSON-RPC initialize, notifications/initialized, tools/list, tools/call, protocol negotiation, request IDs, errors and applicable session semantics.
- Upstream client connects to a separate, independently started MCP Streamable HTTP server with timeout, bounded request/response bodies, cancellation handling, and explicit allowlisted destinations.
- Preserve protocol behavior without claiming transparent proxy support for features not implemented (streaming, SSE, server-initiated messages, resource subscriptions).
- Authenticate clients at the trusted HTTP boundary and validate issuer, audience, signature, expiration and scopes against configured trust anchors. Never trust identity or scopes in MCP arguments.
- Map the authenticated principal and requested tool/arguments to the existing Vortex DFS policy engine. Fail closed for missing/invalid identity, policy, audit requirements, or unreachable dependencies.
- Return policy denial as a structured MCP/JSON-RPC error without forwarding the tool invocation.
- Pin upstream endpoints and prohibit arbitrary user-supplied URLs (SSRF). Do not forward inbound Authorization headers to upstream.

## Milestone 2 — independent evidence

- Separate upstream server with append-only test event log; every received tools/call increments a monotonic counter.
- Allow request: gateway returns success and upstream counter increments exactly once.
- Deny for missing scope, identity, policy mismatch and forged scope in arguments: gateway returns rejection; upstream counter unchanged.
- Concurrent requests, replay, timeout, malformed JSON, oversized payload, upstream disconnect and audit-store failure covered.
- Verify identity separation across tenants, credentials never leak to logs, and authorization cannot be bypassed through other MCP methods or aliases.
- CI produces redacted test logs and artifacts with request IDs, decision reason codes and upstream counters.

## Milestone 3 — production-hardening gates

- Explicit threat model, architecture review, automated dependency and secret scanning, SAST and independent security review.
- Durable audit sink with tamper evidence and backpressure/failure semantics; secrets managed outside repository; key rotation and revocation.
- Rate limits, connection caps, timeouts, bounded memory, health/readiness probes, metrics, traces and alerting.
- Container image pinned by digest; reproducible builds, SBOM, release signatures, least-privilege runtime and rollout/rollback procedures.
- Load/soak tests establish p50/p95/p99 latency, throughput, CPU/memory and failure modes; publish measured numbers only.
- Protocol interoperability tests with independent MCP SDK clients/servers, including version compatibility and session behavior.
- Document limitations, supported protocol features, operational runbooks, incident response, backup/recovery and deployment guide.

## Non-goals for initial remote MVP

- No blanket Zero Trust claim; no semantic intent detection; no customer production CRM access; no unsupported production-ready or certified-security language.
- No exposure of the test gateway to the public Internet until authentication, upstream allowlisting and resource limits are enforced and reviewed.

## Commercial acceptance demo

A recorded, reproducible remote MCP session with a real independent upstream process, request/decision correlation IDs, independent upstream receipt counters, latency measurements, and a fail-closed negative test. Evidence links to a specific passing CI commit.


## Implemented experimental HTTP slice (commit 07b23fa)

`backend/src/bin/mcp_gateway.rs` adds a loopback-bound Actix endpoint `POST /mcp` that authenticates a static proof token, parses JSON-RPC `tools/call`, authorizes a fixed `crm_export` operation through the Rust runtime, and forwards allowed requests to a **loopback-only** HTTP upstream. The destination is configured at startup, redirects are disabled, and the HTTP body and request timeout are bounded. This is an incremental code milestone, **not** a functioning general-purpose MCP Streamable HTTP gateway: it does not support MCP initialize/session negotiation, SSE, remote TLS, JWT/OIDC, audit persistence, per-client scopes, or full protocol interoperability. Do not deploy to the public Internet or use customer data. The static credential maps to a single fixed scope and is unsuitable for production authorization. Compilation and integration test status must be checked in CI before citing success.

Local example (requires a separately running HTTP JSON-RPC MCP fixture on loopback port 8790):

```sh
export VORTEX_MCP_UPSTREAM=http://127.0.0.1:8790/mcp
export VORTEX_MCP_CLIENT_TOKEN="$(openssl rand -hex 32)"
cargo run --manifest-path backend/Cargo.toml --bin mcp_gateway
```

The next milestone must implement proper MCP initialize and remote transport semantics, independent upstream receipt counting, real identity verification, and mandatory durable audit before external release.

## Experimental pre-forward local audit (commit 1e0ee1d)

The isolated gateway now requires `VORTEX_MCP_AUDIT_PATH` pointing to a writable local JSONL file. It writes and calls `sync_data()` on a minimal decision record before an authorized tool call can be forwarded. Write/sync failures return HTTP 503 and prevent forwarding. The integration test uses Linux `/dev/full` to inject a write failure and checks the independent upstream counter. Test results are **pending CI verification** as of this change.

Example: `export VORTEX_MCP_AUDIT_PATH=/tmp/vortex-mcp-proof-audit.jsonl` (proof only; use a secure dedicated path, restricted permissions, and managed storage for real deployments).

This is not tamper-evident, distributed, immutable, rotated or centrally monitored audit storage. A local JSONL file alone is insufficient for production compliance. Rejections before tool policy evaluation (such as invalid authentication, session errors, malformed JSON and disallowed tool names) are not currently written to this audit file. Do not claim complete request auditing.

## RS256 JWKS authentication milestone (commit 19be08c8)

Optional configuration: `VORTEX_MCP_OIDC_ISSUER`, `VORTEX_MCP_OIDC_AUDIENCE`, `VORTEX_MCP_OIDC_JWKS_URL`. The gateway fetches JWKS once at startup (HTTPS required outside loopback), pins supported RS256 RSA public keys by unique `kid`, and verifies JWT signature, issuer, audience, expiry, not-before, issued-at, subject and `scope`. Invalid credentials are rejected before MCP session initialization. The isolated HTTP integration test starts an independent loopback JWKS fixture and signs test JWTs with an RSA private key, then verifies both scope enforcement and upstream call counts.

**Scope limitations:** this is direct JWKS verification, **not complete OIDC discovery or enterprise identity integration**. The gateway does not yet fetch `/.well-known/openid-configuration`, refresh JWKS during rotation, validate an IdP's discovery issuer/JWKS relationship, or enforce per-tenant issuer allowlists. The key snapshot is fixed until process restart. The loopback HTTP JWKS test endpoint is strictly a fixture; use HTTPS with a trusted IdP outside local tests. Full OIDC/JWKS production-readiness and CI results remain pending.
