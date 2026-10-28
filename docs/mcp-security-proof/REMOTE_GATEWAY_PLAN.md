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
