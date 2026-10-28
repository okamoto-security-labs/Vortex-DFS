# Vortex DFS — Paid MCP Security Pilot Proposal
**Draft for Kamal · 28 October 2026 · Not an executed agreement**

## Executive proposition
An approved MCP tool does not imply an approved action. Vortex DFS places a deterministic authorization decision between an agent's MCP tool request and the upstream tool server, preventing unauthorized calls from being forwarded.

## Verified evidence
- Rust gateway, independent HTTP upstream, MCP session binding, and scope-based ALLOW/REJECT tested.
- RS256 JWT verification with OIDC discovery, JWKS key rotation, and isolated test issuer.
- Local pre-forward audit records with a fail-closed failure-injection test.
- Official Python MCP SDK Streamable HTTP client ALLOW/REJECT integration passed in GitHub Actions run #47 (commit `1fa6229`): https://github.com/okamoto-security-labs/Vortex-DFS/actions/runs/40776236068
- Independent upstream receipt counter shows denied calls are not forwarded in tested scenarios.

**Boundaries:** This is a reproducible controlled proof, not a production-ready gateway or a complete MCP specification conformance claim. No real customer IdP, public deployment, external security review, or production data integration has been validated.

## Proposed paid pilot: 10 business days (subject to mutual agreement)
**Scope:** one non-production MCP tool server, one customer-approved identity provider, up to three named tools and two authorization profiles, with synthetic test data only.

| Phase | Work | Acceptance evidence |
|---|---|---|
| 1 — Baseline | Confirm threat model, tool inventory, identity claims, deployment topology | Written scope and baseline test cases |
| 2 — Integration | Integrate sandbox IdP, gateway, scoped policy and isolated MCP upstream | Repeatable authorized and unauthorized SDK calls |
| 3 — Adversarial verification | Exercise missing/expired tokens, scope forgery, session crossover, key rotation, audit outage | Test matrix with actual gateway decision and upstream receipt count |
| 4 — Handover | Provide evidence report, configuration, residual risks and deployment recommendation | Reviewable report and live walkthrough or recording |

## Pilot acceptance criteria
1. A valid scoped principal executes an approved tool exactly once.
2. An authenticated principal without the required scope receives a denial and the upstream receipt counter does not increase.
3. Invalid signature, expired token, and cross-principal session reuse cannot execute the protected tool.
4. Audit sink write failure prevents upstream execution.
5. All claims are tied to a commit, CI run, environment configuration, and reproducible test logs.
6. Any SDK incompatibility or unsupported MCP feature is documented as an open issue, not represented as supported.

## Commercial structure — proposed, not agreed
- **Fee:** to be agreed after reviewing Kamal's target MCP server and integration requirements; paid fixed-scope pilot preferred.
- **Payment:** proposed 50% at kickoff, 50% upon delivery of agreed evidence package.
- **Exclusions:** production SLA, SOC monitoring, regulatory certification, managed hosting, unrestricted MCP protocol support, penetration-test certification, or deployment with live customer data.
- **Change control:** additional tools, IdPs, transports, security controls and production deployment require separate scope and pricing.

## Inputs required from Kamal
- Target MCP server or sanitized sandbox endpoint, tool list and expected permitted/denied actions.
- Sandbox IdP details (issuer, audience, JWKS discovery), or approval to use a synthetic issuer.
- Non-production hosting constraints, data handling restrictions, and a technical acceptance contact.
- Confirmation of the pilot's commercial sponsor and budget range.

## Risks and release gates
- Complete Streamable HTTP behavior (including SSE, lifecycle termination and resumability) remains outside this narrow tested subset.
- Centralized tamper-evident audit, rate limiting, SSRF controls, TLS deployment, monitoring, secret management and operational recovery remain release gates.
- JWKS rotation failure currently denies tokens until a successful refresh; production availability behavior requires design review.
- A production deployment needs a security review, infrastructure plan, operational runbook and formal acceptance.

## Links
- Technical demo: `docs/mcp-security-proof/KAMAL_DEMO.md`
- Gateway: `backend/src/bin/mcp_gateway.rs`
- Official SDK probe: `docs/mcp-security-proof/mcp_sdk_probe.py`
- Passing CI: https://github.com/okamoto-security-labs/Vortex-DFS/actions/runs/40776236068

**Suggested positioning:** “A paid, tightly scoped MCP runtime authorization pilot with reproducible evidence that unauthorized tool calls never reach the protected upstream in the tested scenarios.”
