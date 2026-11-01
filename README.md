# Vortex DFS

<p align="center">

![Status](https://img.shields.io/badge/status-experimental%20pre--alpha-orange)
![Runtime](https://img.shields.io/badge/runtime-Rust-black?logo=rust)
![Tests](https://img.shields.io/badge/backend%20tests-200%20passing-success)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

</p>

> Verify before execution.

**Vortex DFS** is an open-source runtime authorization layer for AI agents and other automated systems. It evaluates identity, evidence, authority, policy, and consequences before a protected action reaches its executor.

The runtime decides. The adapter executes only when policy permits.

## Why Vortex exists

An agent proposing an action is not the same as that agent being authorized to perform it. A risk signal is not permission, and a successful plan is not proof that execution is safe.

Vortex makes that boundary explicit:

```text
agent / application / workflow
              │
              ▼
     normalized request context
              │
              ▼
 identity + evidence + policy + consequence
              │
              ▼
       Vortex RuntimeDecision
       ├── ALLOW  ─────────────► execute
       ├── REDACT ─────────────► transform, then execute
       ├── AUDIT  ─────────────► record, then execute
       └── REJECT ─────────────► block
```

Every decision is structured and machine-readable. A rejected request cannot invoke the guarded executor.

## Current status

Vortex DFS is **experimental pre-alpha software**. The repository contains a working Rust runtime, protected HTTP paths, persistent audit support, policy bundle and registry foundations, executable conformance suites, and experimental research components.

Latest local validation on the current `main` branch:

- 200 backend tests passed;
- 0 failed, ignored, or filtered out;
- unit, HTTP, AISVS C9, and runtime-failure conformance suites included.

These results validate the checked-in behavior. They are not a production-security certification, an independent audit, or a latency/throughput guarantee.

## Implemented today

### Runtime decision engine

- deterministic policy evaluation;
- explicit `ALLOW`, `REJECT`, `REDACT`, and `AUDIT` outcomes;
- stable reason codes and policy references;
- typed request, identity, payload, evidence, trust, and consequence contexts;
- fail-closed handling for missing mandatory security state;
- guarded execution that separates evaluation from side effects;
- worst-case consequence composition for derived action chains.

### Identity and authority

- bearer authentication for protected HTTP routes;
- tenant and principal context;
- explicit scope checks;
- API-key proof storage instead of serializing raw credentials into audit events;
- approval, denied-intent, retry, and security-context constraints;
- tenant-isolated audit reads.

### Audit path

- audit events written before permitted execution;
- in-memory storage for tests and PostgreSQL storage for deployed paths;
- paginated and trace-based audit retrieval;
- migration support for runtime audit events and tenant isolation;
- bounded evidence summaries without payload or raw identity disclosure.

Audit storage is persistent when the PostgreSQL-backed path is configured. The project does not yet claim immutable/WORM retention or compliance-ready governance exports.

### Policy distribution foundations

- versioned policy bundles with deterministic digests;
- bundle integrity and metadata validation;
- local policy installation and resolution;
- registry index and version resolution;
- publisher identity and trusted-key foundations;
- a versioned tool-execution policy fixture.

Bundle integrity is implemented. Production-grade publisher authenticity still depends on replacing the experimental signing path with reviewed cryptography and a complete key-management model.

## Executable conformance

Security properties are represented as tests, not only prose.

The [Runtime Failure Conformance Harness](docs/runtime-failure-conformance-harness.md) currently exercises invariants such as:

- missing identity fails closed;
- risk evidence cannot manufacture execution authority;
- degraded approval evidence cannot grant authority;
- denied intent remains constrained;
- a blocked action affects retry state;
- an irreversible derived action reaches the hard execution gate;
- missing or failed security context cannot silently continue.

The [AISVS C9 evaluation](conformance/aisvs-c9/README.md) tests action chains, reversibility, consequence composition, oversight requirements, and fail-closed handling of unclassified effects. External suites are treated as independent inputs; a green test alone is not presented as proof of semantic equivalence.

## Protected HTTP paths

The Actix Web backend includes protected paths for:

- policy evaluation of agent tool execution;
- anonymization with runtime authorization;
- tenant-scoped audit retrieval;
- bounded scanner operations.

Policy installation, registry resolution, provisioning, and key-management foundations are currently exposed through Rust library modules and the `vortex` CLI, not as protected HTTP administration routes.

For example, the anonymization path rejects an empty or invalid request before execution and only invokes transformation after the runtime returns an authorized `REDACT` decision.

## Scanner scope

The repository also contains a gated HTTPS response-header inspector. It checks a small set of defensive headers for exact operator-allowlisted hosts.

It is **not** a vulnerability scanner, CVE detector, pentest engine, or unrestricted public-target scanner. Its deployment requirements, quotas, proxy trust boundary, billing integration, and operational gates are documented in [docs/scanner-deployment.md](docs/scanner-deployment.md).

## Experimental components

### LWE signer

`backend/src/signer_lwe.rs` is a toy-scale research implementation with adversarial and stress tests. It is **not production post-quantum cryptography** and must not protect real keys or production trust decisions.

A production path should use a reviewed implementation of an appropriate standard such as ML-DSA through a maintained cryptographic library.

### eBPF/XDP prototype

`vortex-ebpf/` is an experimental low-level network-enforcement prototype. It is separate from the userspace runtime authorization path and is not an end-to-end kernel-to-runtime enforcement guarantee.

No claim of zero overhead, sub-microsecond enforcement, or production readiness is made without reproducible measurements on the target kernel, NIC, driver, workload, and policy.

## What is not guaranteed yet

- production hardening or independent security review;
- immutable audit retention and compliance exports;
- a complete policy administration control plane;
- production Agent SDK, MCP tool-runner, or SOAR adapters;
- end-to-end eBPF-to-runtime enforcement;
- reviewed production post-quantum cryptography;
- reproducible cross-hardware performance guarantees;
- unrestricted scanner deployment or automated proof of asset ownership.

## Repository map

| Path | Purpose |
|---|---|
| `backend/src/runtime/` | Decision engine, context, evidence, policy, audit, consequence, and execution gate |
| `backend/src/main.rs` | Protected HTTP runtime paths |
| `backend/tests/runtime_failure_conformance.rs` | Executable runtime-failure invariants |
| `backend/tests/aisvs_c9_conformance.rs` | AISVS C9 action-class evaluation |
| `registry/` | Versioned policy registry fixtures |
| `docs/` | Architecture, quality gates, deployment, and operational guidance |
| `publication/` | Runtime Decision Architecture publication |
| `vortex-ebpf/` | Experimental eBPF/XDP prototype |

## Development

Prerequisites: a stable Rust toolchain and the native dependencies required by `sqlx`/PostgreSQL.

```bash
git clone https://github.com/okamoto-security-labs/Vortex-DFS.git
cd Vortex-DFS
```

Run the backend test suite:

```bash
cargo test --manifest-path backend/Cargo.toml
```

Run the same core checks used by CI:

```bash
cargo check --manifest-path backend/Cargo.toml
cargo clippy --manifest-path backend/Cargo.toml -- -D warnings
cargo fmt --manifest-path backend/Cargo.toml --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for engineering principles and pull-request expectations. Security issues should be reported privately according to [SECURITY.md](SECURITY.md).

## Runtime Failure Assessment

Okamoto Security Labs offers a fixed-scope assessment for teams deploying agents with tool or execution authority. The engagement maps failure modes into executable security invariants and tests whether the real execution boundary enforces them.

The pilot covers one agent/runtime workflow, up to 15 failure scenarios, a conformance harness, PASS/FAIL evidence, remediation priorities, and a technical handoff.

Learn more at [vortexdfs.com](https://vortexdfs.com/).

## License and citation

Vortex DFS is available under the [Apache License 2.0](LICENSE). Academic and technical references can use the metadata in [CITATION.cff](CITATION.cff).
