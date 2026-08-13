# Vortex DFS

<p align="center">

![Status](https://img.shields.io/badge/Status-Experimental%20Pre--alpha-orange)
![Runtime](https://img.shields.io/badge/Runtime-Execution%20Gate-important)
![Tests](https://img.shields.io/badge/Backend%20Tests-86%20passing-success)
![Decision](https://img.shields.io/badge/Decision-Explicit-important)

</p>

> Verify before execution.

**Vortex DFS** is an open-source deterministic runtime for evaluating policy and evidence before protected execution.

The runtime decides.  
The adapter executes only when policy permits.

---

The backend currently implements four outcomes:
Outcome
Meaning
ALLOW
The operation satisfies policy and may proceed.
REJECT
A required condition failed; the executor is not invoked.
REDACT
Sensitive data requires transformation before execution or disclosure.
AUDIT
The operation may proceed with an explicit audit-required decision.
The execution gate is tested: a REJECT cannot invoke the protected executor, while a permitted REDACT can invoke it.
Latest local validation:
83 backend library tests passed
3 HTTP handler tests passed
0 failures
These tests validate runtime behavior. They are not a latency, throughput, or production-security certification.
What Vortex does
Vortex evaluates a request against explicit runtime policy before allowing an action to execute.
Instead of asking:
Is this probably safe?
Vortex asks:
Does this request satisfy the policy required for this operation?
The goal is not to make AI systems more intelligent.
The goal is to make automated execution more trustworthy.
Where Vortex fits
Technology
Primary responsibility
SIEM
Collect, normalize, and correlate security events
EDR
Monitor and protect endpoints
SOAR
Execute automated playbooks
AI agents
Generate recommendations and proposed actions
Policy engines
Define organizational rules
Vortex DFS
Evaluate whether a protected action satisfies runtime policy before execution
Vortex sits between intelligence and execution.
AI agent / application / workflow
                │
                ▼
        Vortex DFS Runtime
                │
                ▼
ALLOW / REDACT / AUDIT ──────► Protected execution
                │
                └────────────► REJECT: execution blocked
Implemented runtime flow
Input
  │
  ▼
Request normalization
  │
  ▼
Evidence collection
  │
  ▼
Runtime policy evaluation
  │
  ▼
Validation and reason-code generation
  │
  ▼
RuntimeDecision
  │
  ├── ALLOW
  ├── REJECT
  ├── REDACT
  └── AUDIT
  │
  ▼
Guarded execution
The runtime returns structured decision data, including:
outcome;
stable reason code;
policy identifier and version;
evidence summary;
trust band when applicable;
decision latency;
request and trace identifiers.
Runtime guarantees implemented today
Deterministic runtime evaluation
Explicit policy enforcement
Stable machine-readable reason codes
Evidence-driven decisions
Fail-closed rejection behavior
Structured runtime decisions
Policy identifiers and versions included in decisions
Execution gate that prevents a rejected request from reaching its executor
Current HTTP example
The anonymization handler builds a RequestContext, records evidence, evaluates policy, and only then calls the anonymizer.
Empty content
  → structural evidence fails
  → REJECT
  → anonymizer is not called

Sensitive content
  → sensitive-data evidence detected
  → REDACT
  → anonymizer executes after authorization
What is not implemented yet

The following are roadmap items, not current production guarantees:
Persistent or immutable audit storage
Production identity and authentication enforcement in the HTTP path
External policy bundles and policy administration
Production Tool Runner integration
Production Agent SDK adapter
End-to-end eBPF-to-runtime enforcement
Reproducible hardware-level latency benchmarks
Independently reviewed post-quantum cryptography

## Experimental components
--
LWE signer

signer_lwe.rs is a toy-scale experimental LWE implementation used for research and testing.
It is not production post-quantum cryptography.
Do not rely on it for real cryptographic protection. Production use should migrate to a reviewed PQC implementation such as ML-DSA/Dilithium through an appropriate library.

### eBPF/XDP

The vortex-ebpf component is an experimental low-level network enforcement prototype.
It is separate from the userspace runtime execution path.

It must not be described as:
zero-overhead security;
guaranteed sub-microsecond enforcement;
end-to-end agent authorization;
complete kernel-to-runtime integration.

Those claims require reproducible benchmarking on the target kernel, NIC, driver, packet profile, and policy.

### Auditability

The runtime produces an audit-ready structured decision.
Adapters can record:
outcome;
reason code;
policy reference;
evidence summary;
trace identifier;
latency.
A durable audit sink, immutable retention, compliance exports, and governance dashboards are not included yet.

Development

Run backend tests:
´´´
cargo test --manifest-path backend/Cargo.toml
Check formatting:
´´´
´´´
cargo fmt --manifest-path backend/Cargo.toml --check
´´´
Run static analysis:
´´´
cargo clippy --manifest-path backend/Cargo.toml -- -D warnings
´´´
The backend CI workflow validates Cargo checks, Clippy, and tests for pushes and pull requests to main.

eBPF builds require a separate nightly Rust toolchain and bpf-linker.

### Project direction

Vortex DFS is building a deterministic authorization boundary for systems that need to act on data, policies, and automated decisions.
Its core thesis is simple:

Automation without trust is simply faster uncertainty.
Vortex does not replace SIEM, EDR, SOAR, AI agents, or policy engines.
It provides a place to verify whether a protected action should execute.

### Contributing

Contributions are welcome, especially for:
runtime policies;
test coverage;
benchmarks;
audit adapters;
Tool Runner integrations;
Agent SDK integrations;
observability;
security review;
documentation.
Before opening a pull request:
keep behavior deterministic;
add tests for security invariants;
update documentation;
avoid claiming roadmap features as implemented;
run the backend test suite.

### License

See LICENSE.
Vortex doesn't guess. It computes.
## Current status

Vortex DFS is an **experimental pre-alpha** with a working protected execution path for anonymization:

```text
HTTP request
  → RequestContext
  → Evidence
  → RuntimePolicy
  → RuntimeDecision
  → Execution Gate
  → Anonymizer only when permitted

