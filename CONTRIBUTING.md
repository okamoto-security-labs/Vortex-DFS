# Contributing to Vortex DFS

Thank you for contributing to Vortex DFS.

Vortex DFS is a deterministic runtime trust and authorization layer for autonomous systems. It evaluates policy and trust **before** an external executor—such as an Agent SDK, workflow engine, service, or tool runner—is allowed to act.

> Trust. Authorize. Execute.

## What we value

A contribution should improve at least one of these areas:

- runtime authorization;
- policy evaluation;
- trust and evidence processing;
- explicit decision semantics;
- auditability and observability;
- performance and reliability;
- developer experience and documentation.

The runtime must remain deterministic, explainable, and safe by default.

## High-value contribution areas

### Runtime authorization

Relevant modules include:

- `src/runtime/authorization.rs`
- `src/runtime/evaluator.rs`
- `src/runtime/decision.rs`
- `src/runtime/policy.rs`

Useful review questions:

- Can execution bypass authorization?
- Are `ALLOW`, `REVIEW REQUIRED`, and `BLOCK` mutually clear?
- Are thresholds and boundary conditions correct?
- Does every result include an explicit reason?
- Does a denied request stop before the executor starts?

### Runtime evidence and dynamic trust

The current integration milestone can use controlled trust inputs for deterministic validation. The roadmap replaces these inputs with evidence derived from runtime context.

Useful contributions include:

- request-context normalization;
- tool-permission evidence;
- policy-profile loading;
- telemetry correlation;
- trust-signal aggregation;
- decision evidence and trace records;
- fail-closed behavior when evidence is incomplete.

### Agent and workflow integrations

Vortex should remain independent from any single executor. Integrations may include:

- Agent SDKs;
- MCP servers and tool runners;
- CI/CD systems;
- workflow engines;
- microservices and serverless workers;
- local or hosted policy gateways.

The executor may depend on Vortex. The Vortex runtime must not depend on executor-specific behavior.

### Testing

Every bug fix should include a regression test whenever practical.

High-value tests include:

- threshold boundary tests;
- authorization bypass attempts;
- malformed or incomplete evidence;
- concurrent authorization requests;
- property-based tests;
- fuzzing;
- integration tests that prove blocked requests never reach execution;
- benchmark reproducibility.

Current core behavior:

```text
score >= 0.90  -> ALLOW
0.60..0.90     -> REVIEW REQUIRED
score < 0.60   -> BLOCK
```

Policy behavior may evolve. Changes to public semantics must be discussed before implementation.

### Documentation

Documentation is part of the security boundary. Contributions are welcome for:

- architecture diagrams;
- authorization-flow examples;
- policy-profile documentation;
- integration guides;
- threat models;
- benchmark methodology;
- deployment and operations guidance.

Do not present roadmap items as completed functionality.

## Development setup

```bash
git clone https://github.com/okamoto-security-labs/Vortex-DFS.git
cd Vortex-DFS

cargo fmt --check
cargo check --all-targets
cargo test
cargo run --release
```

The repository may contain additional Rust packages. Validate the backend separately when your change touches it:

```bash
cargo check --manifest-path backend/Cargo.toml
```

## Pull request workflow

The `main` branch is protected. All changes must go through a pull request and pass the required CI checks.

Before opening a PR:

```bash
cargo fmt
cargo check --all-targets
cargo test
```

A good pull request should contain:

1. a clear problem statement;
2. the architectural intent;
3. a focused implementation;
4. tests or a reason why tests are not applicable;
5. documentation for public behavior changes;
6. benchmark evidence when making performance claims.

Keep PRs small enough to review. Separate refactoring from behavior changes when possible.

## Engineering principles

- **Authorization precedes execution.**
- **Fail closed when required evidence is absent.**
- **Return typed decisions, not ambiguous booleans.**
- **Prefer explicit code over clever abstractions.**
- **Security over convenience.**
- **Readability over premature optimization.**
- **No `unsafe` in critical paths without a documented, reviewed justification.**
- **No new dependency without a concrete need and security review.**
- **No benchmark claim without methodology and reproducible output.**

## What we generally do not accept

- broad refactors without a defined engineering problem;
- breaking public APIs without prior discussion;
- style-only changes that create review noise;
- speculative abstractions with no current consumer;
- hidden fallbacks that silently authorize execution;
- hardcoded secrets or credentials;
- generated code submitted without human review and understanding;
- marketing claims that exceed the implemented behavior.

## Security reporting

Do not publicly disclose a suspected vulnerability before maintainers have had a reasonable opportunity to investigate it.

Use GitHub private vulnerability reporting when available, or contact:

- Email: `gugaokamoto1@gmail.com`
- GitHub: `okamoto-security-labs`
- LinkedIn: `gustavo-okamoto-de-carvalho-ti`

Please include:

- affected revision or commit;
- reproduction steps;
- expected and observed behavior;
- possible impact;
- any suggested mitigation.

## Project philosophy

Identity answers **who**.

Authority answers **what** an actor may do.

Runtime trust answers **whether the action should execute now**.

Vortex DFS exists to make that final decision explicit, deterministic, and auditable.

## Security

Please refer to SECURITY.md for responsible vulnerability disclosure.

Security vulnerabilities should not be disclosed publicly before they have been investigated and resolved.

Built at **Okamoto Security Labs**.
