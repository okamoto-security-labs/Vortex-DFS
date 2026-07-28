# Vortex DFS

> **Deterministic runtime security for AI systems.**
>
> *Vortex doesn't guess. It computes.*

## Overview

Vortex DFS is an open-source runtime focused on deterministic
validation, policy-driven security decisions, evidence integrity and
post-quantum security.

## Engineering Principles

-   Deterministic Runtime
-   Fail-Closed Validation
-   Stable Reason Codes
-   Evidence-Based Decisions
-   Runtime Isolation
-   Security-First Architecture
-   Architecture Decision Records (ADRs)
-   CI-Enforced Quality Gates
-   Automated Engineering Review (CodeRabbit)

## Why Vortex?

Instead of asking "Is this probably malicious?", Vortex asks "Does this
request satisfy the active runtime policy?"

## Runtime Pipeline

Client ↓ Gateway ↓ RequestContext ↓ RuntimePolicy ↓ RuntimeValidator ↓
RuntimeDecision ↓ Audit ↓ Response

## Security Guarantees

-   Deterministic execution
-   Fail-closed semantics
-   Stable reason codes
-   Runtime isolation
-   Evidence integrity
-   Auditable decisions

## Engineering

The project follows documented engineering governance.

-   docs/engineering/REVIEW_POLICY.md
-   docs/engineering/QUALITY_GATES.md
-   docs/adr/

CI:

-   cargo fmt
-   cargo check
-   cargo clippy
-   cargo test
-   GitHub Actions
-   CodeRabbit

## Roadmap

-   Stable Runtime API
-   crates.io publication
-   Independent security audit
-   Property testing
-   Fuzzing
-   Benchmarks

## Philosophy

Vortex favors explicit behavior, deterministic execution, security-first
engineering, reviewable architecture and long-term maintainability.

Every pull request should leave the project in a better state than it
found it.

## License

BUSL-1.1

> Vortex doesn't guess. It computes.
