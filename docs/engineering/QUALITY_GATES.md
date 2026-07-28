# Vortex Engineering Review Policy

Version: 1.0
Status: Active

---

# Purpose

This document defines the engineering review policy for the Vortex project.

Its purpose is to preserve deterministic behavior, architectural consistency,
security guarantees, and long-term maintainability.

Every pull request is evaluated against this document.

This policy applies equally to:

- Human reviewers
- CodeRabbit
- AI assistants
- External contributors
- Repository maintainers

---

# Engineering Principles

Every contribution must preserve:

- Deterministic behavior
- Explicit security decisions
- Stable public behavior
- Backward compatibility when applicable
- Small and reviewable changes
- Clear documentation

The burden of proof belongs to the change.

A pull request should demonstrate that it improves or preserves existing guarantees.

---

# Runtime Invariants

The runtime is the primary security boundary of Vortex.

The following invariants are mandatory.

## Request processing

Every request must follow the documented runtime pipeline.

Request

↓

RequestContext

↓

RuntimePolicy

↓

RuntimeValidator

↓

RuntimeDecision

↓

Execution

↓

Audit

No component may bypass this pipeline.

---

## Determinism

Equal inputs

+

Equal RuntimePolicy

↓

Equal RuntimeDecision

Runtime behavior must never depend on:

- HashMap iteration
- Random ordering
- Undefined state
- Timing side effects

---

## Fail Closed

Missing security evidence must never become successful validation unless the active RuntimePolicy explicitly allows fail-open behavior.

Fail-open is always an explicit policy decision.

---

## Evidence Integrity

Unknown

Unavailable

False

True

are four distinct security states.

They must never be silently merged.

---

## Decision Integrity

Every denial must include:

- stable reason code
- policy context
- sufficient audit context

Human-readable messages are supplementary.

Machine-readable reason codes are authoritative.

---

# Automatic Request Changes

The following findings require Request Changes.

## Runtime

- Validation bypass
- Runtime bypass
- Policy bypass
- Audit bypass
- Missing reason codes
- Nondeterministic decisions
- Silent behavior changes

---

## Rust

Reachable production code containing:

- unwrap()
- expect()
- panic!()
- todo!()
- unreachable!()

requires explicit justification.

unsafe requires:

- documented invariant
- dedicated tests
- reviewer approval

---

## Cryptography

Reject:

- custom production cryptography
- insecure randomness
- hard-coded secrets
- production claims without evidence

Research implementations must remain clearly identified.

---

## Tests

Every change requires tests appropriate for its risk.

Security fixes require regression tests.

New runtime behavior requires:

- positive path
- negative path
- boundary conditions

Changes affecting determinism require repeated execution tests.

---

# Documentation

Architecture changes require updates to:

ARCHITECTURE.md

RUNTIME.md

when applicable.

Documentation must distinguish:

Implemented

Experimental

Planned

---

# CI Requirements

A pull request cannot be merged unless:

✓ cargo fmt

✓ cargo check

✓ cargo clippy -D warnings

✓ cargo test

✓ GitHub Actions

✓ CodeRabbit Review

---

# Review Philosophy

Reviews should focus on:

Correctness

Security

Determinism

Maintainability

Architecture

Reviews should not focus on:

Formatting already enforced by tooling

Personal coding style

Subjective preferences

---

# Project Philosophy

Vortex favors:

Explicit behavior

Small components

Deterministic execution

Security-first engineering

Reviewable architecture

Long-term maintainability

over implementation convenience.

Every pull request should leave the project in a better state than it was found.
