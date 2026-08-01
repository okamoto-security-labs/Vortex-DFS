# Contributing to Vortex DFS

Thank you for contributing to Vortex DFS.

Vortex DFS is not another AI framework.

It is a deterministic runtime authorization layer that decides whether an AI agent is allowed to execute before execution begins.

Our philosophy is simple:

> Runtime first.
> Authorization first.
> Determinism first.

---

# What we value

Every contribution should improve at least one of these areas:

- Runtime authorization
- Trust evaluation
- Policy engine
- Deterministic execution
- Auditability
- Performance
- Developer experience

If it doesn't improve one of these, it probably doesn't belong here.

---

# Areas where contributions are welcome

## Runtime authorization

Review the authorization pipeline.

Examples:

- authorization.rs
- evaluator.rs
- decision.rs
- policy.rs

Questions worth asking:

- Can an execution bypass authorization?
- Are policy decisions deterministic?
- Are edge cases correctly handled?
- Is every decision auditable?

---

## Trust evaluation

Improve how runtime trust is calculated.

Examples:

- Runtime evidence
- Trust signals
- Risk aggregation
- Confidence computation
- Policy profiles

Future milestones will replace static trust values with runtime-derived evidence.

---

## Testing

High-value contributions include:

- Unit tests
- Integration tests
- Benchmark scenarios
- Failure simulations
- Adversarial inputs

Every bug should have a regression test.

---

## Documentation

Help explain:

- Runtime architecture
- Authorization pipeline
- SDK integration
- Enterprise deployment
- Security guarantees

Clear documentation is part of the product.

---

# Coding principles

We prefer:

- Explicit code
- Deterministic behavior
- Small modules
- Strong typing
- Readability over cleverness

Avoid unnecessary abstractions.

---

# Pull Requests

Before opening a PR:

- cargo fmt
- cargo check --all-targets
- cargo test

The CI pipeline must pass.

Every feature should include tests whenever practical.

---

# Security

If you discover a security issue:

Please do not disclose it publicly.

Open a private security report or contact the maintainers directly.

---

# Things we generally avoid

- Breaking public APIs without discussion
- Unnecessary dependencies
- Dead code
- Large refactors without motivation
- AI-generated code submitted without review

---

# Our philosophy

Authorization is not a feature.

Authorization is the first runtime decision.

Everything else comes afterwards.

---

Built by

Okamoto Security Labs
