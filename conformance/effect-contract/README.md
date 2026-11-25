# Vortex Effect Contract Harness

Status: **v0.1 / experimental**

## The problem

An agent can lose the response to a state-changing tool call after the remote service has committed the effect. A timeout is therefore not proof that the operation failed. Retrying may duplicate a charge, deployment, account change, or publication.

MCP tool annotations such as idempotentHint are descriptive hints, not proof that a server enforces idempotency. This harness makes that trust boundary explicit: a hint never authorizes a retry. The simulator retries only when the synthetic tool contract declares server-enforced idempotency and the same operation key is reused. Otherwise, an uncertain outcome is held for reconciliation.

## Run

Requires Python 3.10+ and only the standard library:

    python3 conformance/effect-contract/run.py
    python3 conformance/effect-contract/run.py --json

The process exits nonzero if any scenario fails. JSON output is intended for CI artifacts or later integration into Vortex evaluation tooling.

## Scenarios

The fixture covers:

- acknowledgement lost after a committed write, with and without a server idempotency guarantee;
- duplicate delivery with and without a server idempotency guarantee;
- unknown timeout outcome, which must be held for reconciliation;
- misleading MCP idempotency hints, which do not change the decision.

The simulator's local operation ledger blocks a duplicate delivery when no server guarantee exists. It does not claim to recover an operation after loss of that ledger or process state.

## Scope and limits

This is a deterministic **synthetic simulator**, not an MCP client, live-server probe, certification, or proof of exactly-once behavior. It does not test vendor APIs, persistence, concurrent requests, key expiry, payload binding, authorization changes, or receipt authenticity. Those need isolated staging fixtures and independent observation of committed effects before any live connector can be assessed.

A production integration would need a durable operation journal, server-defined idempotency scope and retention, operation-key binding to normalized inputs, and an authoritative receipt or reconciliation path. If those guarantees are missing, the safe outcome is to stop automatic execution and surface the uncertainty.

## Relationship to existing Vortex work

This adds a focused side-effect ambiguity fixture beside the [Runtime Failure Conformance Harness](../../docs/runtime-failure-conformance-harness.md). It is complementary to the runtime authorization tests: authorization answers whether an action may begin; this harness examines whether the system may repeat it after an uncertain outcome.

## References

- [MCP tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/): annotations are hints and should be treated as untrusted unless the server is trusted.
- [OWASP MCP Security Testing Guide: resilience abuse](https://github.com/OWASP/MCP-Security-Testing-Guide/blob/main/03.%20MCP%20Threats%20and%20Attack%20Patterns/3.18-resilience-abuse.md): describes controlled tests for retry safety and independently observed committed effects.
- [LIMBO research](https://arxiv.org/abs/2609.29095): evaluates duplicate side effects under agent tool failures and varying tool contracts.
