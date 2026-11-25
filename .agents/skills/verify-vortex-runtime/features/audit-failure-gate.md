# Audit failure prevents the executor

## Sub-features

A request requiring a persisted audit record must stop if the audit store fails.

## How to get to it (user POV)

A permitted request reaches the runtime while the required audit service is unavailable.

## Driving it with the Rust test harness

Run:

```bash
cargo test --manifest-path backend/Cargo.toml audit_failure_prevents_executor_invocation
```

The test supplies a failing in-memory audit-store implementation and an executor closure that records whether it was called.

## Observable proof

The assertions require the audit call to return an error and the executor flag to remain false.

## Gotchas

This is a unit test of the runtime gate using a deliberately failing test double. It does not establish PostgreSQL availability, durability, or deployed-service behavior.
