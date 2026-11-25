# Irreversible derived action reaches the hard gate

## Sub-features

A benign declared operation can expand into a more consequential derived action.

## How to get to it (user POV)

An agent or workflow proposes a permitted operation whose effective action chain includes an irreversible effect.

## Driving it with the Rust test harness

Run:

```bash
cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance irreversible_derived_action_must_reach_execution_gate
```

The test composes the worst-case reversibility of the action chain before evaluating the request.

## Observable proof

The test checks the expected `REJECT` decision, confirms execution is not permitted, and requires the scenario fixture to declare derived actions.

## Gotchas

This test validates the runtime decision path and consequence composition. It does not invoke a real external tool adapter.
