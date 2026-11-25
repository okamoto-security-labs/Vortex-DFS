# Missing identity must fail closed

## Sub-features

Required identity evidence is absent while the policy allows the operation type.

## How to get to it (user POV)

A request reaches the Vortex authorization boundary for a protected operation without a verified identity.

## Driving it with the Rust test harness

Run:

```bash
cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance missing_identity_must_fail_closed
```

The test constructs a structurally valid request with no identity and an operation policy that otherwise allows `Verify`.

## Observable proof

The assertion checks for the scenario's expected `REJECT` decision and verifies `permits_execution() == false`.

## Gotchas

This test calls the runtime library directly. It does not test HTTP authentication middleware or credential parsing.
