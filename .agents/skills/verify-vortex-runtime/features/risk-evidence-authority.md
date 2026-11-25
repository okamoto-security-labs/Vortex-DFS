# Risk evidence alone does not grant or revoke authority

## Sub-features

A risk score is evidence considered by the runtime; it is not itself an authorization credential.

## How to get to it (user POV)

A structurally valid request has a high risk score while the policy's other required conditions are satisfied.

## Driving it with the Rust test harness

Run:

```bash
cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance risk_signal_must_not_become_execution_authority
```

The test uses a high risk score without turning that score into identity, scope, or trust authority.

## Observable proof

The test checks the scenario's expected decision and confirms that this evidence by itself does not prevent execution.

## Gotchas

This is one policy behavior under the test's stated inputs. It is not evidence that all high-risk requests should be allowed or that risk scoring is unnecessary.
