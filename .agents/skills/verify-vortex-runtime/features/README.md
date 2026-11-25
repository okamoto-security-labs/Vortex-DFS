# Runtime verification feature map

This map links reviewer-facing security claims to executable checks. The source of truth is the test code and the checked-out commit, not this prose alone.

## Verification order

1. [Missing identity](missing-identity.md)
2. [Irreversible derived action](irreversible-derived-action.md)
3. [Audit failure gate](audit-failure-gate.md)
4. [Risk evidence and authority](risk-evidence-authority.md)

Run the complete focused conformance file with:

```bash
cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance
```

Run the audit-gate unit test with:

```bash
cargo test --manifest-path backend/Cargo.toml audit_failure_prevents_executor_invocation
```

## Evidence standard

For each claim, retain the test output, commit SHA, Rust version, and exact command. The focused conformance suite exercises the Rust runtime directly. It does not by itself prove deployed HTTP behavior, production database durability, or a full agent-to-tool integration.
