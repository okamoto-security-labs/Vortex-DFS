---
name: verify-vortex-runtime
description: Reproduce and capture evidence for Vortex DFS runtime authorization invariants before describing the runtime as fail-closed.
---

# Verify the Vortex runtime

Use this skill when preparing a review, demo, or security claim about the runtime authorization boundary. The repository already contains executable conformance tests; this workflow runs the real tests and preserves their output as evidence.

## Scope

This verifies the Rust runtime and its current conformance tests. It does not start the deployed HTTP service, exercise a production database, or certify the system for production. Do not infer end-to-end API behavior from unit or integration tests that call the library directly.

## 1. Inspect the checkout

Run from the repository root:

```bash
git rev-parse --show-toplevel
git rev-parse HEAD
git status --short
rustc --version
cargo --version
cargo metadata --manifest-path backend/Cargo.toml --no-deps --format-version 1 >/dev/null
```

If the Rust toolchain or Cargo metadata check fails, stop and report the exact failure. Do not write a passing result.

## 2. Run the focused runtime checks

The failure-conformance suite covers scenario metadata and runtime decisions:

```bash
cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance
```

The audit-gate check proves that an audit-store error prevents the supplied executor from being called:

```bash
cargo test --manifest-path backend/Cargo.toml audit_failure_prevents_executor_invocation
```

The latter is a unit test in `backend/src/runtime/engine.rs`, not an HTTP or PostgreSQL integration test.

## 3. Preserve the evidence

Run each command with output captured. Example:

```bash
set -o pipefail
evidence_dir="${TMPDIR:-/tmp}/vortex-runtime-evidence-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$evidence_dir"
{
  printf 'commit='
  git rev-parse HEAD
  rustc --version
  cargo --version
  printf '\ncommand: cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance\n'
  cargo test --manifest-path backend/Cargo.toml --test runtime_failure_conformance
} 2>&1 | tee "$evidence_dir/runtime-failure-conformance.log"
```

Capture the audit-gate command in a separate log using the same pattern. Keep logs outside the source tree unless a reviewer explicitly requests a committed report. A failed or skipped test stays failed or skipped in the report; do not convert it into a pass.

## 4. Interpret the result

Use the feature map in `features/README.md` to match each claim to its test and observable assertion. State the tested commit and command. State the limitations alongside any result.

Do not claim that:
- the whole HTTP request path was tested by these library tests;
- `REDACT` proves a particular redaction transformation was correct unless that transformation was separately tested;
- an in-memory audit store proves PostgreSQL durability;
- passing tests are a production certification or an independent security audit.

## 5. Cleanup

The workflow creates only log files under the evidence directory and normal Cargo build artifacts under `backend/target`. Preserve the evidence logs for review. Remove only a temporary evidence directory after its contents have been copied or attached; do not delete test output before a reviewer can inspect it.
