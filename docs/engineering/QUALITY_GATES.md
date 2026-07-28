# Quality Gates

A change cannot be merged unless all gates pass.

---

## Formatting

✓ cargo fmt

---

## Static analysis

✓ cargo check

✓ cargo clippy -D warnings

---

## Tests

✓ cargo test

---

## Security

✓ CodeRabbit Review

✓ Architecture Review

---

## Documentation

Architecture updated when required.

---

## CI

GitHub Actions green.

---

## Runtime

No weakening of:

- RuntimePolicy

- RuntimeDecision

- RequestContext

- SecurityEvidence

without explicit ADR.
