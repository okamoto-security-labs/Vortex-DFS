# Vortex Runtime Failure Conformance Harness

Status: **v0.1 / experimental**

## Purpose

The Runtime Failure Conformance Harness turns externally observed runtime failure
classes into generalized, reproducible Vortex security invariants.

The harness does **not** copy vendor implementations and does **not** assert that
an external product is vulnerable beyond what a public issue or report states.

The transformation is:

```text
observed failure
    ↓
generalized failure property
    ↓
Vortex scenario
    ↓
runtime invariant
    ↓
executable conformance test
```

## Required scenario fields

Every case contains at least:

- `scenario`
- `preconditions`
- `evidence`
- `authority`
- `proposed_action`
- `derived_actions`
- `expected_decision`
- `invariant`
- `external_reference`

## Design rules

1. **Evidence is not authority.** A detector or classifier produces evidence; it
   does not directly grant or revoke runtime authority.

2. **Declared authority does not automatically propagate.** Derived actions are
   evaluated according to their effective operation and consequence.

3. **Unknown or missing mandatory security state must not become silent
   execution.** Fail-closed behavior must be explicit and testable.

4. **External incidents are references, not dependencies.** Each case must be
   generalized enough to remain valid even if the upstream product changes.

5. **No vendor-specific patches in the harness.** The asset being accumulated is
   the runtime invariant and its reproducible test.

## Initial cases

### `missing_identity_must_fail_closed`

When identity is mandatory but unavailable at execution time, operation
recognition alone cannot create authority. Expected outcome: `REJECT`.

### `derived_actions_must_be_independently_gated`

A declared action may expand into more consequential operations. Effective
reversibility is computed over the action chain and an irreversible derived
operation must reach the hard execution gate. Expected outcome: `REJECT`.

## Running

From `backend/`:

```bash
cargo test --test runtime_failure_conformance
```

## Adding a new failure class

Before adding an external issue as a case:

1. Verify that the public report actually describes the claimed behavior.
2. Extract the general runtime property rather than the vendor-specific bug.
3. State the expected runtime decision.
4. Add the scenario metadata under `backend/tests/runtime_failures/`.
5. Add or extend an executable assertion in
   `backend/tests/runtime_failure_conformance.rs`.
6. Keep the external reference factual and narrowly scoped.

A scenario is not considered mapped until its invariant is executable.
