# Vortex Review Policy

Every PR must preserve:

- Determinism

- Fail Closed

- Stable Reason Codes

- Runtime Isolation

- Evidence Integrity

- Auditability

- Backward Compatibility

Every security regression requires Request Changes.

Never approve:

- unwrap()

- panic!()

- unsafe

inside runtime.

Never approve weakening RuntimePolicy.

Never approve undocumented decision changes.

Require regression tests for every security bug.
