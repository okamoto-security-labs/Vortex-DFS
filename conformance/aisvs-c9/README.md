# AISVS C9 Action-Class Conformance Evaluation

This directory records an external semantic evaluation of the Vortex Runtime
Decision Architecture against the AISVS C9 action-class conformance suite.

The external suite is treated as an independent conformance input, not as the
definition of Vortex semantics.

## Evaluation baseline

- Vortex baseline: d919d9ae4c55118e3fcc42e95c77cc8a00c75b41
- External suite baseline: 6c281e2c7c2e1643c399905d6bc47947436fbf16
- External suite: aisvs-c9-action-class-conformance

## Result classes

Each external property is classified as one of:

- ALIGNED
- PARTIALLY_ALIGNED
- ARCHITECTURAL_GAP
- INTENTIONAL_DIFFERENCE
- OUT_OF_SCOPE

A green external test alone is not considered proof of Vortex conformance.
Semantic equivalence must be established explicitly.
