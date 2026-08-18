# ADR-0001: Separate Evidence, Authority, and Consequence

**Status:** Proposed

## Context

Earlier DFS experiments combined multiple security dimensions into a single scalar score.

Those dimensions included:

- signal / risk characteristics;
- telemetry completeness;
- behavioral coherence;
- reversibility;
- approval state;
- environment risk;
- execution authority.

This created semantic ambiguity.

For example, some DFS components interpreted a higher score as greater trust and therefore greater autonomy, while other components interpreted a higher score as greater risk and therefore stronger restrictions.

Runtime authorization should not depend on a scalar that mixes evidence quality, authority, and consequence.

### Historical Rationale

This separation is informed by earlier Detection Fidelity Score (DFS)
experiments.

DFS originated as a methodology for measuring whether detection capability
survives transformations of its underlying evidence. The model later evolved
to connect signal degradation with a Trust Decision Boundary and, subsequently,
with the actions a decision could authorize.

Later runtime experiments introduced explicit agent authorization, scoped
resources, temporal constraints, single-use authorization, circuit breaking,
and pre-execution enforcement.

Those experiments exposed an architectural limitation: evidence quality,
behavioral coherence, action risk, reversibility, and execution authority had
progressively become coupled through scalar decision logic.

Vortex retains the useful runtime primitives while separating their semantics.

Evidence describes what supports a decision.

Authority describes what an actor is permitted to do.

Consequence describes what can happen if the permitted action is wrong.

These properties may influence policy together, but they are not
interchangeable and must not manufacture one another.

## Decision

Vortex will model these as independent security planes.

### Evidence Plane

Answers:

> What evidence supports this decision, and how reliable is that evidence?

Possible properties:

- origin;
- provenance;
- integrity;
- completeness;
- behavioral coherence;
- telemetry quality.

Evidence may inform a decision.

Evidence does not grant authority.

### Authority Plane

Answers:

> Is this principal authorized to perform this specific action on this specific resource under the current constraints?

Possible properties:

- agent / principal identity;
- delegated authority;
- action scope;
- resource scope;
- environment;
- temporal bounds;
- approval requirements.

Authority must be explicit.

A high-confidence signal must never manufacture execution authority.

### Consequence Plane

Answers:

> If this decision is wrong, what effect can the action produce?

Possible properties:

- reversibility;
- blast radius;
- data sensitivity;
- external side effects;
- financial impact;
- destructive impact.

Consequence does not determine whether evidence is true.

It determines how much certainty and authority policy should require before execution.

### Policy Decision

The policy engine consumes these independent planes and produces an explicit decision.

Conceptually:

```text
Evidence
    \
Authority ----> Policy ----> ALLOW | REVIEW | DENY
    /
Consequence
```

No single aggregate score is required to represent all three dimensions.

## Security Principles

1. Evidence may support a decision, but evidence does not grant authority.
2. Authority must be explicit and scoped to the requested action and resource.
3. Missing authority must fail closed.
4. Consequence must remain independent from evidence confidence.
5. Higher-consequence actions may require stronger evidence or explicit approval.
6. Runtime decisions must remain explainable from their individual inputs.
7. Unknown values must remain unknown and must not silently become trusted defaults.
8. A valid authorization does not imply that execution remains safe under the current runtime context.

## Historical Note

This decision incorporates lessons from earlier Detection Fidelity Score experiments.

Those experiments contained useful primitives such as:

- pre-execution evaluation;
- scoped authorization;
- time-bounded and single-use capability concepts;
- reversibility;
- blast radius;
- runtime circuit breaking;
- audit chaining.

The primitives remain useful.

The architectural change is to stop compressing them into one scalar trust/risk score.

## Consequences

### Positive

- Clear semantics.
- Easier policy reasoning.
- Easier testing.
- Better auditability.
- Fewer contradictory thresholds.
- Easier integration with external identity and policy systems.

### Negative

- More explicit state must be carried through the runtime.
- Policies become multidimensional instead of threshold-only.
- Migration from score-based logic requires deliberate refactoring.

## Non-Goals

This ADR does not define:

- a final consequence taxonomy;
- a global risk score;
- an intent inference model;
- a specific IAM provider;
- a specific policy language.

Those decisions belong in separate ADRs.
