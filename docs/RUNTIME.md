# Vortex-DFS Runtime Architecture

**Status:** Draft  
**Version:** 0.1  
**Project:** Vortex-DFS  
**Organization:** Okamoto Security Labs  

## 1. Purpose

The Vortex runtime defines how requests, payloads, cryptographic
operations, and enforcement decisions move through the platform.

Its purpose is to provide a consistent execution model across different
security capabilities.

These capabilities may include:

- sensitive-data protection;
- cryptographic signing and verification;
- API identity validation;
- deterministic trust evaluation;
- AI-agent action validation;
- userspace enforcement;
- kernel-level policy enforcement.

The runtime is not a single algorithm.

It is the orchestration layer that connects evidence collection,
validation, policy, execution, and audit.

## 2. Core Principle

The Vortex runtime follows one fundamental rule:

> No protected action should execute before its required evidence has
> been validated.

A request must not be considered trustworthy merely because:

- it reached a valid endpoint;
- it contains syntactically valid JSON;
- it was sent by a previously known client;
- it includes a signature;
- it produces a high confidence score;
- it originated from an internal system.

Trust must be derived from current, validated, and relevant evidence.

## 3. Runtime Responsibilities

The runtime is responsible for:

1. receiving a request or execution event;
2. constructing a normalized request context;
3. validating structural and identity requirements;
4. extracting security-relevant evidence;
5. applying policy;
6. evaluating deterministic trust conditions;
7. selecting an enforcement decision;
8. executing or rejecting the requested operation;
9. recording an auditable result.

## 4. Runtime Flow

```text
Request or Execution Event
            |
            v
    Request Context Creation
            |
            v
    Structural Validation
            |
            v
     Identity Validation
            |
            v
    Evidence Extraction
            |
            v
      Policy Evaluation
            |
            v
       Trust Evaluation
            |
            v
   Enforcement Decision
            |
      +-----+-----+---------+
      |           |         |
      v           v         v
    ALLOW       REJECT    REDACT
      |                     |
      v                     v
   Execute               Transform
      |                     |
      +----------+----------+
                 |
                 v
             Audit Event
                 |
                 v
              Response
```

Not every request requires every stage.

The runtime must determine which stages are mandatory according to the
requested operation and active policy.

## 5. Runtime Stages

### 5.1 Request Reception

A request may enter Vortex through:

- an HTTP API;
- an internal service call;
- an AI-agent tool request;
- a message-processing pipeline;
- a gateway;
- an eBPF telemetry event;
- a scheduled security operation.

The entry surface must not define the final security decision.

It only provides the initial event to the runtime.

### 5.2 Request Context Creation

The runtime converts the incoming request into a normalized
`RequestContext`.

The context should contain, where applicable:

- request identifier;
- trace identifier;
- timestamp;
- source address;
- client identity;
- authenticated principal;
- target operation;
- payload metadata;
- content type;
- locale;
- policy identifier;
- runtime version;
- execution environment;
- collected evidence;
- accumulated validation failures.

The request context should remain independent from individual features
such as anonymization or cryptographic verification.

### 5.3 Structural Validation

Structural validation confirms that the request can be processed safely.

It may include:

- body size limits;
- required field validation;
- content-type validation;
- encoding validation;
- numeric bounds;
- array bounds;
- protocol boundary validation;
- malformed payload rejection;
- unsupported operation rejection.

Structural validation occurs before high-cost or security-sensitive
processing.

A structurally invalid request should normally fail closed.

### 5.4 Identity Validation

Identity validation determines who or what is requesting the operation.

Evidence may include:

- API keys;
- cryptographic credentials;
- hardware registration;
- service identity;
- workload identity;
- signed tokens;
- session identity;
- device identity.

A valid identity does not automatically imply permission.

Identity validation answers:

> Who is making the request?

Policy evaluation answers:

> Is this identity allowed to perform this action?

### 5.5 Evidence Extraction

The runtime extracts evidence relevant to the requested operation.

Examples include:

- presence of sensitive information;
- anonymization detections;
- payload integrity;
- signature validity;
- key status;
- algorithm status;
- replay indicators;
- trust metrics;
- runtime telemetry;
- protocol metadata;
- objective-fidelity signals;
- agent tool-request metadata.

Evidence must be represented using named fields.

Opaque positional arrays should not be used when a named structure can
express the same information more clearly.

### 5.6 Policy Evaluation

Policy determines which conditions must be satisfied.

Policy may define:

- required authentication;
- allowed operations;
- required signature algorithms;
- minimum trust band;
- maximum payload size;
- mandatory anonymization;
- fail-open or fail-closed behavior;
- audit requirements;
- rate limits;
- kernel enforcement behavior;
- AI-agent tool permissions.

Policy must remain separate from the mechanisms that collect evidence.

For example:

- cryptographic code verifies a signature;
- policy decides whether that signature type is acceptable;
- the trust engine evaluates the resulting evidence;
- the enforcement layer applies the final decision.

### 5.7 Trust Evaluation

The trust engine converts validated evidence and policy requirements
into a deterministic result.

The same:

- evidence;
- policy;
- runtime configuration;
- system state;

must produce the same trust result.

The current project uses the following trust bands:

- `HighTrust`
- `Operational`
- `Fragile`
- `Critical`

These bands must not be treated as vague labels.

Each band must have:

- documented thresholds;
- documented evidence requirements;
- documented enforcement meaning;
- reproducible tests;
- versioned policy behavior.

### 5.8 Enforcement Decision

The runtime produces an explicit decision.

Supported conceptual decisions include:

- `ALLOW`
- `REJECT`
- `REDACT`
- `AUDIT`

Future decisions may include:

- `QUARANTINE`
- `CHALLENGE`
- `DEFER`
- `RATE_LIMIT`

New decisions must have precise operational semantics.

### 5.9 Execution

Execution occurs only after mandatory validation and enforcement stages
have completed.

Execution may invoke:

- the anonymizer;
- a signing operation;
- signature verification;
- crypto-agility analysis;
- key provisioning;
- hardware registration;
- an AI-agent tool;
- a userspace policy action;
- an eBPF map update.

The runtime should not mix feature implementation with decision logic.

### 5.10 Audit

Every security-relevant decision should produce an audit event where
appropriate.

An audit event should contain:

- event identifier;
- trace identifier;
- timestamp;
- operation;
- decision;
- reason code;
- identity;
- policy identifier;
- evaluated evidence;
- trust result;
- execution result;
- latency;
- runtime version.

Audit records should avoid storing raw sensitive content unless
explicitly required.

Sensitive values should be:

- redacted;
- hashed;
- tokenized;
- summarized;
- excluded.

## 6. Request Context

A future Rust representation may follow this conceptual structure:

```rust
pub struct RequestContext {
    pub request_id: String,
    pub trace_id: String,
    pub timestamp_ms: u64,
    pub operation: Operation,
    pub identity: Option<IdentityContext>,
    pub payload: PayloadContext,
    pub policy_id: Option<String>,
    pub evidence: SecurityEvidence,
    pub failures: Vec<ValidationFailure>,
}
```

This structure is illustrative.

The implementation may use UUIDs, compact identifiers, borrowed values,
or strongly typed wrappers.

The important requirement is architectural:

> Feature handlers should not independently recreate security context.

## 7. Security Evidence

Security evidence should use named fields.

A conceptual representation may include:

```rust
pub struct SecurityEvidence {
    pub structural_validity: bool,
    pub identity_verified: bool,
    pub payload_integrity_valid: Option<bool>,
    pub signature_valid: Option<bool>,
    pub sensitive_data_detected: Option<bool>,
    pub replay_detected: Option<bool>,
    pub trust_metrics: Option<TrustMetrics>,
    pub runtime_signals: Vec<RuntimeSignal>,
}
```

Evidence fields should distinguish:

- `false`;
- not evaluated;
- unavailable;
- unsupported;
- failed evaluation.

A missing signal must not silently become a successful result.

## 8. Policy Model

Policy should be versioned and explicit.

A conceptual policy may include:

```rust
pub struct RuntimePolicy {
    pub id: String,
    pub version: String,
    pub required_identity: bool,
    pub require_signature: bool,
    pub require_anonymization: bool,
    pub minimum_trust_band: TrustBand,
    pub fail_closed: bool,
    pub audit_required: bool,
}
```

Policies should be loaded independently from feature implementations.

The same runtime component should be able to apply different policies to
different operations.

## 9. Decision Model

A decision should contain more than a boolean.

A conceptual representation may include:

```rust
pub struct RuntimeDecision {
    pub outcome: DecisionOutcome,
    pub reason_code: DecisionReason,
    pub trust_band: Option<TrustBand>,
    pub policy_id: String,
    pub evidence_summary: EvidenceSummary,
    pub latency_us: u64,
}
```

A boolean such as `valid: true` may still be returned by a specialized
endpoint, but internally the runtime should preserve the complete
decision context.

## 10. Reason Codes

Human-readable text may change.

Machine-readable reason codes should remain stable and testable.

Examples:

```text
STRUCTURE_INVALID
IDENTITY_MISSING
IDENTITY_INVALID
POLICY_DENIED
SIGNATURE_INVALID
KEY_REVOKED
PAYLOAD_INTEGRITY_FAILED
SENSITIVE_DATA_REDACTED
TRUST_BELOW_THRESHOLD
REPLAY_DETECTED
RUNTIME_ERROR
OPERATION_ALLOWED
```

A decision may contain both:

- a stable reason code;
- a human-readable explanation.

## 11. Failure Model

The runtime should classify failures.

### 11.1 Client Failure

Examples:

- malformed request;
- unsupported content type;
- missing required field;
- invalid identity;
- invalid signature.

### 11.2 Policy Failure

Examples:

- operation not allowed;
- trust below required threshold;
- forbidden algorithm;
- mandatory anonymization not performed.

### 11.3 Runtime Failure

Examples:

- unavailable key store;
- policy loading failure;
- internal execution error;
- audit sink unavailable;
- eBPF map update failure.

### 11.4 Security Failure

Examples:

- replay detected;
- tampering detected;
- revoked key;
- integrity violation;
- objective-fidelity violation.

The runtime must avoid exposing unnecessary internal details to
untrusted clients.

Detailed failure evidence may be recorded internally while the external
response remains limited.

## 12. Fail-Closed and Fail-Open Behavior

Mandatory security controls should normally fail closed.

Examples include:

- required identity validation;
- required signature verification;
- payload boundary validation;
- revoked-key checks;
- mandatory policy loading.

Some telemetry or non-blocking audit operations may fail open when policy
explicitly permits it.

Fail-open behavior must never be implicit.

It must be:

- documented;
- policy-controlled;
- observable;
- tested.

## 13. Current Backend State

The current backend entrypoint exposes:

- `GET /health`
- `POST /benchmark/anonymize`
- `GET /benchmark/pqc/verify`

The current flow is:

```text
HTTP Request
     |
     v
Actix Handler
     |
     v
Direct Feature Invocation
     |
     v
JSON Response
```

The anonymization benchmark directly invokes:

```text
AnonymizerEngine::anonymize
```

The PQC verification benchmark directly invokes:

```text
keygen
   |
   v
sign
   |
   v
verify
```

The current backend entrypoint does not yet implement:

- a shared request context;
- centralized structural validation;
- centralized identity validation;
- centralized policy evaluation;
- a unified trust-engine call;
- a complete decision object;
- centralized audit events.

This is not inherently incorrect for a benchmark server.

It means the current entrypoint should be documented as a benchmark and
development surface rather than the complete Vortex runtime.

## 14. Benchmark Runtime

Benchmark endpoints have different goals from production endpoints.

They measure specific operations while minimizing unrelated overhead.

Benchmark handlers may bypass parts of the production runtime when the
benchmark methodology explicitly requires it.

This distinction must be clear:

```text
Production Runtime
------------------
Validation
Identity
Policy
Trust
Execution
Audit

Benchmark Runtime
-----------------
Controlled Input
Measured Operation
Latency Result
```

Benchmark results must state what is included and excluded from the
measurement.

For example, anonymization latency may exclude:

- network latency;
- authentication;
- database access;
- audit persistence;
- policy loading.

## 15. Production Runtime Target

The target production flow is:

```text
HTTP Request
     |
     v
RequestContext
     |
     v
Validator
     |
     v
Identity Provider
     |
     v
Evidence Extractors
     |
     v
Policy Engine
     |
     v
Trust Engine
     |
     v
Decision Engine
     |
     +---------------------+
     |                     |
     v                     v
Feature Executor        Rejection
     |
     v
Audit Sink
     |
     v
HTTP Response
```

## 16. Proposed Module Structure

A future module layout may be:

```text
backend/src/
|
+-- runtime/
|   |
|   +-- mod.rs
|   +-- context.rs
|   +-- operation.rs
|   +-- evidence.rs
|   +-- validator.rs
|   +-- identity.rs
|   +-- policy.rs
|   +-- trust.rs
|   +-- decision.rs
|   +-- executor.rs
|   +-- audit.rs
|   +-- error.rs
|
+-- api/
|   |
|   +-- health.rs
|   +-- anonymize.rs
|   +-- pqc.rs
|   +-- benchmark.rs
|
+-- anonymizer_engine.rs
+-- signer_lwe.rs
+-- pqc_endpoints.rs
+-- key_store.rs
+-- provisioner.rs
+-- hardware_register.rs
```

This is a target structure, not a requirement to refactor everything at
once.

## 17. Runtime Boundaries

The runtime should orchestrate components without absorbing their
internal implementation.

### Runtime Owns

- request lifecycle;
- security context;
- policy selection;
- trust evaluation;
- decision creation;
- audit coordination;
- feature dispatch.

### Feature Components Own

- anonymization logic;
- signature generation;
- signature verification;
- key operations;
- crypto-agility inspection;
- hardware registration;
- specialized protocol processing.

### Kernel Components Own

- verifier-compatible packet parsing;
- compact policy lookup;
- bounded telemetry;
- low-level pass or drop enforcement.

## 18. eBPF Integration Model

The eBPF component should not attempt to implement the complete runtime.

The preferred architecture is:

```text
Packet or Kernel Event
          |
          v
       eBPF/XDP
          |
          +------> Lightweight Telemetry
          |                 |
          |                 v
          |          Userspace Runtime
          |                 |
          |                 v
          |          Policy Evaluation
          |                 |
          |                 v
          +<-------- eBPF Policy Map
          |
          v
      PASS / DROP
```

Userspace should perform:

- complex policy evaluation;
- trust scoring;
- cryptographic operations;
- persistent audit;
- policy distribution.

The kernel should perform:

- bounded parsing;
- compact lookups;
- immediate enforcement;
- lightweight event emission.

## 19. AI-Agent Runtime Model

A future AI-agent request may follow this flow:

```text
Agent Objective
       |
       v
Tool Request
       |
       v
Identity and Session Validation
       |
       v
Objective-Fidelity Evidence
       |
       v
Tool Policy Evaluation
       |
       v
Deterministic Trust Evaluation
       |
       v
ALLOW / REJECT / REDACT / AUDIT
       |
       v
Tool Execution
```

The runtime must not trust the agent's own explanation as sufficient
evidence.

Agent evidence may include:

- original objective;
- current action;
- requested tool;
- requested arguments;
- data sensitivity;
- delegation depth;
- policy scope;
- cryptographic identity;
- prior execution state.

## 20. Runtime Invariants

The runtime should enforce the following invariants.

### Invariant 1

No mandatory validation stage may be skipped without an explicit policy.

### Invariant 2

No execution may occur after a `REJECT` decision.

### Invariant 3

A decision must identify the policy used to produce it.

### Invariant 4

Unavailable mandatory evidence must not be interpreted as valid
evidence.

### Invariant 5

The same validated evidence and policy must produce the same
deterministic decision.

### Invariant 6

Experimental components must not silently become production security
boundaries.

### Invariant 7

Sensitive raw payloads must not be written to audit logs by default.

### Invariant 8

Kernel enforcement logic must remain bounded and verifier-friendly.

## 21. Testing Strategy

Runtime tests should include:

### Unit Tests

- structural validation;
- identity decisions;
- policy evaluation;
- trust thresholds;
- reason codes;
- evidence handling.

### Integration Tests

- endpoint-to-decision flow;
- anonymization with audit;
- verification with policy;
- rejected request behavior;
- missing evidence behavior.

### Determinism Tests

The same input and policy should produce identical:

- decision outcome;
- reason code;
- trust band;
- evidence summary.

Timing fields and generated identifiers may differ.

### Adversarial Tests

- malformed payloads;
- oversized input;
- invalid signature;
- replayed request;
- revoked key;
- policy bypass attempt;
- missing mandatory evidence;
- conflicting evidence;
- sensitive audit content.

### Kernel Integration Tests

- packet boundary validation;
- policy-map lookup;
- pass behavior;
- drop behavior;
- userspace map updates;
- telemetry loss behavior.

## 22. Observability

The runtime should expose operational metrics without leaking sensitive
content.

Useful metrics include:

- request count;
- operation count;
- decision count by outcome;
- rejection count by reason code;
- trust-band distribution;
- validation latency;
- execution latency;
- audit latency;
- policy-loading failures;
- eBPF map-update failures.

Metrics should use bounded labels.

Raw identities, payloads, API keys, and unbounded request values must not
be used as metric labels.

## 23. Versioning

Runtime behavior should be versioned.

Versioned elements may include:

- runtime version;
- policy version;
- trust-model version;
- evidence schema version;
- decision schema version;
- audit schema version.

An audit event should provide enough version information to reproduce or
explain the decision later.

## 24. Migration Strategy

The current benchmark server should not be replaced in a single large
refactor.

A safer migration path is:

### Phase 1

Introduce shared runtime types:

- `Operation`
- `RequestContext`
- `SecurityEvidence`
- `RuntimeDecision`
- `DecisionOutcome`
- `DecisionReason`

### Phase 2

Wrap the anonymization benchmark with a minimal runtime flow.

### Phase 3

Wrap PQC verification with the same decision model.

### Phase 4

Introduce policy evaluation.

### Phase 5

Extract production and benchmark route modules.

### Phase 6

Add centralized audit.

### Phase 7

Connect userspace policy decisions to eBPF maps.

## 25. First Implementation Target

The first runtime integration should use the anonymization endpoint.

It has a simple execution path and does not require key storage.

Target flow:

```text
AnonymizeRequest
       |
       v
RequestContext
       |
       v
Structural Validation
       |
       v
AnonymizerEngine
       |
       v
SecurityEvidence
       |
       v
RuntimeDecision
       |
       v
Audit Event
       |
       v
HTTP Response
```

This initial implementation should preserve the existing benchmark
metrics while introducing the shared runtime types.

## 26. Documentation Rule

Any component described as part of the Vortex runtime must be classified
as one of:

- implemented;
- partially implemented;
- experimental;
- planned.

Documentation must not present target runtime flows as current production
behavior.

The current backend entrypoint is an implemented benchmark server.

The unified deterministic runtime described in this document is a target
architecture under active development.
