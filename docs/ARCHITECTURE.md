# Vortex-DFS Architecture

**Status:** Draft  
**Version:** 0.1  
**Project:** Vortex-DFS  
**Organization:** Okamoto Security Labs  

## 1. Purpose

Vortex-DFS is a deterministic security runtime designed to protect
AI-facing systems, sensitive data, cryptographic operations, and
machine-to-machine execution paths.

Its core principle is simple:

> Trust must be verified before execution, not inferred after failure.

Vortex does not rely on probabilistic classification as its final
security boundary. It transforms validated signals into explicit,
auditable decisions.

## 2. Mission

Vortex provides deterministic security controls for systems that cannot
afford ambiguous execution.

The platform is designed around four responsibilities:

1. Protect sensitive data before it reaches external systems or models.
2. Verify cryptographic identity and payload integrity.
3. Evaluate operational trust using deterministic rules.
4. Enforce explicit allow, reject, audit, or redact decisions.

## 3. Design Principles

### 3.1 Deterministic Decisions

The same validated input and policy must produce the same decision.

### 3.2 Verify Before Execution

Security checks should occur before a protected action is completed,
whenever technically possible.

### 3.3 Explicit Failure

Invalid, malformed, untrusted, or unverifiable inputs must fail with a
clear and auditable reason.

### 3.4 Minimal Trust Assumptions

Clients, payloads, sessions, cryptographic material, and runtime signals
must not be considered trustworthy by default.

### 3.5 Separation of Mechanism and Policy

Cryptographic verification, data inspection, trust evaluation, and
runtime enforcement are separate responsibilities.

### 3.6 Evidence Over Confidence

A Vortex decision should be explainable through validated evidence,
not only through a confidence score.

## 4. High-Level Architecture

```text
                    [ Client / AI System ]
                              |
                              v
                    [ Vortex API / Gateway ]
                              |
                  +-----------+-----------+
                  |                       |
                  v                       v
        [ Data Protection ]      [ Crypto Verification ]
        PII detection            Sign / Verify / Audit
        Redaction                Key management
                  |                       |
                  +-----------+-----------+
                              |
                              v
                   [ Deterministic Trust ]
                   Signals -> TrustBand
                              |
                              v
                    [ Enforcement Decision ]
                 ALLOW / REJECT / REDACT / AUDIT
                              |
                              v
                  [ Runtime Enforcement Layer ]
                     API / Gateway / eBPF
```

## 5. Architectural Layers

### 5.1 Interface Layer

Exposes the public HTTP API and receives client requests.

Current public services include:

- `/v1/shield/anonymize`
- `/v1/pqc/sign`
- `/v1/pqc/verify`
- `/v1/pqc/audit`

### 5.2 Data Protection Layer

Responsible for detecting and redacting sensitive information before
the content reaches downstream systems.

Primary component:

- `anonymizer_engine.rs`

### 5.3 Cryptographic Layer

Responsible for cryptographic signing, verification, key handling, and
crypto-agility analysis.

Primary components:

- `signer_lwe.rs`
- `pqc_endpoints.rs`
- `key_store.rs`

### 5.4 Trust Evaluation Layer

Transforms validated security signals into deterministic operational
bands and decisions.

Primary component:

- `pqc_core.rs`

Current trust bands:

- `HighTrust`
- `Operational`
- `Fragile`
- `Critical`

The current filename reflects its original PQC context. This component
may later be renamed or extracted into a dedicated trust-engine module.

### 5.5 Enforcement Layer

Applies the final security decision.

Current and experimental enforcement surfaces include:

- HTTP API responses
- Gateway validation
- Request rejection
- Data redaction
- eBPF/XDP packet enforcement

### 5.6 Kernel Runtime Layer

The experimental `vortex-ebpf` component executes at XDP and can inspect
network packets before they enter the normal Linux networking stack.

The current implementation:

- validates Ethernet and IPv4 packet boundaries;
- identifies IPv4 TCP traffic;
- passes unrelated traffic;
- currently drops IPv4 TCP packets that reach the prototype decision path.

This component is experimental and must not yet be represented as a
complete integration with the userspace trust engine.

## 6. Decision Model

A Vortex decision is produced from validated evidence.

```text
Input
  |
  v
Structural Validation
  |
  v
Security Signal Extraction
  |
  v
Cryptographic or Policy Verification
  |
  v
Trust Evaluation
  |
  v
Explicit Decision
```

A decision must contain, where applicable:

- result;
- reason;
- evaluated signals;
- policy or threshold used;
- trace identifier;
- processing latency;
- cryptographic evidence.

## 7. Current Boundaries

Vortex-DFS currently contains production-facing APIs and experimental
research components.

The following distinctions must remain explicit.

### 7.1 Production-Facing Components

- PII anonymization API
- Crypto-agility audit API
- API-key provisioning
- HTTP request controls

### 7.2 Research or Experimental Components

- Toy-scale LWE signature construction
- Physics-derived trust scoring
- eBPF/XDP runtime enforcement
- Full AI-agent objective-fidelity enforcement

Experimental components must not be presented as standardized,
independently audited, or production-grade cryptographic replacements.

## 8. Target Architecture

The long-term architecture connects application security, deterministic
trust evaluation, and low-level enforcement.

```text
AI Agent / Application
          |
          v
     Vortex Gateway
          |
          v
Intent / Identity / Payload Validation
          |
          v
Deterministic Trust Engine
          |
     +----+----+
     |         |
     v         v
 Userspace    Kernel Policy
 Enforcement  eBPF/XDP Maps
     |         |
     +----+----+
          |
          v
ALLOW / REJECT / REDACT / AUDIT
```

The kernel component should remain small and verifier-friendly.

Complex scoring and policy evaluation should occur in userspace, while
eBPF maps may distribute compact enforcement decisions to the kernel.

## 9. Runtime Flow

A protected request should move through the following conceptual flow:

```text
Request
  |
  v
Interface Validation
  |
  v
Payload Inspection
  |
  +----------------------+
  |                      |
  v                      v
Data Protection     Crypto Verification
  |                      |
  +-----------+----------+
              |
              v
      Trust Evaluation
              |
              v
      Enforcement Decision
              |
      +-------+-------+
      |       |       |
      v       v       v
    Allow   Reject   Redact
                      |
                      v
                    Audit
```

Not every request must pass through every component.

For example:

- an anonymization request may not require signature verification;
- a signature verification request may not require PII inspection;
- an eBPF packet decision may use a compact kernel policy instead of the
  complete userspace trust model.

## 10. Trust Model

Vortex assumes that external inputs may be malformed, manipulated,
ambiguous, replayed, or cryptographically invalid.

Trust must be derived from evidence such as:

- valid structural boundaries;
- authenticated API identity;
- valid cryptographic signatures;
- payload integrity;
- policy compliance;
- expected runtime behavior;
- deterministic trust thresholds.

Trust is not permanent.

A previously valid client, key, payload, or session may become untrusted
when its evidence changes or expires.

## 11. Enforcement Decisions

Vortex uses explicit enforcement outcomes.

### `ALLOW`

The request or action satisfies the required validation and policy
conditions.

### `REJECT`

The request or action violates a mandatory structural, cryptographic,
trust, or policy condition.

### `REDACT`

Sensitive content is removed or replaced before the request continues.

### `AUDIT`

The request is inspected and recorded without necessarily blocking its
execution.

Future implementations may introduce additional outcomes, but they must
remain deterministic and clearly documented.

## 12. Kernel and Userspace Responsibilities

The eBPF layer and userspace layer have different responsibilities.

### Kernel Responsibilities

The kernel component should perform small, bounded, verifier-compatible
operations such as:

- packet boundary validation;
- protocol identification;
- compact policy lookup;
- allow or drop enforcement;
- lightweight telemetry emission.

### Userspace Responsibilities

Userspace should perform more complex operations such as:

- cryptographic verification;
- trust scoring;
- policy evaluation;
- API-key validation;
- payload inspection;
- PII anonymization;
- audit record generation;
- eBPF map updates.

The kernel must not contain unnecessary cryptographic or high-complexity
decision logic.

## 13. Security Guarantees

Vortex aims to provide the following properties where supported by the
implemented component:

### 13.1 Deterministic Evaluation

The same validated input, policy, and system state should produce the
same result.

### 13.2 Explicit Rejection

Invalid input should fail closed when a mandatory security condition is
not satisfied.

### 13.3 Auditable Decisions

Security decisions should expose enough evidence to explain why an
action was allowed, rejected, redacted, or audited.

### 13.4 Bounded Processing

Inputs should be validated before potentially unsafe memory access,
parsing, or cryptographic processing.

### 13.5 Separation of Trust Domains

API identity, payload integrity, cryptographic validity, runtime
behavior, and policy compliance must be evaluated as separate forms of
evidence.

These properties describe architectural goals. Each implementation must
document which guarantees are currently enforced and which remain
planned.

## 14. Non-Goals

Vortex is not currently:

- a general-purpose firewall;
- a complete intrusion detection system;
- a replacement for standardized production PQC libraries;
- an autonomous AI model;
- a probabilistic malware classifier;
- a complete agent sandbox;
- a complete endpoint detection and response platform;
- a formally verified operating system security layer.

## 15. Security Limitations

The current project includes experimental and research-oriented
components.

Important limitations include:

- the LWE signature implementation is toy-scale and must not be treated
  as a standardized production PQC primitive;
- trust thresholds require continued validation and documentation;
- the eBPF/XDP component is currently a prototype;
- eBPF enforcement is not yet fully integrated with the userspace trust
  engine;
- objective-fidelity enforcement for AI agents remains a target
  capability;
- security claims require reproducible evidence and independent review.

These limitations must remain visible in technical documentation and
public communication.

## 16. Security Statement

Vortex prioritizes deterministic behavior, explicit failure, testable
security properties, and transparent documentation of limitations.

Security claims must be supported by:

- reproducible tests;
- documented threat models;
- benchmark methodology;
- adversarial validation;
- regression testing;
- independent review where available.

Discovered vulnerabilities should be documented with:

- affected component;
- technical root cause;
- security impact;
- remediation;
- regression test;
- remaining limitations.

## 17. Architectural Roadmap

### Phase 1 — Architecture Documentation

- document the current backend request flow;
- map endpoints to handlers and internal components;
- separate production and experimental modules;
- document security boundaries.

### Phase 2 — Trust Engine Separation

- evaluate renaming or extracting `pqc_core.rs`;
- define named trust-signal structures;
- remove ambiguous vector indexes;
- document thresholds and scoring rationale.

### Phase 3 — Runtime Integration

- introduce userspace-to-kernel policy distribution;
- create compact eBPF policy maps;
- add telemetry transport through ring buffers or perf events;
- preserve a small verifier-friendly kernel program.

### Phase 4 — AI Runtime Controls

- define objective-fidelity evidence;
- validate tool requests before execution;
- connect identity, intent, payload, and policy signals;
- generate auditable runtime decisions.

### Phase 5 — Production Hardening

- replace experimental cryptographic primitives with standardized
  implementations where required;
- introduce persistent and protected key storage;
- expand adversarial testing;
- perform independent security review;
- publish reproducible benchmarks.

## 18. Component Map

```text
Vortex-DFS
|
+-- Interface Layer
|   |
|   +-- HTTP API
|   +-- API-key validation
|   +-- Request routing
|
+-- Data Protection Layer
|   |
|   +-- anonymizer_engine.rs
|
+-- Cryptographic Layer
|   |
|   +-- signer_lwe.rs
|   +-- pqc_endpoints.rs
|   +-- key_store.rs
|
+-- Trust Evaluation Layer
|   |
|   +-- pqc_core.rs
|
+-- Provisioning and Identity
|   |
|   +-- provisioner.rs
|   +-- hardware_register.rs
|
+-- Runtime Enforcement
    |
    +-- HTTP rejection
    +-- Gateway controls
    +-- Data redaction
    +-- vortex-ebpf
```

## 19. Documentation Policy

Architecture documentation must distinguish clearly between:

- implemented behavior;
- experimental behavior;
- planned behavior;
- security guarantees;
- architectural goals.

Future capabilities must not be described as current production
features.

When the implementation changes, this document should be updated in the
same pull request whenever the change affects:

- public endpoints;
- trust evaluation;
- cryptographic behavior;
- enforcement decisions;
- security boundaries;
- kernel integration.
