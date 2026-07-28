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

### 3.1 Deterministic decisions

The same validated input and policy must produce the same decision.

### 3.2 Verify before execution

Security checks should occur before a protected action is completed,
whenever technically possible.

### 3.3 Explicit failure

Invalid, malformed, untrusted, or unverifiable inputs must fail with a
clear and auditable reason.

### 3.4 Minimal trust assumptions

Clients, payloads, sessions, cryptographic material, and runtime signals
must not be considered trustworthy by default.

### 3.5 Separation of mechanism and policy

Cryptographic verification, data inspection, trust evaluation, and
runtime enforcement are separate responsibilities.

### 3.6 Evidence over confidence

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
5. Architectural Layers
5.1 Interface Layer

Exposes the public HTTP API and receives client requests.

Current public services include:

/v1/shield/anonymize
/v1/pqc/sign
/v1/pqc/verify
/v1/pqc/audit
5.2 Data Protection Layer

Responsible for detecting and redacting sensitive information before
the content reaches downstream systems.

Primary component:

anonymizer_engine.rs
5.3 Cryptographic Layer

Responsible for cryptographic signing, verification, key handling, and
crypto-agility analysis.

Primary components:

signer_lwe.rs
pqc_endpoints.rs
key_store.rs
5.4 Trust Evaluation Layer

Transforms validated security signals into deterministic operational
bands and decisions.

Primary component:

pqc_core.rs

Current trust bands:

HighTrust
Operational
Fragile
Critical

The current filename reflects its original PQC context. This component
may later be renamed or extracted into a dedicated trust-engine module.

5.5 Enforcement Layer

Applies the final security decision.

Current and experimental enforcement surfaces include:

HTTP API responses
Gateway validation
Request rejection
Data redaction
eBPF/XDP packet enforcement
5.6 Kernel Runtime Layer

The experimental vortex-ebpf component executes at XDP and can inspect
network packets before they enter the normal Linux networking stack.

The current implementation:

validates Ethernet and IPv4 boundaries;
identifies TCP traffic;
passes unrelated traffic;
rejects selected TCP packets at XDP.

This component is experimental and must not yet be represented as a
complete integration with the userspace trust engine.

6. Decision Model

A Vortex decision is produced from validated evidence.

```

Input
  |
  v
Structural validation
  |
  v
Security signal extraction
  |
  v
Cryptographic or policy verification
  |
  v
Trust evaluation
  |
  v
Explicit decision

```

A decision must contain, where applicable:

result;
reason;
evaluated signals;
policy or threshold used;
trace identifier;
processing latency;
cryptographic evidence.
7. Current Boundaries

Vortex-DFS currently contains production-facing APIs and experimental
research components.

The following distinctions must remain explicit:

Production-facing
PII anonymization API
Crypto-agility audit API
API-key provisioning
HTTP request controls
Research or experimental
Toy-scale LWE signature construction
Physics-derived trust scoring
eBPF/XDP runtime enforcement
Full AI-agent objective-fidelity enforcement

Experimental components must not be presented as standardized,
independently audited, or production-grade cryptographic replacements.

8. Target Architecture

The long-term architecture connects application security, deterministic
trust evaluation, and low-level enforcement.
```
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
 Userspace    Kernel policy
 enforcement  eBPF/XDP maps
     |         |
     +----+----+
          |
          v
ALLOW / REJECT / REDACT / AUDIT

```

The kernel component should remain small and verifier-friendly.
Complex scoring and policy evaluation should occur in userspace, while
eBPF maps may distribute compact enforcement decisions to the kernel.

9. Non-Goals

Vortex is not currently:

a general-purpose firewall;
an intrusion detection system;
a replacement for standardized production PQC libraries;
an autonomous AI model;
a probabilistic malware classifier;
a complete agent sandbox.
10. Security Statement

Vortex prioritizes deterministic behavior, explicit failure, testable
security properties, and transparent documentation of limitations.

Security claims must be supported by:

reproducible tests;
documented threat models;
benchmark methodology;
adversarial validation;
independent review where available.

