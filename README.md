Vortex DFS




Status


Runtime


Tests


Decision




Verify before execution.


Every AI action must first cross an explicit trust boundary.


The runtime decides.


The adapter executes only when policy permits.





Deterministic Runtime Trust Layer for AI-Enabled Systems


A deterministic authorization boundary for protected execution.





Current Status

Vortex DFS is an experimental, open-source pre-alpha. Its implemented
vertical slice protects the anonymization endpoint:


HTTP request → RequestContext → evidence → RuntimePolicy → RuntimeDecision
             → execution gate → anonymizer (only when permitted)

The backend currently implements four outcomes: ALLOW, REJECT, REDACT,
and AUDIT. The execution gate is tested so a REJECT does not invoke the
protected executor, while a permitted REDACT decision can invoke it.


The latest local backend validation recorded 83 library tests and 3 HTTP
handler tests passing. Those tests demonstrate runtime behavior; they are not
a latency, throughput, or production-security certification.


What is not delivered yet


Persistent or immutable audit storage

Production identity/authentication enforcement in the HTTP path

Externally loaded policy bundles and policy administration

Production Tool Runner or Agent SDK adapters

End-to-end eBPF-to-runtime enforcement

Independently reviewed post-quantum cryptography


signer_lwe.rs is a toy-scale experimental LWE demonstration, not a
production PQC implementation. The eBPF/XDP component is also experimental and
separate from the userspace runtime path.



Every security decision starts with a question.


Is this safe?


Can we trust this decision?


Can this action be executed automatically?


What evidence supports this outcome?


Will the same input produce the same result tomorrow?



These questions are no longer theoretical.


Modern security increasingly depends on automated decisions made by AI systems, orchestration platforms, policy engines and autonomous workflows.


The problem is no longer collecting more telemetry.


Nor generating more alerts.


The real challenge is determining whether an automated decision can be trusted before it is executed.


Every unanswered question increases operational risk.


Every uncertain decision reduces confidence.


Every incident costs someone a night's sleep.


Vortex exists to replace uncertainty with deterministic runtime validation.



Vortex doesn't guess. It computes.




Why Vortex Exists

Security has evolved.


Organizations already have:



SIEMs

EDRs

SOAR platforms

Detection Rules

Threat Intelligence

AI Assistants

AI Agents


Yet one question remains unanswered:



Can we trust the decision that follows?



Modern AI systems optimize for intelligence.


Security systems must optimize for trust.


Trust cannot be inferred from probabilities alone.


It must be engineered.


Vortex introduces deterministic runtime validation, explicit policy evaluation and evidence-driven decision making to ensure that automated actions remain explainable, reproducible and auditable.


Confidence is not a feature.


It is an engineering outcome.



What is Vortex?

Vortex is a deterministic runtime trust layer for AI-enabled systems.


It evaluates automated decisions against explicit runtime policies before those decisions are allowed to execute.


Rather than asking:



"Is this probably malicious?"



Vortex asks:



"Does this decision satisfy the runtime policy?"



This distinction changes how automated security decisions are validated.


Instead of relying solely on probabilistic confidence, Vortex produces deterministic outcomes backed by explicit evidence and stable decision logic.



Where Vortex Fits

Vortex does not replace existing security platforms.


It complements them.


Technology	Primary Responsibility
SIEM	Collect, normalize and correlate security events
EDR	Monitor and protect endpoints
SOAR	Execute automated playbooks
AI Agents	Generate recommendations and proposed actions
Policy Engines	Define organizational rules
Vortex DFS	Validate whether automated decisions satisfy runtime policy before execution

Vortex operates between intelligence and execution.


Logs
EDR
SIEM
AI Agents
Policy Engines

        │

        ▼

+----------------------+
|     VORTEX DFS       |
| Runtime Trust Layer  |
+----------------------+

        │

        ▼

ALLOW / REJECT / REDACT / AUDIT


Engineering Philosophy

Security engineering should produce confidence, not uncertainty.


Vortex is built around a small number of principles that influence every architectural decision.


Deterministic Decisions

The same input under the same policy should always produce the same result.



Explicit Runtime Policies

Security decisions must be governed by policies that are visible, reviewable and version controlled.



Evidence Before Execution

Actions should never execute without sufficient supporting evidence.



Fail Closed

When uncertainty exceeds policy tolerance, execution stops.


Safe failure is preferable to unsafe automation.



Explainability

Every decision must explain itself.


Every outcome should include sufficient context for investigation and auditing.



Reproducibility

A security decision should be reproducible days, weeks or months later using the same policy version and evidence.



Auditability

The runtime returns structured decision data — outcome, stable reason code,
policy reference, evidence summary, and latency — so an adapter can record it.
Persistent audit storage and immutable retention are not implemented yet.



Current Runtime Guarantees

Vortex is designed around engineering guarantees rather than feature lists.


✔ Deterministic runtime evaluation


✔ Explicit policy enforcement


✔ Stable reason codes


✔ Evidence-driven decisions


✔ Fail-closed execution


✔ Reproducible outcomes for the same in-memory input and policy


✔ Structured runtime decisions for adapters to record


✔ Policy identifiers and versions carried in decisions


They describe the implemented runtime core. Production governance, audit
retention, and organization-wide policy management remain future work.



Core Runtime Flow

Every runtime decision follows the same deterministic evaluation pipeline.


Input

      │

      ▼

Normalization

      │

      ▼

Evidence Extraction

      │

      ▼

Policy Evaluation

      │

      ▼

Decision Validation

      │

      ▼

Reason Code Generation

      │

      ▼

ALLOW / REJECT / REDACT / AUDIT

      │

      ▼

Structured RuntimeDecision
Adapter-owned audit sink (optional)

Within the current runtime evaluation, every stage is deterministic and every
returned decision carries a stable outcome, reason code, policy reference, and
evidence summary.


Runtime Architecture

Vortex is intentionally designed as a deterministic runtime layer.


Its responsibility is not to generate intelligence.


Its responsibility is to validate whether automated decisions satisfy explicit runtime policies before execution.


                  ┌───────────────────────┐
                  │   External Systems    │
                  │───────────────────────│
                  │ SIEM                  │
                  │ EDR                   │
                  │ SOAR                  │
                  │ AI Agents             │
                  │ LLM Applications      │
                  │ Detection Engines     │
                  └───────────┬───────────┘
                              │
                              ▼

                 ┌────────────────────────────┐
                 │        VORTEX DFS          │
                 │────────────────────────────│
                 │ Input Normalization        │
                 │ Evidence Extraction        │
                 │ Runtime Validation         │
                 │ Policy Evaluation          │
                 │ Decision Engine            │
                 │ Reason Code Generator      │
                 │ Runtime Decision Builder   │
                 └───────────┬────────────────┘
                             │
                             ▼

           ┌──────────────────────────────────┐
           │ Runtime Decision                 │
           │----------------------------------│
           │ ALLOW                            │
           │ REJECT                           │
           │ REDACT                           │
           │ AUDIT                            │
           └──────────────────────────────────┘

The runtime is intentionally small.


Every additional component increases complexity.


Every additional dependency expands the trusted computing base.


Vortex favors deterministic simplicity over opaque automation.



Runtime Decision Model

Every request entering Vortex follows the same deterministic lifecycle.


Receive Request
        │
        ▼
Normalize Input
        │
        ▼
Extract Evidence
        │
        ▼
Select Active Runtime Policy
        │
        ▼
Evaluate Constraints
        │
        ▼
Generate Decision
        │
        ▼
Generate Reason Codes
        │
Return Result

This lifecycle never changes.


Policies may evolve.


Rules may evolve.


Evidence may evolve.


The evaluation model remains deterministic.



Runtime Decisions

Vortex produces explicit runtime outcomes.


ALLOW

The decision satisfies every required runtime policy.


Execution may continue.



REJECT

The runtime policy was violated.


Execution stops immediately.



REDACT

Sensitive information must be removed before execution or disclosure.



AUDIT

Execution may proceed with an explicit AUDIT decision. Persisting an audit
event is the responsibility of the adapter; a durable audit sink is not yet
included.



Structured Decisions

Every evaluation produces a structured RuntimeDecision.


It exists to answer one question:



Why was this decision made?



Typical information includes:



Runtime Decision

Policy Version

Reason Codes

Evidence Summary

Request and trace identifiers

Runtime Metadata

Validation Status


An HTTP response currently exposes the outcome, reason code, policy reference,
trace ID, and latency. Future adapters can persist or enrich that record.


This is the audit-ready record emitted by the runtime. A durable Decision Card
store is planned, not yet included.



Policy Engine

Policies define the boundaries of trusted execution.


Policies are:



Explicit

Human readable

Version controlled

Reviewable

Testable


A runtime policy is not business logic.


It is an engineering contract.


Changing a policy changes system behavior.


Therefore every policy should be versioned, reviewed and tested.



Reason Codes

Every runtime outcome includes stable Reason Codes.


Reason Codes exist for machines and humans.


Instead of ambiguous explanations like:



Validation failed.



Vortex produces explicit outcomes such as:


POLICY_NOT_SATISFIED

MISSING_REQUIRED_EVIDENCE

INPUT_SCHEMA_INVALID

RUNTIME_TIMEOUT

REDACTION_REQUIRED

POLICY_VERSION_MISMATCH

Stable Reason Codes simplify:



debugging

incident response

automation

dashboards

governance

long-term maintenance



Evidence Model

Automation without evidence is trust without verification.


Vortex evaluates decisions using evidence collected during runtime.


Evidence may include:



Request metadata

Runtime context

Identity information

Security telemetry

Detection results

Policy inputs

Validation artifacts


Evidence is evaluated before execution.


Never after.



Security by Design

Security is not implemented as a final validation step.


Security influences every runtime stage.


Design principles include:



Least privilege

Explicit trust boundaries

Fail closed

Audit-ready structured decisions; immutable storage is planned

Deterministic evaluation

Policy isolation

Versioned governance

Reproducible execution


These principles are architectural decisions, not optional features.



Engineering Over Automation

Many systems optimize for automation.


Vortex optimizes for trustworthy automation.


Automation without accountability creates operational risk.


Automation with deterministic validation creates confidence.


The objective is not to automate more.


The objective is to automate responsibly.


Engineering

Vortex is engineered as long-term infrastructure.


Every architectural decision is expected to remain understandable months or years after it was introduced.


Engineering discipline is treated as a core feature of the project.



Architecture Decision Records (ADRs)

Major architectural changes are documented using Architecture Decision Records (ADRs).


ADRs capture:



Context

Decision

Alternatives considered

Consequences

Implementation status


This ensures architectural knowledge remains available even as the project evolves.



Quality Gates

Every contribution is expected to satisfy objective quality requirements before integration.


Quality Gates include:



Successful compilation

Automated testing

Static analysis

Documentation updates

API compatibility verification

Policy validation

Review approval


The GitHub Actions workflow currently validates the Rust backend on pushes and
pull requests to main. eBPF builds have separate nightly and linker
requirements and are not yet part of the same production validation path.



Code Review

Every change is reviewed from two perspectives:


Technical Correctness


Does the implementation solve the intended problem?

Does it preserve deterministic behavior?

Does it introduce unnecessary complexity?


Engineering Quality


Readability

Maintainability

Backward compatibility

Documentation

Test coverage

Long-term operational impact


Good code is not enough.


Good engineering is required.



Testing Philosophy

Testing exists to verify engineering guarantees.


Tests validate:



Deterministic evaluation

Runtime policies

Decision consistency

Reason Code stability

Error handling

Fail-closed behavior

Regression prevention


Every bug fixed becomes a permanent test whenever possible.



Documentation Philosophy

Documentation is treated as part of the product.


Every feature should answer three questions:



Why does it exist?

How does it work?

Why was it designed this way?


The goal is not merely to explain APIs.


The goal is to preserve engineering intent.



Versioning

Vortex follows Semantic Versioning.


Policy changes, runtime behavior and public APIs evolve through controlled, documented releases.


Backward compatibility is preserved whenever practical.


Breaking changes are intentional, documented and justified.



Governance

Engineering decisions are expected to be transparent.


Project governance is based on:



Public discussions

Documented decisions

Version-controlled policies

Peer review

Reproducible releases


Transparency builds confidence.


Confidence builds adoption.



Security

Security is foundational.


Every contribution should preserve the project's core security guarantees:



Deterministic runtime evaluation

Explicit trust boundaries

Fail-closed execution

Stable decision semantics

Auditability

Evidence integrity


Security is considered during design, implementation, testing and review.


It is never treated as a final verification step.



CI/CD

The repository has a backend CI workflow for cargo check, strict Clippy, and
tests on main pull requests and pushes.


The CI pipeline verifies:



Build integrity

Test execution

Static analysis through Clippy

Backend unit and handler tests


Automation accelerates engineering.


It never replaces engineering judgment.



Reliability

Reliability is measured through predictability.


A reliable runtime should:



Produce deterministic outcomes

Remain understandable

Be observable

Be debuggable

Behave consistently across environments


Predictability is more valuable than complexity.



Project Structure

docs/
├── adr/
├── architecture/
├── benchmarks/
├── engineering/
├── history/
├── research/

src/

examples/

sdk/

policies/

tests/

Every directory has a clear responsibility.


Organization reduces long-term maintenance costs.



Contributing

We welcome contributions of every size.


Examples include:



Bug fixes

Documentation improvements

Runtime policies

Benchmarks

Architecture discussions

Security research

Performance improvements

Test cases


Large pull requests are appreciated.


Thoughtful engineering discussions are equally valuable.



Before Opening a Pull Request

Please ensure that:



Tests pass

Documentation is updated

Policies remain deterministic

New behavior is explained

Existing guarantees remain preserved


Engineering consistency is more important than implementation speed.



Closing Thoughts

Security has spent decades improving detection.


The next decade will focus on validating automated decisions.


Organizations already know how to collect telemetry.


They already know how to detect threats.


The remaining challenge is trust.


Can an automated decision be explained?


Can it be reproduced?


Can it be audited?


Can it be executed safely?


These are engineering questions.


Vortex is one possible answer.


Not by replacing existing security platforms.


But by introducing deterministic runtime validation between intelligence and execution.


Because automation without trust is simply faster uncertainty.


Trust cannot be inferred.


It must be engineered.



Vortex doesn't guess.


It computes.


Runtime Placement

For the boundary between low-latency network enforcement and application
authorization, see Runtime Low-Latency Enforcement.


Vortex sits at the boundary where reasoning becomes execution.


Modern systems increasingly rely on autonomous components:



AI Models

AI Agents

Workflow Engines

Policy Engines

Orchestrators


These systems generate decisions.


Vortex is designed to determine whether those decisions are trusted enough to
become actions. Today, the shipped adapter demonstrates that boundary for the
anonymization endpoint; the agent, OS, cloud, and tool integrations below are
target adapters rather than completed integrations.


Human
    │
    ▼
Application
    │
    ▼
LLM
    │
    ▼
AI Agent
    │
    ▼
Orchestrator
    │
    ▼
+------------------------+
|      VORTEX DFS        |
| Runtime Trust Layer    |
+------------------------+
    │
    ├──────────────┐
    ▼              ▼
ALLOW / REDACT / AUDIT         REJECT
    │
    ▼
Trusted Execution
    │
    ▼
Operating System
Cloud APIs
Databases
Networks
GitHub
Kubernetes
Email
Filesystem

Vortex does not attempt to make systems more intelligent.


It ensures that intelligence becomes trustworthy execution.

