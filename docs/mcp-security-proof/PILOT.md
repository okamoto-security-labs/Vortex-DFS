# MCP execution-boundary feasibility pilot

**Status:** Proposed scope for technical discussion. Not a statement of completed customer integration.

## Objective

Evaluate whether a deterministic guard at the MCP tool execution boundary can prevent unauthorized actions without disrupting legitimate operations in one customer-selected workflow.

## Customer inputs

- One MCP server/tool workflow and a nonproduction test environment.
- An agreed set of authorized and unauthorized operations.
- A description of caller identity, authorization scopes, and existing audit controls.
- A technical contact for asynchronous integration questions.

## Deliverables

1. A narrow adapter design and implementation plan for the selected workflow.
2. A reproducible test matrix covering authorized execution, missing evidence, denied scopes, audit failure, and attempted bypass.
3. Evidence for every scenario: input context, policy version, decision, reason code, and whether the protected operation ran.
4. A concise findings report with limitations, false positives observed, and remediation recommendations.

## Acceptance criteria

- No selected test case can invoke the protected executor after a REJECT decision.
- Legitimate operations are measured as well as denied operations.
- Any bypass, unsupported path, or inconclusive result is explicitly reported.
- No claim of production readiness is made without deployment-specific validation.

## Existing evidence

The experimental Vortex DFS Rust backend has a guarded execution engine and validation logic. [GitHub Actions run 40735863523](https://github.com/okamoto-security-labs/Vortex-DFS/actions/runs/40735863523) recorded **197 passing tests and zero failures** at commit `0ff151d` on 28 October 2026. This is backend test evidence, not a live MCP integration result.

## Boundaries

The repository is pre-alpha. A production MCP Tool Runner integration is not yet established. The pilot requires customer-specific scoping, and would not include a production security guarantee or certification.

## Commercial terms

Fixed fee and delivery dates to be agreed after confirming integration complexity, environment access, and acceptance criteria. Work begins only after written agreement on scope and terms. Technical review and scoping can be handled asynchronously.
