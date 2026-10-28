# Vortex DFS — MCP Runtime Security Proof

**Status:** Experimental technical proof, not a production MCP integration.

## Problem
An approved MCP tool does not imply every action it performs is authorized. Vortex DFS evaluates evidence and policy before protected execution.

## Existing code evidence
- `backend/src/runtime/engine.rs`: `missing_required_evidence_rejects_before_execution` tests missing structural evidence results in REJECT.
- `rejected_request_never_invokes_the_executor` tests a rejected request does not invoke the executor.
- `audit_failure_prevents_executor_invocation` tests mandatory audit failure prevents execution.
- `backend/src/runtime/validator.rs` checks operation, identity, scopes, payload integrity, signatures and replay evidence according to policy.

These are code-level test definitions, not fresh test execution results.

## Proposed MCP pilot
Integrate one MCP workflow with a guarded execution boundary; test permitted actions, insufficient authorization, missing evidence, and bypass attempts. Report decisions, reason codes, legitimate-action rejection rate, and integration limitations.

## Limitations
Production MCP Tool Runner integration and production identity enforcement in the HTTP path are not yet implemented, per the repository README. No claim of production effectiveness or zero false positives is made.

## Next step
A paid, fixed-scope feasibility pilot, subject to agreement on architecture, scope, acceptance criteria and price.
