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

## Verified CI evidence (28 October 2026)

[GitHub Actions run 40735863523](https://github.com/okamoto-security-labs/Vortex-DFS/actions/runs/40735863523) completed successfully on branch `docs/mcp-security-proof-kamal` at commit `0ff151d9ea39d84672db47c584ddafd0fbd98b4e`. The job `Rust runtime tests` ran `cargo test --manifest-path backend/Cargo.toml --locked`. Its logs report 157 + 8 + 13 + 10 + 9 = **197 tests passed, zero failed**; the remaining test suites and doc-tests reported zero tests. This validates the repository backend test suite at that commit. It does not constitute an end-to-end MCP adapter security test or a production deployment assessment.


## MCP JSON-RPC tool-call integration test (new; awaiting CI verification)

Source: [backend/tests/mcp_guarded_tool_call.rs](https://github.com/okamoto-security-labs/Vortex-DFS/blob/docs/mcp-security-proof-kamal/backend/tests/mcp_guarded_tool_call.rs).

The test feeds actual JSON-RPC 2.0 `tools/call` request payloads into a minimal local adapter that invokes the existing Vortex DFS `evaluate_and_execute` gate. It asserts that an authorized request invokes the protected test executor once; missing identity, missing scope, forged scope in untrusted tool arguments, and unknown tool name do not invoke it. Identity is supplied by the trusted test transport, never inferred from request arguments.

Run with `cargo test --manifest-path backend/Cargo.toml --locked --test mcp_guarded_tool_call`.

**Scope:** in-process MCP method integration test with a local test fixture. It does not implement an MCP transport, remote MCP server, production authentication, customer CRM export, or production audit persistence. These test cases are new and are **not included** in the historical 197-pass CI run; verify the new CI result before citing them as passed.
