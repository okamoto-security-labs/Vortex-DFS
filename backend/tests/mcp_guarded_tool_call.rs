//! Minimal MCP JSON-RPC tools/call integration proof.
//! The authenticated principal is supplied by the trusted transport boundary,
//! never taken from untrusted JSON-RPC arguments. No external CRM is contacted.
use serde_json::{json, Value};
use vortex_dfs::runtime::{
    evaluate_and_execute, GuardedExecution, IdentityContext, Operation, PayloadContext,
    RequestContext, RuntimePolicy,
};

fn policy() -> RuntimePolicy {
    RuntimePolicy::new("mcp.customer-export", "1")
        .allow_operation(Operation::AgentToolExecution)
        .with_required_scope("crm:export")
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(false)
        .with_fail_closed(true)
}

fn dispatch(
    raw_json_rpc: &str,
    trusted_identity: Option<IdentityContext>,
    execution_count: &mut usize,
) -> Value {
    let request: Value = match serde_json::from_str(raw_json_rpc) {
        Ok(value) => value,
        Err(_) => return json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || request.get("method").and_then(Value::as_str) != Some("tools/call")
        || request.pointer("/params/name").and_then(Value::as_str) != Some("crm_export")
        || !request.pointer("/params/arguments/customer_group").is_some_and(Value::is_string)
    {
        return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Unsupported or invalid tool call"}});
    }

    let mut context = RequestContext::new(
        format!("mcp-{id}"), format!("mcp-{id}"),
        Operation::AgentToolExecution,
        PayloadContext::new(raw_json_rpc.len()).with_content_type("application/json"),
    );
    context.evidence.set_structural_validity(true);
    if let Some(identity) = trusted_identity {
        context = context.with_identity(identity);
    }

    // The tool handler is invoked only inside the Vortex execution gate.
    match evaluate_and_execute(context, &policy(), |_| {
        *execution_count += 1;
        json!({"content":[{"type":"text","text":"Export job accepted in isolated test fixture"}]})
    }) {
        GuardedExecution::Executed { output, .. } => json!({"jsonrpc":"2.0","id":id,"result":output}),
        GuardedExecution::Blocked { evaluation } => json!({
            "jsonrpc":"2.0","id":id,
            "error":{"code":-32003,"message":"Vortex policy rejected tool execution",
                     "data":{"decision":"REJECT","reason_code":evaluation.decision.reason_code.as_str()}}
        }),
    }
}

fn tool_call() -> &'static str {
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm_export","arguments":{"customer_group":"test"}}}"#
}

#[test]
fn authorized_mcp_tool_call_executes_exactly_once() {
    let mut count = 0;
    let identity = IdentityContext::new("operator", "trusted-test-transport", true)
        .with_scope("crm:export");
    let response = dispatch(tool_call(), Some(identity), &mut count);
    assert_eq!(count, 1);
    assert!(response.get("result").is_some(), "{response}");
    assert!(response.get("error").is_none());
}

#[test]
fn missing_scope_blocks_mcp_tool_call_before_executor() {
    let mut count = 0;
    let identity = IdentityContext::new("operator", "trusted-test-transport", true);
    let response = dispatch(tool_call(), Some(identity), &mut count);
    assert_eq!(count, 0);
    assert_eq!(response.pointer("/error/data/decision"), Some(&json!("REJECT")));
}

#[test]
fn missing_identity_blocks_mcp_tool_call_before_executor() {
    let mut count = 0;
    let response = dispatch(tool_call(), None, &mut count);
    assert_eq!(count, 0);
    assert_eq!(response.pointer("/error/data/decision"), Some(&json!("REJECT")));
}

#[test]
fn tool_arguments_cannot_grant_their_own_authorization() {
    let mut count = 0;
    let forged = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"crm_export","arguments":{"customer_group":"test","scopes":["crm:export"],"verified":true}}}"#;
    let response = dispatch(forged, None, &mut count);
    assert_eq!(count, 0);
    assert_eq!(response.pointer("/error/data/decision"), Some(&json!("REJECT")));
}

#[test]
fn invalid_tool_name_never_reaches_executor() {
    let mut count = 0;
    let identity = IdentityContext::new("operator", "trusted-test-transport", true)
        .with_scope("crm:export");
    let raw = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unknown","arguments":{"customer_group":"test"}}}"#;
    let response = dispatch(raw, Some(identity), &mut count);
    assert_eq!(count, 0);
    assert_eq!(response.pointer("/error/code"), Some(&json!(-32602)));
}
