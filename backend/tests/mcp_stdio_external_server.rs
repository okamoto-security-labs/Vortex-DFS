//! Process-boundary MCP stdio proof. No external network or customer data.
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use serde_json::{json, Value};
use vortex_dfs::runtime::{evaluate_and_execute, GuardedExecution, IdentityContext, Operation, PayloadContext, RequestContext, RuntimePolicy};

struct Server {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Server {
    fn start() -> Self {
        let script = format!("{}/../docs/mcp-security-proof/isolated_mcp_server.py", env!("CARGO_MANIFEST_DIR"));
        let mut child = Command::new("python3").arg("-u").arg(script)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
            .spawn().expect("start isolated external MCP server");
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self { child, input, output }
    }
    fn send(&mut self, request: Value) -> Value {
        writeln!(self.input, "{}", request).unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        self.output.read_line(&mut line).expect("read server response");
        serde_json::from_str(&line).expect("valid JSON-RPC response")
    }
    fn notify(&mut self, request: Value) {
        writeln!(self.input, "{}", request).unwrap();
        self.input.flush().unwrap();
    }
    fn handshake(&mut self) {
        let response = self.send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"vortex-test","version":"0.1.0"}
        }}));
        assert_eq!(response.pointer("/result/protocolVersion"), Some(&json!("2025-06-18")));
        self.notify(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        let tools = self.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}));
        assert_eq!(tools.pointer("/result/tools/0/name"), Some(&json!("crm_export")));
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn policy() -> RuntimePolicy {
    RuntimePolicy::new("mcp.external-fixture", "1")
        .allow_operation(Operation::AgentToolExecution)
        .with_required_scope("crm:export")
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(false)
        .with_fail_closed(true)
}
fn guarded_call(server: &mut Server, identity: Option<IdentityContext>, arguments: Value) -> Value {
    let request = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"crm_export","arguments":arguments}});
    let raw = request.to_string();
    let mut context = RequestContext::new("mcp-stdio-3", "mcp-stdio-3",
        Operation::AgentToolExecution,
        PayloadContext::new(raw.len()).with_content_type("application/json"));
    context.evidence.set_structural_validity(true);
    if let Some(identity) = identity {
        context = context.with_identity(identity);
    }
    match evaluate_and_execute(context, &policy(), |_| server.send(request)) {
        GuardedExecution::Executed { output, .. } => output,
        GuardedExecution::Blocked { evaluation } => json!({"jsonrpc":"2.0","id":3,"error":{
            "code":-32003,"message":"Vortex policy rejected execution",
            "data":{"decision":"REJECT","reason_code":evaluation.decision.reason_code.as_str()}}}),
    }
}
#[test]
fn external_stdio_mcp_allow_and_reject_without_forwarding() {
    let mut server = Server::start();
    server.handshake();
    let valid = IdentityContext::new("operator","trusted-test-transport",true).with_scope("crm:export");
    let allowed = guarded_call(&mut server, Some(valid), json!({"customer_group":"test"}));
    assert_eq!(allowed.pointer("/result/content/0/text"), Some(&json!("Isolated export fixture accepted")));

    let denied = guarded_call(&mut server, Some(IdentityContext::new("operator","trusted-test-transport",true)),
        json!({"customer_group":"test"}));
    assert_eq!(denied.pointer("/error/data/decision"), Some(&json!("REJECT")));
    assert_eq!(denied.pointer("/error/data/reason_code"), Some(&json!("SCOPE_DENIED")));

    let forged = guarded_call(&mut server, None,
        json!({"customer_group":"test","scopes":["crm:export"],"verified":true}));
    assert_eq!(forged.pointer("/error/data/decision"), Some(&json!("REJECT")));

    // Server stays alive and handles the next request, showing that denials
    // were local decisions rather than server-side errors or process failure.
    let listed = server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}));
    assert_eq!(listed.pointer("/result/tools/0/name"), Some(&json!("crm_export")));
}
