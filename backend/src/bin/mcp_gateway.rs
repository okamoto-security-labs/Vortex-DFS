//! Experimental MCP Streamable HTTP gateway. Not production-ready.
//! Run behind TLS; bind to loopback by default. Never expose publicly without review.
use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer};
use serde_json::{json, Value};
use std::{env, time::Duration};
use vortex_dfs::runtime::{
    evaluate_request, IdentityContext, Operation, PayloadContext, RequestContext, RuntimePolicy,
};

struct State {
    upstream: String,
    client_token: String,
    client: reqwest::Client,
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
async fn mcp(req: HttpRequest, body: web::Bytes, state: web::Data<State>) -> HttpResponse {
    let auth = req.headers().get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok()).unwrap_or("");
    let expected = format!("Bearer {}", state.client_token);
    // Avoid exposing a public unauthenticated MCP proxy. Token is a temporary
    // pre-shared proof credential, not a replacement for OIDC/JWT validation.
    if !constant_time_equal(auth.as_bytes(), expected.as_bytes()) {
        return HttpResponse::Unauthorized().json(json!({"error":"unauthorized"}));
    }
    if body.len() > 65536 {
        return HttpResponse::PayloadTooLarge().finish();
    }
    let request: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(v) if v.is_object() => v,
        _ => return HttpResponse::BadRequest().json(error(Value::Null,-32700,"Invalid JSON-RPC request")),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return HttpResponse::BadRequest().json(error(id,-32600,"Invalid JSON-RPC version"));
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method != "tools/call" {
        // Do not expose upstream methods without explicit security review.
        return HttpResponse::Ok().json(error(id,-32601,"Only tools/call is supported by this experimental gateway"));
    }
    if request.pointer("/params/name").and_then(Value::as_str) != Some("crm_export")
        || request.pointer("/params/arguments/customer_group").and_then(Value::as_str).is_none()
    {
        return HttpResponse::Ok().json(error(id,-32602,"Invalid or disallowed tool"));
    }
    let policy = RuntimePolicy::new("mcp.remote-proof", "1")
        .allow_operation(Operation::AgentToolExecution)
        .with_required_scope("crm:export")
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(false)
        .with_fail_closed(true);
    // In this experimental proof, a configured gateway credential represents a
    // single fixed principal with a fixed scope. Never accept client-supplied scopes.
    let identity = IdentityContext::new("proof-client","gateway-static-credential",true)
        .with_scope("crm:export");
    let mut context = RequestContext::new(uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(), Operation::AgentToolExecution,
        PayloadContext::new(body.len()).with_content_type("application/json"))
        .with_identity(identity);
    context.evidence.set_structural_validity(true);
    let evaluation = evaluate_request(context, &policy);
    if !evaluation.permits_execution() {
        return HttpResponse::Ok().json(json!({"jsonrpc":"2.0","id":id,"error":{
            "code":-32003,"message":"Vortex policy rejected execution",
            "data":{"reason_code":evaluation.decision.reason_code.as_str()}}}));
    }
    // No redirects; destination is fixed at startup and never taken from requests.
    let response = match state.client.post(&state.upstream)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .json(&request).send().await {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadGateway().json(error(id,-32002,"Upstream unavailable")),
        };
    if !response.status().is_success() {
        return HttpResponse::BadGateway().json(error(id,-32002,"Upstream error"));
    }
    match response.json::<Value>().await {
        Ok(value) if value.is_object() && value.get("jsonrpc").and_then(Value::as_str)==Some("2.0")
            && value.get("id")==Some(&id) => HttpResponse::Ok().json(value),
        _ => HttpResponse::BadGateway().json(error(id,-32002,"Invalid upstream response")),
    }
}
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let upstream = env::var("VORTEX_MCP_UPSTREAM").expect("VORTEX_MCP_UPSTREAM required");
    let url = reqwest::Url::parse(&upstream).expect("valid upstream URL");
    assert_eq!(url.scheme(), "http", "experimental gateway accepts only loopback HTTP upstream");
    assert!(matches!(url.host_str(), Some("127.0.0.1")|Some("localhost")|Some("::1")),
        "upstream must be loopback for this proof");
    assert!(url.username().is_empty() && url.password().is_none() && url.fragment().is_none());
    let client_token = env::var("VORTEX_MCP_CLIENT_TOKEN").expect("VORTEX_MCP_CLIENT_TOKEN required");
    assert!(client_token.len() >= 32, "use a random credential of at least 32 characters");
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let state = web::Data::new(State {upstream, client_token, client});
    let listen_port: u16 = env::var("VORTEX_MCP_LISTEN_PORT").ok()
        .map(|p| p.parse().expect("valid listen port")).unwrap_or(8788);
    HttpServer::new(move || App::new().app_data(state.clone())
        .app_data(web::PayloadConfig::new(65536))
        .route("/mcp",web::post().to(mcp)))
        .bind(("127.0.0.1",listen_port))?.run().await
}
