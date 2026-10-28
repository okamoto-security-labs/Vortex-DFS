//! Process-to-process HTTP proof: independent upstream counts forwarded tools/call.
//! This is NOT a full Streamable HTTP MCP conformance test.
use serde_json::{json, Value};
use std::{net::TcpListener, process::{Child, Command, Stdio}, time::Duration};

struct Guard(Child);
impl Drop for Guard { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
async fn wait_ready(client: &reqwest::Client, url: &str) {
    for _ in 0..100 {
        if client.get(url).send().await.is_ok() { return; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fixture did not start: {url}");
}
async fn counter(client: &reqwest::Client, url: &str) -> u64 {
    client.get(url).send().await.unwrap().json::<Value>().await.unwrap()
        .get("received_tool_calls").and_then(Value::as_u64).unwrap()
}
#[tokio::test]
async fn http_gateway_forwards_only_authorized_calls() {
    let fixture_port = free_port();
    let gateway_port = free_port();
    assert_ne!(fixture_port, gateway_port);
    let script = format!("{}/../docs/mcp-security-proof/http_mcp_fixture.py", env!("CARGO_MANIFEST_DIR"));
    let _fixture = Guard(Command::new("python3").arg("-u").arg(script)
        .env("VORTEX_MCP_FIXTURE_PORT", fixture_port.to_string())
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let client = reqwest::Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
    let count_url = format!("http://127.0.0.1:{fixture_port}/_count");
    wait_ready(&client, &count_url).await;
    let token = "test-gateway-token-with-more-than-32-characters";
    let readonly = "readonly-gateway-token-with-more-than-32-characters";
    let _gateway = Guard(Command::new(env!("CARGO_BIN_EXE_mcp_gateway"))
        .env("VORTEX_MCP_UPSTREAM", format!("http://127.0.0.1:{fixture_port}/mcp"))
        .env("VORTEX_MCP_LISTEN_PORT", gateway_port.to_string())
        .env("VORTEX_MCP_CLIENT_TOKEN", token)
        .env("VORTEX_MCP_READONLY_TOKEN", readonly)
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let endpoint = format!("http://127.0.0.1:{gateway_port}/mcp");
    // A non-POST probe establishes that the gateway is listening.
    wait_ready(&client, &endpoint).await;
    assert_eq!(counter(&client, &count_url).await, 0);
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
    let init = client.post(&endpoint).bearer_auth(token).json(&initialize).send().await.unwrap();
    assert_eq!(init.status(), reqwest::StatusCode::OK);
    let session = init.headers().get("mcp-session-id").unwrap().to_str().unwrap().to_string();
    let init_json: Value = init.json().await.unwrap();
    assert_eq!(init_json.pointer("/result/protocolVersion"),Some(&json!("2025-06-18")));
    let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    let ready = client.post(&endpoint).bearer_auth(token).header("mcp-session-id",&session)
        .json(&notification).send().await.unwrap();
    assert_eq!(ready.status(),reqwest::StatusCode::ACCEPTED);
    let list = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
    let listed: Value = client.post(&endpoint).bearer_auth(token).header("mcp-session-id",&session)
        .json(&list).send().await.unwrap().json().await.unwrap();
    assert_eq!(listed.pointer("/result/tools/0/name"),Some(&json!("crm_export")));
    assert_eq!(counter(&client,&count_url).await,0);
    let no_session = client.post(&endpoint).bearer_auth(token).json(&list).send().await.unwrap();
    assert_eq!(no_session.status(),reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(counter(&client,&count_url).await,0);
    let reader_init = client.post(&endpoint).bearer_auth(readonly).json(&initialize).send().await.unwrap();
    let reader_session = reader_init.headers().get("mcp-session-id").unwrap().to_str().unwrap().to_string();
    let reader_ready = client.post(&endpoint).bearer_auth(readonly).header("mcp-session-id",&reader_session)
        .json(&notification).send().await.unwrap();
    assert_eq!(reader_ready.status(),reqwest::StatusCode::ACCEPTED);
    let wrong_principal = client.post(&endpoint).bearer_auth(readonly).header("mcp-session-id",&session)
        .json(&list).send().await.unwrap();
    assert_eq!(wrong_principal.status(),reqwest::StatusCode::BAD_REQUEST);
    let request = json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
        "params":{"name":"crm_export","arguments":{"customer_group":"test"}}});
    let unauthorized = client.post(&endpoint).json(&request).send().await.unwrap();
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(counter(&client, &count_url).await, 0, "unauthorized request reached upstream");

    let disallowed = json!({"jsonrpc":"2.0","id":8,"method":"tools/call",
        "params":{"name":"delete_everything","arguments":{"customer_group":"test","scopes":["crm:export"]}}});
    let blocked: Value = client.post(&endpoint).bearer_auth(token).header("mcp-session-id",&session).json(&disallowed)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(blocked.pointer("/error/code"), Some(&json!(-32602)));
    assert_eq!(counter(&client, &count_url).await, 0, "disallowed tool reached upstream");

    let allowed: Value = client.post(&endpoint).bearer_auth(token).header("mcp-session-id",&session).json(&request)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(allowed.pointer("/result/content/0/text"), Some(&json!("Fixture accepted")));
    assert_eq!(counter(&client, &count_url).await, 1, "allowed tool not forwarded exactly once");

    let forged = json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
        "params":{"name":"delete_everything","arguments":{"customer_group":"test","scopes":["crm:export"],"verified":true}}});
    let _ = client.post(&endpoint).bearer_auth(token).header("mcp-session-id",&session).json(&forged).send().await.unwrap();
    assert_eq!(counter(&client, &count_url).await, 1, "forged tool reached upstream");
    let reader_denied: Value = client.post(&endpoint).bearer_auth(readonly)
        .header("mcp-session-id",&reader_session).json(&request)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(reader_denied.pointer("/error/code"),Some(&json!(-32003)));
    assert_eq!(reader_denied.pointer("/error/data/reason_code"),Some(&json!("SCOPE_DENIED")));
    assert_eq!(counter(&client,&count_url).await,1, "read-only principal reached upstream");

}
