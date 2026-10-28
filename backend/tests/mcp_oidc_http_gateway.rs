//! End-to-end OIDC-style RS256/JWKS proof with a separate HTTP JWKS issuer fixture.
//! Uses loopback HTTP only; not a production identity provider or full OIDC discovery.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use serde_json::{json, Value};
use std::{net::TcpListener, process::{Child, Command, Stdio}, time::{Duration, SystemTime, UNIX_EPOCH}};
struct Guard(Child);
impl Drop for Guard { fn drop(&mut self) { let _=self.0.kill(); let _=self.0.wait(); } }
fn port()->u16 { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }
async fn ready(c:&reqwest::Client,u:&str) {
    for _ in 0..100 {
        if c.get(u).send().await.is_ok() { return; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("service not ready");
}
fn jwt(key:&PKey<openssl::pkey::Private>,sub:&str,scope:&str,exp:u64)->String {
    let h=URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"test-rsa-key"}"#);
    let p=URL_SAFE_NO_PAD.encode(json!({"iss":"https://issuer.test","aud":"vortex-test",
        "sub":sub,"scope":scope,"exp":exp}).to_string());
    let signing_input=format!("{h}.{p}");
    let mut signer=Signer::new(MessageDigest::sha256(),key).unwrap();
    signer.update(signing_input.as_bytes()).unwrap();
    format!("{signing_input}.{}",URL_SAFE_NO_PAD.encode(signer.sign_to_vec().unwrap()))
}
async fn init(c:&reqwest::Client,endpoint:&str,token:&str)->String {
    let init=json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"oidc-test","version":"1"}}});
    let response=c.post(endpoint).bearer_auth(token).json(&init).send().await.unwrap();
    assert_eq!(response.status(),reqwest::StatusCode::OK);
    let session=response.headers().get("mcp-session-id").unwrap().to_str().unwrap().to_string();
    let notification=json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    let ready=c.post(endpoint).bearer_auth(token).header("mcp-session-id",&session)
        .json(&notification).send().await.unwrap();
    assert_eq!(ready.status(),reqwest::StatusCode::ACCEPTED);
    session
}
#[tokio::test]
async fn signed_oidc_jwks_tokens_enforce_principal_and_scope_end_to_end() {
    let rsa=Rsa::generate(2048).unwrap();
    let n=URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
    let e=URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
    let key=PKey::from_rsa(rsa).unwrap();
    let jwks=json!({"keys":[{"kty":"RSA","alg":"RS256","use":"sig",
        "kid":"test-rsa-key","n":n,"e":e}]});
    let upstream_port=port(); let gateway_port=port();
    let script=format!("{}/../docs/mcp-security-proof/http_mcp_fixture.py",env!("CARGO_MANIFEST_DIR"));
    let _upstream=Guard(Command::new("python3").arg("-u").arg(script)
        .env("VORTEX_MCP_FIXTURE_PORT",upstream_port.to_string())
        .env("VORTEX_TEST_JWKS",jwks.to_string())
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let client=reqwest::Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
    let count_url=format!("http://127.0.0.1:{upstream_port}/_count");
    ready(&client,&count_url).await;
    let audit=std::env::temp_dir().join(format!("vortex-oidc-{}.jsonl",uuid::Uuid::new_v4()));
    let _gateway=Guard(Command::new(env!("CARGO_BIN_EXE_mcp_gateway"))
        .env("VORTEX_MCP_UPSTREAM",format!("http://127.0.0.1:{upstream_port}/mcp"))
        .env("VORTEX_MCP_LISTEN_PORT",gateway_port.to_string())
        .env("VORTEX_MCP_AUDIT_PATH",&audit)
        .env("VORTEX_MCP_OIDC_ISSUER","https://issuer.test")
        .env("VORTEX_MCP_OIDC_AUDIENCE","vortex-test")
        .env("VORTEX_MCP_OIDC_JWKS_URL",format!("http://127.0.0.1:{upstream_port}/.well-known/jwks.json"))
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let endpoint=format!("http://127.0.0.1:{gateway_port}/mcp");
    ready(&client,&endpoint).await;
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let allowed=jwt(&key,"alice","crm:export",now+300);
    let readonly=jwt(&key,"bob","crm:read",now+300);
    let expired=jwt(&key,"eve","crm:export",now-1);
    let call=json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"crm_export","arguments":{"customer_group":"test"}}});
    let invalid=client.post(&endpoint).bearer_auth(&expired).json(&call).send().await.unwrap();
    assert_eq!(invalid.status(),reqwest::StatusCode::UNAUTHORIZED);
    let alice_session=init(&client,&endpoint,&allowed).await;
    let bob_session=init(&client,&endpoint,&readonly).await;
    let cross=client.post(&endpoint).bearer_auth(&readonly).header("mcp-session-id",&alice_session)
        .json(&call).send().await.unwrap();
    assert_eq!(cross.status(),reqwest::StatusCode::BAD_REQUEST);
    let denied:Value=client.post(&endpoint).bearer_auth(&readonly).header("mcp-session-id",&bob_session)
        .json(&call).send().await.unwrap().json().await.unwrap();
    assert_eq!(denied.pointer("/error/data/reason_code"),Some(&json!("SCOPE_DENIED")));
    let success:Value=client.post(&endpoint).bearer_auth(&allowed).header("mcp-session-id",&alice_session)
        .json(&call).send().await.unwrap().json().await.unwrap();
    assert_eq!(success.pointer("/result/content/0/text"),Some(&json!("Fixture accepted")));
    let count:Value=client.get(&count_url).send().await.unwrap().json().await.unwrap();
    assert_eq!(count["received_tool_calls"],json!(1));
    let events=std::fs::read_to_string(&audit).unwrap();
    assert!(events.contains("alice") && events.contains("bob"));
    assert!(!events.contains(&allowed));
    let _=std::fs::remove_file(audit);
}
