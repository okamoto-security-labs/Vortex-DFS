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
fn jwt(key:&PKey<openssl::pkey::Private>,issuer:&str,kid:&str,sub:&str,scope:&str,exp:u64)->String {
    let h=URL_SAFE_NO_PAD.encode(json!({"alg":"RS256","typ":"JWT","kid":kid}).to_string());
    let p=URL_SAFE_NO_PAD.encode(json!({"iss":issuer,"aud":"vortex-test",
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
    let issuer=format!("http://127.0.0.1:{upstream_port}");
    let jwks_file=std::env::temp_dir().join(format!("vortex-jwks-{}.json",uuid::Uuid::new_v4()));
    std::fs::write(&jwks_file,jwks.to_string()).unwrap();
    let script=format!("{}/../docs/mcp-security-proof/http_mcp_fixture.py",env!("CARGO_MANIFEST_DIR"));
    let _upstream=Guard(Command::new("python3").arg("-u").arg(script)
        .env("VORTEX_MCP_FIXTURE_PORT",upstream_port.to_string())
        .env("VORTEX_TEST_JWKS_FILE",&jwks_file)
        .env("VORTEX_TEST_ISSUER",&issuer)
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let client=reqwest::Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
    let count_url=format!("http://127.0.0.1:{upstream_port}/_count");
    ready(&client,&count_url).await;
    let audit=std::env::temp_dir().join(format!("vortex-oidc-{}.jsonl",uuid::Uuid::new_v4()));
    let _gateway=Guard(Command::new(env!("CARGO_BIN_EXE_mcp_gateway"))
        .env("VORTEX_MCP_UPSTREAM",format!("http://127.0.0.1:{upstream_port}/mcp"))
        .env("VORTEX_MCP_LISTEN_PORT",gateway_port.to_string())
        .env("VORTEX_MCP_AUDIT_PATH",&audit)
        .env("VORTEX_MCP_OIDC_ISSUER",&issuer)
        .env("VORTEX_MCP_OIDC_AUDIENCE","vortex-test")
        .env("VORTEX_MCP_OIDC_REFRESH_SECS","5")
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let endpoint=format!("http://127.0.0.1:{gateway_port}/mcp");
    ready(&client,&endpoint).await;
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let allowed=jwt(&key,&issuer,"test-rsa-key","alice","crm:export",now+300);
    let readonly=jwt(&key,&issuer,"test-rsa-key","bob","crm:read",now+300);
    let expired=jwt(&key,&issuer,"test-rsa-key","eve","crm:export",now-1);
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
    // Independent Python stdlib client, separate from Rust reqwest test driver.
    let probe=format!("{}/../docs/mcp-security-proof/mcp_client_probe.py",env!("CARGO_MANIFEST_DIR"));
    for (token,decision) in [(&allowed,"ALLOW"),(&readonly,"REJECT")] {
        let output=Command::new("python3").arg(&probe).arg(&endpoint).arg(token).arg(decision)
            .output().expect("launch independent Python MCP client");
        assert!(output.status.success(),"Python probe failed: {}",
            String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("\"verified\": true"));
    }
    let count:Value=client.get(&count_url).send().await.unwrap().json().await.unwrap();
    assert_eq!(count["received_tool_calls"],json!(2),"independent client forwarding mismatch");
    // Real SDK interoperability: a separate Python process uses the official
    // MCP Python ClientSession + Streamable HTTP transport.
    let sdk_probe=format!("{}/../docs/mcp-security-proof/mcp_sdk_probe.py",env!("CARGO_MANIFEST_DIR"));
    for (token,decision) in [(&allowed,"ALLOW"),(&readonly,"REJECT")] {
        let output=Command::new("python3").arg(&sdk_probe).arg(&endpoint).arg(token).arg(decision)
            .output().expect("launch official MCP Python SDK client");
        assert!(output.status.success(),"official SDK interoperability failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("\"verified\": true"));
    }
    let count:Value=client.get(&count_url).send().await.unwrap().json().await.unwrap();
    assert_eq!(count["received_tool_calls"],json!(3),"official SDK forwarding mismatch");
    // Rotate to a second signing key and confirm that old key stops authorizing.
    let new_rsa=Rsa::generate(2048).unwrap();
    let new_n=URL_SAFE_NO_PAD.encode(new_rsa.n().to_vec());
    let new_e=URL_SAFE_NO_PAD.encode(new_rsa.e().to_vec());
    let new_key=PKey::from_rsa(new_rsa).unwrap();
    let rotated=json!({"keys":[{"kty":"RSA","alg":"RS256","use":"sig",
        "kid":"rotated-key","n":new_n,"e":new_e}]});
    std::fs::write(&jwks_file,rotated.to_string()).unwrap();
    let rotated_token=jwt(&new_key,&issuer,"rotated-key","carol","crm:export",now+300);
    let mut rotated_session=None;
    for _ in 0..35 {
        let init=json!({"jsonrpc":"2.0","id":22,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rotation","version":"1"}}});
        let response=client.post(&endpoint).bearer_auth(&rotated_token)
            .json(&init).send().await.unwrap();
        if response.status()==reqwest::StatusCode::OK {
            rotated_session=Some(response.headers().get("mcp-session-id").unwrap()
                .to_str().unwrap().to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let carol_session=rotated_session.expect("rotated JWKS key was not loaded");
    let old=client.post(&endpoint).bearer_auth(&allowed)
        .json(&call).send().await.unwrap();
    assert_eq!(old.status(),reqwest::StatusCode::UNAUTHORIZED,"revoked old key accepted");
    let notification=json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    assert_eq!(client.post(&endpoint).bearer_auth(&rotated_token)
        .header("mcp-session-id",&carol_session).json(&notification)
        .send().await.unwrap().status(),reqwest::StatusCode::ACCEPTED);
    let after_rotation:Value=client.post(&endpoint).bearer_auth(&rotated_token)
        .header("mcp-session-id",&carol_session).json(&call)
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(after_rotation.pointer("/result/content/0/text"),Some(&json!("Fixture accepted")));
    let count:Value=client.get(&count_url).send().await.unwrap().json().await.unwrap();
    assert_eq!(count["received_tool_calls"],json!(4));
    let events=std::fs::read_to_string(&audit).unwrap();
    assert!(events.contains("alice") && events.contains("bob"));
    assert!(!events.contains(&allowed));
    let _=std::fs::remove_file(audit);
    let _=std::fs::remove_file(jwks_file);
}
