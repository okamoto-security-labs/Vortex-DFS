//! Experimental MCP Streamable HTTP gateway. Not production-ready.
//! Run behind TLS; bind to loopback by default. Never expose publicly without review.
use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer};
use serde_json::{json, Value};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use openssl::{bn::BigNum, hash::MessageDigest, pkey::{PKey, Public}, rsa::Rsa, sign::Verifier};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, env, fs::{File, OpenOptions}, io::Write, sync::Mutex, time::{Duration, Instant}};
use vortex_dfs::runtime::{
    evaluate_request, IdentityContext, Operation, PayloadContext, RequestContext, RuntimePolicy,
};

struct State {
    upstream: String,
    client_token: Option<String>,
    jwt: Option<JwtConfig>,
    oidc: Option<OidcConfig>,
    client: reqwest::Client,
    readonly_token: Option<String>,
    sessions: Mutex<HashMap<String, Session>>,
    audit: Mutex<File>,
}
struct Session {
    principal: String,
    created: Instant,
    initialized: bool,
    scope_export: bool,
}
struct JwtConfig { key: Vec<u8>, issuer: String, audience: String }
struct OidcConfig { keys: HashMap<String, PKey<Public>>, issuer: String, audience: String }
struct Principal { id: String, scope_export: bool }
const SESSION_TTL: Duration = Duration::from_secs(3600);
const PROTOCOL: &str = "2025-06-18";
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
async fn mcp(req: HttpRequest, body: web::Bytes, state: web::Data<State>) -> HttpResponse {
    let auth = req.headers().get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok()).unwrap_or("");
    let identity = if let Some(oidc) = &state.oidc {
        match auth.strip_prefix("Bearer ").and_then(|t| verify_rs256(t, oidc)) {
            Some(p) => p,
            None => return HttpResponse::Unauthorized().json(json!({"error":"unauthorized"})),
        }
    } else if let Some(jwt) = &state.jwt {
        match auth.strip_prefix("Bearer ").and_then(|t| verify_hs256(t, jwt)) {
            Some(p) => p,
            None => return HttpResponse::Unauthorized().json(json!({"error":"unauthorized"})),
        }
    } else {
        let full = format!("Bearer {}", state.client_token.as_deref().unwrap_or(""));
        let readonly = state.readonly_token.as_ref().map(|t| format!("Bearer {t}"));
        if constant_time_equal(auth.as_bytes(), full.as_bytes()) {
            Principal { id: "exporter".into(), scope_export: true }
        } else if readonly.as_ref().is_some_and(|t| constant_time_equal(auth.as_bytes(),t.as_bytes())) {
            Principal { id: "reader".into(), scope_export: false }
        } else {
            return HttpResponse::Unauthorized().json(json!({"error":"unauthorized"}));
        }
    };
    let principal = identity.id.as_str();
    if body.len() > 65536 { return HttpResponse::PayloadTooLarge().finish(); }
    let request: Value = match serde_json::from_slice::<Value>(&body) {
        Ok(v) if v.is_object() => v,
        _ => return HttpResponse::BadRequest().json(error(Value::Null,-32700,"Invalid JSON-RPC request")),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return HttpResponse::BadRequest().json(error(id,-32600,"Invalid JSON-RPC version"));
    }
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "initialize" {
        if request.pointer("/params/protocolVersion").and_then(Value::as_str) != Some(PROTOCOL) {
            return HttpResponse::Ok().json(error(id,-32602,"Unsupported MCP protocol version"));
        }
        let session_id = uuid::Uuid::new_v4().to_string();
        {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.retain(|_,s| s.created.elapsed() < SESSION_TTL);
            if sessions.len() >= 1024 { return HttpResponse::ServiceUnavailable().finish(); }
            sessions.insert(session_id.clone(), Session { principal: identity.id.clone(), created: Instant::now(), initialized: false, scope_export: identity.scope_export });
        }
        return HttpResponse::Ok().insert_header(("Mcp-Session-Id", session_id))
            .json(json!({"jsonrpc":"2.0","id":id,"result":{
                "protocolVersion":PROTOCOL,"capabilities":{"tools":{}},
                "serverInfo":{"name":"vortex-mcp-gateway-proof","version":"0.2.0"}
            }}));
    }
    let session_id = req.headers().get("Mcp-Session-Id").and_then(|h| h.to_str().ok()).unwrap_or("");
    let session_ok = {
        let mut sessions = state.sessions.lock().unwrap();
        match sessions.get_mut(session_id) {
            Some(session) if session.principal == principal && session.scope_export == identity.scope_export && session.created.elapsed() < SESSION_TTL => {
                if method == "notifications/initialized" { session.initialized = true; true }
                else { session.initialized }
            }
            _ => false
        }
    };
    if !session_ok {
        return HttpResponse::BadRequest().json(error(id,-32001,"Missing, expired, or uninitialized MCP session"));
    }
    if method == "notifications/initialized" {
        if request.get("id").is_some() { return HttpResponse::BadRequest().finish(); }
        return HttpResponse::Accepted().finish();
    }
    if request.get("id").is_none() { return HttpResponse::BadRequest().finish(); }
    if method == "tools/list" {
        return HttpResponse::Ok().json(json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{
            "name":"crm_export","description":"Isolated fixture export",
            "inputSchema":{"type":"object","properties":{"customer_group":{"type":"string"}},
            "required":["customer_group"]}
        }]}}));
    }
    if method != "tools/call" {
        return HttpResponse::Ok().json(error(id,-32601,"Unsupported MCP method"));
    }
    if request.pointer("/params/name").and_then(Value::as_str) != Some("crm_export")
        || request.pointer("/params/arguments/customer_group").and_then(Value::as_str).is_none()
    {
        return HttpResponse::Ok().json(error(id,-32602,"Invalid or disallowed tool"));
    }
    let policy = RuntimePolicy::new("mcp.remote-proof", "2")
        .allow_operation(Operation::AgentToolExecution)
        .with_required_scope("crm:export")
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(false)
        .with_fail_closed(true);
    let scope_export = identity.scope_export;
    let mut identity = IdentityContext::new(principal,if state.oidc.is_some() {"oidc-rs256"} else if state.jwt.is_some() {"jwt-hs256"} else {"gateway-static-credential"},true);
    if scope_export { identity = identity.with_scope("crm:export"); }
    let mut context = RequestContext::new(uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(), Operation::AgentToolExecution,
        PayloadContext::new(body.len()).with_content_type("application/json"))
        .with_identity(identity);
    context.evidence.set_structural_validity(true);
    let evaluation = evaluate_request(context, &policy);
    // Persist a minimal decision record before forwarding any external effect.
    // Failure to write OR sync the record is fail-closed.
    let event = json!({
        "event_id": uuid::Uuid::new_v4().to_string(),
        "request_id": evaluation.context.request_id,
        "principal": principal,
        "tool": "crm_export",
        "decision": evaluation.decision.outcome.as_str(),
        "reason_code": evaluation.decision.reason_code.as_str(),
        "session_id": session_id,
    });
    let audited = (|| -> std::io::Result<()> {
        let mut audit = state.audit.lock().map_err(|_| std::io::Error::other("audit lock poisoned"))?;
        writeln!(audit, "{event}")?;
        audit.sync_data()
    })();
    if audited.is_err() {
        log::error!("MCP audit persistence failed; blocking execution");
        return HttpResponse::ServiceUnavailable().json(error(id,-32004,"Audit unavailable"));
    }
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
/// Verify RS256 JWTs against a pinned startup JWKS snapshot. No alg fallback.
fn verify_rs256(token: &str, cfg: &OidcConfig) -> Option<Principal> {
    if token.len() > 8192 { return None; }
    let mut parts = token.split('.');
    let h = parts.next()?; let p = parts.next()?; let sig = parts.next()?;
    if parts.next().is_some() { return None; }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    if header.get("alg")?.as_str()? != "RS256" || header.get("typ")?.as_str()? != "JWT" { return None; }
    let kid = header.get("kid")?.as_str()?;
    let key = cfg.keys.get(kid)?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), key).ok()?;
    verifier.update(format!("{h}.{p}").as_bytes()).ok()?;
    if !verifier.verify(&URL_SAFE_NO_PAD.decode(sig).ok()?).ok()? { return None; }
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    validate_claims(&claims, &cfg.issuer, &cfg.audience)
}
fn validate_claims(claims: &Value, issuer: &str, audience: &str) -> Option<Principal> {
    if claims.get("iss")?.as_str()? != issuer { return None; }
    let aud = claims.get("aud")?;
    let audience_ok = aud.as_str() == Some(audience) ||
        aud.as_array().is_some_and(|arr| arr.iter().any(|v| v.as_str()==Some(audience)));
    if !audience_ok { return None; }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let exp = claims.get("exp")?.as_u64()?;
    if exp <= now || exp > now.saturating_add(3600) { return None; }
    if claims.get("nbf").is_some_and(|v| v.as_u64().is_none_or(|n| n > now)) { return None; }
    if claims.get("iat").is_some_and(|v| v.as_u64().is_none_or(|n| n > now)) { return None; }
    let sub = claims.get("sub")?.as_str()?;
    if sub.is_empty() || sub.len() > 128 { return None; }
    let scopes = claims.get("scope")?.as_str()?;
    Some(Principal { id: sub.to_string(),
        scope_export: scopes.split_whitespace().any(|s| s=="crm:export") })
}
fn parse_jwks(value: &Value, issuer: String, audience: String) -> Result<OidcConfig, String> {
    let entries = value.get("keys").and_then(Value::as_array).ok_or("JWKS keys missing")?;
    if entries.len() > 32 { return Err("JWKS exceeds 32 keys".into()); }
    let mut keys = HashMap::new();
    for entry in entries {
        if entry.get("kty").and_then(Value::as_str) != Some("RSA")
            || entry.get("alg").and_then(Value::as_str) != Some("RS256")
            || entry.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") { continue; }
        let kid = entry.get("kid").and_then(Value::as_str).ok_or("kid missing")?;
        if kid.is_empty() || kid.len() > 128 || keys.contains_key(kid) { return Err("duplicate/invalid kid".into()); }
        let n = URL_SAFE_NO_PAD.decode(entry.get("n").and_then(Value::as_str).ok_or("n missing")?)
            .map_err(|_| "invalid modulus")?;
        let e = URL_SAFE_NO_PAD.decode(entry.get("e").and_then(Value::as_str).ok_or("e missing")?)
            .map_err(|_| "invalid exponent")?;
        if n.len() < 256 || n.len() > 512 || e.is_empty() || e.len() > 8 { return Err("unsupported RSA key size".into()); }
        let rsa = Rsa::from_public_components(
            BigNum::from_slice(&n).map_err(|_| "invalid n")?,
            BigNum::from_slice(&e).map_err(|_| "invalid e")?
        ).map_err(|_| "invalid RSA key")?;
        let key = PKey::from_rsa(rsa).map_err(|_| "invalid RSA public key")?;
        keys.insert(kid.to_string(), key);
    }
    if keys.is_empty() { return Err("no usable RS256 keys".into()); }
    Ok(OidcConfig { keys, issuer, audience })
}
async fn load_oidc_config(client: &reqwest::Client) -> Option<OidcConfig> {
    let issuer = env::var("VORTEX_MCP_OIDC_ISSUER").ok()?;
    let audience = env::var("VORTEX_MCP_OIDC_AUDIENCE").expect("OIDC audience required");
    let jwks_url = env::var("VORTEX_MCP_OIDC_JWKS_URL").expect("OIDC JWKS URL required");
    let url = reqwest::Url::parse(&jwks_url).expect("valid JWKS URL");
    let loopback = url.scheme() == "http"
        && matches!(url.host_str(),Some("127.0.0.1")|Some("localhost")|Some("::1"));
    assert!(url.scheme()=="https" || loopback, "JWKS must use HTTPS or loopback test HTTP");
    assert!(url.username().is_empty() && url.password().is_none() && url.fragment().is_none());
    let response = client.get(url).send().await.expect("JWKS fetch failed");
    assert!(response.status().is_success(), "JWKS fetch HTTP failure");
    let body = response.bytes().await.expect("JWKS body unavailable");
    assert!(body.len() <= 65536, "JWKS body too large");
    let data: Value = serde_json::from_slice(&body).expect("invalid JWKS JSON");
    Some(parse_jwks(&data, issuer, audience).expect("invalid JWKS"))
}
/// Strict single-algorithm JWT proof verifier. No OIDC discovery or JWKS support.
fn verify_hs256(token: &str, cfg: &JwtConfig) -> Option<Principal> {
    if token.len() > 8192 { return None; }
    let mut parts = token.split('.');
    let h = parts.next()?;
    let p = parts.next()?;
    let sig = parts.next()?;
    if parts.next().is_some() { return None; }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    if header.get("alg")?.as_str()? != "HS256" || header.get("typ")?.as_str()? != "JWT" { return None; }
    let mut mac = Hmac::<Sha256>::new_from_slice(&cfg.key).ok()?;
    mac.update(format!("{h}.{p}").as_bytes());
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(sig).ok()?).ok()?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    if claims.get("iss")?.as_str()? != cfg.issuer { return None; }
    let aud = claims.get("aud")?;
    let audience_ok = aud.as_str() == Some(&cfg.audience) ||
        aud.as_array().is_some_and(|arr| arr.iter().any(|v| v.as_str()==Some(&cfg.audience)));
    if !audience_ok { return None; }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let exp = claims.get("exp")?.as_u64()?;
    if exp <= now || exp > now.saturating_add(3600) { return None; }
    if claims.get("nbf").is_some_and(|v| v.as_u64().is_none_or(|n| n > now)) { return None; }
    if claims.get("iat").is_some_and(|v| v.as_u64().is_none_or(|n| n > now)) { return None; }
    let sub = claims.get("sub")?.as_str()?;
    if sub.is_empty() || sub.len()>128 { return None; }
    let scopes = claims.get("scope")?.as_str()?;
    Some(Principal { id: sub.to_string(),
        scope_export: scopes.split_whitespace().any(|s| s=="crm:export") })
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
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let oidc = load_oidc_config(&client).await;
    if oidc.is_some() {
        assert!(env::var("VORTEX_MCP_JWT_HS256_SECRET").is_err()
            && env::var("VORTEX_MCP_CLIENT_TOKEN").is_err(),
            "OIDC mode must not be combined with other auth modes");
    }
    let jwt = match env::var("VORTEX_MCP_JWT_HS256_SECRET") {
        Ok(secret) => {
            assert!(secret.len() >= 32, "JWT secret must be at least 32 bytes");
            Some(JwtConfig { key: secret.into_bytes(),
                issuer: env::var("VORTEX_MCP_JWT_ISSUER").expect("JWT issuer required"),
                audience: env::var("VORTEX_MCP_JWT_AUDIENCE").expect("JWT audience required") })
        }
        Err(_) => None,
    };
    let (client_token, readonly_token) = if oidc.is_some() { (None, None) } else if jwt.is_some() {
        assert!(env::var("VORTEX_MCP_CLIENT_TOKEN").is_err(),
            "do not combine JWT mode with static credentials");
        (None, None)
    } else {
        let token = env::var("VORTEX_MCP_CLIENT_TOKEN").expect("static token required in proof mode");
        assert!(token.len() >= 32, "token too short");
        let readonly = env::var("VORTEX_MCP_READONLY_TOKEN").ok();
        if let Some(ref t) = readonly { assert!(t.len() >= 32 && t != &token); }
        (Some(token), readonly)
    };
    // Required append-only local audit sink for the isolated proof. For real
    // production, use a durable managed store with tamper evidence and rotation.
    let audit_path = env::var("VORTEX_MCP_AUDIT_PATH").expect("VORTEX_MCP_AUDIT_PATH required");
    let audit = OpenOptions::new().create(true).append(true).open(&audit_path)
        .expect("open audit sink");
    let state = web::Data::new(State {upstream, client_token, readonly_token, jwt, oidc, client,
        sessions: Mutex::new(HashMap::new()), audit: Mutex::new(audit)});
    let listen_port: u16 = env::var("VORTEX_MCP_LISTEN_PORT").ok()
        .map(|p| p.parse().expect("valid listen port")).unwrap_or(8788);
    HttpServer::new(move || App::new().app_data(state.clone())
        .app_data(web::PayloadConfig::new(65536))
        .route("/mcp",web::post().to(mcp)))
        .bind(("127.0.0.1",listen_port))?.run().await
}

#[cfg(test)]
mod jwt_tests {
    use super::*;
    fn sign(claims: Value, key: &[u8]) -> String {
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let p = URL_SAFE_NO_PAD.encode(claims.to_string());
        let input = format!("{h}.{p}");
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{input}.{signature}")
    }
    #[test]
    fn jwt_verifies_signature_claims_and_scopes() {
        let cfg = JwtConfig { key: b"proof-key-32-bytes-or-longer-123456".to_vec(),
            issuer: "https://issuer.example".into(), audience: "vortex-gateway".into() };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = json!({"iss":cfg.issuer,"aud":cfg.audience,"sub":"alice",
            "exp":now+300,"nbf":now-1,"scope":"crm:export other"});
        let token = sign(claims.clone(),&cfg.key);
        let verified = verify_hs256(&token,&cfg).unwrap();
        assert_eq!(verified.id,"alice");
        assert!(verified.scope_export);
        let mut tampered = claims.clone();
        tampered["sub"] = json!("mallory");
        let altered_payload = URL_SAFE_NO_PAD.encode(tampered.to_string());
        let mut pieces = token.split('.');
        let header = pieces.next().unwrap();
        let _payload = pieces.next().unwrap();
        let signature = pieces.next().unwrap();
        assert!(verify_hs256(&format!("{header}.{altered_payload}.{signature}"),&cfg).is_none());
        let mut expired = claims.clone(); expired["exp"] = json!(now-1);
        assert!(verify_hs256(&sign(expired,&cfg.key),&cfg).is_none());
        let mut future = claims.clone(); future["nbf"] = json!(now+500);
        assert!(verify_hs256(&sign(future,&cfg.key),&cfg).is_none());
        let mut wrong_aud = claims.clone(); wrong_aud["aud"] = json!("wrong");
        assert!(verify_hs256(&sign(wrong_aud,&cfg.key),&cfg).is_none());
        let mut readonly = claims.clone(); readonly["scope"] = json!("crm:read");
        assert!(!verify_hs256(&sign(readonly,&cfg.key),&cfg).unwrap().scope_export);
        let none_alg = claims; 
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let p = URL_SAFE_NO_PAD.encode(none_alg.to_string());
        assert!(verify_hs256(&format!("{h}.{p}."),&cfg).is_none());
    }
}
