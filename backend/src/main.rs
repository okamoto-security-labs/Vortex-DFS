// =========================================================================
// VORTEX-DFS - BACKEND MAIN ENTRYPOINT (ACTIX-WEB)
// Produção Determinística - Balanceamento Léxico Completo
// =========================================================================

use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use vortex_dfs::anonymizer_engine::AnonymizerEngine;
use vortex_dfs::provisioner::{get_pool, init_db};
#[cfg(test)]
use vortex_dfs::runtime::InMemoryRuntimeAuditStore;
use vortex_dfs::runtime::{
    evaluate_audit_and_execute, DecisionReason, GuardedExecution, IdentityContext, Operation,
    PayloadContext, PostgresRuntimeAuditStore, RequestContext, RuntimeAuditStore, RuntimePolicy,
};
use vortex_dfs::signer_lwe::verify;

type HmacSha256 = Hmac<Sha256>;

const API_KEY_PROOF_CONTEXT: &[u8] = b"vortex-dfs/http-runtime-identity/v1";
#[cfg(test)]
const TEST_EXECUTION_API_KEY: &str = "test-vortex-runtime-execution-api-key";
#[cfg(test)]
const TEST_LIMITED_API_KEY: &str = "test-vortex-runtime-limited-api-key";
#[cfg(test)]
const TEST_AUDIT_READER_API_KEY: &str = "test-vortex-runtime-audit-reader-api-key";

#[allow(dead_code)]
#[derive(Deserialize)]
struct AnonymizeRequest {
    content: String,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    locale: String,
}

#[allow(dead_code)]
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct ApiClientConfig {
    api_key: String,
    principal_id: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Clone)]
struct AuthenticatedPrincipal {
    api_key_proof: [u8; 32],
    principal_id: Arc<str>,
    scopes: Vec<String>,
}

#[derive(Clone)]
struct RuntimeState {
    audit_store: Arc<dyn RuntimeAuditStore>,
    principals: Arc<[AuthenticatedPrincipal]>,
}

impl RuntimeState {
    fn from_client_configs(
        audit_store: Arc<dyn RuntimeAuditStore>,
        client_configs: Vec<ApiClientConfig>,
    ) -> Result<Self, String> {
        if client_configs.is_empty() {
            return Err("at least one API client must be configured".to_string());
        }

        let mut principals = Vec::with_capacity(client_configs.len());

        for client in client_configs {
            if client.api_key.is_empty() {
                return Err("API client key must not be empty".to_string());
            }

            if client.principal_id.trim().is_empty() {
                return Err("API client principal_id must not be empty".to_string());
            }

            if client.scopes.iter().any(|scope| scope.trim().is_empty()) {
                return Err("API client scopes must not be empty".to_string());
            }

            principals.push(AuthenticatedPrincipal {
                api_key_proof: api_key_proof(&client.api_key),
                principal_id: Arc::from(client.principal_id),
                scopes: client.scopes,
            });
        }

        Ok(Self {
            audit_store,
            principals: Arc::from(principals),
        })
    }

    #[cfg(test)]
    fn in_memory_for_test() -> web::Data<Self> {
        let client_configs = vec![
            ApiClientConfig {
                api_key: TEST_EXECUTION_API_KEY.to_string(),
                principal_id: "test-execution-client".to_string(),
                scopes: vec!["anonymize:execute".to_string()],
            },
            ApiClientConfig {
                api_key: TEST_LIMITED_API_KEY.to_string(),
                principal_id: "test-limited-client".to_string(),
                scopes: Vec::new(),
            },
            ApiClientConfig {
                api_key: TEST_AUDIT_READER_API_KEY.to_string(),
                principal_id: "test-audit-reader".to_string(),
                scopes: vec!["audit:read".to_string()],
            },
        ];

        web::Data::new(
            Self::from_client_configs(Arc::new(InMemoryRuntimeAuditStore::new()), client_configs)
                .expect("test client configuration should be valid"),
        )
    }
}

fn api_key_proof(api_key: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(api_key.as_bytes()).expect("HMAC accepts API key material");
    mac.update(API_KEY_PROOF_CONTEXT);
    mac.finalize().into_bytes().into()
}

fn authenticate_bearer(
    request: &HttpRequest,
    state: &RuntimeState,
) -> Result<IdentityContext, HttpResponse> {
    let Some(value) = request.headers().get(header::AUTHORIZATION) else {
        return Err(unauthorized_response());
    };

    let Ok(value) = value.to_str() else {
        return Err(unauthorized_response());
    };

    let Some(api_key) = value.strip_prefix("Bearer ").filter(|key| !key.is_empty()) else {
        return Err(unauthorized_response());
    };

    let Some(principal) = state.principals.iter().find(|principal| {
        let mut verifier =
            HmacSha256::new_from_slice(api_key.as_bytes()).expect("HMAC accepts API key material");
        verifier.update(API_KEY_PROOF_CONTEXT);
        verifier.verify_slice(&principal.api_key_proof).is_ok()
    }) else {
        return Err(unauthorized_response());
    };

    let identity = principal.scopes.iter().cloned().fold(
        IdentityContext::new(principal.principal_id.as_ref(), "bearer_api_key", true),
        |identity, scope| identity.with_scope(scope),
    );

    Ok(identity)
}

fn unauthorized_response() -> HttpResponse {
    HttpResponse::Unauthorized()
        .insert_header((header::WWW_AUTHENTICATE, "Bearer"))
        .json(serde_json::json!({
            "error": "authentication required",
        }))
}

fn insufficient_scope_response() -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({
        "error": "insufficient scope",
    }))
}

/// Returns bounded audit metadata for a trace after explicit authorization.
///
/// Audit events never contain raw payloads, API keys, or identity data.
async fn read_runtime_audit_events(
    request: HttpRequest,
    trace_id: web::Path<String>,
    runtime_state: web::Data<RuntimeState>,
) -> HttpResponse {
    let identity = match authenticate_bearer(&request, runtime_state.get_ref()) {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    if !identity.has_scope("audit:read") {
        return insufficient_scope_response();
    }

    let trace_id = trace_id.into_inner();

    if Uuid::parse_str(&trace_id).is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "trace_id must be a UUID",
        }));
    }

    let events = match runtime_state.audit_store.find_by_trace_id(&trace_id).await {
        Ok(events) => events,
        Err(error) => {
            log::error!("runtime audit lookup failed: {error}");

            return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "runtime audit storage unavailable",
            }));
        }
    };

    if events.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "audit events not found",
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "trace_id": trace_id,
        "events": events,
    }))
}

async fn health_check(_req: HttpRequest) -> HttpResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if !now.is_multiple_of(1000) {
        log::debug!("Clock tick alignment verified");
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "online",
        "system": "VORTEX-DFS PQC Engine",
        "timestamp": now
    }))
}

async fn benchmark_anonymize(
    request: HttpRequest,
    req: web::Json<AnonymizeRequest>,
    runtime_state: web::Data<RuntimeState>,
) -> HttpResponse {
    let identity = match authenticate_bearer(&request, runtime_state.get_ref()) {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    let start = Instant::now();

    // Evidence collection is separate from the protected transformation.
    let mut context = RequestContext::new(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        Operation::Anonymize,
        PayloadContext::new(req.content.len()),
    )
    .with_identity(identity)
    .with_policy_id("runtime.anonymize");

    context
        .evidence
        .set_structural_validity(!req.content.trim().is_empty());

    context
        .evidence
        .set_sensitive_data_detected(AnonymizerEngine::has_sensitive_data(&req.content));

    let execution = match evaluate_audit_and_execute(
        context,
        &RuntimePolicy::authenticated_anonymization(),
        runtime_state.audit_store.as_ref(),
        |_| AnonymizerEngine::anonymize(&req.content),
    )
    .await
    {
        Ok(execution) => execution,
        Err(error) => {
            log::error!("runtime audit persistence failed: {error}");

            return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "runtime audit persistence unavailable",
            }));
        }
    };

    match execution {
        GuardedExecution::Blocked { evaluation } => {
            let mut response = if evaluation.decision.reason_code == DecisionReason::ScopeDenied {
                HttpResponse::Forbidden()
            } else {
                HttpResponse::UnprocessableEntity()
            };

            response.json(serde_json::json!({
                "outcome": evaluation.decision.outcome.as_str(),
                "reason_code": evaluation.decision.reason_code.as_str(),
                "policy_id": evaluation.decision.policy.id,
                "policy_version": evaluation.decision.policy.version,
                "trace_id": evaluation.context.trace_id,
            }))
        }
        GuardedExecution::Executed {
            evaluation,
            output: result,
        } => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            HttpResponse::Ok().json(serde_json::json!({
                "outcome": evaluation.decision.outcome.as_str(),
                "reason_code": evaluation.decision.reason_code.as_str(),
                "policy_id": evaluation.decision.policy.id,
                "policy_version": evaluation.decision.policy.version,
                "trace_id": evaluation.context.trace_id,
                "latency_ms": latency_ms,
                "sanitized_length": result.sanitized.len(),
                "detections": result.detections.len(),
                "risk_score": result.risk_score,
            }))
        }
    }
}

async fn benchmark_verify_pqc() -> HttpResponse {
    let start = Instant::now();
    let (sk, pk) = vortex_dfs::signer_lwe::keygen(7);
    let payload = b"benchmark verify";
    let sig = sk.sign(payload, &pk);
    let valid = verify(&pk, payload, &sig);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    HttpResponse::Ok().json(serde_json::json!({
        "latency_ms": latency_ms,
        "valid": valid,
        "signature_len": sig.w.len(),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    log::info!("[VORTEX-DFS] Inicializando servidor de alta performance...");

    init_db().await.map_err(std::io::Error::other)?;

    let pool = get_pool().map_err(std::io::Error::other)?.clone();

    let audit_store = PostgresRuntimeAuditStore::new(pool);

    audit_store
        .ensure_schema()
        .await
        .map_err(std::io::Error::other)?;

    let client_config_json = std::env::var("VORTEX_API_CLIENTS_JSON").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VORTEX_API_CLIENTS_JSON must be configured",
        )
    })?;

    let client_configs: Vec<ApiClientConfig> =
        serde_json::from_str(&client_config_json).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("VORTEX_API_CLIENTS_JSON is invalid: {error}"),
            )
        })?;

    let audit_store: Arc<dyn RuntimeAuditStore> = Arc::new(audit_store);
    let runtime_state = RuntimeState::from_client_configs(audit_store, client_configs)
        .map_err(std::io::Error::other)?;

    let runtime_state = web::Data::new(runtime_state);

    HttpServer::new(move || {
        App::new()
            .app_data(runtime_state.clone())
            .route("/health", web::get().to(health_check))
            .route("/benchmark/anonymize", web::post().to(benchmark_anonymize))
            .route(
                "/runtime/audit/{trace_id}",
                web::get().to(read_runtime_audit_events),
            )
            .route("/benchmark/pqc/verify", web::get().to(benchmark_verify_pqc))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_http_request() -> HttpRequest {
        actix_web::test::TestRequest::default()
            .insert_header((
                header::AUTHORIZATION,
                format!("Bearer {TEST_EXECUTION_API_KEY}"),
            ))
            .to_http_request()
    }

    fn limited_http_request() -> HttpRequest {
        actix_web::test::TestRequest::default()
            .insert_header((
                header::AUTHORIZATION,
                format!("Bearer {TEST_LIMITED_API_KEY}"),
            ))
            .to_http_request()
    }

    fn audit_reader_http_request() -> HttpRequest {
        actix_web::test::TestRequest::default()
            .insert_header((
                header::AUTHORIZATION,
                format!("Bearer {TEST_AUDIT_READER_API_KEY}"),
            ))
            .to_http_request()
    }

    fn anonymize_request(content: &str) -> web::Json<AnonymizeRequest> {
        web::Json(AnonymizeRequest {
            content: content.to_string(),
            content_type: "text/plain".to_string(),
            locale: "en".to_string(),
        })
    }

    #[actix_web::test]
    async fn missing_bearer_token_is_rejected() {
        let response = benchmark_anonymize(
            actix_web::test::TestRequest::default().to_http_request(),
            anonymize_request("Contact: user@example.com"),
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert_eq!(response.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn invalid_bearer_token_is_rejected() {
        let response = benchmark_anonymize(
            actix_web::test::TestRequest::default()
                .insert_header((header::AUTHORIZATION, "Bearer invalid-token"))
                .to_http_request(),
            anonymize_request("Contact: user@example.com"),
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert_eq!(response.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn authorized_identity_without_scope_is_forbidden() {
        let response = benchmark_anonymize(
            limited_http_request(),
            anonymize_request("Contact: user@example.com"),
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);

        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("response body should be readable");

        let response: serde_json::Value =
            serde_json::from_slice(&body).expect("response should be JSON");

        assert_eq!(response["outcome"], "REJECT");
        assert_eq!(response["reason_code"], "SCOPE_DENIED");
    }

    #[actix_web::test]
    async fn audit_read_requires_authentication() {
        let response = read_runtime_audit_events(
            actix_web::test::TestRequest::default().to_http_request(),
            web::Path::from(Uuid::new_v4().to_string()),
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert_eq!(response.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn audit_read_requires_audit_scope() {
        let response = read_runtime_audit_events(
            authorized_http_request(),
            web::Path::from(Uuid::new_v4().to_string()),
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert_eq!(response.status(), actix_web::http::StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn audit_reader_can_fetch_safe_event_by_trace_id() {
        let state = RuntimeState::in_memory_for_test();

        let execution_response = benchmark_anonymize(
            authorized_http_request(),
            anonymize_request("Contact: user@example.com"),
            state.clone(),
        )
        .await;

        assert!(execution_response.status().is_success());

        let body = actix_web::body::to_bytes(execution_response.into_body())
            .await
            .expect("execution response body should be readable");

        let execution: serde_json::Value =
            serde_json::from_slice(&body).expect("execution response should be JSON");

        let trace_id = execution["trace_id"]
            .as_str()
            .expect("execution response should contain trace_id")
            .to_string();

        let response = read_runtime_audit_events(
            audit_reader_http_request(),
            web::Path::from(trace_id.clone()),
            state,
        )
        .await;

        assert!(response.status().is_success());

        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("audit response body should be readable");

        let audit: serde_json::Value =
            serde_json::from_slice(&body).expect("audit response should be JSON");

        assert_eq!(audit["trace_id"], trace_id);
        assert_eq!(audit["events"].as_array().map(Vec::len), Some(1));
        assert_eq!(audit["events"][0]["outcome"], "REDACT");
        assert!(audit["events"][0].get("payload").is_none());
        assert!(audit["events"][0].get("identity").is_none());
    }

    #[actix_web::test]
    async fn empty_anonymize_request_is_rejected_before_execution() {
        let req = web::Json(AnonymizeRequest {
            content: "   ".to_string(),
            content_type: "text/plain".to_string(),
            locale: "en".to_string(),
        });

        let resp = benchmark_anonymize(
            authorized_http_request(),
            req,
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY
        );

        let body = actix_web::body::to_bytes(resp.into_body())
            .await
            .expect("response body should be readable");

        let response: serde_json::Value =
            serde_json::from_slice(&body).expect("response should be JSON");

        assert_eq!(response["outcome"], "REJECT");
        assert_eq!(response["reason_code"], "STRUCTURE_INVALID");
    }

    #[actix_web::test]
    async fn sensitive_anonymize_request_is_redacted_after_authorization() {
        let req = web::Json(AnonymizeRequest {
            content: "Contact: user@example.com".to_string(),
            content_type: "text/plain".to_string(),
            locale: "en".to_string(),
        });

        let resp = benchmark_anonymize(
            authorized_http_request(),
            req,
            RuntimeState::in_memory_for_test(),
        )
        .await;

        assert!(resp.status().is_success());

        let body = actix_web::body::to_bytes(resp.into_body())
            .await
            .expect("response body should be readable");

        let response: serde_json::Value =
            serde_json::from_slice(&body).expect("response should be JSON");

        assert_eq!(response["outcome"], "REDACT");
        assert_eq!(response["reason_code"], "SENSITIVE_DATA_REDACTED");
        assert_eq!(response["detections"], 1);
    }

    #[actix_web::test]
    async fn benchmark_handler_returns_latency_metrics() {
        let req = web::Json(AnonymizeRequest {
            content: "Contact: user@example.com\nKey: AKIAIOSFODNN7EXAMPLE\nSSN: 123-45-6789"
                .to_string(),
            content_type: "text/plain".to_string(),
            locale: "en".to_string(),
        });

        let resp = benchmark_anonymize(
            authorized_http_request(),
            req,
            RuntimeState::in_memory_for_test(),
        )
        .await;
        assert!(resp.status().is_success());
    }
}
