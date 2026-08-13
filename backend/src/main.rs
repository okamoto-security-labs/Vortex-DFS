// =========================================================================
// VORTEX-DFS - BACKEND MAIN ENTRYPOINT (ACTIX-WEB)
// Produção Determinística - Balanceamento Léxico Completo
// =========================================================================

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use vortex_dfs::anonymizer_engine::AnonymizerEngine;
use vortex_dfs::provisioner::{get_pool, init_db};
use vortex_dfs::runtime::{
    evaluate_audit_and_execute, GuardedExecution, Operation,
    PayloadContext, PostgresRuntimeAuditStore, RequestContext, RuntimeAuditStore, RuntimePolicy,
};
use vortex_dfs::signer_lwe::verify;
#[cfg(test)]
use vortex_dfs::runtime::InMemoryRuntimeAuditStore;

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

#[derive(Clone)]
struct AuditState {
    store: Arc<dyn RuntimeAuditStore>,
}

impl AuditState {
    #[cfg(test)]
    fn in_memory_for_test() -> web::Data<Self> {
        web::Data::new(Self {
            store: Arc::new(InMemoryRuntimeAuditStore::new()),
        })
    }
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
    req: web::Json<AnonymizeRequest>,
    audit_state: web::Data<AuditState>,
) -> HttpResponse {
    let start = Instant::now();

    // Evidence collection is separate from the protected transformation.
    let mut context = RequestContext::new(
        Uuid::new_v4().to_string(),
        Uuid::new_v4().to_string(),
        Operation::Anonymize,
        PayloadContext::new(req.content.len()),
    )
    .with_policy_id("benchmark.anonymize");

    context
        .evidence
        .set_structural_validity(!req.content.trim().is_empty());

    context
        .evidence
        .set_sensitive_data_detected(AnonymizerEngine::has_sensitive_data(&req.content));

    let execution = match evaluate_audit_and_execute(
        context,
        &RuntimePolicy::anonymization_benchmark(),
        audit_state.store.as_ref(),
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
            HttpResponse::UnprocessableEntity().json(serde_json::json!({
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

    init_db()
        .await
        .map_err(std::io::Error::other)?;

    let pool = get_pool()
        .map_err(std::io::Error::other)?
        .clone();

    let audit_store = PostgresRuntimeAuditStore::new(pool);

    audit_store
        .ensure_schema()
        .await
        .map_err(std::io::Error::other)?;

    let audit_state = web::Data::new(AuditState {
        store: Arc::new(audit_store),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(audit_state.clone())
            .route("/health", web::get().to(health_check))
            .route("/benchmark/anonymize", web::post().to(benchmark_anonymize))
            .route("/benchmark/pqc/verify", web::get().to(benchmark_verify_pqc))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn empty_anonymize_request_is_rejected_before_execution() {
        let req = web::Json(AnonymizeRequest {
            content: "   ".to_string(),
            content_type: "text/plain".to_string(),
            locale: "en".to_string(),
        });

        let resp = benchmark_anonymize(req, AuditState::in_memory_for_test()).await;

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

        let resp = benchmark_anonymize(req, AuditState::in_memory_for_test()).await;

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

        let resp = benchmark_anonymize(req, AuditState::in_memory_for_test()).await;
        assert!(resp.status().is_success());
    }
}
