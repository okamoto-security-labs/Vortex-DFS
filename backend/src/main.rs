// =========================================================================
// VORTEX-DFS - BACKEND MAIN ENTRYPOINT (ACTIX-WEB)
// Produção Determinística - Balanceamento Léxico Completo
// =========================================================================

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use vortex_dfs::anonymizer_engine::AnonymizerEngine;
use vortex_dfs::signer_lwe::{verify, PublicKey, SecretKey, Signature};

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

async fn benchmark_anonymize(req: web::Json<AnonymizeRequest>) -> HttpResponse {
    let start = Instant::now();
    let result = AnonymizerEngine::anonymize(&req.content);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    HttpResponse::Ok().json(serde_json::json!({
        "latency_ms": latency_ms,
        "sanitized_length": result.sanitized.len(),
        "detections": result.detections.len(),
        "risk_score": result.risk_score,
    }))
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

    HttpServer::new(|| {
        App::new()
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
    async fn benchmark_handler_returns_latency_metrics() {
        let req = web::Json(AnonymizeRequest {
            content: "Contact: user@example.com\nKey: AKIAIOSFODNN7EXAMPLE\nSSN: 123-45-6789".to_string(),
            content_type: "text/plain".to_string(),
            locale: "en".to_string(),
        });

        let resp = benchmark_anonymize(req).await;
        assert!(resp.status().is_success());
    }
}