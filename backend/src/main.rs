// main.rs — Vortex DFS · HTTP entrypoint
//
// WHY actix-web AND NOT axum/tonic/warp:
// actix-web uses its own single-threaded async executor per core, which avoids
// cross-thread synchronization overhead on the hot path. For a CPU-bound workload
// like regex scanning, this maps better to physical cores than work-stealing
// schedulers. Benchmark internally before switching runtimes.

use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
use serde::{Deserialize, Serialize};
use std::time::Instant;

mod anonymizer_engine;
use anonymizer_engine::{AnonymizerEngine, AnonymizeResult};

// ---------------------------------------------------------------------------
// Request / Response contracts
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AnonymizeRequest {
    content:      String,
    #[serde(default = "default_content_type")]
    content_type: String,   // "text" | "code" — informs heuristic tuning
    #[serde(default)]
    locale:       String,   // BCP-47; used for locale-specific PII heuristics
}

fn default_content_type() -> String { "text".into() }

#[derive(Serialize)]
struct AnonymizeResponse {
    sanitized:    String,
    token_map_enc: String,          // base64(AES-256-GCM(JSON(token_map)))
    risk_score:   f32,
    detections:   Vec<DetectionOut>,
    trace_id:     String,
    latency_ms:   f64,
}

#[derive(Serialize)]
struct DetectionOut {
    pattern:   String,
    count:     usize,
    positions: Vec<(usize, usize)>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error:    &'static str,
    trace_id: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

async fn handle_anonymize(
    req:  HttpRequest,
    body: web::Json<AnonymizeRequest>,
) -> HttpResponse {
    let t0 = Instant::now();

    // Enforce content size limit before doing any work.
    // WHY HERE AND NOT ONLY AT NGINX: defense in depth — nginx can be
    // misconfigured or bypassed in dev environments.
    if body.content.len() > 64 * 1024 {
        return HttpResponse::PayloadTooLarge().json(ErrorResponse {
            error:    "Payload exceeds 64KB limit",
            trace_id: uuid::Uuid::new_v4().to_string(),
        });
    }

    // Reject empty payload — no-op requests shouldn't consume regex engine time
    if body.content.is_empty() {
        return HttpResponse::UnprocessableEntity().json(ErrorResponse {
            error:    "content field must not be empty",
            trace_id: uuid::Uuid::new_v4().to_string(),
        });
    }

    let result: AnonymizeResult = AnonymizerEngine::anonymize(&body.content);

    // Encrypt token_map before it leaves this process.
    // WHY: the map contains the original PII values. If it's returned in
    // plaintext, the anonymization is trivially reversible by any observer
    // of the HTTP response (proxy, log aggregator, SIEM).
    let token_map_enc = encrypt_token_map(&result.token_map);

    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let detections: Vec<DetectionOut> = result.detections.iter().map(|d| DetectionOut {
        pattern:   d.pattern_label.clone(),
        count:     d.count,
        positions: d.positions.clone(),
    }).collect();

    // Structured access log — do NOT log sanitized content or token_map.
    // risk_score and trace_id are safe for log aggregators.
    log::info!(
        "trace_id={} risk_score={:.2} detections={} latency_ms={:.2}",
        result.trace_id, result.risk_score, detections.len(), latency_ms
    );

    HttpResponse::Ok().json(AnonymizeResponse {
        sanitized:     result.sanitized,
        token_map_enc,
        risk_score:    result.risk_score,
        detections,
        trace_id:      result.trace_id,
        latency_ms,
    })
}

/// Encrypt token_map with AES-256-GCM using a fresh random nonce per request.
///
/// WHY PER-REQUEST NONCE: GCM is catastrophically broken if a (key, nonce) pair
/// is ever reused. Fresh nonces make this physically impossible.
///
/// WHY NOT RETURNING THE KEY HERE:
/// In production, the encryption key is derived from the session key exchanged
/// during mTLS handshake (via HKDF). This stub uses a random key to show the
/// pattern — wire in your KMS/HSM key derivation before production.
fn encrypt_token_map(map: &std::collections::HashMap<String, String>) -> String {
    let json = serde_json::to_vec(map).unwrap_or_default();

    // Generate ephemeral key — replace with session-derived key in production
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);

    let mut nonce_bytes = [0u8; 12]; // 96-bit nonce is GCM standard
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher   = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce    = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, json.as_ref()).unwrap_or_default();

    // Prepend nonce to ciphertext so the receiver can decrypt
    // Format: base64(nonce || ciphertext)
    let mut payload = nonce_bytes.to_vec();
    payload.extend(ciphertext);
    base64::encode(payload)
}

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Force-init the lazy statics at startup so the first request isn't slow.
    // WHY: Lazy compilation of 20+ regex patterns takes ~5ms — acceptable at
    // boot, unacceptable as first-request latency spike.
    let _ = &*anonymizer_engine::REGEX_SET;
    log::info!("RegexSet compiled and ready ({} patterns)", anonymizer_engine::PATTERNS.len());

    HttpServer::new(|| {
        App::new()
            // WHY DEFAULT_HEADERS: adds X-Content-Type-Options, X-Frame-Options etc.
            // Basic hardening even before a WAF is in front.
            .wrap(middleware::DefaultHeaders::new()
                .add(("X-Content-Type-Options", "nosniff"))
                .add(("X-Frame-Options", "DENY"))
                .add(("Cache-Control", "no-store"))
            )
            .wrap(middleware::Logger::new(
                // Log format: method, path, status, latency — NO body, NO headers
                // WHY: headers may contain Bearer tokens; bodies may contain PII
                "%r %s %Dms"
            ))
            .route("/v1/shield/anonymize", web::post().to(handle_anonymize))
            .route("/healthz", web::get().to(|| async { HttpResponse::Ok().body("ok") }))
    })
    .bind("0.0.0.0:8080")?
    .workers(num_cpus::get()) // one worker per physical core
    .run()
    .await
}
