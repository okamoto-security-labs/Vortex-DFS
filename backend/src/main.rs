// main.rs — Vortex DFS · HTTP entrypoint — hardened
//
// SECURITY POSTURE:
// - Rate limiting: 10 req/min per IP for demo, 300/min for authenticated
// - CORS: restricted to okamotosecurytlabs.com.br only
// - API key auth: Bearer vdfs_live_[256-bit hex]
// - File lock: Mutex around customers.json writes
// - Input sanitization: 64KB cap, empty body rejection
// - No PII in logs: trace_id and risk_score only
//
// ============================================================================
// CHANGELOG DE SEGURANÇA (referência: relatório de auditoria adversarial)
// ============================================================================
// FIX (build quebrado): auth_and_rate() tinha um trecho de outro contexto
//     colado por engano no meio do match Some(h) => {...}, apagando a linha
//     que extraía `key` do header. Restaurado.
// FIX Finding #3: KeyStore agora é criado UMA VEZ em main() e injetado via
//     app_data — não é mais recalculado a partir da API key a cada request.
// FIX gap de rate limiting: handlers de /v1/pqc/sign, /v1/pqc/verify e
//     /v1/pqc/audit agora chamam auth_and_rate() — antes nenhum dos três
//     tinha rate limit (ver changelog de pqc_endpoints.rs).
// FIX Finding #3, parte 2: PostgresKeyStore substitui o InMemoryKeyStore
//     como padrão — chave persistida, criptografada em repouso, não é
//     mais perdida a cada restart/hibernação do processo no Render.
// ============================================================================

mod key_store;
mod pqc_core;
mod pqc_endpoints;
mod signer_lwe;

use actix_web::middleware::DefaultHeaders;
use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit,
};
use base64::Engine as _;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod anonymizer_engine;
mod provisioner;
mod stripe_webhook;
use anonymizer_engine::{AnonymizeResult, AnonymizerEngine};
use key_store::{KeyStore, PostgresKeyStore};
use provisioner::find_by_api_key;

// ---------------------------------------------------------------------------
// Rate limiter — token bucket per IP
//
// WHY IN-MEMORY: for a single-instance free tier, an in-memory map is
// sufficient and has zero latency overhead. When scaling to multiple
// instances, replace with Redis INCR + TTL.
//
// LIMITS:
// - Demo (no key):        10 requests per 60 seconds per IP
// - Authenticated:       300 requests per 60 seconds per IP
// ---------------------------------------------------------------------------

struct RateBucket {
    count: u32,
    window_start: u64, // Unix seconds
}

static RATE_MAP: Lazy<Mutex<HashMap<String, RateBucket>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Returns true if the request is allowed, false if rate limit exceeded.
/// window = 60 seconds, limit varies by auth type.
fn check_rate_limit(ip: &str, limit: u32) -> bool {
    let now = now_secs();
    let mut map = RATE_MAP.lock().unwrap();
    let bucket = map.entry(ip.to_string()).or_insert(RateBucket {
        count: 0,
        window_start: now,
    });

    if now - bucket.window_start >= 60 {
        bucket.count = 0;
        bucket.window_start = now;
    }

    bucket.count += 1;
    bucket.count <= limit
}

/// Evict stale entries every ~1000 requests to prevent memory growth.
fn maybe_evict_stale() {
    let now = now_secs();
    if now % 1000 != 0 {
        return;
    }
    if let Ok(mut map) = RATE_MAP.try_lock() {
        map.retain(|_, v| now - v.window_start < 120);
    }
}

// ---------------------------------------------------------------------------
// Request / Response contracts
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AnonymizeRequest {
    content: String,
    #[serde(default = "default_content_type")]
    content_type: String,
    #[serde(default)]
    locale: String,
}

fn default_content_type() -> String {
    "text".into()
}

#[derive(Serialize)]
struct AnonymizeResponse {
    sanitized: String,
    token_map_enc: String,
    risk_score: f32,
    detections: Vec<DetectionOut>,
    trace_id: String,
    latency_ms: f64,
}

#[derive(Serialize)]
struct DetectionOut {
    pattern: String,
    count: usize,
    positions: Vec<(usize, usize)>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn err(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": msg })
}

// ---------------------------------------------------------------------------
// IP extraction
// ---------------------------------------------------------------------------
fn client_ip(req: &HttpRequest) -> String {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            req.peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

// ---------------------------------------------------------------------------
// Authentication + rate limiting (combined for single pass)
//
// Retorna Ok((is_demo, resolved_key)) ou Err(HttpResponse). `resolved_key`
// é usada como lookup no KeyStore: "demo" para chamadas sem Authorization
// ou em modo demo, ou a API key real do cliente autenticado.
// ---------------------------------------------------------------------------
fn auth_and_rate(req: &HttpRequest) -> Result<(bool, String), HttpResponse> {
    let ip = client_ip(req);
    let demo_mode = std::env::var("ALLOW_DEMO").unwrap_or_default() == "true";

    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        None => {
            if !demo_mode {
                return Err(HttpResponse::Unauthorized().json(err(
                    "Missing Authorization header. Use: Authorization: Bearer vdfs_live_...",
                )));
            }
            if !check_rate_limit(&format!("demo:{}", ip), 10) {
                return Err(HttpResponse::TooManyRequests().json(err(
                    "Rate limit exceeded: 10 requests/minute for demo. Subscribe for higher limits."
                )));
            }
            Ok((true, "demo".to_string()))
        }

        Some(h) => {
            let key = h.strip_prefix("Bearer ").unwrap_or(&h).to_string();

            if key.is_empty() {
                return Err(HttpResponse::Unauthorized().json(err("Invalid Authorization format")));
            }

            if demo_mode && !key.starts_with("vdfs_live_") {
                if !check_rate_limit(&format!("demo:{}", ip), 10) {
                    return Err(HttpResponse::TooManyRequests()
                        .json(err("Rate limit exceeded: 10 requests/minute for demo.")));
                }
                return Ok((true, "demo".to_string()));
            }

            match find_by_api_key(&key) {
                Some(c) if c.status == "active" => {
                    let rl_key = if key.len() >= 20 { &key[..20] } else { &key[..] };
                    if !check_rate_limit(&format!("auth:{}", rl_key), 300) {
                        return Err(HttpResponse::TooManyRequests().json(err(
                            "Rate limit exceeded: 300 requests/minute. Contact support to increase."
                        )));
                    }
                    Ok((false, key))
                }
                Some(_) => Err(HttpResponse::Forbidden().json(err(
                    "Subscription inactive or expired. Renew at okamotosecurytlabs.com.br",
                ))),
                None => Err(HttpResponse::Unauthorized().json(err("Invalid API key"))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------
fn add_cors(resp: HttpResponse, req: &HttpRequest) -> HttpResponse {
    let origin = req
        .headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let allowed = [
        "https://okamotosecurytlabs.com.br",
        "https://www.okamotosecurytlabs.com.br",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ];

    let cors_origin = if allowed.contains(&origin) {
        origin.to_string()
    } else {
        "https://okamotosecurytlabs.com.br".to_string()
    };

    let status = resp.status();
    let body = resp.into_body();
    HttpResponse::build(status)
        .insert_header(("Access-Control-Allow-Origin", cors_origin.as_str()))
        .insert_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        .insert_header((
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        ))
        .message_body(body)
        .unwrap_or_else(|_| HttpResponse::InternalServerError().finish())
}

async fn handle_preflight(req: HttpRequest) -> HttpResponse {
    add_cors(HttpResponse::NoContent().finish(), &req)
}

// ---------------------------------------------------------------------------
// Main anonymize handler
// ---------------------------------------------------------------------------
async fn handle_anonymize(req: HttpRequest, body: web::Json<AnonymizeRequest>) -> HttpResponse {
    maybe_evict_stale();
    let t0 = Instant::now();

    if let Err(e) = auth_and_rate(&req) {
        return add_cors(e, &req);
    }

    if body.content.len() > 64 * 1024 {
        return add_cors(
            HttpResponse::PayloadTooLarge().json(err("Payload exceeds 64KB limit")),
            &req,
        );
    }

    if body.content.is_empty() {
        return add_cors(
            HttpResponse::UnprocessableEntity().json(err("content must not be empty")),
            &req,
        );
    }

    let result: AnonymizeResult = AnonymizerEngine::anonymize(&body.content);
    let token_map_enc = encrypt_token_map(&result.token_map);
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let detections: Vec<DetectionOut> = result
        .detections
        .iter()
        .map(|d| DetectionOut {
            pattern: d.pattern_label.clone(),
            count: d.count,
            positions: d.positions.clone(),
        })
        .collect();

    log::info!(
        "trace_id={} risk={:.2} detections={} latency_ms={:.2}",
        result.trace_id,
        result.risk_score,
        detections.len(),
        latency_ms
    );

    add_cors(
        HttpResponse::Ok().json(AnonymizeResponse {
            sanitized: result.sanitized,
            token_map_enc,
            risk_score: result.risk_score,
            detections,
            trace_id: result.trace_id,
            latency_ms,
        }),
        &req,
    )
}

// ---------------------------------------------------------------------------
// AES-256-GCM token map encryption
// ---------------------------------------------------------------------------
fn encrypt_token_map(map: &HashMap<String, String>) -> String {
    let json = serde_json::to_vec(map).unwrap_or_default();
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut key_bytes);
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).unwrap();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, json.as_ref()).unwrap_or_default();
    let mut payload = nonce_bytes.to_vec();
    payload.extend(ciphertext);
    base64::engine::general_purpose::STANDARD.encode(payload)
}

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    if let Err(e) = provisioner::init_db().await {
        log::error!("Database initialization failed: {}", e);
        std::process::exit(1);
    }

    let _ = &*anonymizer_engine::REGEX_SET;
    log::info!(
        "Vortex DFS ready — {} patterns loaded",
        anonymizer_engine::PATTERNS.len()
    );

    // FIX Finding #3, parte 2: PostgresKeyStore — chave gerada uma vez,
    // criptografada em repouso, persistida no mesmo Postgres/Supabase
    // que o provisioner.rs já usa. Requer VORTEX_MASTER_KEY (32 bytes
    // base64) e a tabela pqc_keys (ver migrations/001_pqc_keys.sql).
    // Sem VORTEX_MASTER_KEY, /v1/pqc/sign e /v1/pqc/verify falham com
    // 500 — intencional (fail loud, não fail silent com chave fraca).
    let pg_pool = provisioner::get_pool().expect(
        "Postgres pool deve estar inicializado antes do KeyStore (provisioner::init_db já rodou acima)",
    );
    let key_store_arc: std::sync::Arc<dyn KeyStore> =
        std::sync::Arc::new(PostgresKeyStore::new(pg_pool));
    let key_store: web::Data<dyn KeyStore> = web::Data::from(key_store_arc);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(key_store.clone())
            .wrap(
                DefaultHeaders::new()
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("Cache-Control", "no-store"))
                    .add(("X-Powered-By", "Vortex DFS"))
                    .add((
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    )),
            )
            .wrap(middleware::Logger::new("%r %s %Dms"))
            .route(
                "/v1/shield/anonymize",
                web::method(actix_web::http::Method::OPTIONS).to(handle_preflight),
            )
            .route("/v1/shield/anonymize", web::post().to(handle_anonymize))
            .route(
                "/v1/webhook/stripe",
                web::post().to(stripe_webhook::handle_stripe_webhook),
            )
            .route(
                "/healthz",
                web::get().to(|| async { HttpResponse::Ok().body("ok") }),
            )
            .route("/v1/pqc/sign", web::post().to(pqc_endpoints::handle_sign))
            .route(
                "/v1/pqc/verify",
                web::post().to(pqc_endpoints::handle_verify),
            )
            .route("/v1/pqc/audit", web::post().to(pqc_endpoints::handle_audit))
            .route(
                "/v1/pqc/sign",
                web::method(actix_web::http::Method::OPTIONS).to(handle_preflight),
            )
            .route(
                "/v1/pqc/verify",
                web::method(actix_web::http::Method::OPTIONS).to(handle_preflight),
            )
            .route(
                "/v1/pqc/audit",
                web::method(actix_web::http::Method::OPTIONS).to(handle_preflight),
            )
    })
    .bind(&bind_addr)?
    .workers(num_cpus::get())
    .run()
    .await
}