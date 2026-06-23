// pqc_endpoints.rs — Vortex DFS · Post-Quantum Cryptography endpoints
//
// THREE ENDPOINTS:
//   POST /v1/pqc/sign    — assina payload com LWE, retorna assinatura + TrustBand
//   POST /v1/pqc/verify  — verifica assinatura LWE
//   POST /v1/pqc/audit   — crypto-agility scanner: inventário + recomendações NIST

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::signer_lwe::{keygen, verify, Signature};
use crate::pqc_core::{PqcVector, TrustBand};

// ---------------------------------------------------------------------------
// Deterministic seed from API key (demo: fixed seed)
// Produção: derive de HSM ou KMS
// ---------------------------------------------------------------------------
fn seed_from_key(key: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &byte in key.as_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn trust_band_str(band: &TrustBand) -> &'static str {
    match band {
        TrustBand::HighTrust    => "high_trust",
        TrustBand::Operational  => "operational",
        TrustBand::Fragile      => "fragile",
        TrustBand::Critical     => "critical",
    }
}

// ---------------------------------------------------------------------------
// /v1/pqc/sign
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignRequest {
    pub payload:  String,          // dados a assinar (texto ou base64)
    pub nonce:    Option<u64>,     // aleatoriedade — produção: OsRng
    pub distance: Option<f64>,     // parâmetro de confiança física [0,1]
    pub entropy:  Option<f64>,     // entropia do contexto [0,1]
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature: SignatureOut,
    pub trust:     TrustOut,
    pub algorithm: &'static str,
    pub warning:   &'static str,
    pub latency_ms: f64,
}

#[derive(Serialize)]
pub struct SignatureOut {
    pub z: Vec<i64>,
    pub w: Vec<i64>,
    pub c: i64,
}

#[derive(Serialize)]
pub struct TrustOut {
    pub band:  &'static str,
    pub score: f64,
}

pub async fn handle_sign(req: HttpRequest, body: web::Json<SignRequest>) -> HttpResponse {
    let t0 = Instant::now();

    if body.payload.is_empty() {
        return HttpResponse::UnprocessableEntity()
            .json(serde_json::json!({ "error": "payload must not be empty" }));
    }
    if body.payload.len() > 64 * 1024 {
        return HttpResponse::PayloadTooLarge()
            .json(serde_json::json!({ "error": "payload exceeds 64KB" }));
    }

    // Derive seed from Authorization header key (or fixed demo seed)
    let api_key = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("demo");
    let seed  = seed_from_key(api_key);
    let nonce = body.nonce.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    });

    let (sk, pk) = keygen(seed);
    let sig      = sk.sign(body.payload.as_bytes(), &pk, nonce);

    // Trust evaluation
    let distance = body.distance.unwrap_or(0.1);
    let entropy  = body.entropy.unwrap_or(0.9);
    let trust_score;
    let trust_band;
    match PqcVector::new(distance, entropy) {
        Ok(vec) => {
            trust_score = vec.evaluate_trust_score();
            trust_band  = vec.classify();
        }
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": e }));
        }
    }

    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    log::info!(
        "pqc_sign payload_len={} trust={} latency_ms={:.3}",
        body.payload.len(), trust_band_str(&trust_band), latency_ms
    );

    HttpResponse::Ok().json(SignResponse {
        signature: SignatureOut { z: sig.z, w: sig.w, c: sig.c },
        trust: TrustOut {
            band:  trust_band_str(&trust_band),
            score: trust_score,
        },
        algorithm: "Fiat-Shamir/LWE-N16-Q257 (demo — upgrade to ML-DSA for production)",
        warning:   "N=16/Q=257 is for demonstration only. Production requires N>=512.",
        latency_ms,
    })
}

// ---------------------------------------------------------------------------
// /v1/pqc/verify
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub payload:   String,
    pub signature: SignatureIn,
    pub distance:  Option<f64>,
    pub entropy:   Option<f64>,
}

#[derive(Deserialize)]
pub struct SignatureIn {
    pub z: Vec<i64>,
    pub w: Vec<i64>,
    pub c: i64,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid:      bool,
    pub trust:      TrustOut,
    pub algorithm:  &'static str,
    pub latency_ms: f64,
}

pub async fn handle_verify(req: HttpRequest, body: web::Json<VerifyRequest>) -> HttpResponse {
    let t0 = Instant::now();

    if body.payload.is_empty() {
        return HttpResponse::UnprocessableEntity()
            .json(serde_json::json!({ "error": "payload must not be empty" }));
    }

    let api_key = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("demo");
    let seed = seed_from_key(api_key);

    let (_sk, pk) = keygen(seed);
    let sig = Signature {
        z: body.signature.z.clone(),
        w: body.signature.w.clone(),
        c: body.signature.c,
    };

    let valid = verify(&pk, body.payload.as_bytes(), &sig);

    let distance = body.distance.unwrap_or(0.1);
    let entropy  = body.entropy.unwrap_or(0.9);
    let trust_score;
    let trust_band;
    match PqcVector::new(distance, entropy) {
        Ok(vec) => {
            trust_score = vec.evaluate_trust_score();
            trust_band  = vec.classify();
        }
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": e }));
        }
    }

    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    log::info!(
        "pqc_verify valid={} trust={} latency_ms={:.3}",
        valid, trust_band_str(&trust_band), latency_ms
    );

    HttpResponse::Ok().json(VerifyResponse {
        valid,
        trust: TrustOut {
            band:  trust_band_str(&trust_band),
            score: trust_score,
        },
        algorithm: "Fiat-Shamir/LWE-N16-Q257 (demo — upgrade to ML-DSA for production)",
        latency_ms,
    })
}

// ---------------------------------------------------------------------------
// /v1/pqc/audit — Crypto-Agility Scanner
//
// Analisa payload em busca de padrões de criptografia clássica e retorna:
//   - inventário de algoritmos detectados
//   - avaliação de risco quantum
//   - recomendações de migração NIST (ML-KEM, ML-DSA)
//   - roadmap híbrido (clássica + PQC)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditRequest {
    pub content: String,   // código, config, certificado, ou texto livre
    pub context: Option<String>, // "code", "config", "certificate", "text"
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub inventory:       Vec<CryptoFinding>,
    pub quantum_risk:    QuantumRisk,
    pub recommendations: Vec<Migration>,
    pub hybrid_roadmap:  HybridRoadmap,
    pub summary:         AuditSummary,
    pub latency_ms:      f64,
}

#[derive(Serialize)]
pub struct CryptoFinding {
    pub algorithm:   &'static str,
    pub category:    &'static str,   // "symmetric", "asymmetric", "hash", "kex"
    pub quantum_safe: bool,
    pub occurrences: usize,
    pub risk_level:  &'static str,   // "critical", "high", "medium", "low"
    pub context:     Vec<String>,    // trechos onde foi encontrado
}

#[derive(Serialize)]
pub struct QuantumRisk {
    pub score:       f64,   // 0.0 (safe) → 1.0 (critical)
    pub band:        &'static str,
    pub harvest_now_decrypt_later: bool,
    pub estimated_threat_horizon:  &'static str,
}

#[derive(Serialize)]
pub struct Migration {
    pub from:        &'static str,
    pub to:          &'static str,
    pub nist_standard: &'static str,
    pub priority:    &'static str,
    pub effort:      &'static str,
    pub notes:       &'static str,
}

#[derive(Serialize)]
pub struct HybridRoadmap {
    pub phase_1: RoadmapPhase,
    pub phase_2: RoadmapPhase,
    pub phase_3: RoadmapPhase,
}

#[derive(Serialize)]
pub struct RoadmapPhase {
    pub name:        &'static str,
    pub description: &'static str,
    pub actions:     Vec<&'static str>,
}

#[derive(Serialize)]
pub struct AuditSummary {
    pub total_findings:      usize,
    pub quantum_unsafe:      usize,
    pub quantum_safe:        usize,
    pub critical_count:      usize,
    pub recommendation:      String,
}

// Padrões de detecção de algoritmos criptográficos
struct CryptoPattern {
    pattern:      &'static str,
    algorithm:    &'static str,
    category:     &'static str,
    quantum_safe: bool,
    risk_level:   &'static str,
}

static CRYPTO_PATTERNS: &[CryptoPattern] = &[
    // Assimétricos clássicos — vulneráveis ao algoritmo de Shor
    CryptoPattern { pattern: "RSA",       algorithm: "RSA",       category: "asymmetric", quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "rsa",       algorithm: "RSA",       category: "asymmetric", quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "ECDSA",     algorithm: "ECDSA",     category: "asymmetric", quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "ecdsa",     algorithm: "ECDSA",     category: "asymmetric", quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "ECDH",      algorithm: "ECDH",      category: "kex",        quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "ecdh",      algorithm: "ECDH",      category: "kex",        quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "Ed25519",   algorithm: "Ed25519",   category: "asymmetric", quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "ed25519",   algorithm: "Ed25519",   category: "asymmetric", quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "P-256",     algorithm: "P-256",     category: "kex",        quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "P-384",     algorithm: "P-384",     category: "kex",        quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "secp256k1", algorithm: "secp256k1", category: "kex",        quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "DH ",       algorithm: "DH",        category: "kex",        quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "DSA",       algorithm: "DSA",       category: "asymmetric", quantum_safe: false, risk_level: "critical" },

    // Simétricos — seguros contra Grover (com chaves >= 256 bits)
    CryptoPattern { pattern: "AES-256",   algorithm: "AES-256",   category: "symmetric",  quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "AES-128",   algorithm: "AES-128",   category: "symmetric",  quantum_safe: false, risk_level: "medium" },
    CryptoPattern { pattern: "AES-192",   algorithm: "AES-192",   category: "symmetric",  quantum_safe: false, risk_level: "medium" },
    CryptoPattern { pattern: "ChaCha20",  algorithm: "ChaCha20",  category: "symmetric",  quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "3DES",      algorithm: "3DES",      category: "symmetric",  quantum_safe: false, risk_level: "high" },
    CryptoPattern { pattern: "DES",       algorithm: "DES",       category: "symmetric",  quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "RC4",       algorithm: "RC4",       category: "symmetric",  quantum_safe: false, risk_level: "critical" },

    // Hashes
    CryptoPattern { pattern: "SHA-256",   algorithm: "SHA-256",   category: "hash",       quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "SHA-384",   algorithm: "SHA-384",   category: "hash",       quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "SHA-512",   algorithm: "SHA-512",   category: "hash",       quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "SHA3-",     algorithm: "SHA3",      category: "hash",       quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "SHA-1",     algorithm: "SHA-1",     category: "hash",       quantum_safe: false, risk_level: "high" },
    CryptoPattern { pattern: "MD5",       algorithm: "MD5",       category: "hash",       quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "BLAKE2",    algorithm: "BLAKE2",    category: "hash",       quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "BLAKE3",    algorithm: "BLAKE3",    category: "hash",       quantum_safe: true,  risk_level: "low" },

    // PQC — já seguros
    CryptoPattern { pattern: "ML-KEM",    algorithm: "ML-KEM",    category: "kex",        quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "ML-DSA",    algorithm: "ML-DSA",    category: "asymmetric", quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "Kyber",     algorithm: "Kyber",     category: "kex",        quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "Dilithium", algorithm: "Dilithium", category: "asymmetric", quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "SPHINCS",   algorithm: "SPHINCS+",  category: "asymmetric", quantum_safe: true,  risk_level: "low" },
    CryptoPattern { pattern: "FALCON",    algorithm: "FALCON",    category: "asymmetric", quantum_safe: true,  risk_level: "low" },

    // TLS / Protocolos
    CryptoPattern { pattern: "TLS 1.0",   algorithm: "TLS 1.0",  category: "protocol",   quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "TLS 1.1",   algorithm: "TLS 1.1",  category: "protocol",   quantum_safe: false, risk_level: "critical" },
    CryptoPattern { pattern: "TLS 1.2",   algorithm: "TLS 1.2",  category: "protocol",   quantum_safe: false, risk_level: "high" },
    CryptoPattern { pattern: "TLS 1.3",   algorithm: "TLS 1.3",  category: "protocol",   quantum_safe: false, risk_level: "medium" },
    CryptoPattern { pattern: "SSL",       algorithm: "SSL",       category: "protocol",   quantum_safe: false, risk_level: "critical" },
];

pub async fn handle_audit(_req: HttpRequest, body: web::Json<AuditRequest>) -> HttpResponse {
    let t0 = Instant::now();

    if body.content.is_empty() {
        return HttpResponse::UnprocessableEntity()
            .json(serde_json::json!({ "error": "content must not be empty" }));
    }
    if body.content.len() > 64 * 1024 {
        return HttpResponse::PayloadTooLarge()
            .json(serde_json::json!({ "error": "payload exceeds 64KB" }));
    }

    let content = &body.content;

    // Scan for crypto patterns
    let mut findings: Vec<CryptoFinding> = Vec::new();
    let mut seen_algorithms: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for pat in CRYPTO_PATTERNS {
        if seen_algorithms.contains(pat.algorithm) { continue; }

        let occurrences: Vec<String> = content
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(pat.pattern))
            .map(|(i, line)| format!("line {}: {}", i + 1, line.trim()))
            .take(3) // max 3 contextos por algoritmo
            .collect();

        if !occurrences.is_empty() {
            seen_algorithms.insert(pat.algorithm);
            findings.push(CryptoFinding {
                algorithm:    pat.algorithm,
                category:     pat.category,
                quantum_safe: pat.quantum_safe,
                risk_level:   pat.risk_level,
                occurrences:  occurrences.len(),
                context:      occurrences,
            });
        }
    }

    // Quantum risk score
    let critical = findings.iter().filter(|f| f.risk_level == "critical" && !f.quantum_safe).count();
    let high     = findings.iter().filter(|f| f.risk_level == "high"     && !f.quantum_safe).count();
    let medium   = findings.iter().filter(|f| f.risk_level == "medium"   && !f.quantum_safe).count();
    let unsafe_count = findings.iter().filter(|f| !f.quantum_safe).count();
    let safe_count   = findings.iter().filter(|f|  f.quantum_safe).count();

    let risk_score = ((critical as f64 * 1.0 + high as f64 * 0.6 + medium as f64 * 0.3)
        / (findings.len().max(1) as f64))
        .clamp(0.0, 1.0);

    let (risk_band, harvest_risk) = if critical > 0 {
        ("critical", true)
    } else if high > 0 {
        ("high", true)
    } else if medium > 0 {
        ("medium", false)
    } else {
        ("low", false)
    };

    // Migration recommendations
    let mut recommendations: Vec<Migration> = Vec::new();
    if seen_algorithms.contains("RSA") || seen_algorithms.contains("ECDSA") || seen_algorithms.contains("DSA") {
        recommendations.push(Migration {
            from: "RSA / ECDSA / DSA",
            to: "ML-DSA (CRYSTALS-Dilithium)",
            nist_standard: "FIPS 204",
            priority: "critical",
            effort: "high",
            notes: "Replace all digital signature schemes. ML-DSA is the primary NIST standard for post-quantum signatures.",
        });
    }
    if seen_algorithms.contains("ECDH") || seen_algorithms.contains("DH") {
        recommendations.push(Migration {
            from: "ECDH / DH",
            to: "ML-KEM (CRYSTALS-Kyber)",
            nist_standard: "FIPS 203",
            priority: "critical",
            effort: "medium",
            notes: "Replace all key encapsulation mechanisms. ML-KEM is the primary NIST standard for post-quantum KEX.",
        });
    }
    if seen_algorithms.contains("Ed25519") {
        recommendations.push(Migration {
            from: "Ed25519",
            to: "ML-DSA or FALCON (FIPS 206)",
            nist_standard: "FIPS 204 / FIPS 206",
            priority: "critical",
            effort: "medium",
            notes: "Ed25519 is vulnerable to Shor's algorithm. FALCON offers smaller signatures than ML-DSA.",
        });
    }
    if seen_algorithms.contains("AES-128") || seen_algorithms.contains("AES-192") {
        recommendations.push(Migration {
            from: "AES-128 / AES-192",
            to: "AES-256",
            nist_standard: "FIPS 197",
            priority: "medium",
            effort: "low",
            notes: "Grover's algorithm halves effective key length. AES-256 provides 128-bit post-quantum security.",
        });
    }
    if seen_algorithms.contains("SHA-1") || seen_algorithms.contains("MD5") {
        recommendations.push(Migration {
            from: "SHA-1 / MD5",
            to: "SHA-256 or SHA3-256",
            nist_standard: "FIPS 180-4 / FIPS 202",
            priority: "high",
            effort: "low",
            notes: "Deprecated hash functions. Replace immediately regardless of quantum threat.",
        });
    }
    if seen_algorithms.contains("3DES") || seen_algorithms.contains("DES") || seen_algorithms.contains("RC4") {
        recommendations.push(Migration {
            from: "DES / 3DES / RC4",
            to: "AES-256-GCM or ChaCha20-Poly1305",
            nist_standard: "FIPS 197",
            priority: "critical",
            effort: "medium",
            notes: "Broken symmetric ciphers. Replace immediately.",
        });
    }
    if seen_algorithms.contains("TLS 1.0") || seen_algorithms.contains("TLS 1.1") || seen_algorithms.contains("SSL") {
        recommendations.push(Migration {
            from: "SSL / TLS 1.0 / TLS 1.1",
            to: "TLS 1.3 with PQC cipher suites",
            nist_standard: "NIST SP 800-52r2",
            priority: "critical",
            effort: "medium",
            notes: "Deprecated protocols with known vulnerabilities. TLS 1.3 + ML-KEM hybrid is the target state.",
        });
    }

    // Hybrid roadmap
    let roadmap = HybridRoadmap {
        phase_1: RoadmapPhase {
            name: "Inventory & Assessment",
            description: "Map all cryptographic usage across systems before migration",
            actions: vec![
                "Run Vortex PQC Audit on all codebases and configurations",
                "Identify all certificates, keys, and cryptographic dependencies",
                "Classify data by sensitivity and retention period",
                "Prioritize systems handling long-lived sensitive data (HNDL risk)",
            ],
        },
        phase_2: RoadmapPhase {
            name: "Hybrid Architecture (Classical + PQC)",
            description: "Deploy hybrid schemes to maintain compatibility while gaining quantum resistance",
            actions: vec![
                "Implement ML-KEM alongside ECDH for key exchange (hybrid KEX)",
                "Add ML-DSA alongside ECDSA for signatures (hybrid signing)",
                "Update TLS to 1.3 with X25519+ML-KEM hybrid cipher suites",
                "Adopt crypto-agility: abstract crypto primitives behind interfaces",
                "Deploy HSM/KMS with PQC support for key management",
            ],
        },
        phase_3: RoadmapPhase {
            name: "Full PQC Migration",
            description: "Complete migration to NIST-standardized post-quantum algorithms",
            actions: vec![
                "Replace all ECDH/DH with ML-KEM (FIPS 203)",
                "Replace all ECDSA/RSA/DSA with ML-DSA (FIPS 204) or FALCON (FIPS 206)",
                "Upgrade all AES to AES-256 minimum",
                "Revoke and reissue all certificates with PQC algorithms",
                "Validate migration with Vortex PQC Audit (zero classical asymmetric findings)",
            ],
        },
    };

    let recommendation = if findings.is_empty() {
        "No cryptographic patterns detected. Provide code, configuration, or certificate content for analysis.".to_string()
    } else if unsafe_count == 0 {
        "All detected algorithms are quantum-safe. No immediate action required.".to_string()
    } else if critical > 0 {
        format!("{} critical quantum-vulnerable algorithm(s) detected. Immediate migration required. Harvest-Now-Decrypt-Later attacks are a current threat.", critical)
    } else {
        format!("{} quantum-vulnerable algorithm(s) detected. Plan migration to NIST PQC standards.", unsafe_count)
    };

    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    log::info!(
        "pqc_audit findings={} unsafe={} risk={} latency_ms={:.3}",
        findings.len(), unsafe_count, risk_band, latency_ms
    );

    HttpResponse::Ok().json(AuditResponse {
        inventory: findings,
        quantum_risk: QuantumRisk {
            score: risk_score,
            band: risk_band,
            harvest_now_decrypt_later: harvest_risk,
            estimated_threat_horizon: "2030-2035 (NIST/CISA estimate for cryptographically relevant quantum computer)",
        },
        recommendations,
        hybrid_roadmap: roadmap,
        summary: AuditSummary {
            total_findings: unsafe_count + safe_count,
            quantum_unsafe: unsafe_count,
            quantum_safe:   safe_count,
            critical_count: critical,
            recommendation,
        },
        latency_ms,
    })
}
