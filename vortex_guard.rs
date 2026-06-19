// vortex_guard.rs - Vortex DFS
// Middleware de verificação de integridade — lógica pura, sem Axum/async.
// Integre com Axum chamando evaluate() dentro do handler assíncrono.

use crate::intent_hash;

pub const MAX_BODY_SIZE: usize = 1 * 1024 * 1024; // 1 MB

#[derive(Debug, PartialEq)]
pub enum GuardDecision {
    Allow,
    Block(BlockReason),
}

#[derive(Debug, PartialEq)]
pub enum BlockReason {
    MissingSignature,
    BodyTooLarge { size: usize, limit: usize },
    /// Motivo técnico interno — NUNCA loga a assinatura do atacante
    InvalidSignature(String),
    InvalidSessionId,
}

/// Sanitiza session_id do cliente antes de qualquer uso em logs.
///
/// ANTES: session_id ia direto pro log → log injection possível.
/// AGORA: apenas [a-zA-Z0-9-_], máx 64 chars.
pub fn sanitize_session_id(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();

    if clean.is_empty() { "INVALID_SESSION".to_string() } else { clean }
}

/// Carrega a chave HMAC da variável de ambiente.
///
/// ANTES: b"SECRET_KEY_DO_SISTEMA" hardcoded no fonte — visível em qualquer
///        clone do repositório, no binário compilado (via `strings`), e no
///        histórico do git para sempre.
/// AGORA: nunca toca o código. Injete via:
///   export VORTEX_HMAC_KEY="$(openssl rand -hex 32)"
///   # ou via AWS Secrets Manager / HashiCorp Vault
pub fn load_hmac_key() -> Result<Vec<u8>, String> {
    std::env::var("VORTEX_HMAC_KEY")
        .map(|k| k.into_bytes())
        .map_err(|_| "VORTEX_HMAC_KEY não definida no ambiente".to_string())
}

/// Núcleo da decisão do guard — pura, síncrona, totalmente testável.
///
/// Retorna (GuardDecision, session_id_sanitizado).
/// O caller (Axum handler) usa o session_id retornado para logging.
pub fn evaluate(
    body: &[u8],
    signature_hex: Option<&str>,
    raw_session_id: &str,
    hmac_key: &[u8],
) -> (GuardDecision, String) {
    let session_id = sanitize_session_id(raw_session_id);

    // Guarda 1: DoS — corpo grande demais
    if body.len() > MAX_BODY_SIZE {
        return (GuardDecision::Block(BlockReason::BodyTooLarge {
            size: body.len(), limit: MAX_BODY_SIZE,
        }), session_id);
    }

    // Guarda 2: assinatura ausente
    let sig_hex = match signature_hex {
        Some(s) => s,
        None => return (GuardDecision::Block(BlockReason::MissingSignature), session_id),
    };

    // Guarda 3: verificação HMAC
    // ATENÇÃO: nunca logue sig_hex aqui — é dado do atacante
    match intent_hash::verify_signature(body, sig_hex, hmac_key) {
        Ok(()) => (GuardDecision::Allow, session_id),
        Err(e) => (GuardDecision::Block(
            BlockReason::InvalidSignature(format!("{:?}", e))
        ), session_id),
    }
}

// ---- Integração Axum (referência, não compilada aqui) -----------
//
// pub async fn vortex_intent_guard(req: Request<Body>, next: Next) -> impl IntoResponse {
//     let hmac_key = match load_hmac_key() {
//         Ok(k) => k,
//         Err(e) => {
//             error!(target: "vortex_security", "Chave HMAC não configurada: {}", e);
//             return (StatusCode::INTERNAL_SERVER_ERROR, "Configuração incompleta").into_response();
//         }
//     };
//
//     let (parts, body) = req.into_parts();
//     let bytes = match body.collect().await {
//         Ok(c) => c.to_bytes(),
//         Err(_) => return (StatusCode::BAD_REQUEST, "Payload inválido").into_response(),
//     };
//
//     let sig = parts.headers.get("X-Intent-Signature").and_then(|h| h.to_str().ok());
//     let raw_sid = parts.headers.get("X-Session-ID")
//         .and_then(|h| h.to_str().ok()).unwrap_or("");
//
//     let (decision, session_id) = evaluate(&bytes, sig, raw_sid, &hmac_key);
//
//     match decision {
//         GuardDecision::Allow => {
//             info!(target: "vortex_security", session_id = %session_id, "Requisição autorizada");
//             let req = Request::from_parts(parts, Body::from(bytes));
//             next.run(req).await.into_response()
//         }
//         GuardDecision::Block(reason) => {
//             // NUNCA loga a assinatura do atacante — apenas o motivo técnico
//             warn!(target: "vortex_security",
//                   event = "BLOCKED",
//                   session_id = %session_id,
//                   reason = ?reason,
//                   "Requisição bloqueada");
//             (StatusCode::FORBIDDEN, "Acesso negado").into_response()
//         }
//     }
// }
