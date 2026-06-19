// intent_hash.rs - Vortex DFS
// HMAC-SHA256 com rejeição explícita de entradas malformadas.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// Assinatura hex malformada — rejeitar antes de qualquer comparação
    InvalidHexEncoding,
    /// Tamanho inesperado — HMAC-SHA256 sempre produz 32 bytes
    InvalidSignatureLength,
    /// HMAC não confere
    SignatureMismatch,
}

/// Verifica HMAC-SHA256 do payload contra assinatura hex.
///
/// ANTES: unwrap_or_default() silenciava decode falho → vec![] vs 32 bytes = armadilha.
/// AGORA: cada falha tem um motivo explícito e auditável.
pub fn verify_signature(
    payload: &[u8],
    signature_hex: &str,
    secret: &[u8],
) -> Result<(), VerifyError> {
    let provided_bytes = hex::decode(signature_hex)
        .map_err(|_| VerifyError::InvalidHexEncoding)?;

    if provided_bytes.len() != 32 {
        return Err(VerifyError::InvalidSignatureLength);
    }

    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC aceita qualquer tamanho de chave");
    mac.update(payload);

    // Comparação em tempo constante — protege contra timing attacks
    mac.verify_slice(&provided_bytes)
        .map_err(|_| VerifyError::SignatureMismatch)
}

/// Gera HMAC-SHA256 de um payload.
/// Em produção: a chave vem de variável de ambiente ou vault, nunca do código.
pub fn sign_payload(payload: &[u8], secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC aceita qualquer tamanho de chave");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}
