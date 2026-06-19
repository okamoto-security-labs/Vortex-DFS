// OKA_Signer.rs - Vortex DFS
// Verificação de integridade do binário via SHA-256.

use sha2::{Sha256, Digest};
use std::io::Read;

#[derive(Debug, PartialEq)]
pub enum IntegrityError {
    /// /proc/self/exe inacessível (container sem /proc, permissão negada, etc.)
    BinaryNotAccessible(String),
    /// Erro de I/O durante leitura
    ReadError(String),
    /// Hash calculado não confere com o esperado
    HashMismatch { expected: String, got: String },
}

/// Verifica a integridade do binário em execução via SHA-256.
///
/// ANTES: .expect() → panic e downtime se /proc/self/exe não abrir.
/// AGORA: retorna Result — o chamador decide se trata como fatal ou degraded.
///
/// Em containers OCI sem /proc: verifique o hash do binário em disco
/// antes do entrypoint e injete o hash esperado via variável de ambiente.
pub fn verify_self_integrity(expected_hash: &str) -> Result<(), IntegrityError> {
    let mut file = std::fs::File::open("/proc/self/exe")
        .map_err(|e| IntegrityError::BinaryNotAccessible(e.to_string()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => return Err(IntegrityError::ReadError(e.to_string())),
        }
    }

    let got = format!("{:x}", hasher.finalize());

    if got != expected_hash {
        return Err(IntegrityError::HashMismatch {
            expected: expected_hash.to_string(),
            got,
        });
    }

    Ok(())
}
