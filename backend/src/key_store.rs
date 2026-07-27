// VORTEX-DFS Engine - Core Cryptographic KeyStore Module
// Clean Architecture & Strict Type-Safe PQC Implementation

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit,
};
use async_trait::async_trait;
use base64::Engine as _;
use sqlx::{PgPool, Row};

use crate::signer_lwe::{keygen_secure, PublicKey, SecretKey};

// ============================================================================
// CONTRATO DA INTERFACE (TRAIT)
// ============================================================================

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn get_or_create(&self, api_key: &str) -> Result<(SecretKey, PublicKey), String>;
}

// ============================================================================
// IMPLEMENTAÇÃO IN-MEMORY (PARA TESTES E MOCK)
// ============================================================================

pub struct InMemoryKeyStore {
    keys: RwLock<HashMap<String, Arc<(SecretKey, PublicKey)>>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::with_capacity(64)),
        }
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for InMemoryKeyStore {
    async fn get_or_create(&self, api_key: &str) -> Result<(SecretKey, PublicKey), String> {
        // 1. Tenta leitura rápida com trava compartilhada
        {
            let map = self.keys.read().map_err(|e| format!("Lock error: {e}"))?;
            if let Some(pair) = map.get(api_key) {
                let (sk, pk) = pair.as_ref();
                return Ok((sk.clone(), pk.clone()));
            }
        }

        // 2. Se não existir, gera novo par PQC determinístico/seguro
        let pair = keygen_secure();

        // 3. Adquire trava exclusiva para gravação
        let mut map = self.keys.write().map_err(|e| format!("Lock error: {e}"))?;
        let entry = map
            .entry(api_key.to_string())
            .or_insert_with(|| Arc::new(pair));
        let (sk, pk) = entry.as_ref();
        Ok((sk.clone(), pk.clone()))
    }
}

// ============================================================================
// IMPLEMENTAÇÃO MOCK PARA CI/CD
// ============================================================================
#[allow(dead_code)]
pub struct MockKeyStore;

#[allow(dead_code)]
impl MockKeyStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for MockKeyStore {
    async fn get_or_create(&self, _api_key: &str) -> Result<(SecretKey, PublicKey), String> {
        let (sk, pk) = crate::signer_lwe::keygen(999);
        Ok((sk, pk))
    }
}

// ============================================================================
// IMPLEMENTAÇÃO PERSISTENTE POSTGRESQL (SUPABASE / PRODUCTION)
// ============================================================================

pub struct PostgresKeyStore {
    pool: &'static PgPool,
}

impl PostgresKeyStore {
    pub fn new(pool: &'static PgPool) -> Self {
        Self { pool }
    }
}

fn get_master_key() -> Result<[u8; 32], String> {
    let key_str = std::env::var("VORTEX_MASTER_KEY")
        .map_err(|_| "VORTEX_MASTER_KEY não configurada no ambiente".to_string())?;
    
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&key_str)
        .map_err(|e| format!("Falha ao decodificar VORTEX_MASTER_KEY base64: {e}"))?;

    if bytes.len() != 32 {
        return Err(format!(
            "VORTEX_MASTER_KEY deve ter exatamente 32 bytes (recebido {} bytes)",
            bytes.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn encrypt_secret_key(sk: &SecretKey) -> Result<Vec<u8>, String> {
    let key_bytes = get_master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| e.to_string())?;
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let json = serde_json::to_vec(sk).map_err(|e| e.to_string())?;
    let ciphertext = cipher.encrypt(nonce, json.as_ref()).map_err(|e| e.to_string())?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_secret_key(encrypted_data: &[u8]) -> Result<SecretKey, String> {
    if encrypted_data.len() < 12 {
        return Err("Dados criptografados inválidos ou corrompidos".to_string());
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let key_bytes = get_master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| e.to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let json = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        "falha ao decriptar secret key (chave mestra errada ou dado adulterado)".to_string()
    })?;

    serde_json::from_slice(&json).map_err(|e| e.to_string())
}

#[async_trait]
impl KeyStore for PostgresKeyStore {
    async fn get_or_create(&self, api_key: &str) -> Result<(SecretKey, PublicKey), String> {
        let existing = sqlx::query("SELECT secret_key_enc, public_key_json FROM pqc_keys WHERE api_key = $1")
            .bind(api_key)
            .fetch_optional(self.pool)
            .await
            .map_err(|e| format!("erro ao consultar pqc_keys: {e}"))?;

        if let Some(row) = existing {
            let secret_key_enc: Vec<u8> = row.try_get("secret_key_enc").map_err(|e| e.to_string())?;
            let public_key_json: serde_json::Value = row.try_get("public_key_json").map_err(|e| e.to_string())?;
            let sk = decrypt_secret_key(&secret_key_enc)?;
            let pk: PublicKey = serde_json::from_value(public_key_json).map_err(|e| e.to_string())?;
            return Ok((sk, pk));
        }

        let (sk, pk) = keygen_secure();
        let enc_sk = encrypt_secret_key(&sk)?;
        let pk_json = serde_json::to_value(&pk).map_err(|e| e.to_string())?;

        let _ = sqlx::query(
            "INSERT INTO pqc_keys (api_key, secret_key_enc, public_key_json) VALUES ($1, $2, $3) ON CONFLICT (api_key) DO NOTHING"
        )
        .bind(api_key)
        .bind(&enc_sk)
        .bind(&pk_json)
        .execute(self.pool)
        .await;

        let row = sqlx::query("SELECT secret_key_enc, public_key_json FROM pqc_keys WHERE api_key = $1")
            .bind(api_key)
            .fetch_one(self.pool)
            .await
            .map_err(|e| format!("erro ao reconsultar pqc_keys apos insert: {e}"))?;

        let secret_key_enc: Vec<u8> = row.try_get("secret_key_enc").map_err(|e| e.to_string())?;
        let public_key_json: serde_json::Value = row.try_get("public_key_json").map_err(|e| e.to_string())?;
        let sk = decrypt_secret_key(&secret_key_enc)?;
        let pk: PublicKey = serde_json::from_value(public_key_json).map_err(|e| e.to_string())?;
        Ok((sk, pk))
    }
}

// ============================================================================
// SUÍTE DE TESTES UNITÁRIOS E INTEGRAÇÃO LOCAL
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_lwe::verify;

    #[test]
    fn secret_key_survives_encrypt_decrypt_roundtrip() {
        std::env::set_var(
            "VORTEX_MASTER_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        let (sk, _pk) = keygen_secure();
        let enc = encrypt_secret_key(&sk).unwrap();
        let dec = decrypt_secret_key(&enc).unwrap();
        assert_eq!(sk.expose_for_test(), dec.expose_for_test());
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        std::env::set_var(
            "VORTEX_MASTER_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        let (sk, _pk) = keygen_secure();
        let mut enc = encrypt_secret_key(&sk).unwrap();
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(decrypt_secret_key(&enc).is_err());
    }

    #[tokio::test]
    async fn keypair_from_store_signs_and_verifies_correctly_inmemory() {
        let store = InMemoryKeyStore::new();
        let (sk, pk) = store
            .get_or_create("customer_functional_test")
            .await
            .unwrap();
        let data = b"nota fiscal 12345";
        let sig = sk.sign(data, &pk);
        assert!(verify(&pk, data, &sig));
    }
}