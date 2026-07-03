// key_store.rs — Vortex DFS
//
// ============================================================================
// CHANGELOG (parte 2 do fix do Finding #3)
// ============================================================================
// A versão anterior deste arquivo resolvia a metade "não derivar a chave
// da API key" do Finding #3, mas usava InMemoryKeyStore — o que significa
// que TODA chave é perdida a cada restart/hibernação do processo (Render
// free tier reinicia em todo deploy e hiberna com inatividade).
//
// Esta versão adiciona PostgresKeyStore: persiste a chave UMA VEZ, com
// entropia real (keygen_secure), criptografada em repouso com AES-256-GCM,
// no mesmo banco Supabase que o provisioner.rs já usa (reaproveita o
// mesmo PgPool via provisioner::get_pool() — não abre uma segunda conexão).
//
// KeyStore virou uma trait async (via crate `async-trait`) porque consultar
// o Postgres é uma operação async — isso muda a assinatura que os handlers
// em pqc_endpoints.rs chamam (agora precisa de `.await` e tratar `Result`).
// ============================================================================

use std::collections::HashMap;
use std::sync::RwLock;

use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, rand_core::RngCore}};
use async_trait::async_trait;
use base64::Engine as _;
use sqlx::{PgPool, Row};

use crate::signer_lwe::{keygen_secure, PublicKey, SecretKey};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Retorna o par de chaves associado a essa API key, criando um novo
    /// (com entropia real) na primeira vez que essa chave é vista.
    async fn get_or_create(&self, api_key: &str) -> Result<(SecretKey, PublicKey), String>;
}

// ---------------------------------------------------------------------------
// InMemoryKeyStore — mantido só para testes e como fallback de
// desenvolvimento local (sem banco disponível). NÃO USAR EM PRODUÇÃO —
// ver PostgresKeyStore abaixo, que é o que main.rs usa por padrão agora.
// ---------------------------------------------------------------------------

pub struct InMemoryKeyStore {
    keys: RwLock<HashMap<String, (SecretKey, PublicKey)>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self { keys: RwLock::new(HashMap::new()) }
    }
}

#[async_trait]
impl KeyStore for InMemoryKeyStore {
    async fn get_or_create(&self, api_key: &str) -> Result<(SecretKey, PublicKey), String> {
        if let Some((sk, pk)) = self.keys.read().unwrap().get(api_key) {
            return Ok((sk.clone(), pk.clone()));
        }
        let mut keys = self.keys.write().unwrap();
        if let Some((sk, pk)) = keys.get(api_key) {
            return Ok((sk.clone(), pk.clone()));
        }
        let (sk, pk) = keygen_secure();
        keys.insert(api_key.to_string(), (sk.clone(), pk.clone()));
        Ok((sk, pk))
    }
}

// ---------------------------------------------------------------------------
// PostgresKeyStore — implementação de produção.
//
// Requer a tabela `pqc_keys` (ver migrations/001_pqc_keys.sql) e a env var
// VORTEX_MASTER_KEY: 32 bytes em base64, usada para criptografar a chave
// secreta em repouso. Gerar com, por exemplo:
//   openssl rand -base64 32
// NUNCA reusar essa chave mestra para outra coisa, e NUNCA commitar seu
// valor no repositório — vive só nas env vars do Render/Supabase.
// ---------------------------------------------------------------------------

pub struct PostgresKeyStore {
    pool: &'static PgPool,
}

impl PostgresKeyStore {
    pub fn new(pool: &'static PgPool) -> Self {
        Self { pool }
    }
}

fn get_master_key() -> Result<[u8; 32], String> {
    let b64 = std::env::var("VORTEX_MASTER_KEY")
        .map_err(|_| "VORTEX_MASTER_KEY não definida no ambiente".to_string())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("VORTEX_MASTER_KEY não é base64 válido: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "VORTEX_MASTER_KEY precisa decodificar para exatamente 32 bytes, tem {}",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn encrypt_secret_key(sk: &SecretKey) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(sk).map_err(|e| e.to_string())?;
    let key_bytes = get_master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, json.as_ref())
        .map_err(|_| "falha ao criptografar secret key".to_string())?;
    let mut payload = nonce_bytes.to_vec();
    payload.extend(ciphertext);
    Ok(payload)
}

fn decrypt_secret_key(payload: &[u8]) -> Result<SecretKey, String> {
    if payload.len() < 12 {
        return Err("payload de secret key curto demais (corrompido?)".to_string());
    }
    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let key_bytes = get_master_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| e.to_string())?;
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let json = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "falha ao decriptar secret key (chave mestra errada ou dado adulterado)".to_string())?;
    serde_json::from_slice(&json).map_err(|e| e.to_string())
}

#[async_trait]
impl KeyStore for PostgresKeyStore {
    async fn get_or_create(&self, api_key: &str) -> Result<(SecretKey, PublicKey), String> {
        // 1. Tenta buscar chave já existente.
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

        // 2. Não existe: gera com entropia real (OsRng), nunca da API key.
        let (sk, pk) = keygen_secure();
        let secret_key_enc = encrypt_secret_key(&sk)?;
        let public_key_json = serde_json::to_value(&pk).map_err(|e| e.to_string())?;

        // ON CONFLICT DO NOTHING: se duas requisições concorrentes
        // chegarem ao mesmo tempo pra uma API key nova, evita duas
        // linhas/chaves diferentes pro mesmo api_key — a segunda perde
        // a corrida e, no passo 3, lê a versão que a primeira gravou.
        sqlx::query(
            "INSERT INTO pqc_keys (api_key, secret_key_enc, public_key_json) \
             VALUES ($1, $2, $3) ON CONFLICT (api_key) DO NOTHING",
        )
        .bind(api_key)
        .bind(&secret_key_enc)
        .bind(&public_key_json)
        .execute(self.pool)
        .await
        .map_err(|e| format!("erro ao inserir em pqc_keys: {e}"))?;

        // 3. Re-busca pra garantir que devolvemos a versão persistida
        // (a nossa, ou a da requisição concorrente que ganhou a corrida).
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

// ---------------------------------------------------------------------------
// Testes: a parte de criptografia/serialização é testável sem banco.
// A parte de query SQL (fetch_optional/execute) NÃO é coberta aqui —
// precisa de um Postgres real (ver seção de testes de integração no
// CLAUDE.md, a criar). Isso é uma limitação conhecida, não um teste
// que está sendo pulado por preguiça.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_lwe::verify;

    #[test]
    fn secret_key_survives_encrypt_decrypt_roundtrip() {
        std::env::set_var("VORTEX_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let (sk, _pk) = keygen_secure();
        let enc = encrypt_secret_key(&sk).unwrap();
        let dec = decrypt_secret_key(&enc).unwrap();
        assert_eq!(sk.expose_for_test(), dec.expose_for_test());
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        std::env::set_var("VORTEX_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let (sk, _pk) = keygen_secure();
        let mut enc = encrypt_secret_key(&sk).unwrap();
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(decrypt_secret_key(&enc).is_err());
    }

    #[test]
    fn missing_master_key_fails_clearly() {
        std::env::remove_var("VORTEX_MASTER_KEY");
        let (sk, _pk) = keygen_secure();
        let result = encrypt_secret_key(&sk);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn same_api_key_returns_same_keypair_across_calls_inmemory() {
        let store = InMemoryKeyStore::new();
        let (sk1, pk1) = store.get_or_create("customer_abc").await.unwrap();
        let (sk2, pk2) = store.get_or_create("customer_abc").await.unwrap();
        assert_eq!(sk1.expose_for_test(), sk2.expose_for_test());
        assert_eq!(pk1.b, pk2.b);
    }

    #[tokio::test]
    async fn different_api_keys_get_different_keypairs_inmemory() {
        let store = InMemoryKeyStore::new();
        let (sk1, _) = store.get_or_create("customer_abc").await.unwrap();
        let (sk2, _) = store.get_or_create("customer_xyz").await.unwrap();
        assert_ne!(sk1.expose_for_test(), sk2.expose_for_test());
    }

    #[tokio::test]
    async fn keypair_from_store_signs_and_verifies_correctly_inmemory() {
        let store = InMemoryKeyStore::new();
        let (sk, pk) = store.get_or_create("customer_functional_test").await.unwrap();
        let data = b"nota fiscal 12345";
        let sig = sk.sign(data, &pk);
        assert!(verify(&pk, data, &sig));
    }
}
