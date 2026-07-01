// key_store.rs — Vortex DFS (NOVO módulo — fix Finding #3)
//
// ============================================================================
// PROBLEMA ORIGINAL (Finding #3):
//   handle_sign/handle_verify faziam `keygen(seed_from_key(api_key))` a
//   cada requisição. Como isso é determinístico e o código é open source,
//   qualquer um sabendo a string da API key conseguia recalcular a chave
//   secreta real localmente. A chave "demo" está literalmente nos
//   exemplos de curl do README — ou seja, pública por definição.
//
// FIX:
//   A chave passa a ser gerada UMA VEZ, com entropia real (keygen_secure,
//   que usa OsRng), e a partir daí é armazenada. A API key vira uma CHAVE
//   DE BUSCA (lookup key) num mapa/tabela — não mais uma semente da qual
//   o segredo é derivado. Saber a API key não dá a ninguém nenhuma
//   informação matemática sobre a chave secreta.
// ============================================================================

use std::collections::HashMap;
use std::sync::RwLock;

use crate::signer_lwe::{keygen_secure, PublicKey, SecretKey};

/// Abstração de armazenamento de chaves. A implementação em memória abaixo
/// é só para demonstrar a interface — ver aviso de produção no impl.
pub trait KeyStore: Send + Sync {
    /// Retorna o par de chaves associado a essa API key, criando um novo
    /// (com entropia real) na primeira vez que essa chave é vista.
    fn get_or_create(&self, api_key: &str) -> (SecretKey, PublicKey);
}

/// ⚠️ ATENÇÃO — ISTO NÃO É PRODUCTION-READY.
///
/// Esta implementação guarda as chaves em memória (RwLock<HashMap>).
/// Serve só para provar que a lógica de "gerar uma vez, reusar depois"
/// funciona, e para os testes deste módulo.
///
/// Para produção, isso precisa virar:
///   - Persistência real (Postgres, etc.) — se o processo reiniciar,
///     um HashMap em memória perde todas as chaves e todo cliente
///     pagante fica com assinaturas que não verificam mais.
///   - Criptografia em repouso — a secret key nunca deve tocar disco
///     em texto claro. Idealmente um HSM/KMS (AWS KMS, GCP KMS, Vault)
///     guarda o material, e a aplicação nunca vê `s` diretamente.
///   - Múltiplas instâncias do servidor precisam enxergar o MESMO
///     keystore — memória local de processo não escala horizontalmente.
///
/// O `provisioner.rs` que já existe no projeto (gera API keys, gerencia
/// clientes) é o lugar natural pra chamar `keygen_secure()` UMA VEZ, no
/// momento em que o cliente é criado, e gravar o resultado no mesmo
/// lugar onde a API key dele já é persistida.
pub struct InMemoryKeyStore {
    keys: RwLock<HashMap<String, (SecretKey, PublicKey)>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self { keys: RwLock::new(HashMap::new()) }
    }
}

impl KeyStore for InMemoryKeyStore {
    fn get_or_create(&self, api_key: &str) -> (SecretKey, PublicKey) {
        // Caminho rápido: já existe, só lê.
        if let Some((sk, pk)) = self.keys.read().unwrap().get(api_key) {
            return (sk.clone(), pk.clone());
        }
        // Não existe ainda: gera com entropia real e persiste.
        let mut keys = self.keys.write().unwrap();
        // Re-checa depois de pegar o write lock (outra requisição pode
        // ter criado entre o read acima e este write — evita corrida).
        if let Some((sk, pk)) = keys.get(api_key) {
            return (sk.clone(), pk.clone());
        }
        let (sk, pk) = keygen_secure();
        keys.insert(api_key.to_string(), (sk.clone(), pk.clone()));
        (sk, pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_lwe::verify;

    #[test]
    fn same_api_key_returns_same_keypair_across_calls() {
        let store = InMemoryKeyStore::new();
        let (sk1, pk1) = store.get_or_create("customer_abc");
        let (sk2, pk2) = store.get_or_create("customer_abc");
        assert_eq!(sk1.expose_for_test(), sk2.expose_for_test(),
            "a mesma api_key deveria sempre retornar a mesma chave (persistência)");
        assert_eq!(pk1.b, pk2.b);
    }

    #[test]
    fn different_api_keys_get_different_keypairs() {
        let store = InMemoryKeyStore::new();
        let (sk1, _) = store.get_or_create("customer_abc");
        let (sk2, _) = store.get_or_create("customer_xyz");
        assert_ne!(sk1.expose_for_test(), sk2.expose_for_test());
    }

    /// FIX Finding #3 — teste de aceitação principal.
    /// Duas instâncias INDEPENDENTES de KeyStore, cada uma vendo a MESMA
    /// string de api_key, devem gerar chaves DIFERENTES — provando que
    /// não existe mais nenhuma função determinística (api_key) -> secret.
    /// Isso é o oposto exato do que o Finding #3 provava antes do fix.
    #[test]
    fn finding_3_fixed_same_api_key_string_different_stores_yields_different_secrets() {
        let store_a = InMemoryKeyStore::new(); // simula "servidor"
        let store_b = InMemoryKeyStore::new(); // simula "atacante local"

        let (sk_server, _) = store_a.get_or_create("demo");
        let (sk_attacker, _) = store_b.get_or_create("demo");

        assert_ne!(
            sk_server.expose_for_test(),
            sk_attacker.expose_for_test(),
            "FINDING #3 continuaria explorável: mesma api_key string ainda \
             produz a mesma chave secreta em instâncias diferentes."
        );
    }

    #[test]
    fn keypair_from_store_signs_and_verifies_correctly() {
        let store = InMemoryKeyStore::new();
        let (sk, pk) = store.get_or_create("customer_functional_test");
        let data = b"nota fiscal 12345";
        let sig = sk.sign(data, &pk);
        assert!(verify(&pk, data, &sig));
    }
}
