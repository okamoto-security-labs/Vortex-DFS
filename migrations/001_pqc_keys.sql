-- migrations/001_pqc_keys.sql
-- Rodar no SQL editor do Supabase (ou via CLI de migration, se o projeto
-- já tiver um fluxo formal — provisioner.rs não deixou claro qual usa).
--
-- Guarda o par de chaves LWE por API key. A secret key NUNCA fica em
-- texto claro aqui — vai criptografada com AES-256-GCM (chave mestra em
-- VORTEX_MASTER_KEY, fora do banco). A public key não precisa de
-- criptografia (é pública por definição), fica em JSONB.

CREATE TABLE IF NOT EXISTS pqc_keys (
    api_key          TEXT PRIMARY KEY,
    secret_key_enc   BYTEA NOT NULL,
    public_key_json  JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Índice não é estritamente necessário (api_key já é PRIMARY KEY, que
-- cria índice automaticamente), mas deixamos explícito por clareza caso
-- alguém revise o schema depois.
COMMENT ON TABLE pqc_keys IS
    'Chaves de assinatura LWE por cliente. secret_key_enc é AES-256-GCM '
    'criptografado com a chave mestra em VORTEX_MASTER_KEY (env var, '
    'nunca no banco). Gerada uma vez via keygen_secure() (OsRng real), '
    'nunca derivada da própria api_key -- ver Finding #3 na auditoria '
    'de seguranca de 01/07/2026.';