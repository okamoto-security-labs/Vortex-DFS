// =========================================================================
// VORTEX-DFS - PROVISIONER MODULE (SUPABASE POSTGRESQL & STRIPE SYNC)
// Clean Architecture & Single-Declaration Namespace
// =========================================================================

use base64::Engine; // <-- IMPORT NECESSÁRIO PARA RESOLVER A TRAIT DE ENCODE
use once_cell::sync::OnceCell;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

static DB_POOL: OnceCell<PgPool> = OnceCell::new();

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Customer {
    pub api_key: String,
    pub email: String,
    pub plan: String,
    pub billing_period: String,
    pub stripe_customer: String,
    pub stripe_sub: String,
    pub status: String,
    pub created_at: u64,
    pub expires_at: u64,
}

pub fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 24] = rng.gen();
    format!(
        "vortex_live_{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

pub async fn init_db() -> Result<(), String> {
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL not set".to_string())?;

    let options = sqlx::postgres::PgConnectOptions::from_str(&database_url)
        .map_err(|e| format!("URL de banco de dados inválida: {}", e))?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(|e| format!("Falha ao conectar no Supabase: {}", e))?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS customers (
            api_key TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            plan TEXT NOT NULL,
            billing_period TEXT NOT NULL,
            stripe_customer TEXT NOT NULL,
            stripe_sub TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Migration failed: {}", e))?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_customers_api_key ON customers(api_key)")
        .execute(&pool)
        .await
        .map_err(|e| format!("Index creation failed: {}", e))?;

    DB_POOL
        .set(pool)
        .map_err(|_| "DB pool already initialized".to_string())?;

    log::info!("Supabase connection established");
    Ok(())
}

pub(crate) fn get_pool() -> Result<&'static PgPool, String> {
    DB_POOL
        .get()
        .ok_or_else(|| "Database not initialized".to_string())
}

pub async fn upsert_customer(customer: Customer) -> Result<(), String> {
    let pool = get_pool()?;
    sqlx::query(
        r#"
        INSERT INTO customers (api_key, email, plan, billing_period, stripe_customer, stripe_sub, status, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (api_key) DO UPDATE SET
            status = EXCLUDED.status,
            expires_at = EXCLUDED.expires_at,
            plan = EXCLUDED.plan
        "#
    )
    .bind(&customer.api_key)
    .bind(&customer.email)
    .bind(&customer.plan)
    .bind(&customer.billing_period)
    .bind(&customer.stripe_customer)
    .bind(&customer.stripe_sub)
    .bind(&customer.status)
    .bind(customer.created_at as i64)
    .bind(customer.expires_at as i64)
    .execute(pool)
    .await
    .map_err(|e| format!("Upsert customer failed: {e}"))?;

    Ok(())
}

pub fn find_by_api_key(api_key: &str) -> Option<Customer> {
    // Implementação síncrona de cache/fallback se necessária
    let _ = api_key;
    None
}

pub async fn find_by_subscription(sub_id: &str) -> Option<Customer> {
    let pool = get_pool().ok()?;
    let row = sqlx::query("SELECT api_key, email, plan, billing_period, stripe_customer, stripe_sub, status, created_at, expires_at FROM customers WHERE stripe_sub = $1")
        .bind(sub_id)
        .fetch_optional(pool)
        .await
        .ok()?;

    let row = row?;
    Some(Customer {
        api_key: row.get("api_key"),
        email: row.get("email"),
        plan: row.get("plan"),
        billing_period: row.get("billing_period"),
        stripe_customer: row.get("stripe_customer"),
        stripe_sub: row.get("stripe_sub"),
        status: row.get("status"),
        created_at: row.get::<i64, _>("created_at") as u64,
        expires_at: row.get::<i64, _>("expires_at") as u64,
    })
}

pub async fn update_status(sub_id: &str, status: &str) -> Result<(), String> {
    let pool = get_pool()?;
    sqlx::query("UPDATE customers SET status = $1 WHERE stripe_sub = $2")
        .bind(status)
        .bind(sub_id)
        .execute(pool)
        .await
        .map_err(|e| format!("Update status failed: {e}"))?;
    Ok(())
}

pub fn expiry_timestamp(billing_period: &str) -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let seconds = match billing_period {
        "weekly" => 7 * 24 * 3600,
        "monthly" => 30 * 24 * 3600,
        "annual" => 365 * 24 * 3600,
        _ => 30 * 24 * 3600,
    };
    now + seconds
}

pub fn plan_from_price_id(price_id: &str) -> (&'static str, &'static str) {
    match price_id {
        "price_1TkWGLHkQnONoSg0rpy3ETei" => ("starter", "weekly"),
        "price_1TkWS3HkQnONoSg0ZhnLIioB" => ("starter", "monthly"),
        "price_1TkWS3HkQnONoSg0zvXxrMep" => ("starter", "annual"),
        "price_1TkWI5HkQnONoSg0cEwfu5Yw" => ("pro", "weekly"),
        "price_1TkWI5HkQnONoSg0OCFxD8DL" => ("pro", "monthly"),
        "price_1TkWI5HkQnONoSg0wZYGCq6Y" => ("pro", "annual"),
        "price_1TkWIgHkQnONoSg0kg2lr30i" => ("enterprise", "weekly"),
        "price_1TkWJaHkQnONoSg0KrSqRKbG" => ("enterprise", "monthly"),
        "price_1TkWJaHkQnONoSg0jtXBgax4" => ("enterprise", "annual"),
        _ => ("starter", "monthly"),
    }
}

pub async fn send_welcome_email(customer: &Customer) -> Result<(), String> {
    let resend_key = std::env::var("RESEND_API_KEY")
        .map_err(|_| "RESEND_API_KEY not set".to_string())?;
    let from_email = std::env::var("FROM_EMAIL")
        .unwrap_or_else(|_| "gustavo@okamotosecurytlabs.com.br".to_string());

    let client = reqwest::Client::new();
    let resp = client.post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", resend_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "from": from_email,
            "to": [customer.email],
            "subject": "Vortex DFS — Acesso Liberado & Chaves PQC",
            "html": format!("<p>Seu acesso ao Vortex DFS foi provisionado com sucesso. API Key: <code>{}</code></p>", customer.api_key)
        }))
        .send()
        .await
        .map_err(|e| format!("Resend request failed: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Resend error: {}", resp.text().await.unwrap_or_default()))
    }
}

pub async fn send_cancellation_email(customer: &Customer) -> Result<(), String> {
    let resend_key = std::env::var("RESEND_API_KEY")
        .map_err(|_| "RESEND_API_KEY not set".to_string())?;
    let from_email = std::env::var("FROM_EMAIL")
        .unwrap_or_else(|_| "gustavo@okamotosecurytlabs.com.br".to_string());

    let client = reqwest::Client::new();
    let resp = client.post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", resend_key))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "from": from_email,
            "to": [customer.email],
            "subject": "Vortex DFS — Assinatura Cancelada",
            "html": "<p>Sua assinatura foi cancelada e o acesso revogado.</p>"
        }))
        .send()
        .await
        .map_err(|e| format!("Resend request failed: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Resend error: {}", resp.text().await.unwrap_or_default()))
    }
}