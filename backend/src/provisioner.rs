// provisioner.rs — Vortex DFS · Post-payment provisioning
//
// MIGRATION: customers.json → Supabase PostgreSQL
//
// WHY SUPABASE:
// - Render free tier has ephemeral filesystem — customers.json is lost on restart
// - Supabase free tier: 500MB, persistent, zero ops burden
// - sqlx gives us compile-time checked queries with async support
//
// SETUP:
// 1. Add DATABASE_URL to Render environment variables
// 2. Run the migration SQL in Supabase SQL Editor (see bottom of file)
// 3. Deploy

use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::OnceCell;

// ---------------------------------------------------------------------------
// Database pool — initialized once at startup
// ---------------------------------------------------------------------------

static DB_POOL: OnceCell<PgPool> = OnceCell::new();

pub async fn init_db() -> Result<(), String> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL not set".to_string())?;

    let pool = PgPool::connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to Supabase: {}", e))?;

    // Run migrations on startup
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS customers (
            id              SERIAL PRIMARY KEY,
            api_key         TEXT NOT NULL UNIQUE,
            email           TEXT NOT NULL,
            plan            TEXT NOT NULL,
            billing_period  TEXT NOT NULL,
            stripe_customer TEXT NOT NULL,
            stripe_sub      TEXT NOT NULL UNIQUE,
            status          TEXT NOT NULL DEFAULT 'active',
            created_at      BIGINT NOT NULL,
            expires_at      BIGINT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Migration failed: {}", e))?;

    // Index for fast API key lookups (hot path)
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_customers_api_key ON customers(api_key)"
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Index creation failed: {}", e))?;

    DB_POOL.set(pool).map_err(|_| "DB pool already initialized".to_string())?;

    log::info!("Supabase connection established");
    Ok(())
}

fn get_pool() -> Result<&'static PgPool, String> {
    DB_POOL.get().ok_or_else(|| "Database not initialized".to_string())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Customer {
    pub api_key:         String,
    pub email:           String,
    pub plan:            String,
    pub billing_period:  String,
    pub stripe_customer: String,
    pub stripe_sub:      String,
    pub status:          String,
    pub created_at:      u64,
    pub expires_at:      u64,
}

// ---------------------------------------------------------------------------
// API key generation
//
// WHY THIS FORMAT:
// - "vdfs_live_" prefix → instantly identifiable as a Vortex DFS key
// - 32 bytes of random hex → 256 bits of entropy, brute-force impossible
// - Our own anonymizer_engine.rs detects and redacts these if exposed
// ---------------------------------------------------------------------------

pub fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
    format!("vdfs_live_{}", hex::encode(bytes))
}

// ---------------------------------------------------------------------------
// Customer persistence — Supabase PostgreSQL
// ---------------------------------------------------------------------------

pub async fn upsert_customer(customer: Customer) -> Result<(), String> {
    let pool = get_pool()?;

    sqlx::query(
        r#"
        INSERT INTO customers
            (api_key, email, plan, billing_period, stripe_customer, stripe_sub,
             status, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (stripe_sub) DO UPDATE SET
            api_key        = EXCLUDED.api_key,
            email          = EXCLUDED.email,
            plan           = EXCLUDED.plan,
            billing_period = EXCLUDED.billing_period,
            status         = EXCLUDED.status,
            expires_at     = EXCLUDED.expires_at
        "#,
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
    .map_err(|e| format!("upsert_customer failed: {}", e))?;

    Ok(())
}

pub fn find_by_api_key(api_key: &str) -> Option<Customer> {
    // Synchronous wrapper for use in auth_and_rate (called from sync context)
    // Uses tokio::task::block_in_place to avoid blocking the async runtime
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(find_by_api_key_async(api_key))
    })
}

async fn find_by_api_key_async(api_key: &str) -> Option<Customer> {
    let pool = get_pool().ok()?;

    let row = sqlx::query!(
        r#"
        SELECT api_key, email, plan, billing_period, stripe_customer,
               stripe_sub, status, created_at, expires_at
        FROM customers
        WHERE api_key = $1
        "#,
        api_key
    )
    .fetch_optional(pool)
    .await
    .ok()??;

    Some(Customer {
        api_key:         row.api_key,
        email:           row.email,
        plan:            row.plan,
        billing_period:  row.billing_period,
        stripe_customer: row.stripe_customer,
        stripe_sub:      row.stripe_sub,
        status:          row.status,
        created_at:      row.created_at as u64,
        expires_at:      row.expires_at as u64,
    })
}

pub async fn find_by_subscription(sub_id: &str) -> Option<Customer> {
    let pool = get_pool().ok()?;

    let row = sqlx::query!(
        r#"
        SELECT api_key, email, plan, billing_period, stripe_customer,
               stripe_sub, status, created_at, expires_at
        FROM customers
        WHERE stripe_sub = $1
        "#,
        sub_id
    )
    .fetch_optional(pool)
    .await
    .ok()??;

    Some(Customer {
        api_key:         row.api_key,
        email:           row.email,
        plan:            row.plan,
        billing_period:  row.billing_period,
        stripe_customer: row.stripe_customer,
        stripe_sub:      row.stripe_sub,
        status:          row.status,
        created_at:      row.created_at as u64,
        expires_at:      row.expires_at as u64,
    })
}

pub async fn update_status(sub_id: &str, status: &str) -> Result<(), String> {
    let pool = get_pool()?;

    sqlx::query!(
        "UPDATE customers SET status = $1 WHERE stripe_sub = $2",
        status,
        sub_id
    )
    .execute(pool)
    .await
    .map_err(|e| format!("update_status failed: {}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Expiry calculation
// ---------------------------------------------------------------------------

pub fn expiry_timestamp(billing_period: &str) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let seconds = match billing_period {
        "weekly"  => 7   * 24 * 3600,
        "monthly" => 30  * 24 * 3600,
        "annual"  => 365 * 24 * 3600,
        _         => 30  * 24 * 3600,
    };

    now + seconds
}

// ---------------------------------------------------------------------------
// Plan detection from Stripe Price ID
// ---------------------------------------------------------------------------

pub fn plan_from_price_id(price_id: &str) -> (&'static str, &'static str) {
    match price_id {
        "price_1TkWGLHkQnONoSg0rpy3ETei" => ("starter",    "weekly"),
        "price_1TkWS3HkQnONoSg0ZhnLIioB" => ("starter",    "monthly"),
        "price_1TkWS3HkQnONoSg0zvXxrMep" => ("starter",    "annual"),
        "price_1TkWI5HkQnONoSg0cEwfu5Yw" => ("pro",        "weekly"),
        "price_1TkWI5HkQnONoSg0OCFxD8DL" => ("pro",        "monthly"),
        "price_1TkWI5HkQnONoSg0wZYGCq6Y" => ("pro",        "annual"),
        "price_1TkWIgHkQnONoSg0kg2lr30i" => ("enterprise", "weekly"),
        "price_1TkWJaHkQnONoSg0KrSqRKbG" => ("enterprise", "monthly"),
        "price_1TkWJaHkQnONoSg0jtXBgax4" => ("enterprise", "annual"),
        _                                 => ("starter",    "monthly"),
    }
}

// ---------------------------------------------------------------------------
// Email delivery via Resend (unchanged)
// ---------------------------------------------------------------------------

pub async fn send_welcome_email(customer: &Customer) -> Result<(), String> {
    let resend_key = std::env::var("RESEND_API_KEY")
        .map_err(|_| "RESEND_API_KEY not set".to_string())?;

    let from_email = std::env::var("FROM_EMAIL")
        .unwrap_or_else(|_| "gustavo@okamotosecurytlabs.com.br".to_string());

    let plan_display = match customer.plan.as_str() {
        "starter"    => "Starter",
        "pro"        => "Pro",
        "enterprise" => "Enterprise",
        _            => "Starter",
    };

    let period_display = match customer.billing_period.as_str() {
        "weekly"  => "week",
        "monthly" => "month",
        "annual"  => "year",
        _         => "month",
    };

    let html_body = format!(r#"
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:monospace;background:#04080F;color:#E2E8F0;padding:40px;margin:0">
  <div style="max-width:560px;margin:0 auto">
    <div style="color:#0EA5E9;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;margin-bottom:8px">
      Okamoto Security Labs
    </div>
    <h1 style="font-family:Georgia,serif;font-weight:400;font-size:28px;color:#F8FAFC;margin:0 0 32px">
      Your Vortex DFS key is ready.
    </h1>
    <div style="background:#0F172A;border:1px solid #1E293B;border-radius:8px;padding:24px;margin-bottom:24px">
      <div style="font-size:11px;color:#64748B;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:8px">
        API Key · {plan_display} · per {period_display}
      </div>
      <div style="color:#0EA5E9;font-size:13px;word-break:break-all;letter-spacing:0.05em">
        {api_key}
      </div>
    </div>
    <div style="font-size:13px;color:#94A3B8;line-height:1.75;margin-bottom:32px">
      Add this key to your environment:<br>
      <code style="background:#0F172A;padding:2px 6px;border-radius:4px;color:#0EA5E9">
        export VORTEX_API_KEY="{api_key}"
      </code>
    </div>
    <div style="border-top:1px solid #1E293B;padding-top:24px;font-size:12px;color:#475569">
      <div style="margin-bottom:8px">
        <strong style="color:#94A3B8">Documentation</strong><br>
        <a href="https://okamotosecurytlabs.com.br" style="color:#0EA5E9">okamotosecurytlabs.com.br</a>
      </div>
      <div style="margin-bottom:8px">
        <strong style="color:#94A3B8">Support</strong><br>
        <a href="mailto:gustavo@okamotosecurytlabs.com.br" style="color:#0EA5E9">gustavo@okamotosecurytlabs.com.br</a>
      </div>
      <div style="margin-top:16px;color:#334155;font-size:11px">
        Keep this key confidential. Do not commit it to version control.<br>
        Vortex DFS will detect and redact it automatically if exposed.
      </div>
    </div>
  </div>
</body>
</html>
"#,
        plan_display = plan_display,
        period_display = period_display,
        api_key = customer.api_key,
    );

    let payload = serde_json::json!({
        "from": format!("Okamoto Security Labs <{}>", from_email),
        "to":   [&customer.email],
        "subject": format!("Your Vortex DFS {} key", plan_display),
        "html": html_body,
    });

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", resend_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Resend HTTP error: {}", e))?;

    if resp.status().is_success() {
        log::info!("Welcome email sent to {}", customer.email);
        Ok(())
    } else {
        let err = resp.text().await.unwrap_or_default();
        Err(format!("Resend API error: {}", err))
    }
}

pub async fn send_cancellation_email(customer: &Customer) -> Result<(), String> {
    let resend_key = std::env::var("RESEND_API_KEY")
        .map_err(|_| "RESEND_API_KEY not set".to_string())?;

    let from_email = std::env::var("FROM_EMAIL")
        .unwrap_or_else(|_| "gustavo@okamotosecurytlabs.com.br".to_string());

    let payload = serde_json::json!({
        "from": format!("Okamoto Security Labs <{}>", from_email),
        "to":   [&customer.email],
        "subject": "Your Vortex DFS subscription has been cancelled",
        "html": format!(r#"
<body style="font-family:monospace;background:#04080F;color:#E2E8F0;padding:40px">
  <div style="max-width:560px;margin:0 auto">
    <div style="color:#0EA5E9;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;margin-bottom:8px">
      Okamoto Security Labs
    </div>
    <h1 style="font-family:Georgia,serif;font-weight:400;font-size:24px;color:#F8FAFC">
      Subscription cancelled.
    </h1>
    <p style="color:#94A3B8;font-size:13px;line-height:1.75">
      Your Vortex DFS access has been deactivated.<br>
      API key <code style="color:#0EA5E9">{}</code> is no longer valid.
    </p>
    <p style="color:#94A3B8;font-size:13px">
      To reactivate, visit
      <a href="https://okamotosecurytlabs.com.br" style="color:#0EA5E9">okamotosecurytlabs.com.br</a>
    </p>
  </div>
</body>"#, &customer.api_key[..20]),
    });

    let client = reqwest::Client::new();
    client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", resend_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Resend HTTP error: {}", e))?;

    Ok(())
}
