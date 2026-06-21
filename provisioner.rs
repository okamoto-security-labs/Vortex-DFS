// provisioner.rs — Vortex DFS · Post-payment provisioning
//
// WHY THIS MODULE EXISTS:
// When Stripe confirms a payment, we need to:
//   1. Generate a cryptographically secure API key
//   2. Persist it to disk (JSON — no DB needed for first 100 customers)
//   3. Email it to the customer via Resend
//
// DESIGN DECISION — JSON over PostgreSQL:
// A database adds a network hop, connection pooling overhead, and ops burden.
// For the first 100 customers a JSON file on disk is faster, simpler, and
// zero-cost. We'll migrate to Postgres when concurrent writes become a risk
// (>50 simultaneous checkouts). Until then, file locking is sufficient.
//
// DESIGN DECISION — Resend over SendGrid/SES:
// Resend has a native Rust-friendly REST API, 3000 emails/month free,
// and takes 5 minutes to configure. No SDK needed — plain HTTP POST.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Customer {
    pub api_key:         String,
    pub email:           String,
    pub plan:            String,       // "starter" | "pro" | "enterprise"
    pub billing_period:  String,       // "weekly" | "monthly" | "annual"
    pub stripe_customer: String,
    pub stripe_sub:      String,
    pub status:          String,       // "active" | "past_due" | "cancelled"
    pub created_at:      u64,          // Unix timestamp
    pub expires_at:      u64,          // Unix timestamp
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomerStore {
    customers: Vec<Customer>,
}

const STORE_PATH: &str = "/data/customers.json";

// ---------------------------------------------------------------------------
// API key generation
//
// WHY THIS FORMAT:
// - "vdfs_live_" prefix → instantly identifiable as a Vortex DFS key
//   (same pattern as Stripe's sk_live_, GitHub's ghp_, etc.)
// - 32 bytes of random hex → 256 bits of entropy, brute-force impossible
// - Our own anonymizer_engine.rs will detect and redact these keys
//   if a customer accidentally pastes one into a prompt
// ---------------------------------------------------------------------------

pub fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
    format!("vdfs_live_{}", hex::encode(bytes))
}

// ---------------------------------------------------------------------------
// Customer persistence
// ---------------------------------------------------------------------------

fn load_store() -> CustomerStore {
    if !Path::new(STORE_PATH).exists() {
        return CustomerStore { customers: vec![] };
    }
    let data = fs::read_to_string(STORE_PATH).unwrap_or_default();
    serde_json::from_str(&data).unwrap_or(CustomerStore { customers: vec![] })
}

fn save_store(store: &CustomerStore) -> Result<(), String> {
    // WHY CREATE_DIR_ALL: Railway's /data volume may not exist on first boot
    if let Some(parent) = Path::new(STORE_PATH).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;

    // WHY WRITE TO TEMP THEN RENAME:
    // A crash mid-write corrupts the file. Writing to a temp file and
    // atomically renaming guarantees the store is never in a partial state.
    let tmp = format!("{}.tmp", STORE_PATH);
    fs::write(&tmp, json).map_err(|e| e.to_string())?;
    fs::rename(&tmp, STORE_PATH).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn upsert_customer(customer: Customer) -> Result<(), String> {
    let mut store = load_store();

    // Update existing customer if stripe_sub matches, otherwise append
    if let Some(existing) = store.customers.iter_mut()
        .find(|c| c.stripe_sub == customer.stripe_sub)
    {
        *existing = customer;
    } else {
        store.customers.push(customer);
    }

    save_store(&store)
}

pub fn find_by_subscription(sub_id: &str) -> Option<Customer> {
    load_store().customers.into_iter()
        .find(|c| c.stripe_sub == sub_id)
}

pub fn update_status(sub_id: &str, status: &str) -> Result<(), String> {
    let mut store = load_store();
    if let Some(c) = store.customers.iter_mut().find(|c| c.stripe_sub == sub_id) {
        c.status = status.to_string();
    }
    save_store(&store)
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
        "weekly"  => 7  * 24 * 3600,
        "monthly" => 30 * 24 * 3600,
        "annual"  => 365 * 24 * 3600,
        _         => 30 * 24 * 3600,
    };

    now + seconds
}

// ---------------------------------------------------------------------------
// Plan detection from Stripe Price ID
//
// WHY HARDCODED MAP:
// The Stripe price IDs are fixed — they don't change after creation.
// A hardcoded map is O(1), zero network cost, and trivially auditable.
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
// Email delivery via Resend
//
// SETUP: set RESEND_API_KEY env var in Railway dashboard
// Get your key at resend.com → API Keys → Create API Key
// Verify your domain okamotosecurytlabs.com.br in Resend → Domains
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

    // WHY HTML EMAIL:
    // Plain text gets flagged as transactional spam more often.
    // A minimal branded HTML template improves deliverability and
    // reinforces the product identity at the moment of activation.
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
        <a href="https://okamotosecurytlabs.com.br" style="color:#0EA5E9">
          okamotosecurytlabs.com.br
        </a>
      </div>
      <div style="margin-bottom:8px">
        <strong style="color:#94A3B8">Support</strong><br>
        <a href="mailto:gustavo@okamotosecurytlabs.com.br" style="color:#0EA5E9">
          gustavo@okamotosecurytlabs.com.br
        </a>
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

// ---------------------------------------------------------------------------
// Send cancellation notice
// ---------------------------------------------------------------------------

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
      <a href="https://okamotosecurytlabs.com.br" style="color:#0EA5E9">
        okamotosecurytlabs.com.br
      </a>
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
