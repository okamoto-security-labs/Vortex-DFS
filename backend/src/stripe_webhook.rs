// stripe_webhook.rs — Vortex DFS · Stripe webhook + provisioning pipeline
//
// FLOW:
//   checkout.session.completed  → generate key + send welcome email
//   invoice.payment_succeeded   → renew expiry
//   invoice.payment_failed      → mark past_due (Stripe retries automatically)
//   customer.subscription.deleted → revoke key + send cancellation email

use actix_web::{web, HttpRequest, HttpResponse};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::provisioner::{
    expiry_timestamp, find_by_subscription, generate_api_key, plan_from_price_id,
    send_cancellation_email, send_welcome_email, update_status, upsert_customer, Customer,
};

const TIMESTAMP_TOLERANCE_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

struct StripeSignature {
    timestamp: u64,
    v1: String,
}

fn parse_stripe_signature(header: &str) -> Option<StripeSignature> {
    let mut timestamp = None;
    let mut v1 = None;
    for part in header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = ts.parse().ok();
        } else if let Some(sig) = part.strip_prefix("v1=") {
            v1 = Some(sig.to_string());
        }
    }
    Some(StripeSignature {
        timestamp: timestamp?,
        v1: v1?,
    })
}

fn verify_stripe_signature(raw: &[u8], header: &str, secret: &str) -> Result<(), &'static str> {
    let parsed = parse_stripe_signature(header).ok_or("bad header")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_secs();
    if now.abs_diff(parsed.timestamp) > TIMESTAMP_TOLERANCE_SECS {
        return Err("stale timestamp");
    }
    type H = Hmac<Sha256>;
    let mut mac = H::new_from_slice(secret.as_bytes()).map_err(|_| "bad key")?;
    mac.update(parsed.timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw);
    let expected = hex::encode(mac.finalize().into_bytes());
    if !constant_time_eq(expected.as_bytes(), parsed.v1.as_bytes()) {
        return Err("signature mismatch");
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Event structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")]
    event_type: String,
    id: String,
    data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData {
    object: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Business logic — all async now (Supabase calls)
// ---------------------------------------------------------------------------


async fn checkout_price_id(session: &serde_json::Value) -> Option<String> {
    if let Some(value)=session["line_items"]["data"][0]["price"]["id"].as_str() {
        return Some(value.to_owned());
    }
    if let Some(value)=session["metadata"]["price_id"].as_str() {
        return Some(value.to_owned());
    }
    let id=session["id"].as_str()?;
    if !id.starts_with("cs_") || !id.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'_') {
        return None;
    }
    let secret=std::env::var("STRIPE_SECRET_KEY").ok()?;
    let response=reqwest::Client::new()
        .get(format!("https://api.stripe.com/v1/checkout/sessions/{id}/line_items?limit=1"))
        .bearer_auth(secret)
        .timeout(std::time::Duration::from_secs(5))
        .send().await.ok()?;
    if !response.status().is_success() { return None; }
    let line_items=response.json::<serde_json::Value>().await.ok()?;
    line_items["data"][0]["price"]["id"].as_str().map(ToOwned::to_owned)
}

async fn on_checkout_completed(obj: &serde_json::Value) -> Result<(), &'static str> {
    if obj["payment_status"].as_str() != Some("paid") {
        return Err("checkout payment has not settled");
    }
    let email = obj["customer_details"]["email"].as_str().unwrap_or("").to_owned();
    let cust_id = obj["customer"].as_str().unwrap_or("").to_owned();
    let sub_id = obj["subscription"].as_str().unwrap_or("").to_owned();
    let Some(price_id) = checkout_price_id(obj).await else {
        return Err("checkout price unresolved");
    };
    let (plan, billing_period) = plan_from_price_id(&price_id);
    if plan == "scanner_100_monthly" && (email.is_empty() || sub_id.is_empty()) {
        return Err("scanner checkout missing customer email or subscription");
    }
    if !sub_id.is_empty() {
        if let Some(existing) = find_by_subscription(&sub_id).await {
            send_welcome_email(&existing).await.map_err(|error| {
                log::error!("Subscription access email delivery failed: {error}");
                "welcome email delivery failed"
            })?;
            return Ok(());
        }
    }
    let customer = Customer {
        api_key: generate_api_key(),
        email,
        plan: plan.to_owned(),
        billing_period: billing_period.to_owned(),
        stripe_customer: cust_id,
        stripe_sub: sub_id,
        status: "active".to_owned(),
        created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        expires_at: expiry_timestamp(billing_period),
    };
    upsert_customer(customer.clone()).await.map_err(|error| {
        log::error!("Subscription persistence failed: {error}");
        "customer persistence failed"
    })?;
    send_welcome_email(&customer).await.map_err(|error| {
        log::error!("Welcome delivery failed: {error}");
        "welcome email delivery failed"
    })?;
    Ok(())
}
async fn on_payment_succeeded(obj: &serde_json::Value) {
    let sub_id = obj["subscription"].as_str().unwrap_or("");
    if let Some(mut customer) = find_by_subscription(sub_id).await {
        customer.expires_at = expiry_timestamp(&customer.billing_period.clone());
        customer.status = "active".to_string();
        if let Err(e) = upsert_customer(customer).await {
            log::error!("Failed to renew subscription {}: {}", sub_id, e);
        }
    }
}

async fn on_payment_failed(obj: &serde_json::Value) {
    let sub_id = obj["subscription"].as_str().unwrap_or("");
    if let Err(e) = update_status(sub_id, "past_due").await {
        log::error!("Failed to mark past_due for {}: {}", sub_id, e);
    }
}

async fn on_subscription_deleted(obj: &serde_json::Value) {
    let sub_id = obj["id"].as_str().unwrap_or("");
    if let Some(customer) = find_by_subscription(sub_id).await {
        if let Err(e) = update_status(sub_id, "cancelled").await {
            log::error!("Failed to cancel {}: {}", sub_id, e);
        }
        if let Err(e) = send_cancellation_email(&customer).await {
            log::error!("Failed to send cancellation email: {}", e);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn handle_stripe_webhook(req: HttpRequest, raw_body: web::Bytes) -> HttpResponse {
    let sig_header = match req
        .headers()
        .get("Stripe-Signature")
        .and_then(|h| h.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            log::warn!("Missing Stripe-Signature");
            return HttpResponse::BadRequest().finish();
        }
    };

    let secret = match std::env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(s) => s,
        Err(_) => {
            log::error!("STRIPE_WEBHOOK_SECRET not set");
            return HttpResponse::InternalServerError().finish();
        }
    };

    if let Err(reason) = verify_stripe_signature(&raw_body, &sig_header, &secret) {
        log::warn!("Signature verification failed: {}", reason);
        return HttpResponse::BadRequest().finish();
    }

    let event: StripeEvent = match serde_json::from_slice(&raw_body) {
        Ok(e) => e,
        Err(e) => {
            log::error!("JSON parse error: {}", e);
            return HttpResponse::UnprocessableEntity().finish();
        }
    };

    log::info!("stripe_event={} id={}", event.event_type, event.id);

    let obj = &event.data.object;
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            if let Err(reason) = on_checkout_completed(obj).await {
                log::error!("Stripe checkout provisioning failed: {reason}");
                return HttpResponse::ServiceUnavailable().finish();
            }
        },
        "invoice.payment_succeeded" => on_payment_succeeded(obj).await,
        "invoice.payment_failed" => on_payment_failed(obj).await,
        "customer.subscription.deleted" => on_subscription_deleted(obj).await,
        _ => {}
    }

    HttpResponse::Ok().finish()
}
