// stripe_webhook.rs — Vortex DFS · Stripe webhook + provisioning pipeline
//
// FLOW:
//   checkout.session.completed  → generate key + send welcome email
//   invoice.payment_succeeded   → renew expiry
//   invoice.payment_failed      → mark past_due (Stripe retries automatically)
//   customer.subscription.deleted → revoke key + send cancellation email

use actix_web::{web, HttpRequest, HttpResponse};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::provisioner::{
    Customer, generate_api_key, upsert_customer, find_by_subscription,
    update_status, expiry_timestamp, plan_from_price_id,
    send_welcome_email, send_cancellation_email,
};

const TIMESTAMP_TOLERANCE_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Signature verification (unchanged from v1)
// ---------------------------------------------------------------------------

struct StripeSignature { timestamp: u64, v1: String }

fn parse_stripe_signature(header: &str) -> Option<StripeSignature> {
    let mut timestamp = None;
    let mut v1 = None;
    for part in header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") { timestamp = ts.parse().ok(); }
        else if let Some(sig) = part.strip_prefix("v1=") { v1 = Some(sig.to_string()); }
    }
    Some(StripeSignature { timestamp: timestamp?, v1: v1? })
}

fn verify_stripe_signature(raw: &[u8], header: &str, secret: &str) -> Result<(), &'static str> {
    let parsed = parse_stripe_signature(header).ok_or("bad header")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "clock")?.as_secs();
    if now.saturating_sub(parsed.timestamp) > TIMESTAMP_TOLERANCE_SECS {
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
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Event structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")] event_type: String,
    id: String,
    data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData { object: serde_json::Value }

// ---------------------------------------------------------------------------
// Business logic
// ---------------------------------------------------------------------------

async fn on_checkout_completed(obj: &serde_json::Value) {
    let email    = obj["customer_details"]["email"].as_str().unwrap_or("").to_string();
    let cust_id  = obj["customer"].as_str().unwrap_or("").to_string();
    let sub_id   = obj["subscription"].as_str().unwrap_or("").to_string();

    // Extract price ID from line items to determine plan
    // WHY METADATA FALLBACK: Payment Links don't always populate line_items
    // in the webhook — we embed plan info in the Payment Link metadata as backup
    let price_id = obj["line_items"]["data"][0]["price"]["id"]
        .as_str()
        .or_else(|| obj["metadata"]["price_id"].as_str())
        .unwrap_or("");

    let (plan, billing_period) = plan_from_price_id(price_id);

    let customer = Customer {
        api_key:         generate_api_key(),
        email:           email.clone(),
        plan:            plan.to_string(),
        billing_period:  billing_period.to_string(),
        stripe_customer: cust_id,
        stripe_sub:      sub_id,
        status:          "active".to_string(),
        created_at:      SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        expires_at:      expiry_timestamp(billing_period),
    };

    if let Err(e) = upsert_customer(customer.clone()) {
        log::error!("Failed to save customer {}: {}", email, e);
        return;
    }

    if let Err(e) = send_welcome_email(&customer).await {
        log::error!("Failed to send welcome email to {}: {}", email, e);
    }
}

async fn on_payment_succeeded(obj: &serde_json::Value) {
    let sub_id = obj["subscription"].as_str().unwrap_or("");
    if let Some(mut customer) = find_by_subscription(sub_id) {
        customer.expires_at = expiry_timestamp(&customer.billing_period.clone());
        customer.status = "active".to_string();
        if let Err(e) = upsert_customer(customer) {
            log::error!("Failed to renew subscription {}: {}", sub_id, e);
        }
    }
}

async fn on_payment_failed(obj: &serde_json::Value) {
    let sub_id = obj["subscription"].as_str().unwrap_or("");
    if let Err(e) = update_status(sub_id, "past_due") {
        log::error!("Failed to mark past_due for {}: {}", sub_id, e);
    }
    // Stripe retries automatically — we don't send email yet to avoid
    // alarming the customer on the first failed attempt
}

async fn on_subscription_deleted(obj: &serde_json::Value) {
    let sub_id = obj["id"].as_str().unwrap_or("");
    if let Some(customer) = find_by_subscription(sub_id) {
        if let Err(e) = update_status(sub_id, "cancelled") {
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
    let sig_header = match req.headers().get("Stripe-Signature")
        .and_then(|h| h.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            log::warn!("Missing Stripe-Signature");
            return HttpResponse::BadRequest().finish();
        }
    };

    let secret = match std::env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(s)  => s,
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
        Ok(e)  => e,
        Err(e) => {
            log::error!("JSON parse error: {}", e);
            return HttpResponse::UnprocessableEntity().finish();
        }
    };

    log::info!("stripe_event={} id={}", event.event_type, event.id);

    let obj = &event.data.object;
    match event.event_type.as_str() {
        "checkout.session.completed"    => on_checkout_completed(obj).await,
        "invoice.payment_succeeded"     => on_payment_succeeded(obj).await,
        "invoice.payment_failed"        => on_payment_failed(obj).await,
        "customer.subscription.deleted" => on_subscription_deleted(obj).await,
        _                               => {}
    }

    // ALWAYS 200 — Stripe retries on any non-2xx for up to 3 days
    HttpResponse::Ok().finish()
}
