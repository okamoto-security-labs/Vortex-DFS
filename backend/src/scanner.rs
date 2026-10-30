//! Defensive HTTP header inspection for operator-allowlisted domains only.
use actix_web::{http::header, web, HttpRequest, HttpResponse};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{net::IpAddr, time::Duration};

#[derive(Deserialize)]
pub struct ScanInput { target: String }

fn target_host(target: &str) -> Option<String> {
    let host = target.strip_prefix("https://")?;
    if host.is_empty() || host.len()>253 || host.contains(&['/',':','?','#','@','\\'][..])
        || host.parse::<IpAddr>().is_ok() || !host.contains('.')
        || host.split('.').any(|x| x.is_empty() || x.starts_with('-') || x.ends_with('-'))
        || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'-' || b==b'.') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn allowed(host: &str) -> bool {
    std::env::var("VORTEX_SCAN_ALLOWED_HOSTS").unwrap_or_default()
        .split(',').any(|x| !x.trim().is_empty() && x.trim().eq_ignore_ascii_case(host))
}

pub async fn run(request: HttpRequest, payload: web::Json<ScanInput>, pool: web::Data<PgPool>) -> HttpResponse {
    let Some(host)=target_host(&payload.target) else {
        return HttpResponse::BadRequest().json(json!({"error":"Only bare https://hostnames are accepted"}));
    };
    if !allowed(&host) { return HttpResponse::Forbidden().json(json!({"error":"Host not operator-allowlisted"})); }
    let bearer=request.headers().get(header::AUTHORIZATION)
        .and_then(|h|h.to_str().ok()).and_then(|v|v.strip_prefix("Bearer "));
    let (subject,limit,paid)=if let Some(token)=bearer {
        let found=sqlx::query_scalar::<_,String>(
            "SELECT api_key FROM customers WHERE api_key=$1 AND status='active' AND expires_at > EXTRACT(EPOCH FROM NOW()) AND plan='scanner_100_monthly'"
        ).bind(token).fetch_optional(pool.get_ref()).await;
        match found {
            Ok(Some(_))=>(format!("subscriber:{}",hex::encode(Sha256::digest(token.as_bytes()))),100,true),
            Ok(None)=>return HttpResponse::Forbidden().json(json!({"error":"Inactive scanner subscription"})),
            Err(_)=>return HttpResponse::ServiceUnavailable().json(json!({"error":"Subscription lookup unavailable"})),
        }
    } else {
        let Some(addr)=request.peer_addr() else { return HttpResponse::ServiceUnavailable().json(json!({"error":"Client IP unavailable"})); };
        (format!("public:{}",addr.ip()),3,false)
    };
    // Transactional atomic quota, period derived from PostgreSQL UTC clock.
    let period=if paid {
        sqlx::query_scalar::<_,String>("SELECT to_char(timezone('UTC',now()),'YYYY-MM')")
            .fetch_one(pool.get_ref()).await.unwrap_or_default()
    } else { "lifetime".to_owned() };
    if period.is_empty() { return HttpResponse::ServiceUnavailable().json(json!({"error":"Period lookup unavailable"})); }
    let used=sqlx::query_scalar::<_,i32>(
        "INSERT INTO scanner_quotas(subject_key,period,used) VALUES ($1,$2,1) \
        ON CONFLICT(subject_key,period) DO UPDATE SET used=scanner_quotas.used+1 \
        WHERE scanner_quotas.used < $3 RETURNING used"
    ).bind(subject).bind(period).bind(limit).fetch_optional(pool.get_ref()).await;
    let used=match used {
        Ok(Some(count))=>count,
        Ok(None)=>return HttpResponse::TooManyRequests().json(json!({"error":"Scan quota exhausted","limit":limit})),
        Err(_)=>return HttpResponse::ServiceUnavailable().json(json!({"error":"Quota storage unavailable; apply scanner migration"}))
    };
    let client=match reqwest::Client::builder().timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none()).build() {
        Ok(c)=>c,Err(_)=>return HttpResponse::ServiceUnavailable().finish()
    };
    let response=match client.get(format!("https://{host}/")).send().await {
        Ok(r)=>r,
        Err(_)=>return HttpResponse::BadGateway().json(json!({"error":"Target connection failed","quota":{"limit":limit,"used":used}}))
    };
    let checks=[
        ("strict-transport-security","HSTS"),
        ("content-security-policy","Content Security Policy"),
        ("x-content-type-options","X-Content-Type-Options"),
        ("referrer-policy","Referrer Policy"),
    ].into_iter().map(|(header,label)|json!({
        "check":label,
        "status":if response.headers().contains_key(header) {"present"} else {"missing"}
    })).collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({"mode":"REAL_HTTP_HEADER_INSPECTION","target":host,
        "http_status":response.status().as_u16(),"findings":checks,
        "quota":{"limit":limit,"used":used,"remaining":limit-used},
        "notice":"Defensive header checks only; no CVE or exploit scanning"}))
}


pub async fn checkout() -> HttpResponse {
    let value=std::env::var("VORTEX_SCANNER_CHECKOUT_URL").unwrap_or_default();
    if !value.starts_with("https://buy.stripe.com/") && !value.starts_with("https://checkout.stripe.com/") {
        return HttpResponse::ServiceUnavailable().json(json!({"error":"Scanner checkout is not configured"}));
    }
    HttpResponse::Found().insert_header((header::LOCATION,value)).finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_url_abuse() {
        for target in ["http://example.com","https://127.0.0.1","https://example.com:443",
            "https://example.com/path","https://user@example.com","https://example.com?x"] {
            assert!(target_host(target).is_none());
        }
    }
    #[test]
    fn accepts_bare_host() { assert_eq!(target_host("https://example.com").as_deref(),Some("example.com")); }
}
