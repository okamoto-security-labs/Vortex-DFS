//! Safe, append-only runtime audit event storage.
//!
//! Audit events deliberately persist only bounded decision metadata.
//! Raw payloads, identity fields, API keys, and unrestricted evidence signals
//! are excluded from this module.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::runtime::{
    DecisionOutcome, DecisionReason, EvidenceSummary, RequestContext, RuntimeDecision,
};

/// Safe record of one Vortex runtime decision.
///
/// This type intentionally excludes `RequestContext.payload`,
/// `RequestContext.identity`, raw input, and unrestricted evidence signals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAuditEvent {
    pub event_id: String,
    pub request_id: String,
    pub trace_id: String,
    pub operation: String,
    pub outcome: DecisionOutcome,
    pub reason_code: DecisionReason,
    pub policy_id: String,
    pub policy_version: String,
    pub evidence_summary: EvidenceSummary,
    pub trust_band: Option<String>,
    pub latency_us: u64,
    pub decided_at_ms: u64,
}

impl RuntimeAuditEvent {
    /// Builds an audit-safe event from a normalized context and decision.
    pub fn from_context_and_decision(context: &RequestContext, decision: &RuntimeDecision) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            request_id: context.request_id.clone(),
            trace_id: context.trace_id.clone(),
            operation: context.operation.as_str().to_string(),
            outcome: decision.outcome,
            reason_code: decision.reason_code,
            policy_id: decision.policy.id.clone(),
            policy_version: decision.policy.version.clone(),
            evidence_summary: decision.evidence_summary.clone(),
            trust_band: decision
                .trust_band
                .map(|trust_band| trust_band.as_str().to_string()),
            latency_us: decision.latency_us,
            decided_at_ms: context.timestamp_ms,
        }
    }
}

/// Explicit error returned by an audit store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditStoreError {
    message: String,
}

impl AuditStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AuditStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AuditStoreError {}

/// Storage contract for safe runtime audit events.
#[async_trait]
pub trait RuntimeAuditStore: Send + Sync {
    /// Appends an event. Stores must not mutate the runtime decision.
    async fn append(&self, event: RuntimeAuditEvent) -> Result<(), AuditStoreError>;

    /// Returns events associated with one trace identifier.
    async fn find_by_trace_id(
        &self,
        trace_id: &str,
    ) -> Result<Vec<RuntimeAuditEvent>, AuditStoreError>;
}

/// In-memory store for tests and local adapters.
///
/// It is intentionally not durable and must not be used as production audit
/// retention.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRuntimeAuditStore {
    events: Arc<RwLock<Vec<RuntimeAuditEvent>>>,
}

impl InMemoryRuntimeAuditStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> Result<usize, AuditStoreError> {
        self.events
            .read()
            .map(|events| events.len())
            .map_err(|error| AuditStoreError::new(error.to_string()))
    }
}

#[async_trait]
impl RuntimeAuditStore for InMemoryRuntimeAuditStore {
    async fn append(&self, event: RuntimeAuditEvent) -> Result<(), AuditStoreError> {
        self.events
            .write()
            .map_err(|error| AuditStoreError::new(error.to_string()))?
            .push(event);

        Ok(())
    }

    async fn find_by_trace_id(
        &self,
        trace_id: &str,
    ) -> Result<Vec<RuntimeAuditEvent>, AuditStoreError> {
        let events = self
            .events
            .read()
            .map_err(|error| AuditStoreError::new(error.to_string()))?;

        Ok(events
            .iter()
            .filter(|event| event.trace_id == trace_id)
            .cloned()
            .collect())
    }
}

/// PostgreSQL-backed runtime audit store.
///
/// Run the migration in `backend/migrations/` before using this store.
#[derive(Debug, Clone)]
pub struct PostgresRuntimeAuditStore {
    pool: PgPool,
}

impl PostgresRuntimeAuditStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RuntimeAuditStore for PostgresRuntimeAuditStore {
    async fn append(&self, event: RuntimeAuditEvent) -> Result<(), AuditStoreError> {
        let evidence_summary = serde_json::to_value(&event.evidence_summary)
            .map_err(|error| AuditStoreError::new(error.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO runtime_audit_events (
                event_id,
                request_id,
                trace_id,
                operation,
                outcome,
                reason_code,
                policy_id,
                policy_version,
                evidence_summary,
                trust_band,
                latency_us,
                decided_at_ms
            )
            VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10, $11, $12
            )
            ON CONFLICT (event_id) DO NOTHING
            "#,
        )
        .bind(&event.event_id)
        .bind(&event.request_id)
        .bind(&event.trace_id)
        .bind(&event.operation)
        .bind(event.outcome.as_str())
        .bind(event.reason_code.as_str())
        .bind(&event.policy_id)
        .bind(&event.policy_version)
        .bind(evidence_summary)
        .bind(&event.trust_band)
        .bind(event.latency_us as i64)
        .bind(event.decided_at_ms as i64)
        .execute(&self.pool)
        .await
        .map_err(|error| AuditStoreError::new(error.to_string()))?;

        Ok(())
    }

    async fn find_by_trace_id(
        &self,
        trace_id: &str,
    ) -> Result<Vec<RuntimeAuditEvent>, AuditStoreError> {
        let rows = sqlx::query(
            r#"
            SELECT
                event_id,
                request_id,
                trace_id,
                operation,
                outcome,
                reason_code,
                policy_id,
                policy_version,
                evidence_summary,
                trust_band,
                latency_us,
                decided_at_ms
            FROM runtime_audit_events
            WHERE trace_id = $1
            ORDER BY decided_at_ms ASC, event_id ASC
            "#,
        )
        .bind(trace_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| AuditStoreError::new(error.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let outcome = match row
                    .try_get::<String, _>("outcome")
                    .map_err(|error| AuditStoreError::new(error.to_string()))?
                    .as_str()
                {
                    "ALLOW" => DecisionOutcome::Allow,
                    "REJECT" => DecisionOutcome::Reject,
                    "REDACT" => DecisionOutcome::Redact,
                    "AUDIT" => DecisionOutcome::Audit,
                    value => {
                        return Err(AuditStoreError::new(format!(
                            "unknown audit outcome: {value}"
                        )))
                    }
                };

                let reason_code = match row
                    .try_get::<String, _>("reason_code")
                    .map_err(|error| AuditStoreError::new(error.to_string()))?
                    .as_str()
                {
                    "OPERATION_ALLOWED" => DecisionReason::OperationAllowed,
                    "AUDIT_REQUIRED" => DecisionReason::AuditRequired,
                    "STRUCTURE_INVALID" => DecisionReason::StructureInvalid,
                    "IDENTITY_MISSING" => DecisionReason::IdentityMissing,
                    "IDENTITY_INVALID" => DecisionReason::IdentityInvalid,
                    "POLICY_DENIED" => DecisionReason::PolicyDenied,
                    "SIGNATURE_INVALID" => DecisionReason::SignatureInvalid,
                    "KEY_REVOKED" => DecisionReason::KeyRevoked,
                    "PAYLOAD_INTEGRITY_FAILED" => DecisionReason::PayloadIntegrityFailed,
                    "SENSITIVE_DATA_DETECTED" => DecisionReason::SensitiveDataDetected,
                    "SENSITIVE_DATA_REDACTED" => DecisionReason::SensitiveDataRedacted,
                    "TRUST_BELOW_THRESHOLD" => DecisionReason::TrustBelowThreshold,
                    "REPLAY_DETECTED" => DecisionReason::ReplayDetected,
                    "UNSUPPORTED_OPERATION" => DecisionReason::UnsupportedOperation,
                    "RUNTIME_ERROR" => DecisionReason::RuntimeError,
                    value => {
                        return Err(AuditStoreError::new(format!(
                            "unknown audit reason: {value}"
                        )))
                    }
                };

                let evidence_summary = row
                    .try_get("evidence_summary")
                    .map_err(|error| AuditStoreError::new(error.to_string()))
                    .and_then(|value: serde_json::Value| {
                        serde_json::from_value(value)
                            .map_err(|error| AuditStoreError::new(error.to_string()))
                    })?;

                Ok(RuntimeAuditEvent {
                    event_id: row
                        .try_get("event_id")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    request_id: row
                        .try_get("request_id")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    trace_id: row
                        .try_get("trace_id")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    operation: row
                        .try_get("operation")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    outcome,
                    reason_code,
                    policy_id: row
                        .try_get("policy_id")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    policy_version: row
                        .try_get("policy_version")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    evidence_summary,
                    trust_band: row
                        .try_get("trust_band")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?,
                    latency_us: row
                        .try_get::<i64, _>("latency_us")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?
                        as u64,
                    decided_at_ms: row
                        .try_get::<i64, _>("decided_at_ms")
                        .map_err(|error| AuditStoreError::new(error.to_string()))?
                        as u64,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Operation, PayloadContext, RuntimePolicy};

    fn event() -> RuntimeAuditEvent {
        let mut context = RequestContext::new(
            "request-001",
            "trace-001",
            Operation::Anonymize,
            PayloadContext::new(512)
                .with_content_type("text/plain")
                .with_digest("sha256:example"),
        );

        context.evidence.set_structural_validity(true);
        context.evidence.set_sensitive_data_detected(true);

        let decision = RuntimeDecision::redact(
            RuntimePolicy::anonymization_benchmark().decision_reference(),
            &context.evidence,
            42,
        );

        RuntimeAuditEvent::from_context_and_decision(&context, &decision)
    }

    #[test]
    fn event_contains_decision_metadata_without_payload_or_identity() {
        let event = event();
        let serialized = serde_json::to_value(&event).unwrap();

        assert_eq!(event.operation, "anonymize");
        assert_eq!(event.outcome, DecisionOutcome::Redact);
        assert_eq!(event.reason_code, DecisionReason::SensitiveDataRedacted);
        assert_eq!(event.evidence_summary.sensitive_data_detected, Some(true));
        assert!(serialized.get("payload").is_none());
        assert!(serialized.get("identity").is_none());
        assert!(serialized.get("signals").is_none());
    }

    #[tokio::test]
    async fn in_memory_store_returns_events_by_trace_id() {
        let store = InMemoryRuntimeAuditStore::new();
        let event = event();

        store.append(event.clone()).await.unwrap();
        store
            .append(RuntimeAuditEvent {
                trace_id: "other-trace".to_string(),
                ..event
            })
            .await
            .unwrap();

        let events = store.find_by_trace_id("trace-001").await.unwrap();

        assert_eq!(store.len().unwrap(), 2);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].trace_id, "trace-001");
    }
}
