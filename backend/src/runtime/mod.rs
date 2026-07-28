//! Vortex-DFS deterministic runtime primitives.
//!
//! This module defines the shared types used to represent requests,
//! security evidence, policies, decisions, and audit-ready context.
//!
//! It does not execute anonymization, cryptographic operations, or
//! kernel enforcement directly.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Operations that may be processed by the Vortex runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    HealthCheck,
    Anonymize,
    Sign,
    Verify,
    CryptoAudit,
    ProvisionApiKey,
    RegisterHardware,
    AgentToolExecution,
    KernelPolicyUpdate,
    Unknown,
}

/// Explicit outcomes produced by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionOutcome {
    Allow,
    Reject,
    Redact,
    Audit,
}

/// Stable machine-readable reason codes.
///
/// Human-readable messages may change, but these values should remain
/// stable so that tests, clients, metrics, and audit systems can depend
/// on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    OperationAllowed,
    StructureInvalid,
    IdentityMissing,
    IdentityInvalid,
    PolicyDenied,
    SignatureInvalid,
    KeyRevoked,
    PayloadIntegrityFailed,
    SensitiveDataDetected,
    SensitiveDataRedacted,
    TrustBelowThreshold,
    ReplayDetected,
    UnsupportedOperation,
    RuntimeError,
}

/// Operational trust classifications used by the runtime.
///
/// This type is initially independent from `pqc_core::TrustBand`.
/// The existing implementation can later be migrated or converted
/// explicitly, avoiding an immediate breaking refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTrustBand {
    Critical,
    Fragile,
    Operational,
    HighTrust,
}

/// Identity information associated with a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Stable identifier for the requesting principal.
    pub principal_id: String,

    /// Authentication mechanism used by the requester.
    pub authentication_method: String,

    /// Whether authentication evidence was successfully verified.
    pub verified: bool,
}

/// Metadata describing the request payload.
///
/// Raw content is deliberately not stored here to reduce the risk of
/// sensitive data leaking into logs or audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadContext {
    pub content_type: Option<String>,
    pub locale: Option<String>,
    pub size_bytes: usize,
    pub digest: Option<String>,
}

impl PayloadContext {
    pub fn new(size_bytes: usize) -> Self {
        Self {
            content_type: None,
            locale: None,
            size_bytes,
            digest: None,
        }
    }
}

/// A validation problem discovered before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFailure {
    pub reason: DecisionReason,
    pub field: Option<String>,
    pub message: String,
}

impl ValidationFailure {
    pub fn new(
        reason: DecisionReason,
        field: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            field,
            message: message.into(),
        }
    }
}

/// Named security evidence collected during request processing.
///
/// Optional values distinguish a negative result from a signal that was
/// not evaluated.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvidence {
    pub structural_validity: Option<bool>,
    pub identity_verified: Option<bool>,
    pub payload_integrity_valid: Option<bool>,
    pub signature_valid: Option<bool>,
    pub sensitive_data_detected: Option<bool>,
    pub replay_detected: Option<bool>,
    pub risk_score: Option<f64>,
    pub trust_band: Option<RuntimeTrustBand>,

    /// Extensible named signals.
    ///
    /// `BTreeMap` is used instead of `HashMap` to preserve deterministic
    /// ordering when evidence is serialized.
    #[serde(default)]
    pub signals: BTreeMap<String, EvidenceValue>,
}

/// Supported values for extensible evidence fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EvidenceValue {
    Boolean(bool),
    Integer(i64),
    UnsignedInteger(u64),
    Float(f64),
    Text(String),
}

impl SecurityEvidence {
    pub fn add_signal(
        &mut self,
        name: impl Into<String>,
        value: EvidenceValue,
    ) -> Option<EvidenceValue> {
        self.signals.insert(name.into(), value)
    }
}

/// Normalized context shared across runtime stages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub trace_id: String,
    pub timestamp_ms: u64,
    pub operation: Operation,
    pub identity: Option<IdentityContext>,
    pub payload: PayloadContext,
    pub policy_id: Option<String>,
    pub evidence: SecurityEvidence,
    pub failures: Vec<ValidationFailure>,
}

impl RequestContext {
    pub fn new(
        request_id: impl Into<String>,
        trace_id: impl Into<String>,
        operation: Operation,
        payload: PayloadContext,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            trace_id: trace_id.into(),
            timestamp_ms: current_timestamp_ms(),
            operation,
            identity: None,
            payload,
            policy_id: None,
            evidence: SecurityEvidence::default(),
            failures: Vec::new(),
        }
    }

    pub fn add_failure(&mut self, failure: ValidationFailure) {
        self.failures.push(failure);
    }

    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }
}

/// Versioned runtime policy applied to a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicy {
    pub id: String,
    pub version: String,
    pub required_identity: bool,
    pub require_signature: bool,
    pub require_anonymization: bool,
    pub minimum_trust_band: Option<RuntimeTrustBand>,
    pub fail_closed: bool,
    pub audit_required: bool,
}

impl RuntimePolicy {
    /// Minimal policy suitable for the first anonymization integration.
    pub fn anonymization_benchmark() -> Self {
        Self {
            id: "benchmark.anonymize".to_string(),
            version: "0.1.0".to_string(),
            required_identity: false,
            require_signature: false,
            require_anonymization: true,
            minimum_trust_band: None,
            fail_closed: true,
            audit_required: true,
        }
    }
}

/// Compact evidence summary included in a decision.
///
/// This prevents the complete request payload or unrestricted evidence
/// from being returned to clients.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub structural_validity: Option<bool>,
    pub identity_verified: Option<bool>,
    pub signature_valid: Option<bool>,
    pub sensitive_data_detected: Option<bool>,
    pub risk_score: Option<f64>,
    pub trust_band: Option<RuntimeTrustBand>,
}

impl From<&SecurityEvidence> for EvidenceSummary {
    fn from(evidence: &SecurityEvidence) -> Self {
        Self {
            structural_validity: evidence.structural_validity,
            identity_verified: evidence.identity_verified,
            signature_valid: evidence.signature_valid,
            sensitive_data_detected: evidence.sensitive_data_detected,
            risk_score: evidence.risk_score,
            trust_band: evidence.trust_band,
        }
    }
}

/// Complete deterministic runtime decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDecision {
    pub outcome: DecisionOutcome,
    pub reason_code: DecisionReason,
    pub policy_id: String,
    pub policy_version: String,
    pub trust_band: Option<RuntimeTrustBand>,
    pub evidence_summary: EvidenceSummary,
    pub latency_us: u64,
}

impl RuntimeDecision {
    pub fn allow(
        policy: &RuntimePolicy,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self {
            outcome: DecisionOutcome::Allow,
            reason_code: DecisionReason::OperationAllowed,
            policy_id: policy.id.clone(),
            policy_version: policy.version.clone(),
            trust_band: evidence.trust_band,
            evidence_summary: EvidenceSummary::from(evidence),
            latency_us,
        }
    }

    pub fn redact(
        policy: &RuntimePolicy,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self {
            outcome: DecisionOutcome::Redact,
            reason_code: DecisionReason::SensitiveDataRedacted,
            policy_id: policy.id.clone(),
            policy_version: policy.version.clone(),
            trust_band: evidence.trust_band,
            evidence_summary: EvidenceSummary::from(evidence),
            latency_us,
        }
    }

    pub fn reject(
        policy: &RuntimePolicy,
        reason_code: DecisionReason,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self {
            outcome: DecisionOutcome::Reject,
            reason_code,
            policy_id: policy.id.clone(),
            policy_version: policy.version.clone(),
            trust_band: evidence.trust_band,
            evidence_summary: EvidenceSummary::from(evidence),
            latency_us,
        }
    }
}

/// Returns Unix time in milliseconds without panicking if the local
/// system clock is earlier than the Unix epoch.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_context() -> RequestContext {
        RequestContext::new(
            "request-001",
            "trace-001",
            Operation::Anonymize,
            PayloadContext {
                content_type: Some("text/plain".to_string()),
                locale: Some("en".to_string()),
                size_bytes: 42,
                digest: None,
            },
        )
    }

    #[test]
    fn request_context_starts_without_failures() {
        let context = example_context();

        assert_eq!(context.operation, Operation::Anonymize);
        assert!(!context.has_failures());
        assert!(context.timestamp_ms > 0);
    }

    #[test]
    fn validation_failure_is_recorded() {
        let mut context = example_context();

        context.add_failure(ValidationFailure::new(
            DecisionReason::StructureInvalid,
            Some("content".to_string()),
            "Content must not be empty",
        ));

        assert!(context.has_failures());
        assert_eq!(context.failures.len(), 1);
        assert_eq!(
            context.failures[0].reason,
            DecisionReason::StructureInvalid
        );
    }

    #[test]
    fn evidence_preserves_deterministic_signal_order() {
        let mut evidence = SecurityEvidence::default();

        evidence.add_signal(
            "z_signal",
            EvidenceValue::Boolean(true),
        );
        evidence.add_signal(
            "a_signal",
            EvidenceValue::UnsignedInteger(10),
        );

        let names: Vec<&String> = evidence.signals.keys().collect();

        assert_eq!(names, vec!["a_signal", "z_signal"]);
    }

    #[test]
    fn allow_decision_contains_policy_and_evidence() {
        let policy = RuntimePolicy::anonymization_benchmark();
        let mut evidence = SecurityEvidence::default();

        evidence.structural_validity = Some(true);
        evidence.sensitive_data_detected = Some(false);
        evidence.risk_score = Some(0.0);

        let decision = RuntimeDecision::allow(&policy, &evidence, 125);

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(
            decision.reason_code,
            DecisionReason::OperationAllowed
        );
        assert_eq!(decision.policy_id, "benchmark.anonymize");
        assert_eq!(decision.policy_version, "0.1.0");
        assert_eq!(
            decision.evidence_summary.structural_validity,
            Some(true)
        );
    }

    #[test]
    fn redaction_produces_explicit_decision() {
        let policy = RuntimePolicy::anonymization_benchmark();
        let mut evidence = SecurityEvidence::default();

        evidence.structural_validity = Some(true);
        evidence.sensitive_data_detected = Some(true);
        evidence.risk_score = Some(0.75);

        let decision = RuntimeDecision::redact(&policy, &evidence, 300);

        assert_eq!(decision.outcome, DecisionOutcome::Redact);
        assert_eq!(
            decision.reason_code,
            DecisionReason::SensitiveDataRedacted
        );
    }

    #[test]
    fn rejection_preserves_stable_reason_code() {
        let policy = RuntimePolicy::anonymization_benchmark();
        let evidence = SecurityEvidence {
            structural_validity: Some(false),
            ..SecurityEvidence::default()
        };

        let decision = RuntimeDecision::reject(
            &policy,
            DecisionReason::StructureInvalid,
            &evidence,
            50,
        );

        assert_eq!(decision.outcome, DecisionOutcome::Reject);
        assert_eq!(
            decision.reason_code,
            DecisionReason::StructureInvalid
        );
    }
}
