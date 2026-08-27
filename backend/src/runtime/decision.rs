//! Deterministic runtime decisions.
//!
//! Runtime decisions use stable outcome and reason enums so clients,
//! tests, telemetry, and audit systems do not depend on mutable
//! human-readable messages.

use crate::runtime::{EvidenceSummary, RuntimeTrustBand, SecurityEvidence};
use serde::{Deserialize, Serialize};

/// Final enforcement outcomes produced by the Vortex runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionOutcome {
    /// Permit the requested operation without transformation.
    Allow,

    /// Reject the requested operation.
    Reject,

    /// Permit execution only after sensitive content is transformed.
    Redact,

    /// Permit the operation while requiring an explicit audit event.
    Audit,
}

impl DecisionOutcome {
    /// Returns a stable machine-readable outcome name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Reject => "REJECT",
            Self::Redact => "REDACT",
            Self::Audit => "AUDIT",
        }
    }

    /// Returns whether execution is permitted in some form.
    pub const fn permits_execution(self) -> bool {
        matches!(self, Self::Allow | Self::Redact | Self::Audit)
    }

    /// Returns whether execution must stop.
    pub const fn blocks_execution(self) -> bool {
        matches!(self, Self::Reject)
    }
}

impl std::fmt::Display for DecisionOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable machine-readable reason codes.
///
/// These values form part of the runtime contract. Existing values
/// should not be renamed casually because external telemetry, clients,
/// and audit pipelines may depend on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionReason {
    /// The operation satisfied the active runtime policy.
    OperationAllowed,

    /// The operation was permitted but requires explicit audit.
    AuditRequired,

    /// The request structure was invalid.
    StructureInvalid,

    /// Required identity information was absent.
    IdentityMissing,

    /// Identity evidence was present but invalid.
    IdentityInvalid,

    /// The active policy explicitly denied the operation.
    PolicyDenied,

    /// The verified identity did not have a required capability.
    ScopeDenied,

    /// A required cryptographic signature was invalid.
    SignatureInvalid,

    /// The referenced key was revoked.
    KeyRevoked,

    /// Payload-integrity validation failed.
    PayloadIntegrityFailed,

    /// Sensitive information was detected.
    SensitiveDataDetected,

    /// Sensitive information was successfully transformed.
    SensitiveDataRedacted,

    /// The evaluated trust band did not satisfy policy.
    TrustBelowThreshold,

    /// The action consequence requires a hard execution gate.
    ConsequenceHardGate,

    /// Replay behavior was detected.
    ReplayDetected,

    /// The requested operation is unsupported.
    UnsupportedOperation,

    /// An unexpected internal runtime failure occurred.
    RuntimeError,
}

impl DecisionReason {
    /// Returns a stable machine-readable reason code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperationAllowed => "OPERATION_ALLOWED",
            Self::AuditRequired => "AUDIT_REQUIRED",
            Self::StructureInvalid => "STRUCTURE_INVALID",
            Self::IdentityMissing => "IDENTITY_MISSING",
            Self::IdentityInvalid => "IDENTITY_INVALID",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::KeyRevoked => "KEY_REVOKED",
            Self::PayloadIntegrityFailed => "PAYLOAD_INTEGRITY_FAILED",
            Self::SensitiveDataDetected => "SENSITIVE_DATA_DETECTED",
            Self::SensitiveDataRedacted => "SENSITIVE_DATA_REDACTED",
            Self::TrustBelowThreshold => "TRUST_BELOW_THRESHOLD",
            Self::ConsequenceHardGate => "CONSEQUENCE_HARD_GATE",
            Self::ReplayDetected => "REPLAY_DETECTED",
            Self::UnsupportedOperation => "UNSUPPORTED_OPERATION",
            Self::RuntimeError => "RUNTIME_ERROR",
        }
    }

    /// Returns whether the reason normally represents a security
    /// rejection rather than an ordinary operational failure.
    pub const fn is_security_failure(self) -> bool {
        matches!(
            self,
            Self::IdentityInvalid
                | Self::PolicyDenied
                | Self::ScopeDenied
                | Self::SignatureInvalid
                | Self::KeyRevoked
                | Self::PayloadIntegrityFailed
                | Self::TrustBelowThreshold
                | Self::ConsequenceHardGate
                | Self::ReplayDetected
        )
    }
}

impl std::fmt::Display for DecisionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Policy metadata included in a runtime decision.
///
/// This keeps the decision structure independent from the complete
/// policy implementation that will be added in `policy.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPolicyReference {
    pub id: String,
    pub version: String,
}

impl DecisionPolicyReference {
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
        }
    }
}

/// Complete deterministic runtime decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDecision {
    /// Final enforcement outcome.
    pub outcome: DecisionOutcome,

    /// Stable reason explaining the outcome.
    pub reason_code: DecisionReason,

    /// Versioned policy responsible for the decision.
    pub policy: DecisionPolicyReference,

    /// Trust band evaluated for the request.
    pub trust_band: Option<RuntimeTrustBand>,

    /// Bounded evidence safe for decision output.
    pub evidence_summary: EvidenceSummary,

    /// Runtime decision latency in microseconds.
    pub latency_us: u64,
}

impl RuntimeDecision {
    /// Creates an allow decision.
    pub fn allow(
        policy: DecisionPolicyReference,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self::new(
            DecisionOutcome::Allow,
            DecisionReason::OperationAllowed,
            policy,
            evidence,
            latency_us,
        )
    }

    /// Creates an allow-with-audit decision.
    pub fn audit(
        policy: DecisionPolicyReference,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self::new(
            DecisionOutcome::Audit,
            DecisionReason::AuditRequired,
            policy,
            evidence,
            latency_us,
        )
    }

    /// Creates a redaction decision.
    pub fn redact(
        policy: DecisionPolicyReference,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self::new(
            DecisionOutcome::Redact,
            DecisionReason::SensitiveDataRedacted,
            policy,
            evidence,
            latency_us,
        )
    }

    /// Creates a rejection decision.
    pub fn reject(
        policy: DecisionPolicyReference,
        reason_code: DecisionReason,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self::new(
            DecisionOutcome::Reject,
            reason_code,
            policy,
            evidence,
            latency_us,
        )
    }

    /// Creates a runtime decision with explicit fields.
    pub fn new(
        outcome: DecisionOutcome,
        reason_code: DecisionReason,
        policy: DecisionPolicyReference,
        evidence: &SecurityEvidence,
        latency_us: u64,
    ) -> Self {
        Self {
            outcome,
            reason_code,
            policy,
            trust_band: evidence.trust_band,
            evidence_summary: EvidenceSummary::from(evidence),
            latency_us,
        }
    }

    /// Returns whether the decision permits execution.
    pub const fn permits_execution(&self) -> bool {
        self.outcome.permits_execution()
    }

    /// Returns whether the decision blocks execution.
    pub const fn blocks_execution(&self) -> bool {
        self.outcome.blocks_execution()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_reference() -> DecisionPolicyReference {
        DecisionPolicyReference::new("benchmark.anonymize", "0.1.0")
    }

    #[test]
    fn allow_decision_preserves_policy_metadata() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_structural_validity(true);
        evidence.set_trust_band(RuntimeTrustBand::Operational);

        let decision = RuntimeDecision::allow(policy_reference(), &evidence, 125);

        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.reason_code, DecisionReason::OperationAllowed);
        assert_eq!(decision.policy.id, "benchmark.anonymize");
        assert_eq!(decision.policy.version, "0.1.0");
        assert_eq!(decision.trust_band, Some(RuntimeTrustBand::Operational));
        assert!(decision.permits_execution());
    }

    #[test]
    fn rejection_blocks_execution() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_signature_valid(false);

        let decision = RuntimeDecision::reject(
            policy_reference(),
            DecisionReason::SignatureInvalid,
            &evidence,
            80,
        );

        assert_eq!(decision.outcome, DecisionOutcome::Reject);
        assert_eq!(decision.reason_code, DecisionReason::SignatureInvalid);
        assert!(decision.blocks_execution());
        assert!(!decision.permits_execution());
    }

    #[test]
    fn redaction_is_an_explicit_execution_path() {
        let mut evidence = SecurityEvidence::new();

        evidence.set_sensitive_data_detected(true);

        let decision = RuntimeDecision::redact(policy_reference(), &evidence, 240);

        assert_eq!(decision.outcome, DecisionOutcome::Redact);
        assert_eq!(decision.reason_code, DecisionReason::SensitiveDataRedacted);
        assert!(decision.permits_execution());
    }

    #[test]
    fn audit_decision_permits_execution() {
        let evidence = SecurityEvidence::new();

        let decision = RuntimeDecision::audit(policy_reference(), &evidence, 50);

        assert_eq!(decision.outcome, DecisionOutcome::Audit);
        assert_eq!(decision.reason_code, DecisionReason::AuditRequired);
        assert!(decision.permits_execution());
    }

    #[test]
    fn reason_codes_have_stable_names() {
        assert_eq!(
            DecisionReason::TrustBelowThreshold.as_str(),
            "TRUST_BELOW_THRESHOLD"
        );

        assert_eq!(
            DecisionReason::PayloadIntegrityFailed.as_str(),
            "PAYLOAD_INTEGRITY_FAILED"
        );
    }

    #[test]
    fn security_failures_are_classified_explicitly() {
        assert!(DecisionReason::SignatureInvalid.is_security_failure());

        assert!(DecisionReason::ReplayDetected.is_security_failure());

        assert!(!DecisionReason::StructureInvalid.is_security_failure());

        assert!(!DecisionReason::RuntimeError.is_security_failure());
    }
}
