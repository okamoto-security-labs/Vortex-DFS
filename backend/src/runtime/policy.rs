//! Versioned runtime policy definitions.
//!
//! Policies describe the requirements that must be satisfied before a
//! protected operation can execute.
//!
//! The policy layer does not perform validation itself. It expresses
//! deterministic requirements consumed by validators and the decision
//! engine.

use crate::runtime::{
    DecisionPolicyReference,
    Operation,
    RuntimeTrustBand,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Versioned policy applied by the Vortex runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicy {
    /// Stable policy identifier.
    pub id: String,

    /// Policy version.
    pub version: String,

    /// Operations allowed by this policy.
    ///
    /// `BTreeSet` preserves deterministic serialization order.
    pub allowed_operations: BTreeSet<Operation>,

    /// Whether a verified identity is required.
    pub require_identity: bool,

    /// Explicit identity capabilities required for execution.
    ///
    /// `BTreeSet` preserves deterministic serialization order.
    pub required_scopes: BTreeSet<String>,

    /// Whether payload-integrity evidence is required.
    pub require_payload_integrity: bool,

    /// Whether a valid cryptographic signature is required.
    pub require_signature: bool,

    /// Whether sensitive content must be anonymized before execution.
    pub require_anonymization: bool,

    /// Minimum trust band accepted by this policy.
    pub minimum_trust_band: Option<RuntimeTrustBand>,

    /// Whether replay evidence must be evaluated.
    pub require_replay_protection: bool,

    /// Whether an audit event must be generated.
    pub audit_required: bool,

    /// Whether missing or unavailable security evidence blocks
    /// execution.
    pub fail_closed: bool,
}

impl RuntimePolicy {
    /// Creates a policy with conservative defaults.
    ///
    /// No operations are allowed until explicitly added.
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            allowed_operations: BTreeSet::new(),
            require_identity: true,
            required_scopes: BTreeSet::new(),
            require_payload_integrity: true,
            require_signature: true,
            require_anonymization: false,
            minimum_trust_band: Some(
                RuntimeTrustBand::Operational,
            ),
            require_replay_protection: true,
            audit_required: true,
            fail_closed: true,
        }
    }

    /// Adds an allowed operation to the policy.
    pub fn allow_operation(
        mut self,
        operation: Operation,
    ) -> Self {
        self.allowed_operations.insert(operation);
        self
    }

    /// Replaces the identity requirement.
    pub const fn with_identity_requirement(
        mut self,
        required: bool,
    ) -> Self {
        self.require_identity = required;
        self
    }

    /// Requires one explicit identity capability.
    pub fn with_required_scope(mut self, scope: impl Into<String>) -> Self {
        self.required_scopes.insert(scope.into());
        self
    }

    /// Replaces the payload-integrity requirement.
    pub const fn with_payload_integrity_requirement(
        mut self,
        required: bool,
    ) -> Self {
        self.require_payload_integrity = required;
        self
    }

    /// Replaces the signature requirement.
    pub const fn with_signature_requirement(
        mut self,
        required: bool,
    ) -> Self {
        self.require_signature = required;
        self
    }

    /// Replaces the anonymization requirement.
    pub const fn with_anonymization_requirement(
        mut self,
        required: bool,
    ) -> Self {
        self.require_anonymization = required;
        self
    }

    /// Replaces the minimum accepted trust band.
    pub const fn with_minimum_trust_band(
        mut self,
        minimum: Option<RuntimeTrustBand>,
    ) -> Self {
        self.minimum_trust_band = minimum;
        self
    }

    /// Replaces the replay-protection requirement.
    pub const fn with_replay_protection(
        mut self,
        required: bool,
    ) -> Self {
        self.require_replay_protection = required;
        self
    }

    /// Replaces the audit requirement.
    pub const fn with_audit_requirement(
        mut self,
        required: bool,
    ) -> Self {
        self.audit_required = required;
        self
    }

    /// Replaces fail-open or fail-closed behavior.
    pub const fn with_fail_closed(
        mut self,
        fail_closed: bool,
    ) -> Self {
        self.fail_closed = fail_closed;
        self
    }

    /// Returns whether the operation is permitted by this policy.
    pub fn permits_operation(
        &self,
        operation: Operation,
    ) -> bool {
        self.allowed_operations.contains(&operation)
    }

    /// Returns whether the evaluated trust band satisfies policy.
    pub fn accepts_trust_band(
        &self,
        trust_band: RuntimeTrustBand,
    ) -> bool {
        self.minimum_trust_band
            .is_none_or(|minimum| {
                trust_band.satisfies(minimum)
            })
    }

    /// Returns policy metadata suitable for runtime decisions.
    pub fn decision_reference(
        &self,
    ) -> DecisionPolicyReference {
        DecisionPolicyReference::new(
            self.id.clone(),
            self.version.clone(),
        )
    }

    /// Policy for protected AI-agent tool execution.
    ///
    /// A capability scope is required, but capability alone is not treated
    /// as complete derived authority. The runtime still requires its normal
    /// integrity, signature, replay, trust and audit guarantees.
    pub fn agent_tool_execution() -> Self {
        Self::new("runtime.agent_tool_execution", "0.1.0")
            .allow_operation(Operation::AgentToolExecution)
            .with_required_scope("agent:tool:execute")
    }

    /// Benchmark policy for the current anonymization endpoint.
    ///
    /// This policy intentionally avoids requiring identity,
    /// cryptographic signatures, or trust evaluation because the
    /// existing endpoint does not yet collect those signals.
    pub fn anonymization_benchmark() -> Self {
        Self::new(
            "benchmark.anonymize",
            "0.1.0",
        )
        .allow_operation(Operation::Anonymize)
        .with_identity_requirement(false)
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_anonymization_requirement(true)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(true)
        .with_fail_closed(true)
    }

    /// Authenticated policy for the protected anonymization adapter.
    pub fn authenticated_anonymization() -> Self {
        Self::new(
            "runtime.anonymize",
            "0.1.0",
        )
        .allow_operation(Operation::Anonymize)
        .with_identity_requirement(true)
        .with_required_scope("anonymize:execute")
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_anonymization_requirement(true)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(true)
        .with_fail_closed(true)
    }

    /// Benchmark policy for the current PQC verification endpoint.
    pub fn pqc_verification_benchmark() -> Self {
        Self::new(
            "benchmark.pqc.verify",
            "0.1.0",
        )
        .allow_operation(Operation::Verify)
        .with_identity_requirement(false)
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(true)
        .with_anonymization_requirement(false)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(true)
        .with_fail_closed(true)
    }

    /// Minimal health-check policy.
    pub fn health_check() -> Self {
        Self::new(
            "system.health",
            "0.1.0",
        )
        .allow_operation(Operation::HealthCheck)
        .with_identity_requirement(false)
        .with_payload_integrity_requirement(false)
        .with_signature_requirement(false)
        .with_anonymization_requirement(false)
        .with_minimum_trust_band(None)
        .with_replay_protection(false)
        .with_audit_requirement(false)
        .with_fail_closed(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_policy_uses_conservative_defaults() {
        let policy = RuntimePolicy::new(
            "production.default",
            "1.0.0",
        );

        assert!(policy.require_identity);
        assert!(policy.require_payload_integrity);
        assert!(policy.require_signature);
        assert!(policy.require_replay_protection);
        assert!(policy.audit_required);
        assert!(policy.fail_closed);

        assert_eq!(
            policy.minimum_trust_band,
            Some(RuntimeTrustBand::Operational)
        );

        assert!(
            !policy.permits_operation(
                Operation::Anonymize
            )
        );
    }

    #[test]
    fn allowed_operations_are_explicit() {
        let policy = RuntimePolicy::new(
            "test.policy",
            "1.0.0",
        )
        .allow_operation(Operation::Anonymize)
        .allow_operation(Operation::Verify);

        assert!(
            policy.permits_operation(
                Operation::Anonymize
            )
        );

        assert!(
            policy.permits_operation(
                Operation::Verify
            )
        );

        assert!(
            !policy.permits_operation(
                Operation::Sign
            )
        );
    }

    #[test]
    fn operational_satisfies_operational_minimum() {
        let policy = RuntimePolicy::new(
            "test.policy",
            "1.0.0",
        );

        assert!(
            policy.accepts_trust_band(
                RuntimeTrustBand::Operational
            )
        );

        assert!(
            policy.accepts_trust_band(
                RuntimeTrustBand::HighTrust
            )
        );
    }

    #[test]
    fn fragile_does_not_satisfy_operational_minimum() {
        let policy = RuntimePolicy::new(
            "test.policy",
            "1.0.0",
        );

        assert!(
            !policy.accepts_trust_band(
                RuntimeTrustBand::Fragile
            )
        );
    }

    #[test]
    fn missing_minimum_accepts_any_trust_band() {
        let policy = RuntimePolicy::new(
            "test.policy",
            "1.0.0",
        )
        .with_minimum_trust_band(None);

        assert!(
            policy.accepts_trust_band(
                RuntimeTrustBand::Critical
            )
        );
    }

    #[test]
    fn agent_tool_execution_uses_conservative_security_requirements() {
        let policy = RuntimePolicy::agent_tool_execution();

        assert!(policy.permits_operation(Operation::AgentToolExecution));
        assert!(!policy.permits_operation(Operation::Anonymize));

        assert!(policy.require_identity);
        assert!(policy.required_scopes.contains("agent:tool:execute"));
        assert!(policy.require_payload_integrity);
        assert!(policy.require_signature);
        assert!(policy.require_replay_protection);
        assert_eq!(
            policy.minimum_trust_band,
            Some(RuntimeTrustBand::Operational)
        );
        assert!(policy.audit_required);
        assert!(policy.fail_closed);
    }

    #[test]
    fn anonymization_benchmark_matches_current_runtime() {
        let policy =
            RuntimePolicy::anonymization_benchmark();

        assert!(
            policy.permits_operation(
                Operation::Anonymize
            )
        );

        assert!(!policy.require_identity);
        assert!(!policy.require_signature);
        assert!(policy.require_anonymization);
        assert_eq!(policy.minimum_trust_band, None);
        assert!(policy.audit_required);
    }

    #[test]
    fn pqc_benchmark_requires_signature_evidence() {
        let policy =
            RuntimePolicy::pqc_verification_benchmark();

        assert!(
            policy.permits_operation(
                Operation::Verify
            )
        );

        assert!(policy.require_signature);
        assert!(!policy.require_identity);
    }

    #[test]
    fn health_check_has_minimal_requirements() {
        let policy = RuntimePolicy::health_check();

        assert!(
            policy.permits_operation(
                Operation::HealthCheck
            )
        );

        assert!(!policy.require_identity);
        assert!(!policy.require_signature);
        assert!(!policy.audit_required);
        assert!(!policy.fail_closed);
    }

    #[test]
    fn decision_reference_preserves_policy_version() {
        let policy =
            RuntimePolicy::anonymization_benchmark();

        let reference =
            policy.decision_reference();

        assert_eq!(
            reference.id,
            "benchmark.anonymize"
        );

        assert_eq!(reference.version, "0.1.0");
    }

    #[test]
    fn allowed_operations_use_deterministic_order() {
        let policy = RuntimePolicy::new(
            "test.policy",
            "1.0.0",
        )
        .allow_operation(Operation::Verify)
        .allow_operation(Operation::Anonymize);

        let operations: Vec<Operation> =
            policy
                .allowed_operations
                .iter()
                .copied()
                .collect();

        assert_eq!(
            operations,
            vec![
                Operation::Anonymize,
                Operation::Verify,
            ]
        );
    }
}
