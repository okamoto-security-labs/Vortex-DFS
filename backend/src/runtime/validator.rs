//! Deterministic runtime validation.
//!
//! Validators compare normalized request context and collected security
//! evidence against an active runtime policy.
//!
//! This module does not execute protected operations and does not make
//! the final enforcement decision. It only reports deterministic
//! validation failures.

use crate::runtime::{
    DecisionReason,
    Operation,
    RequestContext,
    RuntimePolicy,
    ValidationFailure,
};

/// Result produced by runtime validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Failures discovered during validation.
    pub failures: Vec<ValidationFailure>,
}

impl ValidationReport {
    /// Creates an empty validation report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a validation failure.
    pub fn add_failure(
        &mut self,
        failure: ValidationFailure,
    ) {
        self.failures.push(failure);
    }

    /// Returns whether validation completed without failures.
    pub fn is_valid(&self) -> bool {
        self.failures.is_empty()
    }

    /// Returns whether at least one validation failure exists.
    pub fn has_failures(&self) -> bool {
        !self.is_valid()
    }

    /// Returns the first failure, when available.
    pub fn first_failure(
        &self,
    ) -> Option<&ValidationFailure> {
        self.failures.first()
    }

    /// Moves all failures into a request context.
    pub fn apply_to_context(
        self,
        context: &mut RequestContext,
    ) {
        for failure in self.failures {
            context.add_failure(failure);
        }
    }
}

/// Stateless deterministic runtime validator.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeValidator;

impl RuntimeValidator {
    /// Validates a request context against an active runtime policy.
    ///
    /// Validation order is stable:
    ///
    /// 1. operation support
    /// 2. structural validity
    /// 3. identity
    /// 4. payload integrity
    /// 5. signature
    /// 6. replay protection
    /// 7. trust threshold
    /// 8. anonymization requirement
    pub fn validate(
        context: &RequestContext,
        policy: &RuntimePolicy,
    ) -> ValidationReport {
        let mut report = ValidationReport::new();

        Self::validate_operation(
            context,
            policy,
            &mut report,
        );

        Self::validate_structure(
            context,
            policy,
            &mut report,
        );

        Self::validate_identity(
            context,
            policy,
            &mut report,
        );

        Self::validate_payload_integrity(
            context,
            policy,
            &mut report,
        );

        Self::validate_signature(
            context,
            policy,
            &mut report,
        );

        Self::validate_replay_protection(
            context,
            policy,
            &mut report,
        );

        Self::validate_trust(
            context,
            policy,
            &mut report,
        );

        Self::validate_anonymization_requirement(
            context,
            policy,
            &mut report,
        );

        report
    }

    /// Validates a context and writes failures directly into it.
    pub fn validate_context(
        context: &mut RequestContext,
        policy: &RuntimePolicy,
    ) {
        let report = Self::validate(context, policy);
        report.apply_to_context(context);
    }

    fn validate_operation(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        if context.operation == Operation::Unknown {
            report.add_failure(
                ValidationFailure::new(
                    DecisionReason::UnsupportedOperation,
                    Some("operation".to_string()),
                    "The requested operation is unknown",
                ),
            );

            return;
        }

        if !policy.permits_operation(context.operation) {
            report.add_failure(
                ValidationFailure::new(
                    DecisionReason::PolicyDenied,
                    Some("operation".to_string()),
                    format!(
                        "Operation '{}' is not allowed by policy '{}'",
                        context.operation,
                        policy.id,
                    ),
                ),
            );
        }
    }

    fn validate_structure(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        match context.evidence.structural_validity {
            Some(true) => {}

            Some(false) => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::StructureInvalid,
                        None,
                        "Request structure validation failed",
                    ),
                );
            }

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::StructureInvalid,
                        None,
                        "Structural validity was not evaluated",
                    ),
                );
            }

            None => {}
        }
    }

    fn validate_identity(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        if !policy.require_identity {
            return;
        }

        if context.identity.is_none() {
            report.add_failure(
                ValidationFailure::new(
                    DecisionReason::IdentityMissing,
                    Some("identity".to_string()),
                    "A verified identity is required",
                ),
            );

            return;
        }

        match context.evidence.identity_verified {
            Some(true) => {}

            Some(false) => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::IdentityInvalid,
                        Some("identity".to_string()),
                        "Identity verification failed",
                    ),
                );
            }

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::IdentityInvalid,
                        Some("identity".to_string()),
                        "Identity verification was not evaluated",
                    ),
                );
            }

            None => {}
        }
    }

    fn validate_payload_integrity(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        if !policy.require_payload_integrity {
            return;
        }

        match context.evidence.payload_integrity_valid {
            Some(true) => {}

            Some(false) => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::PayloadIntegrityFailed,
                        Some("payload".to_string()),
                        "Payload integrity validation failed",
                    ),
                );
            }

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::PayloadIntegrityFailed,
                        Some("payload".to_string()),
                        "Payload integrity was not evaluated",
                    ),
                );
            }

            None => {}
        }
    }

    fn validate_signature(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        if !policy.require_signature {
            return;
        }

        match context.evidence.signature_valid {
            Some(true) => {}

            Some(false) => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::SignatureInvalid,
                        Some("signature".to_string()),
                        "Cryptographic signature validation failed",
                    ),
                );
            }

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::SignatureInvalid,
                        Some("signature".to_string()),
                        "Signature validity was not evaluated",
                    ),
                );
            }

            None => {}
        }
    }

    fn validate_replay_protection(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        if !policy.require_replay_protection {
            return;
        }

        match context.evidence.replay_detected {
            Some(false) => {}

            Some(true) => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::ReplayDetected,
                        Some("request".to_string()),
                        "Replay behavior was detected",
                    ),
                );
            }

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::ReplayDetected,
                        Some("request".to_string()),
                        "Replay protection was not evaluated",
                    ),
                );
            }

            None => {}
        }
    }

    fn validate_trust(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        let Some(minimum) = policy.minimum_trust_band else {
            return;
        };

        match context.evidence.trust_band {
            Some(actual) if actual.satisfies(minimum) => {}

            Some(actual) => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::TrustBelowThreshold,
                        Some("trust_band".to_string()),
                        format!(
                            "Trust band '{}' does not satisfy minimum '{}'",
                            actual,
                            minimum,
                        ),
                    ),
                );
            }

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::TrustBelowThreshold,
                        Some("trust_band".to_string()),
                        format!(
                            "Trust evaluation is required at minimum '{}'",
                            minimum,
                        ),
                    ),
                );
            }

            None => {}
        }
    }

    fn validate_anonymization_requirement(
        context: &RequestContext,
        policy: &RuntimePolicy,
        report: &mut ValidationReport,
    ) {
        if !policy.require_anonymization {
            return;
        }

        match context.evidence.sensitive_data_detected {
            Some(_) => {}

            None if policy.fail_closed => {
                report.add_failure(
                    ValidationFailure::new(
                        DecisionReason::SensitiveDataDetected,
                        Some("payload".to_string()),
                        "Sensitive-data detection was not evaluated",
                    ),
                );
            }

            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        IdentityContext,
        PayloadContext,
        RuntimeTrustBand,
    };

    fn context_for(
        operation: Operation,
    ) -> RequestContext {
        RequestContext::new(
            "request-001",
            "trace-001",
            operation,
            PayloadContext::new(42),
        )
    }

    fn valid_production_context() -> RequestContext {
        let mut context =
            context_for(Operation::Verify)
                .with_identity(
                    IdentityContext::new(
                        "client-001",
                        "api_key",
                        true,
                    ),
                );

        context
            .evidence
            .set_structural_validity(true);

        context
            .evidence
            .set_payload_integrity_valid(true);

        context
            .evidence
            .set_signature_valid(true);

        context
            .evidence
            .set_replay_detected(false);

        context
            .evidence
            .set_trust_band(
                RuntimeTrustBand::Operational,
            );

        context
    }

    #[test]
    fn valid_context_passes_validation() {
        let policy =
            RuntimePolicy::new(
                "production.verify",
                "1.0.0",
            )
            .allow_operation(Operation::Verify);

        let context = valid_production_context();

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(report.is_valid());
        assert!(report.failures.is_empty());
    }

    #[test]
    fn unknown_operation_is_rejected() {
        let policy =
            RuntimePolicy::new(
                "production.default",
                "1.0.0",
            );

        let context =
            context_for(Operation::Unknown);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(report.has_failures());

        assert_eq!(
            report.first_failure().map(
                |failure| failure.reason
            ),
            Some(
                DecisionReason::UnsupportedOperation
            )
        );
    }

    #[test]
    fn operation_not_allowed_by_policy_fails() {
        let policy =
            RuntimePolicy::health_check();

        let mut context =
            context_for(Operation::Anonymize);

        context
            .evidence
            .set_structural_validity(true);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(
            report.failures.iter().any(
                |failure| {
                    failure.reason
                        == DecisionReason::PolicyDenied
                }
            )
        );
    }

    #[test]
    fn missing_identity_fails_closed() {
        let policy =
            RuntimePolicy::new(
                "production.verify",
                "1.0.0",
            )
            .allow_operation(Operation::Verify);

        let mut context =
            context_for(Operation::Verify);

        context
            .evidence
            .set_structural_validity(true);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(
            report.failures.iter().any(
                |failure| {
                    failure.reason
                        == DecisionReason::IdentityMissing
                }
            )
        );
    }

    #[test]
    fn invalid_signature_is_reported() {
        let policy =
            RuntimePolicy::pqc_verification_benchmark();

        let mut context =
            context_for(Operation::Verify);

        context
            .evidence
            .set_structural_validity(true);

        context
            .evidence
            .set_signature_valid(false);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(
            report.failures.iter().any(
                |failure| {
                    failure.reason
                        == DecisionReason::SignatureInvalid
                }
            )
        );
    }

    #[test]
    fn replay_detection_is_reported() {
        let policy =
            RuntimePolicy::new(
                "production.verify",
                "1.0.0",
            )
            .allow_operation(Operation::Verify);

        let mut context =
            valid_production_context();

        context
            .evidence
            .set_replay_detected(true);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(
            report.failures.iter().any(
                |failure| {
                    failure.reason
                        == DecisionReason::ReplayDetected
                }
            )
        );
    }

    #[test]
    fn trust_below_minimum_is_reported() {
        let policy =
            RuntimePolicy::new(
                "production.verify",
                "1.0.0",
            )
            .allow_operation(Operation::Verify);

        let mut context =
            valid_production_context();

        context
            .evidence
            .set_trust_band(
                RuntimeTrustBand::Fragile,
            );

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(
            report.failures.iter().any(
                |failure| {
                    failure.reason
                        == DecisionReason::TrustBelowThreshold
                }
            )
        );
    }

    #[test]
    fn benchmark_anonymization_does_not_require_identity() {
        let policy =
            RuntimePolicy::anonymization_benchmark();

        let mut context =
            context_for(Operation::Anonymize);

        context
            .evidence
            .set_structural_validity(true);

        context
            .evidence
            .set_sensitive_data_detected(false);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(
            !report.failures.iter().any(
                |failure| {
                    matches!(
                        failure.reason,
                        DecisionReason::IdentityMissing
                            | DecisionReason::IdentityInvalid
                    )
                }
            )
        );
    }

    #[test]
    fn validation_report_can_be_applied_to_context() {
        let policy =
            RuntimePolicy::health_check();

        let mut context =
            context_for(Operation::Anonymize);

        context
            .evidence
            .set_structural_validity(true);

        RuntimeValidator::validate_context(
            &mut context,
            &policy,
        );

        assert!(context.has_failures());

        assert!(
            context.failures.iter().any(
                |failure| {
                    failure.reason
                        == DecisionReason::PolicyDenied
                }
            )
        );
    }

    #[test]
    fn fail_open_allows_missing_non_operation_evidence() {
        let policy =
            RuntimePolicy::new(
                "legacy.verify",
                "1.0.0",
            )
            .allow_operation(Operation::Verify)
            .with_fail_closed(false);

        let context =
            context_for(Operation::Verify);

        let report =
            RuntimeValidator::validate(
                &context,
                &policy,
            );

        assert!(report.is_valid());
    }
}
