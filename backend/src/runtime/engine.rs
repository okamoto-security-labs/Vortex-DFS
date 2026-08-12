//! Deterministic runtime evaluation and enforcement decision selection.

use std::time::Instant;

use crate::runtime::{RequestContext, RuntimeDecision, RuntimePolicy, RuntimeValidator};

/// Result of one protected-request evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeEvaluation {
    pub context: RequestContext,
    pub decision: RuntimeDecision,
}

impl RuntimeEvaluation {
    /// External executors must check this before running.
    pub const fn permits_execution(&self) -> bool {
        self.decision.permits_execution()
    }
}

/// Evaluates evidence and policy before an adapter invokes an executor.
///
/// Any validation failure deterministically produces `REJECT`.
pub fn evaluate_request(mut context: RequestContext, policy: &RuntimePolicy) -> RuntimeEvaluation {
    let started_at = Instant::now();
    let report = RuntimeValidator::validate(&context, policy);
    let first_failure = report.first_failure().cloned();
    report.apply_to_context(&mut context);

    let latency_us = started_at.elapsed().as_micros() as u64;
    let policy_reference = policy.decision_reference();

    let decision = match first_failure {
        Some(failure) => RuntimeDecision::reject(
            policy_reference,
            failure.reason,
            &context.evidence,
            latency_us,
        ),
        None if policy.require_anonymization
            && context.evidence.sensitive_data_detected == Some(true) =>
        {
            RuntimeDecision::redact(policy_reference, &context.evidence, latency_us)
        }
        None if policy.audit_required => {
            RuntimeDecision::audit(policy_reference, &context.evidence, latency_us)
        }
        None => RuntimeDecision::allow(policy_reference, &context.evidence, latency_us),
    };

    RuntimeEvaluation { context, decision }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{DecisionOutcome, DecisionReason, Operation, PayloadContext};

    fn context() -> RequestContext {
        RequestContext::new(
            "request-001",
            "trace-001",
            Operation::Anonymize,
            PayloadContext::new(32),
        )
    }

    #[test]
    fn missing_required_evidence_rejects_before_execution() {
        let evaluation = evaluate_request(context(), &RuntimePolicy::anonymization_benchmark());

        assert_eq!(evaluation.decision.outcome, DecisionOutcome::Reject);
        assert_eq!(
            evaluation.decision.reason_code,
            DecisionReason::StructureInvalid
        );
        assert!(!evaluation.permits_execution());
        assert!(evaluation.context.has_failures());
    }

    #[test]
    fn sensitive_content_requires_redaction() {
        let mut request = context();
        request.evidence.set_structural_validity(true);
        request.evidence.set_sensitive_data_detected(true);

        let evaluation = evaluate_request(request, &RuntimePolicy::anonymization_benchmark());

        assert_eq!(evaluation.decision.outcome, DecisionOutcome::Redact);
        assert!(evaluation.permits_execution());
    }
}
