use std::time::{Duration, Instant};

use super::{
    decision::{Decision, DecisionAction},
    evaluator::evaluate,
};

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub trust_score: f64,
    pub policy_profile: String,
}

impl AuthorizationRequest {
    pub fn new(trust_score: f64, policy_profile: impl Into<String>) -> Self {
        Self {
            trust_score,
            policy_profile: policy_profile.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationReport {
    pub decision: Decision,
    pub policy_profile: String,
    pub latency: Duration,
}

impl AuthorizationReport {
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision.action, DecisionAction::Allow)
    }

    pub fn requires_review(&self) -> bool {
        matches!(self.decision.action, DecisionAction::Escalate)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self.decision.action, DecisionAction::Block)
    }
}

pub fn authorize(request: AuthorizationRequest) -> AuthorizationReport {
    let started_at = Instant::now();
    let decision = evaluate(request.trust_score);

    AuthorizationReport {
        decision,
        policy_profile: request.policy_profile,
        latency: started_at.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::decision::DecisionAction;

    #[test]
    fn approves_request_above_allow_threshold() {
        let report = authorize(AuthorizationRequest::new(0.94, "Enterprise Default"));

        assert!(report.is_allowed());
        assert!(!report.requires_review());
        assert!(!report.is_blocked());
        assert!(matches!(report.decision.action, DecisionAction::Allow));
        assert_eq!(report.decision.trust_score, 0.94);
        assert_eq!(report.policy_profile, "Enterprise Default");
    }

    #[test]
    fn escalates_request_between_thresholds() {
        let report = authorize(AuthorizationRequest::new(0.75, "Enterprise Default"));

        assert!(!report.is_allowed());
        assert!(report.requires_review());
        assert!(!report.is_blocked());
        assert!(matches!(report.decision.action, DecisionAction::Escalate));
        assert_eq!(report.decision.trust_score, 0.75);
    }

    #[test]
    fn blocks_request_below_escalate_threshold() {
        let report = authorize(AuthorizationRequest::new(0.42, "Enterprise Default"));

        assert!(!report.is_allowed());
        assert!(!report.requires_review());
        assert!(report.is_blocked());
        assert!(matches!(report.decision.action, DecisionAction::Block));
        assert_eq!(report.decision.trust_score, 0.42);
    }
}
