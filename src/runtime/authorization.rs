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
