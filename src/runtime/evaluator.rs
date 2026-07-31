use super::decision::{Decision, DecisionAction};
use super::policy::*;

pub fn evaluate(score: f64) -> Decision {
    if score >= ALLOW_THRESHOLD {
        Decision {
            action: DecisionAction::Allow,
            trust_score: score,
            reason: "Trust score satisfies enterprise policy.".into(),
        }
    } else if score >= ESCALATE_THRESHOLD {
        Decision {
            action: DecisionAction::Escalate,
            trust_score: score,
            reason: "Manual review required.".into(),
        }
    } else {
        Decision {
            action: DecisionAction::Block,
            trust_score: score,
            reason: "Trust score below minimum threshold.".into(),
        }
    }
}
