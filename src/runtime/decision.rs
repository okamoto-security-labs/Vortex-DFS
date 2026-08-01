#[derive(Debug, Clone)]
pub enum DecisionAction {
    Allow,
    Escalate,
    Block,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: DecisionAction,
    pub trust_score: f64,
    pub reason: String,
}
