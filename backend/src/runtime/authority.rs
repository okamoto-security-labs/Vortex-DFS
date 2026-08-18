//! Explicit authority carried into protected runtime execution.
//!
//! Authority describes what a principal has been delegated to do.
//! It does not prove that the delegation is authentic, current, or
//! trustworthy; those guarantees belong to runtime evidence and validation.

use crate::runtime::Operation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Explicit delegated authority for one protected runtime action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityContext {
    /// Stable identifier for the authority issuer.
    pub issuer: String,

    /// Principal to whom this authority was delegated.
    pub subject: String,

    /// Operation this authority permits.
    pub operation: Operation,

    /// Optional resources to which the authority is constrained.
    pub resources: BTreeSet<String>,

    /// Beginning of the authority validity interval.
    pub not_before_ms: u64,

    /// End of the authority validity interval.
    pub expires_at_ms: u64,
}

impl AuthorityContext {
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        operation: Operation,
        not_before_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.into(),
            operation,
            resources: BTreeSet::new(),
            not_before_ms,
            expires_at_ms,
        }
    }

    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.insert(resource.into());
        self
    }

    /// Structural validity only. This does not establish authenticity.
    pub fn has_valid_bounds(&self) -> bool {
        !self.issuer.trim().is_empty()
            && !self.subject.trim().is_empty()
            && self.operation != Operation::Unknown
            && self.not_before_ms < self.expires_at_ms
    }

    pub fn is_active_at(&self, timestamp_ms: u64) -> bool {
        self.has_valid_bounds()
            && timestamp_ms >= self.not_before_ms
            && timestamp_ms < self.expires_at_ms
    }

    pub fn permits_operation(&self, operation: Operation) -> bool {
        self.has_valid_bounds() && self.operation == operation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> AuthorityContext {
        AuthorityContext::new(
            "authority-service",
            "agent-001",
            Operation::AgentToolExecution,
            1_000,
            2_000,
        )
    }

    #[test]
    fn authority_is_bound_to_one_operation() {
        let authority = authority();

        assert!(authority.permits_operation(Operation::AgentToolExecution));
        assert!(!authority.permits_operation(Operation::Anonymize));
    }

    #[test]
    fn authority_is_valid_only_inside_temporal_bounds() {
        let authority = authority();

        assert!(!authority.is_active_at(999));
        assert!(authority.is_active_at(1_000));
        assert!(authority.is_active_at(1_999));
        assert!(!authority.is_active_at(2_000));
    }

    #[test]
    fn malformed_authority_fails_structural_validation() {
        let authority =
            AuthorityContext::new("", "agent-001", Operation::AgentToolExecution, 2_000, 1_000);

        assert!(!authority.has_valid_bounds());
    }

    #[test]
    fn resources_are_deterministic_and_explicit() {
        let authority = authority()
            .with_resource("tool:deploy")
            .with_resource("environment:production");

        let resources: Vec<&str> = authority.resources.iter().map(String::as_str).collect();

        assert_eq!(resources, vec!["environment:production", "tool:deploy"]);
    }
}
