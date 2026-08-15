//! Normalized request context used by the Vortex runtime.
//!
//! Feature handlers should build one shared context instead of
//! independently recreating identity, payload, evidence, and trace data.

use crate::runtime::{DecisionReason, Operation, SecurityEvidence};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Identity information associated with a runtime request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Stable tenant or organization identifier for isolation boundaries.
    pub tenant_id: Option<String>,

    /// Stable identifier for the requesting principal.
    pub principal_id: String,

    /// Authentication mechanism used to verify the principal.
    pub authentication_method: String,

    /// Whether authentication evidence was successfully verified.
    pub verified: bool,

    /// Explicit capabilities granted to this identity.
    ///
    /// Scopes are deterministic and are never copied into audit events.
    pub scopes: BTreeSet<String>,
}

impl IdentityContext {
    pub fn new(
        principal_id: impl Into<String>,
        authentication_method: impl Into<String>,
        verified: bool,
    ) -> Self {
        Self {
            tenant_id: None,
            principal_id: principal_id.into(),
            authentication_method: authentication_method.into(),
            verified,
            scopes: BTreeSet::new(),
        }
    }

    /// Associates this identity with one tenant or organization.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Grants one explicit capability to this identity.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.insert(scope.into());
        self
    }

    /// Returns whether the identity has one explicit capability.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

/// Metadata describing a request payload.
///
/// Raw payload contents are deliberately excluded to reduce the risk of
/// sensitive information leaking into logs or audit events.
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

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    pub fn with_locale(mut self, locale: impl Into<String>) -> Self {
        self.locale = Some(locale.into());
        self
    }

    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }
}

/// Validation problem discovered during runtime processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFailure {
    pub reason: DecisionReason,
    pub field: Option<String>,
    pub message: String,
}

impl ValidationFailure {
    pub fn new(reason: DecisionReason, field: Option<String>, message: impl Into<String>) -> Self {
        Self {
            reason,
            field,
            message: message.into(),
        }
    }
}

/// Normalized request context shared across runtime stages.
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
            evidence: SecurityEvidence::new(),
            failures: Vec::new(),
        }
    }

    pub fn with_identity(mut self, identity: IdentityContext) -> Self {
        self.evidence.set_identity_verified(identity.verified);

        self.identity = Some(identity);
        self
    }

    pub fn with_policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    pub fn add_failure(&mut self, failure: ValidationFailure) {
        self.failures.push(failure);
    }

    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    pub fn is_identity_verified(&self) -> bool {
        self.identity
            .as_ref()
            .is_some_and(|identity| identity.verified)
    }

    pub fn request_age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.timestamp_ms)
    }
}

/// Returns Unix time in milliseconds.
///
/// If the system clock is earlier than the Unix epoch, the function
/// returns zero instead of panicking.
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
            PayloadContext::new(42)
                .with_content_type("text/plain")
                .with_locale("en"),
        )
    }

    #[test]
    fn request_context_starts_without_failures() {
        let context = example_context();

        assert_eq!(context.operation, Operation::Anonymize);
        assert!(!context.has_failures());
        assert!(context.timestamp_ms > 0);
        assert_eq!(context.payload.size_bytes, 42);
    }

    #[test]
    fn payload_builder_preserves_metadata() {
        let payload = PayloadContext::new(100)
            .with_content_type("application/json")
            .with_locale("pt-BR")
            .with_digest("sha256:example");

        assert_eq!(payload.content_type.as_deref(), Some("application/json"));
        assert_eq!(payload.locale.as_deref(), Some("pt-BR"));
        assert_eq!(payload.digest.as_deref(), Some("sha256:example"));
    }

    #[test]
    fn identity_updates_runtime_evidence() {
        let context =
            example_context().with_identity(IdentityContext::new("client-001", "api_key", true));

        assert!(context.is_identity_verified());
        assert_eq!(context.evidence.identity_verified, Some(true));
    }

    #[test]
    fn identity_preserves_tenant_boundary() {
        let identity =
            IdentityContext::new("client-001", "bearer_api_key", true).with_tenant_id("tenant-001");

        assert_eq!(identity.tenant_id.as_deref(), Some("tenant-001"));
    }

    #[test]
    fn identity_scopes_are_explicit() {
        let identity = IdentityContext::new("client-001", "bearer_api_key", true)
            .with_scope("anonymize:execute");

        assert!(identity.has_scope("anonymize:execute"));
        assert!(!identity.has_scope("audit:read"));
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
        assert_eq!(context.failures[0].reason, DecisionReason::StructureInvalid);
    }

    #[test]
    fn request_age_never_underflows() {
        let context = example_context();

        assert_eq!(
            context.request_age_ms(context.timestamp_ms.saturating_sub(1)),
            0
        );
    }
}
