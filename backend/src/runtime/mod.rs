//! Deterministic runtime primitives for Vortex-DFS.
//!
//! The runtime module coordinates normalized operations, evidence,
//! policies, trust evaluation, decisions, execution, and audit.
//!
//! Individual security features remain implemented in their own
//! modules. The runtime orchestrates those features without absorbing
//! their internal logic.

pub mod audit;
pub mod context;
pub mod decision;
pub mod engine;
pub mod evidence;
pub mod operation;
pub mod policy;
pub mod trust;
pub mod validator;

pub use audit::{
    AuditStoreError, InMemoryRuntimeAuditStore, PostgresRuntimeAuditStore, RuntimeAuditEvent,
    RuntimeAuditStore,
};

pub use context::{
    current_timestamp_ms, IdentityContext, PayloadContext, RequestContext, ValidationFailure,
};

pub use decision::{DecisionOutcome, DecisionPolicyReference, DecisionReason, RuntimeDecision};

pub use engine::{evaluate_and_execute, evaluate_request, GuardedExecution, RuntimeEvaluation};

pub use evidence::{EvidenceSummary, EvidenceValue, SecurityEvidence};

pub use operation::Operation;
pub use policy::RuntimePolicy;
pub use trust::RuntimeTrustBand;
pub use validator::{RuntimeValidator, ValidationReport};
