//! Deterministic runtime primitives for Vortex-DFS.
//!
//! The runtime module coordinates normalized operations, evidence,
//! policies, trust evaluation, decisions, execution, and audit.
//!
//! Individual security features remain implemented in their own
//! modules. The runtime orchestrates those features without absorbing
//! their internal logic.

pub mod context;
pub mod decision;
pub mod evidence;
pub mod operation;
pub mod trust;

pub use context::{
    current_timestamp_ms,
    IdentityContext,
    PayloadContext,
    RequestContext,
    ValidationFailure,
};

pub use decision::{
    DecisionOutcome,
    DecisionPolicyReference,
    DecisionReason,
    RuntimeDecision,
};

pub use evidence::{
    EvidenceSummary,
    EvidenceValue,
    SecurityEvidence,
};

pub use operation::Operation;
pub use trust::RuntimeTrustBand;
