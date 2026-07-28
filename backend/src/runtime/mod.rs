//! Deterministic runtime primitives for Vortex-DFS.
//!
//! The runtime module coordinates normalized operations, evidence,
//! policies, trust evaluation, decisions, execution, and audit.
//!
//! Individual security features remain implemented in their own
//! modules. The runtime orchestrates those features without absorbing
//! their internal logic.

pub mod operation;
pub mod trust;

pub use operation::Operation;
pub use trust::RuntimeTrustBand;
