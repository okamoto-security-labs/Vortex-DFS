//! Runtime trust classifications.
//!
//! This module defines the operational trust bands used by the runtime.
//! It is intentionally independent from the current `pqc_core` module
//! so the existing implementation can be migrated without an immediate
//! breaking refactor.

use serde::{Deserialize, Serialize};

/// Deterministic operational trust classification.
///
/// The order of the variants is meaningful:
///
/// ```text
/// Critical < Fragile < Operational < HighTrust
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTrustBand {
    /// Evidence indicates a severe trust or integrity failure.
    #[default]
    Critical,

    /// Evidence is incomplete, degraded, or near a rejection boundary.
    Fragile,

    /// Evidence satisfies ordinary operational requirements.
    Operational,

    /// Evidence satisfies the strongest configured trust requirements.
    HighTrust,
}

impl RuntimeTrustBand {
    /// Returns a stable machine-readable representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Fragile => "fragile",
            Self::Operational => "operational",
            Self::HighTrust => "high_trust",
        }
    }

    /// Returns whether this trust band satisfies a minimum requirement.
    pub const fn satisfies(self, minimum: Self) -> bool {
        self.rank() >= minimum.rank()
    }

    /// Returns a stable numeric rank.
    ///
    /// The rank is intended for comparison and serialization support.
    /// It is not a probability or confidence percentage.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::Fragile => 1,
            Self::Operational => 2,
            Self::HighTrust => 3,
        }
    }

    /// Returns whether execution should normally be rejected.
    ///
    /// Final enforcement still depends on active policy.
    pub const fn is_rejection_candidate(self) -> bool {
        matches!(self, Self::Critical | Self::Fragile)
    }
}

impl std::fmt::Display for RuntimeTrustBand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_bands_have_deterministic_order() {
        assert!(RuntimeTrustBand::Fragile > RuntimeTrustBand::Critical);
        assert!(RuntimeTrustBand::Operational > RuntimeTrustBand::Fragile);
        assert!(RuntimeTrustBand::HighTrust > RuntimeTrustBand::Operational);
    }

    #[test]
    fn high_trust_satisfies_operational_requirement() {
        assert!(RuntimeTrustBand::HighTrust.satisfies(RuntimeTrustBand::Operational));
    }

    #[test]
    fn fragile_does_not_satisfy_operational_requirement() {
        assert!(!RuntimeTrustBand::Fragile.satisfies(RuntimeTrustBand::Operational));
    }

    #[test]
    fn rank_is_not_ambiguous() {
        assert_eq!(RuntimeTrustBand::Critical.rank(), 0);
        assert_eq!(RuntimeTrustBand::Fragile.rank(), 1);
        assert_eq!(RuntimeTrustBand::Operational.rank(), 2);
        assert_eq!(RuntimeTrustBand::HighTrust.rank(), 3);
    }

    #[test]
    fn degraded_bands_are_rejection_candidates() {
        assert!(RuntimeTrustBand::Critical.is_rejection_candidate());
        assert!(RuntimeTrustBand::Fragile.is_rejection_candidate());
        assert!(!RuntimeTrustBand::Operational.is_rejection_candidate());
    }

    #[test]
    fn critical_is_the_safe_default() {
        assert_eq!(RuntimeTrustBand::default(), RuntimeTrustBand::Critical);
    }
}
