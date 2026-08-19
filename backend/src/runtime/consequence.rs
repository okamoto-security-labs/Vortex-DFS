//! Consequence-plane primitives for runtime decisions.
//!
//! Consequence describes what may happen if an otherwise valid and
//! authorized action is allowed to execute. It remains independent from
//! evidence quality and execution authority.

use serde::{Deserialize, Serialize};

/// Reversibility of an action's externally observable effect.
///
/// Ordering is intentional: higher values represent effects requiring
/// at least as much oversight as lower values.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum ReversibilityClass {
    Reversible,
    ExternallyReversible,
    Irreversible,
    Unclassified,
}

impl ReversibilityClass {
    /// Returns the conservative class for a chain of actions.
    ///
    /// An empty chain or any unclassified effect fails closed.
    pub fn worst_case<I>(classes: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        let mut seen = false;
        let mut worst = Self::Reversible;

        for class in classes {
            seen = true;

            if class == Self::Unclassified {
                return Self::Unclassified;
            }

            if class > worst {
                worst = class;
            }
        }

        if seen {
            worst
        } else {
            Self::Unclassified
        }
    }

    pub const fn requires_hard_gate(self) -> bool {
        matches!(self, Self::Irreversible | Self::Unclassified)
    }
}


/// Potential impact / blast radius of an action.
///
/// This is independent from reversibility. A reversible action may still
/// carry high consequence, while an irreversible action may have narrow
/// impact.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum ConsequenceTier {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for ConsequenceTier {
    fn default() -> Self {
        Self::Low
    }
}

/// Minimum runtime oversight required by consequence.
///
/// Ordering is intentional. A more restrictive requirement must never
/// be reduced by combining it with a less restrictive property.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum OversightRequirement {
    None,
    Elevated,
    HardGate,
}

impl OversightRequirement {
    pub const fn from_reversibility(class: ReversibilityClass) -> Self {
        match class {
            ReversibilityClass::Reversible => Self::None,
            ReversibilityClass::ExternallyReversible => Self::Elevated,
            ReversibilityClass::Irreversible | ReversibilityClass::Unclassified => Self::HardGate,
        }
    }

    pub const fn from_consequence(tier: ConsequenceTier) -> Self {
        match tier {
            ConsequenceTier::Low => Self::None,
            ConsequenceTier::Medium | ConsequenceTier::High => Self::Elevated,
            ConsequenceTier::Critical => Self::HardGate,
        }
    }

    pub fn worst_case<I>(requirements: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        requirements.into_iter().max().unwrap_or(Self::HardGate)
    }
}

/// Consequence information attached to one runtime request.
///
/// Absence of this context means the current request/runtime has not
/// supplied Consequence Plane input. `Unclassified` means the plane was
/// supplied but reversibility could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequenceContext {
    pub reversibility: ReversibilityClass,

    #[serde(default)]
    pub tier: ConsequenceTier,
}

impl ConsequenceContext {
    /// Backward-compatible constructor.
    ///
    /// Existing callers that provide only reversibility receive a Low
    /// consequence tier until a stronger tier is explicitly supplied.
    pub const fn new(reversibility: ReversibilityClass) -> Self {
        Self {
            reversibility,
            tier: ConsequenceTier::Low,
        }
    }

    pub const fn with_tier(
        reversibility: ReversibilityClass,
        tier: ConsequenceTier,
    ) -> Self {
        Self {
            reversibility,
            tier,
        }
    }

    pub fn required_oversight(self) -> OversightRequirement {
        OversightRequirement::worst_case([
            OversightRequirement::from_reversibility(self.reversibility),
            OversightRequirement::from_consequence(self.tier),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn externally_reversible_is_distinct_from_reversible() {
        assert!(
            ReversibilityClass::ExternallyReversible
                > ReversibilityClass::Reversible
        );
    }

    #[test]
    fn chain_uses_worst_case_not_average() {
        let result = ReversibilityClass::worst_case([
            ReversibilityClass::Reversible,
            ReversibilityClass::Irreversible,
            ReversibilityClass::Reversible,
        ]);

        assert_eq!(result, ReversibilityClass::Irreversible);
    }

    #[test]
    fn unclassified_effect_fails_closed() {
        let result = ReversibilityClass::worst_case([
            ReversibilityClass::Reversible,
            ReversibilityClass::Unclassified,
        ]);

        assert_eq!(result, ReversibilityClass::Unclassified);
        assert!(result.requires_hard_gate());
    }

    #[test]
    fn irreversible_effect_requires_hard_gate() {
        let consequence =
            ConsequenceContext::new(ReversibilityClass::Irreversible);

        assert_eq!(
            consequence.required_oversight(),
            OversightRequirement::HardGate
        );
    }

    #[test]
    fn externally_reversible_effect_requires_elevated_oversight() {
        let consequence =
            ConsequenceContext::new(ReversibilityClass::ExternallyReversible);

        assert_eq!(
            consequence.required_oversight(),
            OversightRequirement::Elevated
        );
    }

    #[test]
    fn oversight_composition_uses_most_restrictive_requirement() {
        let result = OversightRequirement::worst_case([
            OversightRequirement::None,
            OversightRequirement::HardGate,
            OversightRequirement::Elevated,
        ]);

        assert_eq!(result, OversightRequirement::HardGate);
    }

    #[test]
    fn empty_oversight_composition_fails_closed() {
        let result =
            OversightRequirement::worst_case(std::iter::empty());

        assert_eq!(result, OversightRequirement::HardGate);
    }

    #[test]
    fn high_consequence_reversible_action_is_elevated() {
        let consequence = ConsequenceContext::with_tier(
            ReversibilityClass::Reversible,
            ConsequenceTier::High,
        );

        assert_eq!(
            consequence.required_oversight(),
            OversightRequirement::Elevated
        );
    }

    #[test]
    fn low_consequence_irreversible_action_remains_hard_gated() {
        let consequence = ConsequenceContext::with_tier(
            ReversibilityClass::Irreversible,
            ConsequenceTier::Low,
        );

        assert_eq!(
            consequence.required_oversight(),
            OversightRequirement::HardGate
        );
    }

    #[test]
    fn critical_consequence_hard_gates_reversible_action() {
        let consequence = ConsequenceContext::with_tier(
            ReversibilityClass::Reversible,
            ConsequenceTier::Critical,
        );

        assert_eq!(
            consequence.required_oversight(),
            OversightRequirement::HardGate
        );
    }

    #[test]
    fn empty_chain_fails_closed() {
        let result =
            ReversibilityClass::worst_case(std::iter::empty());

        assert_eq!(result, ReversibilityClass::Unclassified);
    }
}
