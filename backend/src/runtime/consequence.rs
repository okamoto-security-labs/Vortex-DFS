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


/// Consequence information attached to one runtime request.
///
/// Absence of this context means the current request/runtime has not
/// supplied Consequence Plane input. `Unclassified` means the plane was
/// supplied but reversibility could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequenceContext {
    pub reversibility: ReversibilityClass,
}

impl ConsequenceContext {
    pub const fn new(reversibility: ReversibilityClass) -> Self {
        Self { reversibility }
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
    fn empty_chain_fails_closed() {
        let result =
            ReversibilityClass::worst_case(std::iter::empty());

        assert_eq!(result, ReversibilityClass::Unclassified);
    }
}
