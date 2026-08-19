use vortex_dfs::runtime::{
    ConsequenceContext,
    OversightRequirement,
    ReversibilityClass,
};

#[test]
fn c9_externally_reversible_is_distinct_from_reversible() {
    assert!(
        ReversibilityClass::ExternallyReversible
            > ReversibilityClass::Reversible
    );

    assert_eq!(
        ConsequenceContext::new(
            ReversibilityClass::ExternallyReversible
        )
        .required_oversight(),
        OversightRequirement::Elevated
    );
}

#[test]
fn c9_unclassified_fails_closed_to_hard_gate() {
    let consequence =
        ConsequenceContext::new(ReversibilityClass::Unclassified);

    assert_eq!(
        consequence.required_oversight(),
        OversightRequirement::HardGate
    );
}

#[test]
fn c9_empty_chain_fails_closed() {
    let effective =
        ReversibilityClass::worst_case(std::iter::empty());

    assert_eq!(
        effective,
        ReversibilityClass::Unclassified
    );

    assert_eq!(
        ConsequenceContext::new(effective).required_oversight(),
        OversightRequirement::HardGate
    );
}

#[test]
fn c9_oversight_is_monotonic_in_reversibility() {
    assert!(
        OversightRequirement::from_reversibility(
            ReversibilityClass::Reversible
        )
        <
        OversightRequirement::from_reversibility(
            ReversibilityClass::ExternallyReversible
        )
    );

    assert!(
        OversightRequirement::from_reversibility(
            ReversibilityClass::ExternallyReversible
        )
        <
        OversightRequirement::from_reversibility(
            ReversibilityClass::Irreversible
        )
    );
}

#[test]
fn c9_worst_case_not_average() {
    let effective = ReversibilityClass::worst_case([
        ReversibilityClass::Reversible,
        ReversibilityClass::Irreversible,
        ReversibilityClass::Reversible,
    ]);

    assert_eq!(
        effective,
        ReversibilityClass::Irreversible
    );
}

#[test]
fn c9_oversight_composition_uses_most_restrictive_requirement() {
    let effective = OversightRequirement::worst_case([
        OversightRequirement::None,
        OversightRequirement::Elevated,
        OversightRequirement::HardGate,
    ]);

    assert_eq!(
        effective,
        OversightRequirement::HardGate
    );
}
