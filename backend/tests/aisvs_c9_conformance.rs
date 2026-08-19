use vortex_dfs::runtime::{ConsequenceContext, OversightRequirement, ReversibilityClass};

#[test]
fn c9_externally_reversible_is_distinct_from_reversible() {
    assert!(ReversibilityClass::ExternallyReversible > ReversibilityClass::Reversible);

    assert_eq!(
        ConsequenceContext::new(ReversibilityClass::ExternallyReversible).required_oversight(),
        OversightRequirement::Elevated
    );
}

#[test]
fn c9_unclassified_fails_closed_to_hard_gate() {
    let consequence = ConsequenceContext::new(ReversibilityClass::Unclassified);

    assert_eq!(
        consequence.required_oversight(),
        OversightRequirement::HardGate
    );
}

#[test]
fn c9_empty_chain_fails_closed() {
    let effective = ReversibilityClass::worst_case(std::iter::empty());

    assert_eq!(effective, ReversibilityClass::Unclassified);

    assert_eq!(
        ConsequenceContext::new(effective).required_oversight(),
        OversightRequirement::HardGate
    );
}

#[test]
fn c9_oversight_is_monotonic_in_reversibility() {
    assert!(
        OversightRequirement::from_reversibility(ReversibilityClass::Reversible)
            < OversightRequirement::from_reversibility(ReversibilityClass::ExternallyReversible)
    );

    assert!(
        OversightRequirement::from_reversibility(ReversibilityClass::ExternallyReversible)
            < OversightRequirement::from_reversibility(ReversibilityClass::Irreversible)
    );
}

#[test]
fn c9_worst_case_not_average() {
    let effective = ReversibilityClass::worst_case([
        ReversibilityClass::Reversible,
        ReversibilityClass::Irreversible,
        ReversibilityClass::Reversible,
    ]);

    assert_eq!(effective, ReversibilityClass::Irreversible);
}

#[test]
fn c9_oversight_composition_uses_most_restrictive_requirement() {
    let effective = OversightRequirement::worst_case([
        OversightRequirement::None,
        OversightRequirement::Elevated,
        OversightRequirement::HardGate,
    ]);

    assert_eq!(effective, OversightRequirement::HardGate);
}

#[test]
fn c9_chain_worst_case_reaches_execution_gate() {
    use vortex_dfs::runtime::{
        evaluate_request, DecisionOutcome, DecisionReason, Operation, PayloadContext,
        RequestContext, RuntimePolicy,
    };

    let effective = ReversibilityClass::worst_case([
        ReversibilityClass::Reversible,
        ReversibilityClass::Irreversible,
        ReversibilityClass::Reversible,
    ]);

    assert_eq!(effective, ReversibilityClass::Irreversible);

    let mut request = RequestContext::new(
        "c9-chain-001",
        "c9-trace-001",
        Operation::Anonymize,
        PayloadContext::new(16),
    )
    .with_consequence(ConsequenceContext::new(effective));

    request.evidence.set_structural_validity(true);

    request.evidence.set_sensitive_data_detected(false);

    let evaluation = evaluate_request(request, &RuntimePolicy::anonymization_benchmark());

    assert_eq!(evaluation.decision.outcome, DecisionOutcome::Reject);

    assert_eq!(
        evaluation.decision.reason_code,
        DecisionReason::ConsequenceHardGate
    );

    assert!(!evaluation.permits_execution());
}

#[test]
fn c9_high_consequence_reversible_is_elevated() {
    use vortex_dfs::runtime::ConsequenceTier;

    let consequence =
        ConsequenceContext::with_tier(ReversibilityClass::Reversible, ConsequenceTier::High);

    assert_eq!(
        consequence.required_oversight(),
        OversightRequirement::Elevated
    );
}

#[test]
fn c9_low_consequence_irreversible_remains_hard_gated() {
    use vortex_dfs::runtime::ConsequenceTier;

    let consequence =
        ConsequenceContext::with_tier(ReversibilityClass::Irreversible, ConsequenceTier::Low);

    assert_eq!(
        consequence.required_oversight(),
        OversightRequirement::HardGate
    );
}

#[test]
fn c9_consequence_and_reversibility_compose_non_compensatorily() {
    use vortex_dfs::runtime::ConsequenceTier;

    let high_but_reversible =
        ConsequenceContext::with_tier(ReversibilityClass::Reversible, ConsequenceTier::High);

    let low_but_irreversible =
        ConsequenceContext::with_tier(ReversibilityClass::Irreversible, ConsequenceTier::Low);

    assert_eq!(
        high_but_reversible.required_oversight(),
        OversightRequirement::Elevated
    );

    assert_eq!(
        low_but_irreversible.required_oversight(),
        OversightRequirement::HardGate
    );
}
