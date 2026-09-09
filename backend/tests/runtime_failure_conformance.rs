use serde::Deserialize;
use vortex_dfs::runtime::{
    evaluate_request, ConsequenceContext, DecisionOutcome, Operation, PayloadContext,
    RequestContext, ReversibilityClass, RuntimePolicy,
};

#[derive(Debug, Deserialize)]
struct RuntimeFailureCase {
    scenario: String,
    preconditions: Vec<String>,
    evidence: Vec<String>,
    authority: Vec<String>,
    proposed_action: String,
    derived_actions: Vec<String>,
    expected_decision: String,
    invariant: String,
    external_reference: String,
}

fn load_case(raw: &str) -> RuntimeFailureCase {
    serde_json::from_str(raw).expect("runtime failure scenario must be valid JSON")
}

fn assert_case_metadata(case: &RuntimeFailureCase) {
    assert!(
        !case.scenario.trim().is_empty(),
        "scenario must not be empty"
    );
    assert!(
        !case.preconditions.is_empty(),
        "preconditions must contain at least one condition"
    );
    assert!(
        !case.evidence.is_empty(),
        "evidence must contain at least one signal"
    );
    assert!(
        !case.authority.is_empty(),
        "authority must contain at least one authority statement"
    );
    assert!(
        !case.proposed_action.trim().is_empty(),
        "proposed_action must not be empty"
    );
    assert!(
        !case.expected_decision.trim().is_empty(),
        "expected_decision must not be empty"
    );
    assert!(
        !case.invariant.trim().is_empty(),
        "invariant must not be empty"
    );
    assert!(
        !case.external_reference.trim().is_empty(),
        "external_reference must not be empty"
    );
}

fn assert_expected_decision(case: &RuntimeFailureCase, actual: DecisionOutcome) {
    let expected = match case.expected_decision.as_str() {
        "ALLOW" => DecisionOutcome::Allow,
        "REJECT" => DecisionOutcome::Reject,
        "REDACT" => DecisionOutcome::Redact,
        "AUDIT" => DecisionOutcome::Audit,
        other => panic!("unsupported expected_decision: {other}"),
    };

    assert_eq!(
        actual, expected,
        "runtime decision violated invariant '{}'",
        case.invariant
    );
}

#[test]
fn runtime_failure_cases_have_required_metadata() {
    let cases = [
        include_str!("runtime_failures/missing_identity_fails_closed.json"),
        include_str!("runtime_failures/irreversible_derived_action_is_hard_gated.json"),
        include_str!("runtime_failures/security_context_failure_must_not_silently_continue.json"),
    ];

    for raw in cases {
        let case = load_case(raw);
        assert_case_metadata(&case);
    }
}

#[test]
fn missing_identity_must_fail_closed() {
    let case = load_case(include_str!(
        "runtime_failures/missing_identity_fails_closed.json"
    ));
    assert_case_metadata(&case);

    let mut request = RequestContext::new(
        "rfh-identity-001",
        "rfh-trace-identity-001",
        Operation::Verify,
        PayloadContext::new(32),
    );
    request.evidence.set_structural_validity(true);

    let policy =
        RuntimePolicy::new("runtime-failure.identity", "0.1.0").allow_operation(Operation::Verify);

    let evaluation = evaluate_request(request, &policy);

    assert_expected_decision(&case, evaluation.decision.outcome);
    assert!(
        !evaluation.permits_execution(),
        "missing identity must never silently permit execution"
    );
}

#[test]
fn irreversible_derived_action_must_reach_execution_gate() {
    let case = load_case(include_str!(
        "runtime_failures/irreversible_derived_action_is_hard_gated.json"
    ));
    assert_case_metadata(&case);

    // The declared operation is benign enough to be allowed by policy.
    // The effective action chain is not: one derived action is irreversible.
    let effective_reversibility = ReversibilityClass::worst_case([
        ReversibilityClass::Reversible,
        ReversibilityClass::Irreversible,
    ]);

    let mut request = RequestContext::new(
        "rfh-derived-001",
        "rfh-trace-derived-001",
        Operation::Anonymize,
        PayloadContext::new(64),
    )
    .with_consequence(ConsequenceContext::new(effective_reversibility));

    request.evidence.set_structural_validity(true);
    request.evidence.set_sensitive_data_detected(false);

    let evaluation = evaluate_request(request, &RuntimePolicy::anonymization_benchmark());

    assert_expected_decision(&case, evaluation.decision.outcome);
    assert!(
        !evaluation.permits_execution(),
        "an irreversible derived action must reach the execution hard gate"
    );

    // Keep the metadata coupled to the intended property.
    assert!(
        !case.derived_actions.is_empty(),
        "execution-expansion scenarios must declare derived actions"
    );
}

#[test]
fn security_context_failure_must_not_silently_continue() {
    let case = load_case(include_str!(
        "runtime_failures/security_context_failure_must_not_silently_continue.json"
    ));

    assert_case_metadata(&case);

    let mut request = RequestContext::new(
        "rfh-security-context-001",
        "rfh-trace-security-context-001",
        Operation::Anonymize,
        PayloadContext::new(64),
    );

    request.evidence.set_structural_validity(true);
    request.evidence.set_sensitive_data_detected(false);
    request.evidence.set_security_context_valid(false);

    let policy = RuntimePolicy::anonymization_benchmark().with_security_context_requirement(true);

    let evaluation = evaluate_request(request, &policy);

    assert_expected_decision(&case, evaluation.decision.outcome);

    assert!(
        !evaluation.permits_execution(),
        "mandatory security-context loss must block execution"
    );
}
