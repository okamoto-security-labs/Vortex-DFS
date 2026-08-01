use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use agent_sdk::llm::{
    ChatOutcome, ChatRequest, ChatResponse, ContentBlock, LlmProvider, StopReason, Usage,
};
use agent_sdk::{
    AgentEvent, AgentInput, CancellationToken, EventStore, InMemoryEventStore, ThreadId,
    ToolContext, builder,
};
use async_trait::async_trait;

use vortex_dfs::runtime::{
    ALLOW_THRESHOLD, AuthorizationRequest, DecisionAction, ESCALATE_THRESHOLD, authorize,
};

struct StubProvider;

#[async_trait]
impl LlmProvider for StubProvider {
    async fn chat(&self, _request: ChatRequest) -> anyhow::Result<ChatOutcome> {
        Ok(ChatOutcome::Success(ChatResponse {
            id: "vortex-test-response".to_string(),
            content: vec![ContentBlock::Text {
                text: "Vortex Agent Envelope test successful.".to_string(),
            }],
            model: self.model().to_string(),
            stop_reason: Some(StopReason::EndTurn),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
                served_speed: None,
            },
        }))
    }

    fn model(&self) -> &str {
        "vortex-stub-model"
    }

    fn provider(&self) -> &'static str {
        "vortex-stub"
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const VORTEX_VERSION: &str = "0.1.0";
    const SDK_VERSION: &str = "0.16.0";
    const POLICY_PROFILE: &str = "Enterprise Default";
    const ITERATIONS: usize = 1_000;

    // Controlled input for this first integration milestone.
    // A future phase will calculate it from real Vortex runtime signals.
    let input_trust_score = 0.94;

    /*
     * VORTEX AUTHORIZATION PHASE
     *
     * This phase happens before the Agent SDK receives permission
     * to execute the request.
     */

    let authorization = authorize(AuthorizationRequest::new(input_trust_score, POLICY_PROFILE));

    let decision = &authorization.decision;
    let vortex_latency = authorization.latency;

    let decision_label = match &decision.action {
        DecisionAction::Allow => "APPROVED",
        DecisionAction::Escalate => "REVIEW REQUIRED",
        DecisionAction::Block => "BLOCKED",
    };

    println!();
    println!("======================================================================");
    println!("VORTEX DFS RUNTIME");
    println!("Enterprise Runtime Trust and Authorization Layer");
    println!("======================================================================");
    println!("Version              : {VORTEX_VERSION}");
    println!("Policy Profile       : {POLICY_PROFILE}");
    println!("Execution Mode       : Deterministic local integration test");
    println!();

    println!("PIPELINE");
    println!();
    println!("Application");
    println!("      │");
    println!("      ▼");
    println!("Vortex Runtime");
    println!("      │");
    println!("      ▼");
    println!("Authorization Decision");
    println!("      │");
    println!("      ▼");
    println!("Agent SDK");
    println!("      │");
    println!("      ▼");
    println!("Execution");
    println!();

    println!("======================================================================");
    println!("RUNTIME AUTHORIZATION");
    println!("======================================================================");
    println!();
    println!("Incoming Agent Request");
    println!("        │");
    println!("        ▼");
    println!("Collect Runtime Context ............... COMPLETE");
    println!("Load Policy Profile ................... COMPLETE");
    println!("Evaluate Trust Boundary ............... COMPLETE");
    println!("Generate Authorization Decision ....... COMPLETE");
    println!();

    println!("----------------------------------------------------------------------");
    println!("AUTHORIZATION DECISION");
    println!("----------------------------------------------------------------------");
    println!();
    println!("Decision             : {decision_label}");
    println!("Input Trust Score    : {:.2}", decision.trust_score);
    println!("Allow Threshold      : {ALLOW_THRESHOLD:.2}");
    println!("Escalate Threshold   : {ESCALATE_THRESHOLD:.2}");
    println!("Policy Profile       : {POLICY_PROFILE}");
    println!(
        "Runtime Overhead     : {:.3} us",
        vortex_latency.as_secs_f64() * 1_000_000.0
    );
    println!("Reason               : {}", decision.reason);
    println!();
    println!("----------------------------------------------------------------------");

    match &decision.action {
        DecisionAction::Allow => {
            println!("Authorization granted by Vortex DFS.");
            println!("Delegating approved execution to Agent SDK...");
        }
        DecisionAction::Escalate => {
            println!("Execution paused by Vortex DFS.");
            println!("Human approval is required before Agent SDK execution.");
            println!("The request was not delegated to the Agent SDK.");
            println!("----------------------------------------------------------------------");
            println!();

            print_denied_audit_summary(
                decision_label,
                "WAITING FOR HUMAN APPROVAL",
                VORTEX_VERSION,
            );

            return Ok(());
        }
        DecisionAction::Block => {
            println!("Authorization denied by Vortex DFS.");
            println!("The request was not delegated to the Agent SDK.");
            println!("----------------------------------------------------------------------");
            println!();

            print_denied_audit_summary(decision_label, "BLOCKED BY POLICY", VORTEX_VERSION);

            return Ok(());
        }
    }

    println!("----------------------------------------------------------------------");
    println!();

    /*
     * AGENT SDK EXECUTION PHASE
     *
     * This code is reached only after Vortex DFS authorizes execution.
     */
    let event_store = Arc::new(InMemoryEventStore::new());

    let agent = builder::<()>()
        .provider(StubProvider)
        .event_store(event_store.clone())
        .build();

    let mut durations = Vec::with_capacity(ITERATIONS);
    let benchmark_start = Instant::now();

    for iteration in 0..ITERATIONS {
        let thread_id = ThreadId::new();
        let execution_start = Instant::now();

        agent
            .run(
                thread_id.clone(),
                AgentInput::Text(format!(
                    "Vortex authorized integration test iteration {iteration}"
                )),
                ToolContext::new(()),
                CancellationToken::new(),
            )
            .await?;

        durations.push(execution_start.elapsed());

        let events = event_store.get_events(&thread_id).await?;

        let mut response = String::new();
        let mut done_received = false;

        for envelope in events {
            match envelope.event {
                AgentEvent::Text { text, .. } => response.push_str(&text),
                AgentEvent::Done { .. } => done_received = true,
                _ => {}
            }
        }

        assert_eq!(response, "Vortex Agent Envelope test successful.");
        assert!(done_received);
    }

    durations.sort();

    let total = benchmark_start.elapsed();
    let total_ns: u128 = durations.iter().map(Duration::as_nanos).sum();
    let average_ns = total_ns as f64 / ITERATIONS as f64;

    let p50 = durations[ITERATIONS * 50 / 100];
    let p95 = durations[ITERATIONS * 95 / 100];
    let p99 = durations[ITERATIONS * 99 / 100];

    println!("======================================================================");
    println!("AGENT SDK — AUTHORIZED EXECUTION");
    println!("======================================================================");
    println!();
    println!("SDK Version          : {SDK_VERSION}");
    println!("Provider             : vortex-stub");
    println!("Execution Mode       : Offline deterministic benchmark");
    println!("Authorization Source : Vortex DFS Runtime");
    println!();
    println!("Iterations           : {ITERATIONS}");
    println!("Successful Runs      : {ITERATIONS}");
    println!("Failed Runs          : 0");
    println!();
    println!("Average Latency      : {:.3} us", average_ns / 1_000.0);
    println!(
        "P50 Latency          : {:.3} us",
        p50.as_secs_f64() * 1_000_000.0
    );
    println!(
        "P95 Latency          : {:.3} us",
        p95.as_secs_f64() * 1_000_000.0
    );
    println!(
        "P99 Latency          : {:.3} us",
        p99.as_secs_f64() * 1_000_000.0
    );
    println!();
    println!(
        "Execution Throughput : {:.2} requests/s",
        ITERATIONS as f64 / total.as_secs_f64()
    );
    println!();

    println!("======================================================================");
    println!("AUDIT SUMMARY");
    println!("======================================================================");
    println!();
    println!("Vortex Version ......................... {VORTEX_VERSION}");
    println!("Runtime Policy Evaluation ............. SUCCESS");
    println!("Trust Boundary Evaluation ............. SUCCESS");
    println!("Authorization Decision ................ {decision_label}");
    println!("Agent SDK Authorization ............... SUCCESS");
    println!("Agent Execution ....................... SUCCESS");
    println!("Completed Execution Cycles ............ {ITERATIONS}");
    println!("Execution Failures .................... 0");
    println!("Policy Violations ..................... NONE");
    println!();
    println!("Final State ........................... AUTHORIZED AND COMPLETED");
    println!();

    println!("======================================================================");
    println!("Vortex DFS evaluates.");
    println!("Agent SDK executes.");
    println!("Every execution begins with an explicit authorization decision.");
    println!("======================================================================");

    Ok(())
}

fn print_denied_audit_summary(decision_label: &str, final_state: &str, vortex_version: &str) {
    println!("======================================================================");
    println!("AUDIT SUMMARY");
    println!("======================================================================");
    println!();
    println!("Vortex Version ......................... {vortex_version}");
    println!("Runtime Policy Evaluation ............. SUCCESS");
    println!("Trust Boundary Evaluation ............. SUCCESS");
    println!("Authorization Decision ................ {decision_label}");
    println!("Agent SDK Authorization ............... NOT GRANTED");
    println!("Agent Execution ....................... NOT STARTED");
    println!("Completed Execution Cycles ............ 0");
    println!("Execution Failures .................... 0");
    println!();
    println!("Final State ........................... {final_state}");
    println!();
    println!("======================================================================");
    println!("Vortex DFS evaluated the request before execution.");
    println!("The Agent SDK did not execute without authorization.");
    println!("======================================================================");
}
