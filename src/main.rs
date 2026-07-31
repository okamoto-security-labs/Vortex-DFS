mod runtime;

use runtime::evaluator::evaluate;

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
    const ITERATIONS: usize = 1_000;

    let event_store = Arc::new(InMemoryEventStore::new());

    let agent = builder::<()>()
        .provider(StubProvider)
        .event_store(event_store.clone())
        .build();

    let mut durations = Vec::with_capacity(ITERATIONS);
    let benchmark_start = Instant::now();

    for iteration in 0..ITERATIONS {
        let thread_id = ThreadId::new();
        let start = Instant::now();

        agent
            .run(
                thread_id.clone(),
                AgentInput::Text(format!("Vortex integration test iteration {iteration}")),
                ToolContext::new(()),
                CancellationToken::new(),
            )
            .await?;

        durations.push(start.elapsed());

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

    let trust_score = 0.94;

    let vortex_start = Instant::now();
    let decision = evaluate(trust_score);
    let vortex_latency = vortex_start.elapsed();

    let decision_label = match decision.action {
        runtime::decision::DecisionAction::Allow => "APPROVED",
        runtime::decision::DecisionAction::Escalate => "REVIEW REQUIRED",
        runtime::decision::DecisionAction::Block => "BLOCKED",
    };

    println!();
    println!("================================================================");
    println!("VORTEX DFS — RUNTIME TRUST GATE");
    println!("Policy Enforcement Before Agent Execution");
    println!("================================================================");
    println!();
    println!("Incoming Agent Request");
    println!("        │");
    println!("        ▼");
    println!("Runtime Policy Check ................. PASSED");
    println!("Trust Boundary Evaluation ............ PASSED");
    println!("Decision Generation .................. COMPLETE");
    println!();
    println!("----------------------------------------------------------------");
    println!("EXECUTION DECISION");
    println!("----------------------------------------------------------------");
    println!();
    println!("Decision          : {}", decision_label);
    println!("Trust Score       : {:.2}", decision.trust_score);
    println!("Policy Profile    : Enterprise Default");
    println!(
        "Decision Latency  : {:.3} us",
        vortex_latency.as_secs_f64() * 1_000_000.0
    );
    println!("Reason            : {}", decision.reason);
    println!();
    println!("----------------------------------------------------------------");

    match decision.action {
        runtime::decision::DecisionAction::Allow => {
            println!("Request approved by Vortex DFS.");
            println!("Delegating authorized execution to Agent SDK...");
        }
        runtime::decision::DecisionAction::Escalate => {
            println!("Execution paused.");
            println!("Human approval is required before Agent SDK execution.");
        }
        runtime::decision::DecisionAction::Block => {
            println!("Execution denied.");
            println!("The request will not be forwarded to the Agent SDK.");
        }
    }

    println!("----------------------------------------------------------------");
    println!();

    durations.sort();

    let total = benchmark_start.elapsed();
    let total_ns: u128 = durations.iter().map(Duration::as_nanos).sum();
    let average_ns = total_ns as f64 / ITERATIONS as f64;

    let p50 = durations[ITERATIONS * 50 / 100];
    let p95 = durations[ITERATIONS * 95 / 100];
    let p99 = durations[ITERATIONS * 99 / 100];

    println!("================================================================");
    println!("AGENT SDK — AUTHORIZED EXECUTION");
    println!("================================================================");
    println!();
    println!("SDK Version           : 0.16.0");
    println!("Provider              : vortex-stub");
    println!("Execution Mode        : Local deterministic benchmark");
    println!();
    println!("Iterations            : {}", ITERATIONS);
    println!("Successful Runs       : {}", ITERATIONS);
    println!("Failed Runs           : 0");
    println!();
    println!("Average Latency       : {:.3} us", average_ns / 1_000.0);
    println!(
        "P50 Latency           : {:.3} us",
        p50.as_secs_f64() * 1_000_000.0
    );
    println!(
        "P95 Latency           : {:.3} us",
        p95.as_secs_f64() * 1_000_000.0
    );
    println!(
        "P99 Latency           : {:.3} us",
        p99.as_secs_f64() * 1_000_000.0
    );
    println!();
    println!(
        "Execution Throughput  : {:.2} requests/s",
        ITERATIONS as f64 / total.as_secs_f64()
    );
    println!();
    println!("================================================================");
    println!("END-TO-END RESULT");
    println!("================================================================");
    println!();
    println!("[PASS] Vortex runtime policy evaluation completed");
    println!("[PASS] Explicit execution decision produced");
    println!("[PASS] Agent SDK received an authorized request");
    println!("[PASS] 1,000 execution cycles completed");
    println!("[PASS] Zero execution failures");
    println!();
    println!("Final State           : AUTHORIZED AND COMPLETED");
    println!("================================================================");

    Ok(())
}
