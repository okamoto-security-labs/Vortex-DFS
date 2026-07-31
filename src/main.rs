use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use agent_sdk::{
    builder, AgentEvent, AgentInput, CancellationToken, EventStore,
    InMemoryEventStore, ThreadId, ToolContext,
};
use agent_sdk::llm::{
    ChatOutcome, ChatRequest, ChatResponse, ContentBlock, LlmProvider,
    StopReason, Usage,
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
                AgentInput::Text(format!(
                    "Vortex integration test iteration {iteration}"
                )),
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

        assert_eq!(
            response,
            "Vortex Agent Envelope test successful."
        );
        assert!(done_received);
    }

    durations.sort();

    let total = benchmark_start.elapsed();
    let total_ns: u128 = durations.iter().map(Duration::as_nanos).sum();
    let average_ns = total_ns as f64 / ITERATIONS as f64;

    let p50 = durations[ITERATIONS * 50 / 100];
    let p95 = durations[ITERATIONS * 95 / 100];
    let p99 = durations[ITERATIONS * 99 / 100];

    println!("Vortex Agent SDK offline benchmark");
    println!("sdk_version=0.16.0");
    println!("provider=vortex-stub");
    println!("iterations={ITERATIONS}");
    println!("successful_runs={ITERATIONS}");
    println!("failed_runs=0");
    println!("average_us={:.3}", average_ns / 1_000.0);
    println!("p50_us={:.3}", p50.as_secs_f64() * 1_000_000.0);
    println!("p95_us={:.3}", p95.as_secs_f64() * 1_000_000.0);
    println!("p99_us={:.3}", p99.as_secs_f64() * 1_000_000.0);
    println!("total_ms={:.3}", total.as_secs_f64() * 1_000.0);
    println!(
        "runs_per_second={:.2}",
        ITERATIONS as f64 / total.as_secs_f64()
    );

    Ok(())
}
