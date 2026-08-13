-- Safe, append-only runtime decision audit records.
-- This table intentionally excludes raw payloads, identity data, API keys,
-- and unrestricted evidence signals.

CREATE TABLE IF NOT EXISTS runtime_audit_events (
    event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    evidence_summary JSONB NOT NULL,
    trust_band TEXT NULL,
    latency_us BIGINT NOT NULL CHECK (latency_us >= 0),
    decided_at_ms BIGINT NOT NULL CHECK (decided_at_ms >= 0)
);

CREATE INDEX IF NOT EXISTS idx_runtime_audit_events_trace_id
    ON runtime_audit_events (trace_id, decided_at_ms);

CREATE INDEX IF NOT EXISTS idx_runtime_audit_events_decided_at
    ON runtime_audit_events (decided_at_ms);
