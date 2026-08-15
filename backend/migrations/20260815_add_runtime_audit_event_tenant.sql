-- Introduces tenant isolation for runtime audit events.
-- Existing legacy events remain unassigned and are intentionally not exposed
-- through tenant-scoped HTTP reads.

ALTER TABLE runtime_audit_events
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_runtime_audit_events_tenant_trace
    ON runtime_audit_events (tenant_id, trace_id, decided_at_ms);
