-- Atomic per-subject quota counters for defensive scans.
-- Public: one lifetime bucket per peer IP. Paid: monthly UTC bucket per customer.
CREATE TABLE IF NOT EXISTS scanner_quotas (
    subject_key TEXT NOT NULL,
    period TEXT NOT NULL,
    used INTEGER NOT NULL CHECK (used BETWEEN 0 AND 100),
    PRIMARY KEY(subject_key, period)
);
