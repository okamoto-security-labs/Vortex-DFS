// lib.rs — Vortex DFS module exports
// WHY THIS FILE EXISTS:
// Render's Rust buildpack expects a lib.rs when Cargo.toml declares
// modules. This re-exports the core modules so both the binary (main.rs)
// and any future integration tests can reference them.

pub mod anonymizer_engine;
pub mod provisioner;
pub mod stripe_webhook;
