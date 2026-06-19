//! # Vortex DFS
//!
//! Deterministic physics-oriented AI defense SDK.
//!
//! ## Architecture
//!
//! ```text
//! [ Network ] → [ protocol ] → [ vortex_guard ] → [ engine ] → [ signer_lwe / pqc_core ]
//! ```
//!
//! Every layer has one job. A packet only reaches the next layer
//! if it fully satisfies the current one.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use vortex_dfs::engine::{VortexGate, TrustState};
//! use vortex_dfs::signer_lwe::keygen;
//!
//! let seed = 0xDEAD_C0DE_CAFE_F00D_u64;
//! let nonce = 0xCAFE_u64;
//!
//! let (sk, pk) = keygen(seed);
//! let gate = VortexGate::new(pk.clone());
//! ```

pub mod protocol;
pub mod signer_lwe;
pub mod engine;
pub mod pqc_core;
pub mod intent_hash;
pub mod oka_signer;
pub mod vortex_guard;
pub mod defency_cargo;
pub mod metrics;
pub mod cyber_guardian;
