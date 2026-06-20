<div align="center">

<img src="https://img.shields.io/badge/VORTEX-DFS-0EA5E9?style=for-the-badge&logoColor=white" />

# Vortex DFS

**Deterministic physics-oriented AI defense.**

> *Vortex doesn't predict attacks. It reacts to the laws of exact sciences.*

<br/>

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-Apache_2.0-0EA5E9?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-10B981?style=for-the-badge)
![PQC](https://img.shields.io/badge/Post--Quantum-Ready-8B5CF6?style=for-the-badge)
![NIST](https://img.shields.io/badge/NIST-2024_Aligned-F59E0B?style=for-the-badge)

<br/>

[![Landing Page](https://img.shields.io/badge/🌐_Landing_Page-Visit-0EA5E9?style=flat-square)](https://okamoto-security-labs.github.io/Vortex-DFS)
[![Article](https://img.shields.io/badge/📄_Technical_Article-Read-8B5CF6?style=flat-square)](./article_lwe_bug.md)

</div>

---

## What is Vortex DFS?

Most security systems ask: *"does this look malicious?"*  
Vortex asks: *"does this obey the laws of physics and mathematics?"*  
If it doesn't — it's blocked. No model. No guesswork. No exceptions.

---

## For decision makers

### The problem with current security

Modern systems rely on heuristics — pattern matching, machine learning, behavioral analysis. These approaches share one fundamental flaw: **they can be fooled**. An attacker who understands the model can craft inputs that appear legitimate.

Quantum computing accelerates this problem. Algorithms that secure today's infrastructure — RSA, ECDSA, AES-CBC — are provably broken by quantum adversaries.

### Three guarantees

| Guarantee | Mechanism |
|---|---|
| 🔐 **Post-quantum by design** | Signatures based on LWE — NIST 2024 standard. A quantum computer does not break this. |
| ⚛ **Physics-bound trust** | Trust scores derived from distance and entropy, evaluated against deterministic thresholds. Not a model. Math. |
| ⊢ **Zero ambiguity** | Every packet is Accept or Reject with a typed, auditable reason. No silent failures. |

### Who needs this

- Financial infrastructure migrating away from RSA/ECDSA
- IoT and embedded systems requiring predictable low-latency security
- AI pipelines that need tamper-evident authentication of inputs
- Any system that cannot afford to be wrong

---

## For developers

### Architecture

```
[ Network / Client ]
        │
        ▼
[ vortex-gateway ]          ← Protocol parsing, CRC-32 validation (Go)
        │
        ▼
[ vortex_guard ]            ← HMAC-SHA256 auth, body limits, session sanitization
        │
        ▼
[ engine ]                  ← Typestate pipeline: Unverified → Verified
        │
        ▼
[ signer_lwe / pqc_core ]   ← Post-quantum signature verification
        │
        ▼
[ metrics / cyber_guardian ] ← Trust scoring, anomaly logging
```

### Modules

| Module | Language | Responsibility |
|---|---|---|
| `protocol.rs` | Rust | Binary packet parsing — safe `from_le_bytes`, CRC-32 |
| `signer_lwe.rs` | Rust | Fiat-Shamir over LWE — post-quantum signatures |
| `engine.rs` | Rust | Typestate pipeline — typed `TrustState` |
| `pqc_core.rs` | Rust | Vectorized trust scoring — cache-line aligned |
| `intent_hash.rs` | Rust | HMAC-SHA256 — constant-time comparison |
| `vortex_guard.rs` | Rust | Axum middleware — auth + sanitization |
| `OKA_Signer.rs` | Rust | Binary self-integrity via SHA-256 |
| `defency_cargo.rs` | Rust | High-throughput 4-layer validation engine |
| `metrics.rs` | Rust | Typed telemetry — `TrustBand`, `MetricsSnapshot` |
| `Cyber_Guardian.rs` | Rust | Binary rotary logger — ring buffer |
| `main.go` | Go | Gateway — protocol parity with Rust |

### Trust pipeline

```
raw bytes
    │
    ├─ CRC mismatch?           → RejectedProtocol
    ├─ Bad sync word?          → RejectedProtocol
    ├─ LWE signature invalid?  → RejectedSignature
    ├─ Metrics out of [0,1]?   → RejectedBounds
    │
    └─ Score evaluation
           ├─ score ≥ 0.95    → HighTrust   ✅
           ├─ score ≥ 0.70    → Operational ✅
           ├─ score ≥ 0.20    → Fragile     ⚠️
           └─ score < 0.20    → Critical    ❌
```

### Quick start

```toml
# Cargo.toml
[dependencies]
vortex-dfs = "0.1"
```

```rust
use vortex_dfs::engine::{VortexGate, TrustState};
use vortex_dfs::signer_lwe::keygen;

let (sk, pk) = keygen(seed);
let gate = VortexGate::new(pk.clone());

let payload = build_telemetry_payload(distance, entropy);
let raw = build_packet(0x0001, &payload);
let sig = sk.sign(&payload, &pk, nonce);

match gate.process_packet(&raw, &sig) {
    TrustState::HighTrust                  => { /* proceed */ }
    TrustState::Operational                => { /* proceed with monitoring */ }
    TrustState::Fragile                    => { /* degrade gracefully */ }
    TrustState::RejectedSignature          => { /* block — forged packet */ }
    TrustState::RejectedProtocol(reason)   => { /* block — malformed */ }
    TrustState::RejectedBounds             => { /* block — invalid metrics */ }
}
```

### Configuration

```bash
# Required — never hardcoded
export VORTEX_HMAC_KEY="$(openssl rand -hex 32)"
```

### Security properties

| Property | Mechanism |
|---|---|
| Post-quantum signatures | Fiat-Shamir over LWE → `pqcrypto-dilithium` in production |
| Timing attack resistance | `subtle::ConstantTimeEq` / `hmac::Equal` |
| No undefined behavior | Zero `unsafe` in critical paths |
| Tamper detection | CRC-32 + hash-bound commitment |
| Log injection prevention | Session IDs sanitized to `[a-zA-Z0-9-_]` |
| DoS prevention | 1MB body limit before any allocation |
| No hardcoded secrets | All keys from environment at runtime |

### Running tests

```bash
cargo test
go test ./...
```

---

## Roadmap

- [ ] `pqcrypto-dilithium` integration (production-grade NIST parameters)
- [ ] Rate limiting in `vortex_guard`
- [ ] Session TTL and rotation
- [ ] Independent security audit
- [ ] `crates.io` publication
- [ ] Go module publication

---

## Technical article

→ [How a tolerance overflow made our post-quantum signatures accept everything](./article_lwe_bug.md)

A deep dive into the LWE verification bug we found and fixed — with full mathematical explanation and code.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<div align="center">

**Built at Okamoto Security Labs**

[🌐 Website](https://okamoto-security-labs.github.io/Vortex-DFS) · [📄 Article](./article_lwe_bug.md) · [⚖️ License](./LICENSE)  [👋CONTRIBUTING](./CONTRIBUTING.md)

<br/>

*Vortex doesn't guess. It computes.*

</div>
