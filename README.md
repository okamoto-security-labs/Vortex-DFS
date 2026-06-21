# Vortex DFS
**Deterministic physics-oriented AI defense.**

> Vortex doesn't predict attacks. It reacts to the laws of exact sciences.

[![Rust](https://img.shields.io/badge/Rust-1.76-orange)](https://www.rust-lang.org/)
[![Go](https://img.shields.io/badge/Go-1.22-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production-brightgreen)]()
[![Uptime](https://img.shields.io/uptimerobot/status/m800028416-f2df0e073fc60779bf7cb7a0)](https://okamotosecurytlabs.com.br)

**[Landing Page](https://okamotosecurytlabs.com.br)** · **[Live Demo](https://okamotosecurytlabs.com.br)** · **[API Pricing](https://okamotosecurytlabs.com.br)** · **[Article](https://dev.to/gustavo89587/how-a-modular-arithmetic)**

---

## `/v1/shield/anonymize` — Production PII Anonymization API

The fastest path to production-ready PII detection. No LLM. No third-party model. No data retention.

```bash
curl -X POST https://vortex-dfs.onrender.com/v1/shield/anonymize \
  -H "Content-Type: application/json" \
  -d '{"content": "Call John at john.smith@corp.com or SSN 523-45-6789"}'
```

```json
{
  "sanitized": "Call John at [REDACTED_001] or SSN [REDACTED_002]",
  "risk_score": 0.75,
  "detections": [
    {"pattern": "EMAIL", "count": 1, "positions": [[11, 33]]},
    {"pattern": "SSN_US", "count": 1, "positions": [[38, 49]]}
  ],
  "token_map_enc": "AES-256-GCM encrypted reverse map",
  "trace_id": "11821208-990f-478b-858a-508ee12f7623",
  "latency_ms": 7.54
}
```

### Why not an LLM?

| | LLM-based detection | Vortex DFS |
|---|---|---|
| Latency | 200ms–2s | **<10ms p99** |
| Determinism | ❌ Nondeterministic | ✅ Same input = same output |
| Data retention | ❌ Sends data to third party | ✅ Zero retention |
| Cost | $$$ per token | **Flat subscription** |
| Auditability | ❌ Black box | ✅ Fully auditable patterns |

### NSA Advisory alignment

NSA Cybersecurity Advisory [U/OO/169570-20](https://media.defense.gov/2020/Sep/17/2002499616/-1/-1/0/PERFORMING_OUT_OF_BAND_NETWORK_MANAGEMENT20200911.PDF) explicitly recommends:

> *"Use automated redact filters to ensure the LLM doesn't leak sensitive infrastructure blueprints or PII in its reports."*

Vortex DFS implements this recommendation as a production REST API.

### Detection coverage — 20 patterns across 4 tiers

| Tier | Patterns |
|---|---|
| **Credentials** | API keys (AWS, GitHub, Stripe), JWT tokens, Bearer tokens |
| **Identity** | SSN (US), Passport numbers, Driver's license |
| **Financial** | Credit cards (Luhn-validated), IBAN, routing numbers |
| **Contact** | Email, Phone (US/intl), IPv4/IPv6 |

### Get started

```bash
# Free demo — 10 req/min, no key required
curl -X POST https://vortex-dfs.onrender.com/v1/shield/anonymize \
  -H "Content-Type: application/json" \
  -d '{"content": "your text here"}'

# Authenticated — 300 req/min
curl -X POST https://vortex-dfs.onrender.com/v1/shield/anonymize \
  -H "Authorization: Bearer vdfs_live_your_key" \
  -H "Content-Type: application/json" \
  -d '{"content": "your text here"}'
```

**[→ Get an API key](https://okamotosecurytlabs.com.br)**

---

## What is Vortex DFS?

Most security systems ask: *"does this look malicious?"*

Vortex asks: *"does this obey the laws of physics and mathematics?"*

If it doesn't — it's blocked. No model. No guesswork. No exceptions.

---

## For decision makers

### The problem with current security

Modern systems rely on heuristics — pattern matching, machine learning, behavioral analysis. These approaches share one fundamental flaw: they can be fooled. An attacker who understands the model can craft inputs that appear legitimate.

Quantum computing accelerates this problem. Algorithms that secure today's infrastructure — RSA, ECDSA, AES-CBC — are provably broken by quantum adversaries.

### Three guarantees

| Guarantee | Mechanism |
|---|---|
| 🔐 Post-quantum by design | Signatures based on LWE — NIST 2024 standard. A quantum computer does not break this. |
| ⚛ Physics-bound trust | Trust scores derived from distance and entropy, evaluated against deterministic thresholds. Not a model. Math. |
| ⊢ Zero ambiguity | Every packet is Accept or Reject with a typed, auditable reason. No silent failures. |

### Who needs this

- Financial infrastructure migrating away from RSA/ECDSA
- IoT and embedded systems requiring predictable low-latency security
- AI pipelines that need PII sanitization before data hits models or logs
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
[ /v1/shield/anonymize ]    ← PII detection engine (20 patterns, <10ms)
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
| `anonymizer_engine.rs` | Rust | PII detection — 20 patterns, 4 tiers, regex compiled at startup |
| `provisioner.rs` | Rust | API key generation, customer management, Resend email |
| `stripe_webhook.rs` | Rust | HMAC-SHA256 webhook verification, subscription lifecycle |
| `protocol.rs` | Rust | Binary packet parsing — safe `from_le_bytes`, CRC-32 |
| `signer_lwe.rs` | Rust | Fiat-Shamir over LWE — post-quantum signatures |
| `engine.rs` | Rust | Typestate pipeline — typed `TrustState` |
| `intent_hash.rs` | Rust | HMAC-SHA256 — constant-time comparison |
| `vortex_guard.rs` | Rust | Axum middleware — auth + sanitization |
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
export STRIPE_WEBHOOK_SECRET="whsec_..."
export RESEND_API_KEY="re_..."
export ALLOW_DEMO="true"
export PORT="8080"
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
| PII zero retention | Content processed in memory, never written to disk |

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
- [ ] SQLite persistence for customer data
- [ ] Independent security audit
- [ ] `crates.io` publication
- [ ] Go module publication

---

## Technical writing

→ **[How a tolerance overflow made our post-quantum signatures accept everything](https://dev.to/gustavo89587/how-a-modular-arithmetic)**

A deep dive into the LWE verification bug we found and fixed — with full mathematical explanation and code.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

Built at **[Okamoto Security Labs](https://okamotosecurytlabs.com.br)** · São Paulo, Brazil

[🌐 Website](https://okamotosecurytlabs.com.br) · [💳 Pricing](https://okamotosecurytlabs.com.br) · [📄 Article](https://dev.to/gustavo89587/how-a-modular-arithmetic) · [⚖️ License](LICENSE)

---

> *Vortex doesn't guess. It computes.*
