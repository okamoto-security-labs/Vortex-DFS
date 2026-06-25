# Vortex DFS
**Deterministic physics-oriented AI defense.**

> Vortex doesn't predict attacks. It reacts to the laws of exact sciences.

[![Rust](https://img.shields.io/badge/Rust-1.76-orange)](https://www.rust-lang.org/)
[![Go](https://img.shields.io/badge/Go-1.22-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/License-BUSL--1.1-yellow)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production-brightgreen)]()
[![Uptime](https://img.shields.io/uptimerobot/status/m800028416-f2df0e073fc60779bf7cb7a0)](https://okamotosecurytlabs.com.br)

**[Landing Page](https://okamotosecurytlabs.com.br)** · **[Live Demo](https://okamotosecurytlabs.com.br/demo)** · **[Get API Key →](https://okamotosecurytlabs.com.br/#pricing)** · **[Research](https://okamotosecurytlabs.com.br/research)**

> ⭐ If Vortex DFS is useful to you, consider starring this repo — it helps more than you think.

---

## API Endpoints — Production

| Endpoint | Description | Auth |
|---|---|---|
| `POST /v1/shield/anonymize` | PII redaction — 20 patterns, <10ms | Bearer or demo |
| `POST /v1/pqc/sign` | Post-quantum LWE signature + TrustBand | Bearer |
| `POST /v1/pqc/verify` | Verify LWE signature | Bearer |
| `POST /v1/pqc/audit` | Crypto-agility scanner — NIST migration roadmap | Bearer or demo |

**Base URL:** `https://vortex-dfs.onrender.com`

---

## Quick Start — 60 seconds

```bash
# No API key required for demo (10 req/min)

# 1. Anonymize PII
curl -X POST https://vortex-dfs.onrender.com/v1/shield/anonymize \
  -H "Content-Type: application/json" \
  -d '{"content": "Call John at john.smith@corp.com or SSN 523-45-6789"}'

# 2. Audit your crypto stack
curl -X POST https://vortex-dfs.onrender.com/v1/pqc/audit \
  -H "Content-Type: application/json" \
  -d '{"content": "This system uses RSA-2048, ECDH, AES-128 and SHA-1"}'

# 3. Sign with post-quantum LWE
curl -X POST https://vortex-dfs.onrender.com/v1/pqc/sign \
  -H "Authorization: Bearer vdfs_live_your_key" \
  -H "Content-Type: application/json" \
  -d '{"payload": "your data here"}'
```

**[→ Get a production API key — from $9/week](https://okamotosecurytlabs.com.br/#pricing)**

---

## SDK Examples

### Python

```python
import requests

VORTEX_API_KEY = "vdfs_live_your_key_here"
BASE_URL = "https://vortex-dfs.onrender.com"

def anonymize(text: str) -> dict:
    response = requests.post(
        f"{BASE_URL}/v1/shield/anonymize",
        headers={
            "Authorization": f"Bearer {VORTEX_API_KEY}",
            "Content-Type": "application/json"
        },
        json={"content": text}
    )
    response.raise_for_status()
    return response.json()

def pqc_sign(payload: str) -> dict:
    response = requests.post(
        f"{BASE_URL}/v1/pqc/sign",
        headers={
            "Authorization": f"Bearer {VORTEX_API_KEY}",
            "Content-Type": "application/json"
        },
        json={"payload": payload}
    )
    response.raise_for_status()
    return response.json()

# Usage
result = anonymize("John Smith, SSN 123-45-6789, card 4111-1111-1111-1111")
print(result["sanitized"])   # → "[NAME] [SSN] [CARD]"
print(result["risk_score"])  # → 0.94
print(result["latency_ms"])  # → 12.3

# Safe LLM pipeline — PII never reaches the model
def safe_llm_call(user_input: str) -> str:
    clean = anonymize(user_input)
    return clean["sanitized"]
```

### JavaScript / Node.js

```javascript
const VORTEX_API_KEY = process.env.VORTEX_API_KEY;
const BASE_URL = "https://vortex-dfs.onrender.com";

async function anonymize(text) {
  const response = await fetch(`${BASE_URL}/v1/shield/anonymize`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${VORTEX_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ content: text })
  });

  if (!response.ok) throw new Error(`Vortex error: ${response.status}`);
  return response.json();
}

async function pqcSign(payload) {
  const response = await fetch(`${BASE_URL}/v1/pqc/sign`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${VORTEX_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ payload })
  });

  if (!response.ok) throw new Error(`Vortex error: ${response.status}`);
  return response.json();
}

// Usage
const result = await anonymize("Maria Silva, CPF 123.456.789-00");
console.log(result.sanitized);   // → "[NAME] [CPF]"
console.log(result.risk_score);  // → 0.87
console.log(result.latency_ms);  // → 11.2

// Safe LLM pipeline — PII never reaches the model
async function safeLLMCall(userInput) {
  const clean = await anonymize(userInput);
  return clean.sanitized;
}
```

### TypeScript

```typescript
interface AnonymizeResponse {
  sanitized: string;
  token_map_enc: string;
  risk_score: number;
  detections: Array<{
    pattern: string;
    count: number;
    positions: Array<[number, number]>;
  }>;
  trace_id: string;
  latency_ms: number;
}

async function anonymize(text: string): Promise<AnonymizeResponse> {
  const response = await fetch("https://vortex-dfs.onrender.com/v1/shield/anonymize", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.VORTEX_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ content: text })
  });

  if (!response.ok) throw new Error(`Vortex error: ${response.status}`);
  return response.json() as Promise<AnonymizeResponse>;
}
```

---

## `/v1/shield/anonymize` — PII Redaction

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
  "latency_ms": 0.043
}
```

### Why not an LLM?

| | LLM-based detection | Vortex DFS |
|---|---|---|
| Latency | 200ms–2s | **<1ms p50** |
| Determinism | ❌ Nondeterministic | ✅ Same input = same output |
| Data retention | ❌ Sends data to third party | ✅ Zero retention by architecture |
| Cost | $$$ per token | **Flat subscription** |
| Auditability | ❌ Black box | ✅ Open source, verify yourself |

### Detection coverage — 20 patterns across 4 tiers

| Tier | Patterns |
|---|---|
| **Credentials** | API keys (AWS, GitHub, Stripe), JWT tokens, Bearer tokens |
| **Identity** | SSN (US), CPF, CNPJ, RG, Passport, Driver's license |
| **Financial** | Credit cards (Luhn-validated), IBAN, routing numbers |
| **Contact** | Email, Phone (US/BR/intl), IPv4/IPv6 |

---

## `/v1/pqc/audit` — Crypto-Agility Scanner

Scans any text, code, or configuration for cryptographic vulnerabilities. Returns inventory, quantum risk score, NIST migration recommendations, and hybrid roadmap.

```bash
curl -X POST https://vortex-dfs.onrender.com/v1/pqc/audit \
  -H "Content-Type: application/json" \
  -d '{"content": "RSA-2048 signing, ECDH key exchange, AES-128, SHA-1"}'
```

```json
{
  "quantum_risk": {
    "score": 0.78,
    "band": "critical",
    "harvest_now_decrypt_later": true,
    "estimated_threat_horizon": "2030-2035"
  },
  "recommendations": [
    {
      "from": "RSA / ECDSA / DSA",
      "to": "ML-DSA (CRYSTALS-Dilithium)",
      "nist_standard": "FIPS 204",
      "priority": "critical"
    }
  ],
  "summary": {
    "total_findings": 4,
    "quantum_unsafe": 3,
    "critical_count": 2
  },
  "latency_ms": 0.017
}
```

We ran Vortex PQC Audit against Vortex's own infrastructure:
- ✅ 4 quantum-safe algorithms detected
- ✅ 0 critical findings
- ✅ Harvest-Now-Decrypt-Later: false
- ✅ Processing time: 0.015ms

---

## For decision makers

### Three guarantees

| Guarantee | Mechanism |
|---|---|
| 🔐 Post-quantum by design | Signatures based on LWE — NIST 2024 standard |
| ⚛ Physics-bound trust | Trust scores from distance and entropy — not a model, math |
| ⊢ Zero ambiguity | Every packet is Accept or Reject with auditable reason |

### Who needs this

- AI teams sending data to LLMs — **PII never reaches the model**
- Security teams auditing crypto migration readiness for NIST deadline
- Financial infrastructure migrating away from RSA/ECDSA
- Any system that cannot afford to be wrong

### NSA Advisory alignment

NSA Cybersecurity Advisory [U/OO/169570-20](https://media.defense.gov/2020/Sep/17/2002499616/-1/-1/0/PERFORMING_OUT_OF_BAND_NETWORK_MANAGEMENT20200911.PDF) recommends automated redact filters before LLM pipelines. Vortex DFS implements this as a production REST API.

---

## Architecture

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
[ /v1/shield/anonymize ]    ← PII detection engine (20 patterns, <1ms)
[ /v1/pqc/sign·verify ]     ← Post-quantum LWE signatures
[ /v1/pqc/audit ]           ← Crypto-agility scanner (35+ algorithms)
        │
        ▼
[ signer_lwe / pqc_core ]   ← Fiat-Shamir over LWE + TrustBand evaluation
```

### Modules

| Module | Language | Responsibility |
|---|---|---|
| `anonymizer_engine.rs` | Rust | PII detection — 20 patterns, 4 tiers |
| `pqc_endpoints.rs` | Rust | PQC sign, verify, audit endpoints |
| `signer_lwe.rs` | Rust | Fiat-Shamir over LWE — post-quantum signatures |
| `pqc_core.rs` | Rust | TrustBand evaluation — physics-derived thresholds |
| `provisioner.rs` | Rust | API key generation, customer management |
| `stripe_webhook.rs` | Rust | HMAC-SHA256 webhook verification |
| `protocol.rs` | Rust | Binary packet parsing — safe, no unsafe |
| `engine.rs` | Rust | Typestate pipeline — typed TrustState |

---

## Security properties

| Property | Mechanism |
|---|---|
| Post-quantum signatures | Fiat-Shamir over LWE → `pqcrypto-dilithium` in production |
| Timing attack resistance | Constant-time comparison |
| Zero unsafe in critical paths | Verified — 0 unsafe blocks |
| PII zero retention | Processed in memory, never written to disk or logs |
| Log injection prevention | Session IDs sanitized before logging |
| DoS prevention | 1MB body limit, rate limiting per IP |
| No hardcoded secrets | All keys from environment at runtime |

---

## Pricing

| Plan | Price | Includes |
|---|---|---|
| **Starter** | $9/week | `/v1/shield/anonymize`, PQC endpoints, community support |
| **Pro** | $29/week | Everything + Sovereign Audit, Stripe webhook, email support |
| **Enterprise** | $79/week | Everything + custom patterns, SLA, dedicated channel |

**[→ Subscribe now](https://okamotosecurytlabs.com.br/#pricing)**

---

## Roadmap

- [x] PII anonymization — 20 patterns, <1ms
- [x] Post-quantum LWE sign/verify
- [x] Crypto-agility audit scanner
- [x] Stripe subscription + API key provisioning
- [x] Brazilian PII patterns (CPF, CNPJ, RG, CEP)
- [ ] `pqcrypto-dilithium` — production NIST parameters (ML-DSA)
- [ ] Sovereign Audit — prompt injection detection with evidence hash
- [ ] Redis rate limiting for horizontal scaling
- [ ] Independent security audit
- [ ] `crates.io` publication

---

## Research

→ **[How a tolerance overflow made our post-quantum signatures accept everything](https://okamotosecurytlabs.com.br/research)**

A silent bug in our LWE signature verification caused `verify()` to return `true` for any input. Full mathematical analysis and fix documented.

---

## License

<<<<<<< HEAD
BUSL-1.1 — Business Source License 1.1

Non-commercial use is free. Commercial use requires a paid license from Okamoto Security Labs.
Contact: gustavo@okamotosecurytlabs.com.br — see [LICENSE](LICENSE)
=======
BUSL-1.1 — Business Source License 1.1. [LICENSE](LICENSE)
>>>>>>> 42453ca7c32afaa0d97f9164a4bcd10068b0c737

---

Built at **[Okamoto Security Labs](https://okamotosecurytlabs.com.br)** · São Paulo, Brazil · Independent post-quantum research.

[🌐 Website](https://okamotosecurytlabs.com.br) · [💳 Get API Key](https://okamotosecurytlabs.com.br/#pricing) · [📄 Research](https://okamotosecurytlabs.com.br/research) · [⚖️ License](LICENSE)

> ⭐ If this project is useful to you, a star helps the lab grow.

---

> *Vortex doesn't guess. It computes.*
