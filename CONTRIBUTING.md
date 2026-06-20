# Contributing to Vortex DFS

Thanks for cloning. If you're here, you probably found something interesting — or something broken. Both are welcome.

---

## Ways to contribute

### 🔍 Security review
This is the most valuable contribution. Read the code, try to break it, tell us what you find.

Specifically:
- `signer_lwe.rs` — review the Fiat-Shamir implementation
- `protocol.rs` — try to craft packets that bypass CRC validation
- `vortex_guard.rs` — test the HMAC verification edge cases
- `pqc_core.rs` — verify the trust score math

Found a vulnerability? Open a private issue or email directly. Don't post it publicly first.

### 🧪 Tests
We have ~60 tests covering happy paths and adversarial inputs. What's missing:

- Fuzzing with `cargo-fuzz`
- Property-based tests with `proptest`
- Integration tests between the Rust and Go sides
- Benchmarks for the critical path latency

### 📐 Production parameters
The current `signer_lwe.rs` uses demo parameters (N=16, Q=65537). The roadmap includes replacing this with `pqcrypto-dilithium`. If you have experience with NIST PQC parameter sets, this is the highest-impact contribution.

### 📖 Documentation
- Examples for common integration patterns
- Explanation of the physics-bound trust model
- Go gateway documentation

---

## How to get started

```bash
git clone https://github.com/okamoto-security-labs/Vortex-DFS.git
cd Vortex-DFS

# Run Rust tests
cargo test

# Run Go tests
cd gateway && go test ./...
```

---

## Ground rules

- **No breaking changes without discussion** — open an issue first
- **Tests are mandatory** — every change needs a test that would have caught the bug
- **Security over performance** — if it's faster but less safe, it's wrong
- **No unsafe without justification** — and justification means a comment explaining exactly why

---

## What we're not looking for

- Dependency additions without strong justification
- Style-only changes
- AI-generated code without review

---

## Contact


linkedin.com/in/gustavo-okamoto-de-carvalho-ti

Open an issue or reach out directly via the repository.

Built at **Okamoto Security Labs**.
