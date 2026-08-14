# CLAUDE.md â€” Vortex DFS

Guia de onboarding para qualquer agente de IA (ou humano) trabalhando neste projeto.
Leia isto por completo antes de fazer qualquer mudanÃ§a â€” economiza retrabalho.

---

## VisÃ£o geral

Vortex DFS Ã© uma API de defesa determinÃ­stica: redaÃ§Ã£o de PII (`/v1/shield/anonymize`),
assinatura pÃ³s-quÃ¢ntica LWE (`/v1/pqc/sign`, `/v1/pqc/verify`), e um scanner de
agilidade criptogrÃ¡fica (`/v1/pqc/audit`). Backend em Rust (`actix-web`), deploy no
Render, banco Supabase, pagamento via Stripe.

**Status real (nÃ£o o do marketing do README):** o fluxo de anonimizaÃ§Ã£o tem
uma fronteira determinÃ­stica funcional: `RequestContext` â†’ evidÃªncias â†’
`RuntimePolicy` â†’ `RuntimeDecision` â†’ executor protegido. O endpoint HTTP usa
`evaluate_and_execute()`, portanto um `REJECT` nÃ£o alcanÃ§a o executor. Isso Ã©
um protÃ³tipo funcional/POC, nÃ£o uma plataforma enterprise pronta: ainda nÃ£o hÃ¡
audit log persistente, identidade real no fluxo HTTP, carregamento externo de
polÃ­ticas ou adaptador de Tool Runner/Agent SDK de produÃ§Ã£o.

`signer_lwe.rs` continua uma implementaÃ§Ã£o LWE toy-scale e experimental. Ela
nÃ£o deve ser apresentada como PQC de produÃ§Ã£o; ver "HistÃ³rico de incidentes"
antes de mexer nessa Ã¡rea.

---

## Stack

- **Linguagem:** Rust 1.75+ (edition 2021)
- **Framework HTTP:** actix-web 4.x
- **Banco:** Supabase (via `provisioner::init_db()`)
- **Pagamento:** Stripe (`stripe_webhook.rs`)
- **Deploy:** Render (free tier â€” hiberna com inatividade, reinicia processo)
- **CDN/proxy:** Cloudflare (por isso `X-Forwarded-For` Ã© a fonte de IP real, nÃ£o o socket)

---

## Ambientes â€” LEIA ISTO ANTES DE RODAR QUALQUER COMANDO

Este projeto tem **dois ambientes que NÃƒO se sincronizam automaticamente**:

1. **GitHub Codespaces** (`@usuario âžœ /workspaces/Vortex-DFS`) â€” onde o Rust
   estÃ¡ instalado e onde `cargo build`/`cargo test` funcionam. Ã‰ aqui que o
   trabalho de verdade deve acontecer.
2. **Windows local** (`PS C:\Users\...\Vortex-DFS>`) â€” nÃ£o tem Rust instalado
   nativamente. `cargo build` aqui falha com "nÃ£o hÃ¡ aplicativos associados".

**Codespaces e Windows local sÃ£o filesystems separados.** Editar um arquivo
localmente no Windows NÃƒO aparece no Codespace atÃ© vocÃª fazer `git push` de um
lado e `git pull` do outro. NÃ£o sÃ£o a mesma pasta montada â€” isso sÃ³ seria
verdade com um devcontainer local via Docker Desktop, que nÃ£o Ã© o setup atual.

**Regra prÃ¡tica: prefira sempre trabalhar e commitar de dentro do Codespace.**
Editar no Windows e tentar sincronizar depois jÃ¡ causou retrabalho significativo
(commit perdido, arquivo duplicado na raiz do repo, confusÃ£o sobre qual versÃ£o
Ã© a "certa"). Se precisar usar o Windows, termine o ciclo completo
(`add` â†’ `commit` â†’ `push`) antes de trocar de ambiente.

No PowerShell, `grep` nÃ£o existe â€” use `Select-String -Path arquivo -Pattern "regex"`.

---

## Estrutura do diretÃ³rio (`backend/src/`)

| Arquivo | Responsabilidade |
|---|---|
| `main.rs` | Entrypoint HTTP, rotas, CORS, rate limiting, auth |
| `signer_lwe.rs` | Assinatura Fiat-Shamir sobre LWE (pÃ³s-quÃ¢ntica, toy-scale) |
| `key_store.rs` | GeraÃ§Ã£o e persistÃªncia de chaves LWE â€” **nÃ£o** derivar de string |
| `pqc_core.rs` | `PqcVector`/`TrustBand` â€” avaliaÃ§Ã£o de confianÃ§a fÃ­sica |
| `pqc_endpoints.rs` | Handlers HTTP de `/v1/pqc/*` |
| `anonymizer_engine.rs` | DetecÃ§Ã£o e redaÃ§Ã£o de PII (20 padrÃµes, 4 tiers) |
| `provisioner.rs` | GeraÃ§Ã£o de API key, gestÃ£o de clientes (Supabase) |
| `stripe_webhook.rs` | VerificaÃ§Ã£o HMAC de webhook do Stripe |
| `runtime/engine.rs` | AvaliaÃ§Ã£o determinÃ­stica e gate estrutural de executor (`evaluate_and_execute`) |

---

## Common Hurdles (soluÃ§Ãµes jÃ¡ descobertas â€” nÃ£o redescubra)

1. **`web::Data<dyn Trait>` nÃ£o aceita `Data::new(ConcreteType)` com anotaÃ§Ã£o de
   trait object.** `Data<T>` nÃ£o ganha `CoerceUnsized` de graÃ§a. O caminho que
   compila:
   ```rust
   let arc: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
   let data: web::Data<dyn KeyStore> = web::Data::from(arc);
   ```

2. **`actix-web` moderno nÃ£o compila com Rust 1.75** (dependÃªncias transitivas
   como `chacha20`/`time-core` exigem `edition2024`). Isso sÃ³ afeta ambientes
   com toolchain desatualizado â€” o Codespace jÃ¡ tem uma versÃ£o compatÃ­vel.
   Se aparecer erro de `edition2024`, o problema Ã© o toolchain, nÃ£o o cÃ³digo.

3. **Fiat-Shamir sobre LWE: o challenge PRECISA depender do commitment.**
   `challenge_hash(data)` sozinho permite forjar qualquer assinatura com sÃ³ a
   chave pÃºblica. Tem que ser `challenge_hash(w, data)`. Ver changelog em
   `signer_lwe.rs` para o histÃ³rico completo (Finding #1).

4. **TolerÃ¢ncia de verificaÃ§Ã£o LWE nunca pode ser derivada de um valor que o
   atacante/dado controla.** Precisa ser uma constante fixa em compile-time,
   com folga confortÃ¡vel abaixo de `Q/2`. Ver `TOLERANCE`/`CHALLENGE_BOUND`
   em `signer_lwe.rs` (Finding #2).

5. **Nonce de assinatura nunca pode vir do cliente.** Reuso de nonce (mesmo
   client-controlled) permite recuperar a chave secreta inteira por Ã¡lgebra
   linear simples (mesma classe de bug que vazou a chave do PS3 em 2010).
   `sign()` nÃ£o aceita mais parÃ¢metro `nonce` â€” gera sempre via `OsRng`
   internamente (Finding #4).

6. **Nunca derivar chave secreta de uma string conhecÃ­vel (API key, nome do
   cliente).** Se o algoritmo Ã© determinÃ­stico e o cÃ³digo Ã© open source,
   qualquer um recalcula a chave sabendo sÃ³ a string. Chave tem que vir de
   `keygen_secure()` (usa `OsRng`), gerada uma vez, e persistida via
   `KeyStore` â€” nunca recalculada por request (Finding #3).

7. **ParÃ¢metros de brinquedo (N=16, Q=257) tÃªm um teto de seguranÃ§a que
   nenhum tuning resolve.** Mesmo com os 4 findings corrigidos, resta um
   risco residual de forjamento por tentativa-e-erro online (~1% por
   tentativa com `CHALLENGE_BOUND=50`). MitigaÃ§Ã£o real: rate limiting
   agressivo nos endpoints PQC (**ainda pendente**, ver Roadmap) e migraÃ§Ã£o
   futura para `pqcrypto-dilithium` (Nâ‰¥512) em produÃ§Ã£o.

8. **`target/` nÃ£o deve estar no `.gitignore`... espera, deve sim.** Foi
   commitado por engano no inÃ­cio do projeto (artefatos de build do Cargo
   inteiros no git). Se reaparecer em `git status`, adicionar/corrigir
   `.gitignore` antes de commitar.

---

## Design Patterns do projeto

- **`KeyStore` trait + `InMemoryKeyStore`:** abstraÃ§Ã£o de armazenamento de
  chaves. A implementaÃ§Ã£o em memÃ³ria Ã© sÃ³ para o estÃ¡gio atual (sem trÃ¡fego
  pagante) â€” perde tudo a cada restart/hibernaÃ§Ã£o do Render. Trocar por
  persistÃªncia real (Postgres/Supabase + criptografia em repouso, idealmente
  HSM/KMS) antes de ter clientes de verdade.
- **`auth_and_rate()` combinado:** autenticaÃ§Ã£o + rate limiting em uma funÃ§Ã£o
  sÃ³, retornando `(is_demo: bool, resolved_key: String)`. Endpoints devem
  chamar essa funÃ§Ã£o em vez de reimplementar extraÃ§Ã£o de header â€” foi
  justamente a duplicaÃ§Ã£o que deixou `/v1/pqc/*` sem rate limit por um tempo.
- **CORS manual** (sem crate `actix-cors`) â€” lista fixa de origins permitidos,
  funÃ§Ã£o `add_cors()` envolve toda resposta.
- **Testes adversariais embutidos no prÃ³prio arquivo** (`#[cfg(test)] mod
  adversarial_core`, `mod stress_tests` dentro de `signer_lwe.rs`) â€” nÃ£o
  ficam em `tests/` separado. Rodam junto com `cargo test` normal.

---

## HistÃ³rico de incidentes

**01/07/2026 â€” Auditoria adversarial encontrou 4 vulnerabilidades crÃ­ticas em
`signer_lwe.rs`/`pqc_endpoints.rs`:**
- Finding #1: forjamento total de assinatura sem chave secreta (challenge nÃ£o
  amarrado ao commitment)
- Finding #2: overflow de tolerÃ¢ncia tornava a verificaÃ§Ã£o vazia em ~75% dos casos
- Finding #3: chave secreta 100% derivÃ¡vel sÃ³ sabendo a API key
- Finding #4: reuso de nonce (client-controlled) recuperava a chave secreta inteira

Todas corrigidas e travadas com 16 testes de regressÃ£o (`cargo test`). Ver
changelog no topo de `signer_lwe.rs`, `key_store.rs` e `main.rs` para detalhe
de cada fix.

---

## Checklist pÃ³s-implementaÃ§Ã£o

Antes de considerar qualquer mudanÃ§a "pronta":

- [ ] `cargo build` limpo (sem `error`, warnings ok mas revisar)
- [ ] `cargo test` â€” todos os testes passando, incluindo os de
      `signer_lwe::adversarial_core` e `signer_lwe::stress_tests`
- [ ] Commit feito **de dentro do Codespace**, nÃ£o do Windows local
- [ ] `git status` revisado antes do `git add` â€” checar se nÃ£o sobrou arquivo
      solto na raiz do repo (jÃ¡ aconteceu antes)
- [ ] Deploy no Render confirmado verde (aba "Events" do dashboard)
- [ ] Se a mudanÃ§a tocar em `signer_lwe.rs`, `key_store.rs`, ou
      `pqc_endpoints.rs`: os 16 testes de seguranÃ§a sÃ£o obrigatÃ³rios,
      nÃ£o opcionais

---

## Roadmap / dÃ­vida tÃ©cnica conhecida

- [ ] `/v1/pqc/sign` e `/v1/pqc/verify` ainda nÃ£o chamam `auth_and_rate()` â€”
      sem rate limit real nesses dois endpoints (`auth_and_rate()` jÃ¡ retorna
      a chave resolvida, pronto pra ser conectado)
- [ ] `InMemoryKeyStore` precisa virar persistÃªncia real antes de qualquer
      cliente pagante
- [ ] CI deve continuar verde; confirme o workflow em `.github/workflows/ci.yml`
- [ ] ProduÃ§Ã£o real de `/pqc/*` deveria migrar para `pqcrypto-dilithium`
      (Nâ‰¥512) â€” os parÃ¢metros atuais (N=16, Q=257) sÃ£o sÃ³ para demonstraÃ§Ã£o


---

# Engineering Journal

---

## 2026-07-28

### Runtime Architecture Refactor (Phase 1)

Status: In Progress

#### Goal

Transform the Vortex backend from endpoint-driven execution into a deterministic runtime architecture.

Target pipeline:

Request
â†’ RequestContext
â†’ RuntimePolicy
â†’ RuntimeValidator
â†’ RuntimeDecision
â†’ Execution
â†’ Audit

#### New Runtime Modules

backend/src/runtime/

- operation.rs
- trust.rs
- context.rs
- evidence.rs
- decision.rs
- policy.rs
- validator.rs

#### Architectural Decisions

- Runtime components are intentionally small and single-purpose.
- Replace monolithic runtime implementation with modular architecture.
- Introduce versioned RuntimePolicy.
- Introduce RequestContext as the normalized request model.
- Introduce SecurityEvidence as the single source of evaluated signals.
- Introduce RuntimeValidator for deterministic policy validation.
- Introduce RuntimeDecision with stable machine-readable reason codes.
- Prefer deterministic collections (BTreeMap/BTreeSet) where ordering matters.
- Runtime remains independent from HTTP handlers until full integration.

#### Documentation Added

docs/ARCHITECTURE.md

docs/RUNTIME.md

#### Current Status

Implemented:

- Runtime architecture
- Operation model
- Trust model
- Context model
- Evidence model
- Decision model
- Policy model
- Validator

Pending:

- Executor
- Audit
- Decision Engine
- Handler integration
- End-to-end runtime flow

#### CI

Current work focuses on restoring a fully green CI while maintaining strict Clippy compliance.

---
## 2026-07-28

### Runtime Engineering

Completed:

- Runtime refactor finalized.
- CI fully green.
- Clippy warnings resolved.
- Runtime validation order documented.
- Deterministic validation tests expanded.
- CodeRabbit configuration finalized.
- CodeRabbit path instructions added.
- CodeRabbit successfully generated runtime unit tests.
- Engineering governance introduced.
- REVIEW_POLICY.md created.
- QUALITY_GATES.md created.
- ADR structure established.

Lessons learned:

- AI review tools require project-specific guidance.
- Stable reason codes are architectural contracts.
- Validation order must be treated as a runtime invariant.
- Documentation is part of the runtime architecture.

Status:

Runtime: Stable

CI: Green

CodeRabbit: Operational

Engineering Governance: Active


----

# Engineering Journal

## Session
**Date:** 2026-07-29
**Start:** 00:00
**End:** 00:25
**Duration:** ~25 minutes

---

## Objective

Continue the documentation refactor and redefine the architectural positioning of the Vortex ecosystem.

---

## Completed

### README (Vortex DFS)

- Rewrote the README structure from scratch.
- Introduced an engineering manifesto instead of a feature-first introduction.
- Defined the central thesis of the project.
- Repositioned Vortex as a **Deterministic Runtime Trust Layer**.
- Added "Why Vortex Exists".
- Added "What is Vortex?".
- Added "Where Vortex Fits".
- Added Runtime Placement.
- Added Runtime Architecture.
- Added Runtime Decision Model.
- Added Runtime Flow.
- Added Engineering Philosophy.
- Added Engineering section.
- Added Governance.
- Added Quality Gates.
- Added Testing Philosophy.
- Added Closing Manifesto.

---

### README (Vortex Lab)

Completely redefined the repository identity.

Previous positioning:

- Performance-focused
- Hardware optimization
- Zero-overhead telemetry

New positioning:

- Research & Engineering Laboratory
- Research before Production
- Engineering before Products

Added:

- Mission
- Research Areas
- Engineering Philosophy
- Current Research
- Benchmarking
- Relationship to Vortex DFS
- Guiding Principles
- Vision
- Closing Thoughts

---

## Architectural Decisions

### AD-001

Vortex is **not** a SIEM.

Vortex is **not** an EDR.

Vortex is **not** a SOAR.

Vortex is a deterministic runtime trust layer positioned between autonomous reasoning and execution.

---

### AD-002

The README should communicate an engineering thesis rather than advertise features.

Documentation now explains:

- Why the problem exists.
- Why Vortex exists.
- How deterministic trust is engineered.

---

### AD-003

The Vortex ecosystem responsibilities are now clearly separated.

Vortex DFS
â†’ Production Runtime Trust Layer.

Vortex Lab
â†’ Research & Engineering Laboratory.

Future commercial platform
â†’ Product built on top of Vortex technologies.

---

## Key Messages Defined

The project now consistently communicates:

> Automation without trust is simply faster uncertainty.

> Trust must be engineered.

> Confidence is not a feature. It is an engineering outcome.

> Vortex doesn't guess. It computes.

---

## Lessons Learned

People naturally attempt to classify Vortex as:

- SIEM
- EDR
- SOAR

The documentation now explicitly explains where Vortex fits within the security ecosystem.

Clear positioning is as important as implementation.

---

## Next Session

- Finish README remaining sections.
- Review repository structure.
- Standardize terminology across repositories.
- Review GitHub profile README.
- Continue Release 1.0 documentation.

---

## Session Outcome

This session did not primarily produce new code.

It produced a clearer engineering identity for the Vortex ecosystem.

The project evolved from being described by **what it does** to being described by **why it exists**.

---

## Engineering Log â€” 2026-07-31

### Vortex DFS + Agent SDK Runtime Integration

Completed the first working end-to-end integration between the Vortex DFS Runtime and the Agent SDK.

### Architecture

Application  
â†“  
Vortex DFS Runtime  
â†“  
Policy Evaluation  
â†“  
Trust Boundary Evaluation  
â†“  
Authorization Decision  
â†“  
Agent SDK  
â†“  
Execution  

### Current Implementation

- Vortex evaluates the request before Agent SDK execution.
- Explicit authorization decisions:
  - APPROVED
  - REVIEW REQUIRED
  - BLOCKED
- Agent SDK execution occurs only after Vortex approval.
- Offline deterministic provider used for integration testing.
- In-memory event store validated.
- Runtime decision latency measured.
- End-to-end audit summary produced.

### Latest Benchmark

- SDK version: 0.16.0
- Iterations: 1,000
- Successful executions: 1,000
- Failed executions: 0
- Average Agent SDK latency: approximately 24â€“28 microseconds
- P99 latency: approximately 42â€“57 microseconds
- Throughput: approximately 33,000â€“39,000 requests per second
- Runtime authorization overhead: sub-microsecond in the local test

### Important Limitation

The current trust score is a controlled deterministic input.

It is not yet calculated from live telemetry or production security signals.

### Next Milestones

- Dynamic trust score calculation 
- Runtime telemetry ingestion
- Tool permission validation
- Multiple policy profiles
- Decision evidence collection
- Agent tool execution tests
- Concurrent agent benchmarks
- Persistent event storage
- Real provider integration

### Session Outcome

The Agent SDK provides execution capability.

Vortex DFS now provides an explicit authorization boundary before that execution.

The current milestone proves the architecture and runtime flow, not production readiness.

---

## Engineering Log â€” 2026-08-12 to 2026-08-13

### Runtime consolidation and anonymization enforcement

Completed:

- Consolidated the canonical runtime entry point in `runtime::engine`.
- Integrated the anonymization HTTP path with `RequestContext`, evidence
  collection, `RuntimePolicy`, and deterministic runtime evaluation.
- Empty anonymization input deterministically returns `REJECT` before the
  anonymizer is called.
- Sensitive content returns `REDACT` and proceeds to the anonymizer only after
  the runtime permits execution.
- Added `GuardedExecution<T>` and `evaluate_and_execute()`. This makes the
  verification boundary structural: `REJECT` returns `Blocked` and cannot
  invoke the supplied executor closure.
- Added regression tests for both invariants: rejected requests do not execute;
  redaction decisions do execute.

Validated in the Codespace:

- Backend library: 83 tests passed, 0 failed.
- HTTP handler tests: 3 passed, 0 failed.
- `vortex-ebpf` built successfully in both development and release profiles
  after installing the required nightly toolchain and `bpf-linker`.

### eBPF/XDP boundary: scope clarified

- The experimental XDP component is a narrow early network enforcement point,
  not an agent authorization engine and not a complete runtime-security claim.
- Do not claim fixed sub-microsecond latency, zero overhead, or zero-copy
  security without a reproducible benchmark on the target NIC, driver, kernel,
  packet shape, and policy.
- Keep any XDP port-policy change in its own PR; do not mix kernel/toolchain
  work with the runtime execution gate.

### Current delivery state

- Runtime execution gate: implemented and tested locally in branch
  `feat/runtime-tool-execution-gate`.
- Before opening/merging its PR: keep the diff limited to
  `backend/src/runtime/engine.rs`, `backend/src/runtime/mod.rs`, and
  `backend/src/main.rs`; run `git diff --check` and the full backend test suite.
- Persistent audit, production identity/signature enforcement, external policy
  loading, and a real Tool Runner/Agent SDK remain future work.

## Runtime Update (2026-08-13 to 2026-08-14)

Implemented a protected userspace runtime slice:
HTTP Bearer authentication -> IdentityContext/scopes -> RequestContext/evidence -> RuntimePolicy/RuntimeValidator -> RuntimeDecision -> safe audit persistence -> protected executor.

- REJECT never invokes the executor; REDACT executes the sanitized path.
- evaluate_audit_and_execute persists the decision before permitted execution. Audit failure blocks execution and returns HTTP 503.
- RuntimeAuditEvent excludes raw payloads, identity fields, API keys and unrestricted evidence signals.
- Added InMemory and PostgreSQL audit stores plus trace-id lookup.
- API keys are represented as HMAC proofs in runtime state; production clients use VORTEX_API_CLIENTS_JSON.
- anonymize:execute protects anonymization; audit:read protects GET /runtime/audit/{trace_id}.
- HTTP behavior: missing/invalid Bearer=401, missing scope=403, invalid trace UUID=400, missing events=404, audit failure=503.
- Run before PR: cargo fmt --check, cargo clippy -- -D warnings, cargo test, git diff --check.

Limitations: experimental/pre-alpha; toy LWE is not production PQC; eBPF is experimental and not integrated end-to-end; no production Tool Runner/Agent SDK or external policy administration yet.

