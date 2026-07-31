# CLAUDE.md — Vortex DFS

Guia de onboarding para qualquer agente de IA (ou humano) trabalhando neste projeto.
Leia isto por completo antes de fazer qualquer mudança — economiza retrabalho.

---

## Visão geral

Vortex DFS é uma API de defesa determinística: redação de PII (`/v1/shield/anonymize`),
assinatura pós-quântica LWE (`/v1/pqc/sign`, `/v1/pqc/verify`), e um scanner de
agilidade criptográfica (`/v1/pqc/audit`). Backend em Rust (`actix-web`), deploy no
Render, banco Supabase, pagamento via Stripe.

**Status real (não o do marketing do README):** a criptografia PQC era uma
implementação de brinquedo com 4 vulnerabilidades críticas até a sessão de
auditoria de 01/07/2026 — ver "Histórico de incidentes" abaixo antes de mexer
em qualquer coisa relacionada a `signer_lwe.rs`.

---

## Stack

- **Linguagem:** Rust 1.75+ (edition 2021)
- **Framework HTTP:** actix-web 4.x
- **Banco:** Supabase (via `provisioner::init_db()`)
- **Pagamento:** Stripe (`stripe_webhook.rs`)
- **Deploy:** Render (free tier — hiberna com inatividade, reinicia processo)
- **CDN/proxy:** Cloudflare (por isso `X-Forwarded-For` é a fonte de IP real, não o socket)

---

## Ambientes — LEIA ISTO ANTES DE RODAR QUALQUER COMANDO

Este projeto tem **dois ambientes que NÃO se sincronizam automaticamente**:

1. **GitHub Codespaces** (`@usuario ➜ /workspaces/Vortex-DFS`) — onde o Rust
   está instalado e onde `cargo build`/`cargo test` funcionam. É aqui que o
   trabalho de verdade deve acontecer.
2. **Windows local** (`PS C:\Users\...\Vortex-DFS>`) — não tem Rust instalado
   nativamente. `cargo build` aqui falha com "não há aplicativos associados".

**Codespaces e Windows local são filesystems separados.** Editar um arquivo
localmente no Windows NÃO aparece no Codespace até você fazer `git push` de um
lado e `git pull` do outro. Não são a mesma pasta montada — isso só seria
verdade com um devcontainer local via Docker Desktop, que não é o setup atual.

**Regra prática: prefira sempre trabalhar e commitar de dentro do Codespace.**
Editar no Windows e tentar sincronizar depois já causou retrabalho significativo
(commit perdido, arquivo duplicado na raiz do repo, confusão sobre qual versão
é a "certa"). Se precisar usar o Windows, termine o ciclo completo
(`add` → `commit` → `push`) antes de trocar de ambiente.

No PowerShell, `grep` não existe — use `Select-String -Path arquivo -Pattern "regex"`.

---

## Estrutura do diretório (`backend/src/`)

| Arquivo | Responsabilidade |
|---|---|
| `main.rs` | Entrypoint HTTP, rotas, CORS, rate limiting, auth |
| `signer_lwe.rs` | Assinatura Fiat-Shamir sobre LWE (pós-quântica, toy-scale) |
| `key_store.rs` | Geração e persistência de chaves LWE — **não** derivar de string |
| `pqc_core.rs` | `PqcVector`/`TrustBand` — avaliação de confiança física |
| `pqc_endpoints.rs` | Handlers HTTP de `/v1/pqc/*` |
| `anonymizer_engine.rs` | Detecção e redação de PII (20 padrões, 4 tiers) |
| `provisioner.rs` | Geração de API key, gestão de clientes (Supabase) |
| `stripe_webhook.rs` | Verificação HMAC de webhook do Stripe |

---

## Common Hurdles (soluções já descobertas — não redescubra)

1. **`web::Data<dyn Trait>` não aceita `Data::new(ConcreteType)` com anotação de
   trait object.** `Data<T>` não ganha `CoerceUnsized` de graça. O caminho que
   compila:
   ```rust
   let arc: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
   let data: web::Data<dyn KeyStore> = web::Data::from(arc);
   ```

2. **`actix-web` moderno não compila com Rust 1.75** (dependências transitivas
   como `chacha20`/`time-core` exigem `edition2024`). Isso só afeta ambientes
   com toolchain desatualizado — o Codespace já tem uma versão compatível.
   Se aparecer erro de `edition2024`, o problema é o toolchain, não o código.

3. **Fiat-Shamir sobre LWE: o challenge PRECISA depender do commitment.**
   `challenge_hash(data)` sozinho permite forjar qualquer assinatura com só a
   chave pública. Tem que ser `challenge_hash(w, data)`. Ver changelog em
   `signer_lwe.rs` para o histórico completo (Finding #1).

4. **Tolerância de verificação LWE nunca pode ser derivada de um valor que o
   atacante/dado controla.** Precisa ser uma constante fixa em compile-time,
   com folga confortável abaixo de `Q/2`. Ver `TOLERANCE`/`CHALLENGE_BOUND`
   em `signer_lwe.rs` (Finding #2).

5. **Nonce de assinatura nunca pode vir do cliente.** Reuso de nonce (mesmo
   client-controlled) permite recuperar a chave secreta inteira por álgebra
   linear simples (mesma classe de bug que vazou a chave do PS3 em 2010).
   `sign()` não aceita mais parâmetro `nonce` — gera sempre via `OsRng`
   internamente (Finding #4).

6. **Nunca derivar chave secreta de uma string conhecível (API key, nome do
   cliente).** Se o algoritmo é determinístico e o código é open source,
   qualquer um recalcula a chave sabendo só a string. Chave tem que vir de
   `keygen_secure()` (usa `OsRng`), gerada uma vez, e persistida via
   `KeyStore` — nunca recalculada por request (Finding #3).

7. **Parâmetros de brinquedo (N=16, Q=257) têm um teto de segurança que
   nenhum tuning resolve.** Mesmo com os 4 findings corrigidos, resta um
   risco residual de forjamento por tentativa-e-erro online (~1% por
   tentativa com `CHALLENGE_BOUND=50`). Mitigação real: rate limiting
   agressivo nos endpoints PQC (**ainda pendente**, ver Roadmap) e migração
   futura para `pqcrypto-dilithium` (N≥512) em produção.

8. **`target/` não deve estar no `.gitignore`... espera, deve sim.** Foi
   commitado por engano no início do projeto (artefatos de build do Cargo
   inteiros no git). Se reaparecer em `git status`, adicionar/corrigir
   `.gitignore` antes de commitar.

---

## Design Patterns do projeto

- **`KeyStore` trait + `InMemoryKeyStore`:** abstração de armazenamento de
  chaves. A implementação em memória é só para o estágio atual (sem tráfego
  pagante) — perde tudo a cada restart/hibernação do Render. Trocar por
  persistência real (Postgres/Supabase + criptografia em repouso, idealmente
  HSM/KMS) antes de ter clientes de verdade.
- **`auth_and_rate()` combinado:** autenticação + rate limiting em uma função
  só, retornando `(is_demo: bool, resolved_key: String)`. Endpoints devem
  chamar essa função em vez de reimplementar extração de header — foi
  justamente a duplicação que deixou `/v1/pqc/*` sem rate limit por um tempo.
- **CORS manual** (sem crate `actix-cors`) — lista fixa de origins permitidos,
  função `add_cors()` envolve toda resposta.
- **Testes adversariais embutidos no próprio arquivo** (`#[cfg(test)] mod
  adversarial_core`, `mod stress_tests` dentro de `signer_lwe.rs`) — não
  ficam em `tests/` separado. Rodam junto com `cargo test` normal.

---

## Histórico de incidentes

**01/07/2026 — Auditoria adversarial encontrou 4 vulnerabilidades críticas em
`signer_lwe.rs`/`pqc_endpoints.rs`:**
- Finding #1: forjamento total de assinatura sem chave secreta (challenge não
  amarrado ao commitment)
- Finding #2: overflow de tolerância tornava a verificação vazia em ~75% dos casos
- Finding #3: chave secreta 100% derivável só sabendo a API key
- Finding #4: reuso de nonce (client-controlled) recuperava a chave secreta inteira

Todas corrigidas e travadas com 16 testes de regressão (`cargo test`). Ver
changelog no topo de `signer_lwe.rs`, `key_store.rs` e `main.rs` para detalhe
de cada fix.

---

## Checklist pós-implementação

Antes de considerar qualquer mudança "pronta":

- [ ] `cargo build` limpo (sem `error`, warnings ok mas revisar)
- [ ] `cargo test` — todos os testes passando, incluindo os de
      `signer_lwe::adversarial_core` e `signer_lwe::stress_tests`
- [ ] Commit feito **de dentro do Codespace**, não do Windows local
- [ ] `git status` revisado antes do `git add` — checar se não sobrou arquivo
      solto na raiz do repo (já aconteceu antes)
- [ ] Deploy no Render confirmado verde (aba "Events" do dashboard)
- [ ] Se a mudança tocar em `signer_lwe.rs`, `key_store.rs`, ou
      `pqc_endpoints.rs`: os 16 testes de segurança são obrigatórios,
      não opcionais

---

## Roadmap / dívida técnica conhecida

- [ ] `/v1/pqc/sign` e `/v1/pqc/verify` ainda não chamam `auth_and_rate()` —
      sem rate limit real nesses dois endpoints (`auth_and_rate()` já retorna
      a chave resolvida, pronto pra ser conectado)
- [ ] `InMemoryKeyStore` precisa virar persistência real antes de qualquer
      cliente pagante
- [ ] GitHub Actions / CI ainda não existe — testes só rodam manualmente
- [ ] Produção real de `/pqc/*` deveria migrar para `pqcrypto-dilithium`
      (N≥512) — os parâmetros atuais (N=16, Q=257) são só para demonstração


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
→ RequestContext
→ RuntimePolicy
→ RuntimeValidator
→ RuntimeDecision
→ Execution
→ Audit

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
→ Production Runtime Trust Layer.

Vortex Lab
→ Research & Engineering Laboratory.

Future commercial platform
→ Product built on top of Vortex technologies.

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


## Engineering Log — 2026-07-31

### Runtime Integration Milestone

Completed the first end-to-end integration between the Vortex DFS Runtime and the Agent SDK.

Architecture:

Application
↓
Vortex Runtime
↓
Policy Evaluation
↓
Trust Evaluation
↓
Authorization Decision
↓
Agent SDK
↓
Execution

Current implementation:

- Runtime policy evaluation
- Trust score evaluation
- Deterministic authorization
- Agent SDK execution only after runtime approval
- Offline deterministic benchmark
- Runtime audit output
- Execution audit summary

Benchmark Results

- Iterations: 1000
- Successful executions: 1000
- Failed executions: 0
- Average latency: ~24–28 µs
- Throughput: ~38k requests/sec

Current limitations

- Trust score is still deterministic.
- Runtime signals are mocked.
- Policy engine uses static thresholds.

Next milestones

- Runtime telemetry ingestion
- Dynamic trust score calculation
- Risk signals
- Runtime evidence collection
- Pluggable policy profiles
- Decision trace logging
- Policy versioning

