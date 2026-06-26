#!/bin/bash
set -e

echo "🔧 Configurando ambiente Vortex DFS..."

# ── Rust ──────────────────────────────────────────────
echo "📦 Atualizando toolchain Rust..."
rustup update stable
rustup component add clippy rustfmt rust-src

# Cache de dependências Rust
if [ -f "Cargo.toml" ]; then
  echo "📦 Baixando dependências Rust..."
  cargo fetch
fi

# ── Go ────────────────────────────────────────────────
echo "📦 Configurando Go..."
go install golang.org/x/tools/cmd/goimports@latest

if [ -f "go.mod" ]; then
  echo "📦 Baixando dependências Go..."
  go mod download
fi

# ── Ferramentas de segurança ──────────────────────────
echo "🔐 Instalando ferramentas de análise..."
cargo install cargo-audit --quiet 2>/dev/null || true
cargo install cargo-deny  --quiet 2>/dev/null || true

# ── HMAC key de dev (nunca usar em produção) ─────────
if [ -z "$VORTEX_HMAC_KEY" ]; then
  export VORTEX_HMAC_KEY=$(openssl rand -hex 32)
  echo "export VORTEX_HMAC_KEY=\"$VORTEX_HMAC_KEY\"" >> ~/.bashrc
  echo "⚠️  VORTEX_HMAC_KEY gerada automaticamente (só para dev local)"
fi

echo ""
echo "✅ Ambiente pronto!"
echo ""
echo "Comandos úteis:"
echo "  cargo build          → compilar"
echo "  cargo test           → testes Rust"
echo "  cargo clippy         → linter"
echo "  go test ./...        → testes Go"
echo "  cargo audit          → verificar vulnerabilidades"
