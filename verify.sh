#!/usr/bin/env bash
# VORTEX-CODEX ULTIMATE ENGINE - Pipeline Determinístico de Ingestão de Sandbox
set -euo pipefail

CODE1="payload_1.c"
CODE2="payload_2.c"
BIN1="bin_payload_1"
BIN2="bin_payload_2"
CFLAGS="-std=c11 -O3 -Wall -Wextra -Werror -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2"
SAN_FLAGS="-fsanitize=address,undefined -g"

echo "[1/4] Análise de Arquivos e Verificação de Existência..."
if [[ ! -f "$CODE1" || ! -f "$CODE2" ]]; then
    echo "ERRO CRÍTICO: Arquivos de código não encontrados no diretório de trabalho." >&2
    exit 1
fi

echo "[2/4] Compilação Estrita com Sanitizers de Memória (Red-Stage TDD)..."
gcc $CFLAGS $SAN_FLAGS "$CODE1" -o "$BIN1"
gcc $CFLAGS $SAN_FLAGS "$CODE2" -o "$BIN2"

echo "[3/4] Execução em Sandbox e Validação Dinâmica de Memória..."
./"$BIN1"
./"$BIN2"

echo "[4/4] Compilação Binária de Produção (Green-Stage).."
gcc $CFLAGS "$CODE1" -o "${BIN1}_prod"
gcc $CFLAGS "$CODE2" -o "${BIN2}_prod"

echo "SUCESSO: Códigos validados, testados contra violações de memória e prontos para implantação."