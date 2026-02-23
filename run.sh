#!/usr/bin/env bash
set -euo pipefail

# Always run relative to the script location (repo root).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RTL_DIR="$ROOT_DIR/rtl"
TB_DIR="$ROOT_DIR/tb"
SCRIPTS_DIR="$ROOT_DIR/scripts"

VECTORS_FILE="$ROOT_DIR/vectors.txt"
SIM_OUT="$ROOT_DIR/sim.out"

NUM_VECTORS="${1:-50}"   # default 50 if not provided

echo "[1/3] Generating OpenSSL reference vectors: ${NUM_VECTORS} -> ${VECTORS_FILE}"
python3 "$SCRIPTS_DIR/gen_vectors.py" "$NUM_VECTORS" "$VECTORS_FILE"

echo "[2/3] Compiling RTL + TB with iverilog"
iverilog -g2012 -Wall -o "$SIM_OUT" \
  "$RTL_DIR/aes_top.v" \
  "$RTL_DIR/aes_core.v" \
  "$RTL_DIR/aes_key_expand_128.v" \
  "$RTL_DIR/aes_round.v" \
  "$RTL_DIR/aes_sbox.v" \
  "$TB_DIR/tb_aes128.sv"

echo "[3/3] Running simulation"
# Run from ROOT so tb can open "vectors.txt" with a relative path.
( cd "$ROOT_DIR" && vvp "$SIM_OUT" )

echo "[DONE]"
