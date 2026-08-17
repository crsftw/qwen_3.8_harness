#!/usr/bin/env bash
# One-time: create an isolated venv and install vLLM (Blackwell/cu128). Kept in its own venv
# so it never clobbers the system torch (2.11+cu128) the rest of the box uses.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/venv"

python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel
# vLLM pulls its own matching torch build for CUDA 12.8 / sm_120 (Blackwell).
"$VENV/bin/pip" install "vllm"
"$VENV/bin/vllm" --version
echo "vLLM installed in $VENV"
