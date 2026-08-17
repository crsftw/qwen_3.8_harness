#!/usr/bin/env bash
# Serve the FP8 uncensored model via vLLM (OpenAI-compatible /v1) for on-demand use.
# Backend #2 alongside Ollama. Goose points at whichever is active (see switch-model.sh).
#
# Hardware: 2x RTX PRO 4000 Blackwell (24GB each, sm_120, native FP8) -> tensor-parallel=2.
# Bind is LOCALHOST-ONLY (127.0.0.1): the model endpoint is not exposed to the LAN, same
# posture as Ollama. Containment of TOOLS is still the gateway; this only serves tokens.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VENV="$HERE/venv"
MODEL="${VLLM_MODEL:-orcarouter/Qwen3.8-27B-Uncensored-FP8}"
SERVED="${VLLM_SERVED_NAME:-qwen3.8-fp8}"
PORT="${VLLM_PORT:-8001}"
MAXLEN="${VLLM_MAX_LEN:-32768}"          # KV-cache budget; raise if VRAM allows
GPUUTIL="${VLLM_GPU_UTIL:-0.90}"
TP="${VLLM_TP:-2}"                         # tensor-parallel across both GPUs

if [[ ! -x "$VENV/bin/vllm" ]]; then
  echo "vLLM not installed. Run: bash $HERE/install-vllm.sh" >&2
  exit 1
fi

# The two GPUs are linked only via PHB (PCIe host bridge, no NVLink). GPU-to-GPU P2P DMA
# across the host bridge is not reliably supported here and makes NCCL's first tensor-parallel
# collective hang forever. Force NCCL to route through host shared memory instead.
export NCCL_P2P_DISABLE=1
export NCCL_DEBUG="${NCCL_DEBUG:-WARN}"

# vLLM auto-selects the FlashInfer attention backend on Blackwell, but FlashInfer's device-
# capability probe fails here ("SM 12.x requires CUDA >= 12.9") and wrongly aborts with
# "requires sm75 or higher". Core CUDA is fine (torch reads sm120 correctly and loads weights),
# so use the Triton attention backend, which JIT-compiles for sm120 and reads capability via torch.
export VLLM_ATTENTION_BACKEND="${VLLM_ATTENTION_BACKEND:-TRITON_ATTN}"

# FlashInfer's JIT reads `nvcc --version` (system nvcc is 12.8) to detect arch; SM 12.0 needs
# CUDA >= 12.9, so detection fails, its arch list empties, and it aborts ("requires sm75+").
# This dense model needs no FlashInfer path once attention is Triton — disable its sampler so
# vLLM uses native torch top-k/top-p sampling. The arch-list env is a belt-and-suspenders so any
# incidental FlashInfer arch check passes instead of crashing.
export VLLM_USE_FLASHINFER_SAMPLER=0
export FLASHINFER_CUDA_ARCH_LIST="${FLASHINFER_CUDA_ARCH_LIST:-12.0f}"

# Optional: bypass torch.compile + CUDA-graph capture (and their post-capture warmup) by setting
# VLLM_EAGER=1. Slower decode, but avoids the graph/warmup path if it hangs on this hardware.
EAGER_ARG=()
[[ "${VLLM_EAGER:-0}" == "1" ]] && EAGER_ARG=(--enforce-eager)

# Optional KV-cache dtype override. The default reshape_and_cache_flash kernel path deadlocks on
# sm120; FP8 KV cache exercises a different kernel that may work on Blackwell. VLLM_KV_DTYPE=fp8 to try.
KV_ARG=()
[[ -n "${VLLM_KV_DTYPE:-}" ]] && KV_ARG=(--kv-cache-dtype "$VLLM_KV_DTYPE")

# vLLM's OpenAI server ignores auth unless --api-key is set; we set a local dummy so Goose
# (which requires a non-empty OPENAI_API_KEY) has a matching token. Not a secret.
exec "$VENV/bin/vllm" serve "$MODEL" \
  --served-model-name "$SERVED" \
  --tensor-parallel-size "$TP" \
  --max-model-len "$MAXLEN" \
  --max-num-seqs "${VLLM_MAX_SEQS:-128}" \
  --gpu-memory-utilization "$GPUUTIL" \
  "${EAGER_ARG[@]}" \
  "${KV_ARG[@]}" \
  --host 127.0.0.1 \
  --port "$PORT" \
  --api-key qh-local-dummy \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_xml \
  --reasoning-parser qwen3
