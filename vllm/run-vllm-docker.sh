#!/usr/bin/env bash
# Serve the FP8 model via the MODEL AUTHOR'S recommended Docker image (vllm/vllm-openai:v0.24.0).
# This pins an OLDER vLLM than the pip venv (0.27.x), which regressed a KV-cache CUDA kernel
# (reshape_and_cache_flash) that deadlocks on Blackwell sm120. The image also bundles a self-contained,
# tested CUDA/torch/flashinfer stack, sidestepping the host nvcc-12.8 / flashinfer issues.
#
# Adapted from the model card for THIS box (2x RTX PRO 4000 Blackwell, 24GB, no NVLink):
#   + --tensor-parallel-size 2   (27GB FP8 weights don't fit on one 24GB card)
#   + NCCL_P2P_DISABLE=1         (PHB-only link: NCCL P2P hangs otherwise)
#   + bind 127.0.0.1:8001        (localhost-only, same posture as Ollama; container listens on 8000)
#   + --disable-custom-all-reduce (custom all-reduce CUDA kernel errors on no-NVLink/PHB link)
#   + no --api-key               (Goose reads keys from its own store, not config.yaml -> 401; localhost-only)
#   + --max-model-len 131072     (128k default; KV pool holds ~243k tokens, so one seq fits. 262144 won't.
#                                 Override with VLLM_MAX_LEN=<n>; keep < ~243000 or a single request is rejected.)
set -euo pipefail

IMAGE="${VLLM_IMAGE:-vllm/vllm-openai:v0.24.0}"
# HF cache stores the snapshot as symlinks into a sibling blobs/ dir, so mount the WHOLE repo
# (repo root -> /model_repo) and point --model at the snapshot subpath; the relative
# ../../blobs/ symlinks then resolve inside the container.
MODEL_REPO="${VLLM_MODEL_REPO:-$HOME/.cache/huggingface/hub/models--orcarouter--Qwen3.8-27B-Uncensored-FP8}"
SNAPSHOT="${VLLM_SNAPSHOT:-21411e351948ec029617fa3c9833adcb2ad25da9}"
SERVED="${VLLM_SERVED_NAME:-qwen3.8-fp8}"
PORT="${VLLM_PORT:-8001}"
MAXLEN="${VLLM_MAX_LEN:-131072}"   # 128k default (was 32768); see header. Override via VLLM_MAX_LEN.
GPUUTIL="${VLLM_GPU_UTIL:-0.85}"   # proven-working on 2x24GB Blackwell
MAXSEQS="${VLLM_MAX_SEQS:-32}"     # plenty for a local agent; < 139 Mamba cache blocks; small graph pool

# GDN linear-attention hangs in EAGER mode on Blackwell but works via torch.compile (graph mode),
# so graph mode is the default. VLLM_EAGER=1 forces eager only for debugging.
EAGER_ARG=()
[[ "${VLLM_EAGER:-0}" == "1" ]] && EAGER_ARG=(--enforce-eager)

# MTP speculative decode (author's default) loads an extra draft model that overflows 24GB here.
# Off by default so it fits; set VLLM_SPEC=1 to re-enable once base serving is confirmed.
SPEC_ARG=()
[[ "${VLLM_SPEC:-0}" == "1" ]] && SPEC_ARG=(--speculative-config '{"method":"mtp","num_speculative_tokens":3}')

docker rm -f qh-vllm >/dev/null 2>&1 || true
# Detached (-d) so the container is independent of the launching shell; logs via `docker logs qh-vllm`.
# No --rm: keep the exited container so logs survive for inspection (start-time `docker rm -f` cleans up).
exec docker run -d --name qh-vllm \
  --gpus all --ipc=host --shm-size=8g \
  -e NCCL_P2P_DISABLE=1 \
  -e VLLM_USE_DEEP_GEMM=0 \
  -e VLLM_ATTENTION_BACKEND="${VLLM_ATTENTION_BACKEND:-TRITON_ATTN}" \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  -v "$MODEL_REPO:/model_repo:ro" \
  -v qh-vllm-cache:/root/.cache/vllm \
  -p 127.0.0.1:"$PORT":8000 \
  "$IMAGE" \
  --model "/model_repo/snapshots/$SNAPSHOT" --served-model-name "$SERVED" \
  --tensor-parallel-size 2 \
  --disable-custom-all-reduce \
  "${EAGER_ARG[@]}" \
  --language-model-only \
  "${SPEC_ARG[@]}" \
  --kv-cache-dtype fp8 \
  --gpu-memory-utilization "$GPUUTIL" \
  --max-model-len "$MAXLEN" --max-num-seqs "$MAXSEQS" \
  --max-num-batched-tokens "${VLLM_MAX_BATCHED:-4096}" \
  --compilation-config "${VLLM_COMPILE_CFG:-{\"cudagraph_mode\":\"PIECEWISE\"}}" \
  --trust-remote-code \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice --tool-call-parser qwen3_coder
