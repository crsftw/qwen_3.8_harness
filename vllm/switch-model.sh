#!/usr/bin/env bash
# Switch the Goose backend between the always-on Ollama Q4 model and the on-demand vLLM FP8 model.
#
#   switch-model.sh ollama   -> point Goose at Ollama (qwen3.8:27b);   stops vLLM to free VRAM
#   switch-model.sh fp8      -> start vLLM (FP8, on-demand) + point Goose at it
#   switch-model.sh status   -> show which backend is active + vLLM health
#
# The tool stack (gateway/MCP/sandbox/approval) is model-agnostic and untouched by this.
# Start a NEW goose session after switching — the provider binds at session start.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="$HOME/.config/goose/config.yaml"
PORT="${VLLM_PORT:-8001}"
SERVED="${VLLM_SERVED_NAME:-qwen3.8-fp8}"

set_provider() {  # $1 = ollama | openai
  python3 - "$CFG" "$1" "$PORT" "$SERVED" <<'PY'
import sys, yaml
cfg_path, which, port, served = sys.argv[1:5]
with open(cfg_path) as f: c = yaml.safe_load(f) or {}
c.setdefault("providers", {})
if which == "ollama":
    c["providers"].setdefault("ollama", {}).update({"enabled": True, "model": "qwen3.8:27b", "configured": True})
    c["active_provider"] = "ollama"
    c["OLLAMA_HOST"] = "localhost:11434"
else:  # openai-compatible vLLM
    c["providers"].setdefault("openai", {}).update({"enabled": True, "model": served, "configured": True})
    c["active_provider"] = "openai"
    c["OPENAI_HOST"] = f"http://127.0.0.1:{port}"
    c["OPENAI_API_KEY"] = "qh-local-dummy"
with open(cfg_path, "w") as f: yaml.safe_dump(c, f, sort_keys=False, default_flow_style=False)
print(f"Goose active_provider -> {c['active_provider']} (model {c['providers'][which if which=='ollama' else 'openai']['model']})")
PY
}

case "${1:-}" in
  ollama)
    bash "$HERE/serve-docker.sh" stop || true
    set_provider ollama
    echo "Now on Ollama. Start a fresh goose session."
    ;;
  fp8)
    # Free VRAM: the FP8 model + Ollama's Q4 can't both fit in 48GB. Unload Ollama's model
    # (the server stays up; the model reloads on demand when you switch back).
    ollama stop qwen3.8:27b 2>/dev/null || true
    bash "$HERE/serve-docker.sh" start
    set_provider openai
    echo "Now on vLLM FP8. Start a fresh goose session (and END any Ollama-backed one — it"
    echo "would reload the Q4 model and contend for VRAM)."
    ;;
  status)
    ap="$(python3 -c "import yaml;print((yaml.safe_load(open('$CFG')) or {}).get('active_provider','?'))")"
    echo "Goose active_provider: $ap"
    bash "$HERE/serve-docker.sh" status
    ;;
  *) echo "usage: $0 {ollama|fp8|status}" >&2; exit 2 ;;
esac
