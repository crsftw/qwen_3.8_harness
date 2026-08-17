#!/usr/bin/env bash
# Launch the policy/approval gateway (MCP server to Goose; MCP client to tool servers).
set -euo pipefail
export PYTHONUNBUFFERED=1
# Approval integration: in an interactive `goose session`, Goose provides the human approval
# UI (GOOSE_MODE=smart_approve), so the gateway defers (auto) — two interactive prompts would
# fight Goose's TUI. For UNATTENDED runs, override with GATEWAY_APPROVAL=queue for fail-closed
# HIGH gating (approve via gateway/approve.py). The gateway always tiers + audits regardless.
export GATEWAY_APPROVAL="${GATEWAY_APPROVAL:-auto_approve}"
# Self-locating: resolve the repo root from this script's location so a fresh
# clone runs without editing paths. QH_ROOT is consumed by policy.json's
# ${QH_ROOT} tool-server paths (see gateway_mcp.py).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export QH_ROOT="${QH_ROOT:-$(dirname "$HERE")}"
exec python3 "$HERE/gateway_mcp.py"
