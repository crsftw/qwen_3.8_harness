# Phase 7 — Observability + the add-a-tool recipe (DONE)

## Audit viewer (`gateway/audit_view.py`)
Makes the security spine legible. Reads `gateway/state/audit.log` (JSONL).
```bash
python3 gateway/audit_view.py           # colored terminal timeline + summary
python3 gateway/audit_view.py --html    # + self-contained local HTML report (state/audit_report.html)
```
Shows every tool call: time, tier (LOW/MEDIUM/HIGH color-coded), tool, decision
(auto / ✓ approved / ✓ approved-human / ✗ denied), outcome, redacted args; footer totals calls per
tier, HIGH approvals, and denials. **The report stays local by design** — it reveals what the agent ran,
so it is never published.

## The add-a-tool recipe (why this architecture was worth it)
Adding a capability is now a fixed, ~10-minute pattern — no harness or gateway code changes:

1. **Pick isolation** by copying the closest existing container:
   - no network needed → clone `sandbox/`
   - internet egress → clone `web/` or `nettools/` (app-layer target validation)
   - isolated lab only → clone `kali/` (`--internal` net)
2. **Write a tiny MCP server** (`<cap>_mcp.py`): reuse the stdlib JSON-RPC plumbing; add each tool as a
   parameterized function (typed args, **argv arrays — never shell strings or free-form flags**,
   ANTI_PATTERNS P2). Return text.
3. **Dockerfile + run-*.sh**: minimal image, non-root, `--cap-drop=ALL`, read-only rootfs, resource
   limits, the right `--network`.
4. **Register in `gateway/policy.json`**: add the server (`cmd`) and a tier per tool.
5. **Done.** The gateway auto-discovers the tools, applies tiers/approval/audit, and Goose/Qwen sees
   them. Verify with a `tools/list` and one agent task.

## Verified (2026-08-15)
Ran against the full session history: 12 calls rendered (HIGH=6, LOW=3, MEDIUM=3; 5 HIGH approvals,
1 denial, 0 errors); HTML report generated.

## Roadmap complete
All planned phases (0–7) are built and agent-verified. Remaining *optional* hardening/extensions:
install gVisor (`docs/phase6-kali.md`) and enable `SANDBOX_RUNTIME=runsc`; add a Playwright browser MCP
if a JS site needs it (`docs/phase4-web.md`); grow the Kali toolset per the recipe above.
