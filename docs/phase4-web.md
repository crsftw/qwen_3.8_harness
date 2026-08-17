# Phase 4 — Web browsing: fetch + search (lightweight) (DONE)

First phase that grants network egress. Capability-separated from the shell sandbox: this container
has network but exposes **no shell**, only two tools.

## Components (`web/`)
- **`web_mcp.py`** — stdlib MCP server. Tools:
  - `web_search(query, count?)` → self-hosted **SearXNG** JSON API at `SEARXNG_URL` (a *trusted*,
    operator-configured endpoint — no SSRF check).
  - `web_fetch(url, max_bytes?)` → fetches a *model-supplied* (untrusted) URL. **SSRF-guarded**:
    resolves DNS and refuses any private / loopback / link-local / reserved IP; follows redirects
    manually, re-validating each hop; http/https only; size + time capped; HTML → text via stdlib.
- **`Dockerfile`** — `python:3.12-slim`, non-root, no shell tool. `run-web.sh` — hardened `docker run`
  on the `qh-web` network (egress on, cap-drop, read-only, resource limits).
- **`searxng/`** — `settings.template.yml` + `run-searxng.sh` (materializes `runtime/settings.yml`
  with a freshly generated `secret_key` — never committed, ANTI_PATTERNS P1). SearXNG runs on `qh-web`,
  reachable as `qh-searxng:8080`; host-exposed only on `127.0.0.1:8888`.

## Trust boundary
`web_search` targets the operator's SearXNG (trusted) → allowed to be an internal address.
`web_fetch` targets anything the model picks (untrusted) → forced public-only. That split is the whole
security design: internal service reachable for search, but the model can never point `web_fetch` at
the LAN, the docker host, your Ollama, or cloud metadata.

## Gateway registration (`policy.json`)
`web_search` = LOW, `web_fetch` = MEDIUM (auto, logged). Exposed to the model as `web_web_search` /
`web_web_fetch` (server-prefix + tool name; cosmetic — could rename the tools to `search`/`fetch`).

## Verified (2026-08-15)
- SSRF filter blocked `169.254.169.254` (metadata), `localhost:11434` (Ollama), `192.168.1.1` (LAN)
- public fetch of `example.com` succeeded (cleaned text); `web_search` returned real SearXNG results
- **agent-driven**: Qwen searched → fetched top URL → summarized MCP citing the URL; both calls logged

## Start / stop
```bash
bash web/searxng/run-searxng.sh     # start search service (idempotent)
docker rm -f qh-searxng             # stop it
# web MCP is launched on demand by the gateway per policy.json
```

## Later (deferred by choice)
Playwright/headless-Chromium MCP for JS-heavy/interactive sites — add as another `qh-web` container +
policy entry when a real page needs it. The fetch/search layer covers most agent reading today.
