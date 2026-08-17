# Hardened sandbox image for qwen_harness.
# Minimal userland + python3 + bash. No secrets baked in (ANTI_PATTERNS P1).
FROM debian:stable-slim

# Common CLI utilities the agent will reach for, plus tools we use to PROVE
# isolation in verification (curl/ping must FAIL when run with --network=none).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 bash coreutils findutils grep sed gawk procps \
        curl iputils-ping dnsutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user; /work is where the (only) writable mount lands at runtime.
RUN useradd --uid 1000 --create-home --shell /bin/bash sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY sandbox_mcp.py /opt/sandbox_mcp.py

USER sandbox
WORKDIR /work
ENTRYPOINT ["python3", "/opt/sandbox_mcp.py"]
