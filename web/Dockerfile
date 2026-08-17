# Web MCP image — egress-enabled, but exposes NO shell (fetch/search only).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin web
COPY web_mcp.py /opt/web_mcp.py
USER web
WORKDIR /home/web
ENTRYPOINT ["python3", "/opt/web_mcp.py"]
