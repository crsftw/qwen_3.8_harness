# Network/recon tools image — unprivileged tools only (no NET_RAW needed).
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 dnsutils whois iputils-tracepath openssl netcat-openbsd ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin net
COPY net_mcp.py /opt/net_mcp.py
USER net
WORKDIR /home/net
ENTRYPOINT ["python3", "/opt/net_mcp.py"]
