FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="DockerVPNGate" \
      org.opencontainers.image.description="VPNGate-based HTTP/SOCKS5 proxy gateway" \
      org.opencontainers.image.source="https://github.com/baoweise-bot/DockerVPNGate"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VPNGATE_DATA_DIR=/var/lib/dockervpngate \
    UI_HOST=0.0.0.0 \
    LOCAL_PROXY_HOST=0.0.0.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iputils-ping \
        openvpn \
        procps \
        tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY proxy_server.py vpn_utils.py vpngate_manager.py docker-healthcheck.py ./
COPY vpngate_app ./vpngate_app
COPY web ./web

RUN mkdir -p "$VPNGATE_DATA_DIR"

VOLUME ["/var/lib/dockervpngate"]
EXPOSE 8787/tcp 7928/tcp 7929/tcp 7930/tcp 7931/tcp 7932/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "/app/docker-healthcheck.py"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "/app/vpngate_manager.py"]
