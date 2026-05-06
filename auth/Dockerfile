FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables nsd \
    && rm -rf /var/lib/apt/lists/*

COPY auth /etc/nsd-config
COPY auth/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
