FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 unbound \
    && rm -rf /var/lib/apt/lists/*

COPY resolver/unbound-weak.conf /etc/unbound/unbound.conf
COPY resolver/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
