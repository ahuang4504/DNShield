FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev iptables iproute2 libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv==0.11.6

COPY pyproject.toml uv.lock .python-version /app/
COPY attacker /app/attacker
COPY client /app/client
COPY detector /app/detector
COPY scripts /app/scripts
COPY detector/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
    && uv sync --frozen --no-dev --group detector --group training

ENTRYPOINT ["/entrypoint.sh"]
