#!/bin/sh
set -eu

ip route replace default via "${DEFAULT_GATEWAY}"

exec /app/.venv/bin/dnshield-attacker
