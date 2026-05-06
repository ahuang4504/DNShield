#!/bin/sh
set -eu

ip route replace default via "${DEFAULT_GATEWAY}"

exec uv run dnshield-client
