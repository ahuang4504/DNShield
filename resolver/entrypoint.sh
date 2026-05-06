#!/bin/sh
set -eu

ip route replace default via "${DEFAULT_GATEWAY}"

exec unbound -d -c /etc/unbound/unbound.conf
