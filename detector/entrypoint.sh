#!/bin/sh
set -eu

iptables -P FORWARD ACCEPT
iptables -I FORWARD 1 -p udp -d "${AUTHORITATIVE_IP}" --dport 53 -j NFQUEUE --queue-num 0
iptables -I FORWARD 1 -p udp --sport 53 -d "${RESOLVER_IP}" -j NFQUEUE --queue-num 0

exec uv run dnshield-detector
