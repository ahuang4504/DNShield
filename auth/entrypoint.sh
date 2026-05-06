#!/bin/sh
set -eu

ip route replace default via "${DEFAULT_GATEWAY}"

authoritative_response_delay_ms="${AUTHORITATIVE_RESPONSE_DELAY_MS}"
if [ "${authoritative_response_delay_ms}" != "0" ]; then
    tc qdisc add dev eth0 root netem delay "${authoritative_response_delay_ms}ms"
fi

authoritative_drop_responses="${AUTHORITATIVE_DROP_RESPONSES}"
if [ "${authoritative_drop_responses}" = "1" ]; then
    iptables -I OUTPUT 1 -p udp --sport 53 -j DROP
    iptables -I OUTPUT 1 -p tcp --sport 53 -j DROP
fi

nsd_conf_path="${NSD_CONF_PATH}"

exec nsd -d -c "${nsd_conf_path}"
