from __future__ import annotations

from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from scapy.packet import Raw


def build_ipv4_udp_packet(
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    udp_payload: bytes,
):
    return bytes(
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=udp_payload)
    )
