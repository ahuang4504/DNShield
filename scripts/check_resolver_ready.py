from __future__ import annotations

import argparse
import json
import socket
import struct

from attacker.attack_utils import build_dns_query


def skip_qname(message: bytes, offset: int):
    while True:
        label_length = message[offset]
        if label_length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if label_length == 0:
            return offset
        offset += label_length


def query_first_ipv4_answer(
    *,
    resolver_ip: str,
    query_name: str,
    timeout_seconds: float,
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_seconds)
    sock.sendto(build_dns_query(0x4444, query_name), (resolver_ip, 53))
    answer_ip = None

    try:
        response, _ = sock.recvfrom(4096)
        answer_count = struct.unpack("!H", response[6:8])[0]
        offset = skip_qname(response, 12) + 4
        for _ in range(answer_count):
            offset = skip_qname(response, offset)
            rr_type, rr_class, _, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
            offset += 10
            rdata = response[offset : offset + rdlength]
            offset += rdlength
            if rr_type == 1 and rr_class == 1 and rdlength == 4:
                answer_ip = socket.inet_ntoa(rdata)
                break
    finally:
        sock.close()

    return answer_ip


def main():
    parser = argparse.ArgumentParser(description="Check whether the DNS resolver is ready")
    parser.add_argument("--resolver-ip", default="172.29.0.10")
    parser.add_argument("--query-name", default="ns1.lab.dnshield")
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    args = parser.parse_args()

    answer_ip = query_first_ipv4_answer(
        resolver_ip=args.resolver_ip,
        query_name=args.query_name,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps({"answer_ip": answer_ip}))


if __name__ == "__main__":
    main()
