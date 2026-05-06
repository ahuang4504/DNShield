from __future__ import annotations

import struct


IPPROTO_UDP = 17
TC_FLAG = 0x0200


def checksum(data: bytes):
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def build_ipv4_udp_packet(
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    udp_payload: bytes,
):
    udp_length = 8 + len(udp_payload)

    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    pseudo_header = src_ip + dst_ip + b"\x00" + bytes([IPPROTO_UDP]) + struct.pack("!H", udp_length)
    udp_checksum = checksum(pseudo_header + udp_header + udp_payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        IPPROTO_UDP,
        0,
        src_ip,
        dst_ip,
    )
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        IPPROTO_UDP,
        ip_checksum,
        src_ip,
        dst_ip,
    )

    return ip_header + udp_header + udp_payload


def build_truncated_response(
    payload: bytes,
    udp_offset: int,
    dns_offset: int,
    question_end: int,
):
    src_ip = payload[12:16]
    dst_ip = payload[16:20]
    src_port, dst_port, _, _ = struct.unpack("!HHHH", payload[udp_offset : udp_offset + 8])
    txid, original_flags, question_count = struct.unpack("!HHH", payload[dns_offset : dns_offset + 6])
    questions = payload[dns_offset + 12 : question_end]
    dns_payload = (
        struct.pack("!H", txid)
        + struct.pack("!H", original_flags | TC_FLAG)
        + struct.pack("!H", question_count)
        + b"\x00\x00\x00\x00\x00\x00"
        + questions
    )

    return build_ipv4_udp_packet(src_ip, dst_ip, src_port, dst_port, dns_payload)
