from __future__ import annotations

import struct
from datetime import datetime

from detector.src.models import DetectorEvent
from detector.src.models import DNSQuery


DNS_PORT = 53
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def parse_qname(packet: bytes, offset: int, dns_base: int = 0):
    labels: list[str] = []
    cursor = offset
    jumped = False
    next_offset = offset
    max_jumps = 32
    jumps = 0

    while True:
        if cursor >= len(packet):
            return None

        label_length = packet[cursor]

        if label_length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                return None
            pointer = dns_base + (((label_length & 0x3F) << 8) | packet[cursor + 1])
            if pointer >= len(packet):
                return None
            if not jumped:
                next_offset = cursor + 2
                jumped = True
            cursor = pointer
            jumps += 1
            if jumps > max_jumps:
                return None
            continue

        cursor += 1

        if label_length == 0:
            return ".".join(labels), (next_offset if jumped else cursor)

        if cursor + label_length > len(packet):
            return None

        label = packet[cursor : cursor + label_length].decode("ascii")

        labels.append(label)
        cursor += label_length


def skip_questions(payload: bytes, dns_offset: int, question_count: int):
    offset = dns_offset + 12

    for _ in range(question_count):
        parsed_name = parse_qname(payload, offset, dns_offset)
        if parsed_name is None:
            return None

        _, offset = parsed_name
        if len(payload) < offset + 4:
            return None

        offset += 4

    return offset


def parse_dns_query_event(
    payload: bytes,
    dns_offset: int,
    observed_at: datetime,
):
    if len(payload) < dns_offset + 12:
        return None

    transaction_id, flags, question_count = struct.unpack("!HHH", payload[dns_offset : dns_offset + 6])
    if flags & 0x8000 != 0 or question_count < 1:
        return None

    parsed_name = parse_qname(payload, dns_offset + 12, dns_offset)
    if parsed_name is None:
        return None

    query_name, query_offset = parsed_name
    if len(payload) < query_offset + 4:
        return None

    qtype, qclass = struct.unpack("!HH", payload[query_offset : query_offset + 4])
    return DetectorEvent(
        query_name=query_name,
        query_type=qtype,
        query_class=qclass,
        transaction_id=transaction_id,
        timestamp=observed_at,
        answers=[],
        authority=[],
        additional=[],
    )


def parse_resource_record(
    payload: bytes,
    offset: int,
    dns_offset: int,
):
    parsed_name = parse_qname(payload, offset, dns_offset)
    if parsed_name is None:
        return None

    owner_name, offset = parsed_name
    if len(payload) < offset + 10:
        return None

    rr_type, rr_class, ttl, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
    offset += 10
    if len(payload) < offset + rdlength:
        return None

    rdata = payload[offset : offset + rdlength]
    rdata_offset = offset
    return (owner_name, rr_type, rr_class, ttl, rdata, rdata_offset, rdlength), offset + rdlength


def parse_section_records(
    payload: bytes,
    offset: int,
    record_count: int,
    dns_offset: int,
):
    records: list[tuple[str, int, int, bytes]] = []
    for _ in range(record_count):
        parsed_record = parse_resource_record(payload, offset, dns_offset)
        if parsed_record is None:
            return None
        (owner_name, rr_type, _, ttl, rdata, _, _), offset = parsed_record
        records.append((owner_name, rr_type, ttl, rdata))
    return records, offset


def parse_dns_response_event(
    payload: bytes,
    resolver_ip: bytes,
    observed_at: datetime,
):
    if len(payload) < 20 + 8 + 12:
        return None

    version_ihl = payload[0]
    if version_ihl >> 4 != 4:
        return None

    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(payload) < ip_header_length + 8 + 12:
        return None

    if payload[9] != IPPROTO_UDP or payload[16:20] != resolver_ip:
        return None

    udp_offset = ip_header_length
    src_port, dst_port, _, _ = struct.unpack("!HHHH", payload[udp_offset : udp_offset + 8])
    if src_port != DNS_PORT:
        return None

    dns_offset = udp_offset + 8
    transaction_id, flags, question_count, answer_count, authority_count, additional_count = struct.unpack(
        "!HHHHHH",
        payload[dns_offset : dns_offset + 12],
    )
    if flags & 0x8000 == 0 or question_count < 1:
        return None

    parsed_name = parse_qname(payload, dns_offset + 12, dns_offset)
    if parsed_name is None:
        return None

    query_name, query_offset = parsed_name
    if len(payload) < query_offset + 4:
        return None

    qtype, qclass = struct.unpack("!HH", payload[query_offset : query_offset + 4])
    question_end = skip_questions(payload, dns_offset, question_count)
    if question_end is None:
        return None

    parsed_answers = parse_section_records(payload, question_end, answer_count, dns_offset)
    if parsed_answers is None:
        return None
    answers, offset = parsed_answers

    parsed_authority = parse_section_records(payload, offset, authority_count, dns_offset)
    if parsed_authority is None:
        return None
    authority, offset = parsed_authority

    parsed_additional = parse_section_records(payload, offset, additional_count, dns_offset)
    if parsed_additional is None:
        return None
    additional, _ = parsed_additional

    query = DNSQuery(name=query_name, qtype=qtype, qclass=qclass)
    event = DetectorEvent(
        query_name=query_name,
        query_type=qtype,
        query_class=qclass,
        transaction_id=transaction_id,
        timestamp=observed_at,
        answers=answers,
        authority=authority,
        additional=additional,
    )
    return query, event, udp_offset, dns_offset, question_end


def parse_dns_query_to_authoritative(
    payload: bytes,
    authoritative_ip: bytes,
    observed_at: datetime,
):
    if len(payload) < 20:
        return None

    version_ihl = payload[0]
    if version_ihl >> 4 != 4:
        return None

    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(payload) < ip_header_length:
        return None

    if payload[16:20] != authoritative_ip:
        return None

    if payload[9] == IPPROTO_UDP:
        if len(payload) < ip_header_length + 8 + 12:
            return None

        udp_offset = ip_header_length
        _, dst_port, _, _ = struct.unpack("!HHHH", payload[udp_offset : udp_offset + 8])
        if dst_port != DNS_PORT:
            return None

        query_event = parse_dns_query_event(payload, udp_offset + 8, observed_at)
        return None if query_event is None else (query_event, "udp")

    if payload[9] == IPPROTO_TCP:
        if len(payload) < ip_header_length + 20:
            return None

        tcp_offset = ip_header_length
        _, dst_port, _, _, data_offset_flags = struct.unpack(
            "!HHIIH",
            payload[tcp_offset : tcp_offset + 14],
        )
        if dst_port != DNS_PORT:
            return None

        tcp_header_length = ((data_offset_flags >> 12) & 0x0F) * 4
        if tcp_header_length < 20:
            return None

        dns_length_offset = tcp_offset + tcp_header_length
        if len(payload) < dns_length_offset + 2:
            return None

        dns_message_length = struct.unpack("!H", payload[dns_length_offset : dns_length_offset + 2])[0]
        dns_offset = dns_length_offset + 2
        if dns_message_length < 12 or len(payload) < dns_offset + dns_message_length:
            return None

        query_event = parse_dns_query_event(payload, dns_offset, observed_at)
        return None if query_event is None else (query_event, "tcp")

    return None
