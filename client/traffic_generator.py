from __future__ import annotations

import json
import os
import random
import signal
import socket
import time

from attacker.attack_utils import build_dns_query


running = True
DNS_PORT = 53
CLIENT_RESPONSE_TIMEOUT_SECONDS = 8


def stop(signum, frame):
    global running
    running = False


def parse_qname(message: bytes, offset: int):
    labels: list[str] = []
    cursor = offset

    while True:
        if cursor >= len(message):
            return None

        label_length = message[cursor]
        cursor += 1
        if label_length == 0:
            return ".".join(labels), cursor

        if label_length & 0xC0:
            return None
        if cursor + label_length > len(message):
            return None

        label = message[cursor : cursor + label_length].decode("ascii")

        labels.append(label)
        cursor += label_length


def parse_dns_response_identity(message: bytes):
    if len(message) < 12:
        return None

    transaction_id = int.from_bytes(message[0:2], "big")
    flags = int.from_bytes(message[2:4], "big")
    question_count = int.from_bytes(message[4:6], "big")
    if flags & 0x8000 == 0 or question_count < 1:
        return None

    parsed_name = parse_qname(message, 12)
    if parsed_name is None:
        return None

    query_name, offset = parsed_name
    if len(message) < offset + 4:
        return None

    return transaction_id, query_name.rstrip(".")


def recv_dns_response(query_socket: socket.socket, expected_txid: int, expected_query_name: str):
    deadline = time.monotonic() + CLIENT_RESPONSE_TIMEOUT_SECONDS

    while True:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise socket.timeout

        query_socket.settimeout(remaining_seconds)
        response_message, _ = query_socket.recvfrom(4096)
        response_identity = parse_dns_response_identity(response_message)
        if response_identity is None:
            continue

        response_txid, response_query_name = response_identity
        if response_txid == expected_txid and response_query_name == expected_query_name:
            return True


def load_domain_corpus(corpus_path: str | None):
    if corpus_path is None:
        return []

    domains: list[str] = []
    with open(corpus_path, "r", encoding="utf-8") as corpus_file:
        for line in corpus_file:
            domain = line.strip().rstrip(".")
            if domain:
                domains.append(domain)
    return domains


def run_client_traffic():
    resolver_ip = os.environ["RESOLVER_IP"]
    target_zone = os.environ["CLIENT_TARGET_ZONE"]
    query_prefix = os.environ.get("CLIENT_QUERY_PREFIX", "client")
    exact_query_name = os.environ.get("CLIENT_EXACT_QUERY_NAME") or None
    domain_corpus_path = os.environ.get("CLIENT_DOMAIN_CORPUS_PATH") or None
    query_count_text = os.environ["CLIENT_QUERY_COUNT"]
    queries_per_second = float(os.environ["CLIENT_QUERIES_PER_SECOND"])
    run_duration_seconds = float(os.environ["CLIENT_RUN_DURATION_SECONDS"])
    domain_corpus = load_domain_corpus(domain_corpus_path)
    domain_corpus_index = 0
    query_count = int(query_count_text) if query_count_text else None
    query_interval_seconds = 1.0 / queries_per_second if queries_per_second > 0 else 0.0
    deadline = None if query_count is not None else time.monotonic() + run_duration_seconds
    queries_sent = 0
    queries_satisfied = 0
    latency_samples_ms: list[float] = []

    query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if domain_corpus:
        random.shuffle(domain_corpus)

    print(f"client run starting qps={queries_per_second:.3f} corpus={len(domain_corpus)}", flush=True)

    while running:
        if query_count is not None and queries_sent >= query_count:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break

        query_name = exact_query_name
        if query_name is None:
            if domain_corpus:
                if domain_corpus_index >= len(domain_corpus):
                    random.shuffle(domain_corpus)
                    domain_corpus_index = 0
                query_name = domain_corpus[domain_corpus_index]
                domain_corpus_index += 1
            else:
                query_name = f"{query_prefix}-{queries_sent:08d}-{os.urandom(4).hex()}.{target_zone}"
        query_index = queries_sent + 1
        query_txid = int.from_bytes(os.urandom(2), "big")
        started_at = time.perf_counter()
        print(
            json.dumps({"event": "client_query_sent", "query_name": query_name, "query_index": query_index}),
            flush=True,
        )
        query_socket.sendto(build_dns_query(query_txid, query_name), (resolver_ip, DNS_PORT))
        queries_sent += 1
        if recv_dns_response(query_socket, query_txid, query_name):
            queries_satisfied += 1
            latency_samples_ms.append((time.perf_counter() - started_at) * 1000.0)

        if query_interval_seconds > 0:
            time.sleep(query_interval_seconds)

    sorted_latency_samples_ms = sorted(latency_samples_ms)
    latency_avg_ms = (
        None
        if not sorted_latency_samples_ms
        else sum(sorted_latency_samples_ms) / len(sorted_latency_samples_ms)
    )

    print(
        f"client run finished queries={queries_sent} satisfied={queries_satisfied}",
        flush=True,
    )
    print(
        json.dumps(
            {
                "event": "client_latency_summary",
                "queries_sent": queries_sent,
                "queries_satisfied": queries_satisfied,
                "latency_samples": len(sorted_latency_samples_ms),
                "latency_avg_ms": latency_avg_ms,
            }
        ),
        flush=True,
    )


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    print("client ready", flush=True)
    while running:
        run_client_traffic()
        if os.environ.get("CLIENT_EXIT_AFTER_RUN") == "1":
            print("client exiting", flush=True)
            return

    print("client stopping", flush=True)


if __name__ == "__main__":
    main()
