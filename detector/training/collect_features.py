import argparse
import signal
import socket
import struct
import subprocess
import sys
from datetime import datetime
from datetime import timezone
from pathlib import Path

import pandas as pd

from detector.src.parser import parse_dns_query_to_authoritative
from detector.src.parser import parse_dns_response_event
from detector.training.features import FEATURE_NAMES
from detector.training.features import extract_features


ETH_P_ALL = 0x0003
ETHERTYPE_IPV4 = 0x0800
running = True


def stop(_, __):
    global running
    running = False


def route_interface_for_ip(ip_text):
    result = subprocess.run(
        ["ip", "route", "get", ip_text],
        check=True,
        text=True,
        capture_output=True,
    )
    parts = result.stdout.split()
    if "dev" not in parts:
        raise RuntimeError(f"could not determine interface for {ip_text}")
    interface_index = parts.index("dev") + 1
    if interface_index >= len(parts):
        raise RuntimeError(f"could not determine interface for {ip_text}")
    return parts[interface_index]


def resolve_interface(interface_name, authoritative_ip_text):
    if interface_name != "auto":
        return interface_name
    return route_interface_for_ip(authoritative_ip_text)


def query_key(event):
    return (
        event.query_name,
        event.query_type,
        event.query_class,
        event.transaction_id,
    )


def response_dict(event):
    return {
        "query_name": event.query_name,
        "answers": event.answers,
        "authority": event.authority,
        "additional": event.additional,
        "timestamp": event.timestamp,
    }


def load_domains(domains_path: Path):
    return {
        line.strip().rstrip(".").lower()
        for line in domains_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def is_whitelisted_final_query(query_event, allowed_domains: set[str]):
    return query_event.query_type == 1 and query_event.query_name in allowed_domains


def is_positive_final_answer(response_event):
    if not response_event.answers:
        return False
    return any(
        owner_name.rstrip(".").lower() == response_event.query_name and rr_type == 1
        for owner_name, rr_type, _, _ in response_event.answers
    )


def open_capture_socket(interface_name):
    capture_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    capture_socket.bind((interface_name, 0))
    capture_socket.settimeout(1.0)
    return capture_socket


def recv_ipv4_payload(capture_socket):
    frame = capture_socket.recv(65535)
    if len(frame) < 14:
        return None
    ether_type = struct.unpack("!H", frame[12:14])[0]
    if ether_type != ETHERTYPE_IPV4:
        return None
    return frame[14:]


def save_rows(rows, output_path):
    if not rows:
        print("no features collected")
        return

    dataframe = pd.DataFrame(rows, columns=FEATURE_NAMES)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataframe.to_parquet(output_path, index=False)
    print(f"\nsaved {len(dataframe)} rows to {output_path}")
    print(dataframe.describe().to_string())


def main():
    parser = argparse.ArgumentParser(description="Collect DNS features from live resolver traffic")
    parser.add_argument(
        "--interface",
        default="auto",
        help="Capture interface name, or auto to route toward the authoritative server",
    )
    parser.add_argument("--resolver-ip", default="172.29.0.10", help="Resolver IP address")
    parser.add_argument("--authoritative-ip", default="172.30.0.10", help="Authoritative IP address")
    parser.add_argument(
        "--domains",
        default="/app/detector/training/data/tranco_top4k_train.txt",
        help="Exact final query names to keep when collecting training features",
    )
    parser.add_argument("--output", required=True, help="Output parquet path")
    parser.add_argument("--progress-every", type=int, default=200, help="Print progress every N rows")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    interface_name = resolve_interface(args.interface, args.authoritative_ip)
    resolver_ip = bytes(int(part) for part in args.resolver_ip.split("."))
    authoritative_ip = bytes(int(part) for part in args.authoritative_ip.split("."))
    output_path = Path(args.output)
    allowed_domains = load_domains(Path(args.domains))

    pending_queries = {}
    rows = []
    capture_socket = open_capture_socket(interface_name)

    print(
        f"listening on {interface_name} for resolver={args.resolver_ip} authoritative={args.authoritative_ip}. "
        f"collecting positive A answers for {len(allowed_domains)} whitelisted domains. press Ctrl+C to stop and save.",
        flush=True,
    )

    try:
        while running:
            payload = recv_ipv4_payload(capture_socket)

            if payload is None:
                continue

            observed_at = datetime.now(timezone.utc)
            parsed_query = parse_dns_query_to_authoritative(payload, authoritative_ip, observed_at)
            if parsed_query is not None:
                query_event, transport = parsed_query
                if transport == "udp" and is_whitelisted_final_query(query_event, allowed_domains):
                    pending_queries[query_key(query_event)] = query_event
                continue

            parsed_response = parse_dns_response_event(payload, resolver_ip, observed_at)
            if parsed_response is None:
                continue

            _, response_event, _, _, _ = parsed_response
            matched_query = pending_queries.pop(query_key(response_event), None)
            if matched_query is None:
                continue
            if not is_positive_final_answer(response_event):
                continue

            rows.append(
                extract_features(
                    response_dict(response_event),
                    {"timestamp": matched_query.timestamp},
                )
            )

            if rows and len(rows) % args.progress_every == 0:
                print(f"collected {len(rows)} feature vectors", flush=True)
    finally:
        capture_socket.close()
        save_rows(rows, output_path)


if __name__ == "__main__":
    main()
