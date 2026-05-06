from __future__ import annotations

import argparse
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_LIST_PATH = REPO_ROOT / "detector" / "training" / "data" / "tranco_top5k.txt"
ROOT_ZONE_PATH = REPO_ROOT / "auth" / "zones" / "root.zone"
ROOT_ZONE_SERIAL = "2026050401"


def load_domains(domain_list_path: Path):
    domains: list[str] = []
    seen_domains: set[str] = set()
    with domain_list_path.open("r", encoding="utf-8") as domain_file:
        for line in domain_file:
            domain = line.strip().rstrip(".").lower()
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)
            domains.append(domain)
    return domains


def benign_answer_ip(index: int):
    host_index = index + 1
    third_octet = (host_index // 254) % 256
    fourth_octet = (host_index % 254) + 1
    return f"198.18.{third_octet}.{fourth_octet}"


def build_root_zone(domains: list[str]):
    lines = [
        "$ORIGIN .",
        "$TTL 300",
        "",
        f"@ IN SOA ns1. hostmaster. {ROOT_ZONE_SERIAL} 300 300 300 300",
        "@ IN NS ns1.",
        "ns1 IN A 172.30.0.10",
        "",
    ]
    for index, domain in enumerate(domains):
        lines.append(f"{domain}. IN A {benign_answer_ip(index)}")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate the authoritative root zone from a domain list")
    parser.add_argument("--domains", default=str(DOMAIN_LIST_PATH), help="Input domain list path")
    parser.add_argument("--output", default=str(ROOT_ZONE_PATH), help="Output root zone path")
    args = parser.parse_args()

    domain_list_path = Path(args.domains)
    output_path = Path(args.output)
    domains = load_domains(domain_list_path)
    output_path.write_text(build_root_zone(domains), encoding="ascii")
    print(f"wrote {output_path} ({len(domains)} domains) from {domain_list_path}")


if __name__ == "__main__":
    main()
