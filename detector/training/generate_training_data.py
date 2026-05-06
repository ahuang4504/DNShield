from __future__ import annotations

import argparse
import random
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path

import dns.rdatatype
import dns.resolver
import pandas as pd

from detector.training.features import FEATURE_NAMES
from detector.training.features import extract_features


def rrset_to_tuples(rrset):
    return [
        (str(rrset.name), dns.rdatatype.to_text(rrset.rdtype), rrset.ttl, rr.to_text())
        for rr in rrset
    ]


def response_to_dicts(answer, qname: str, rtt_ms: float):
    answers = [record for rrset in answer.response.answer for record in rrset_to_tuples(rrset)]
    authority = [record for rrset in answer.response.authority for record in rrset_to_tuples(rrset)]
    additional = [record for rrset in answer.response.additional for record in rrset_to_tuples(rrset)]

    response_timestamp = datetime.now(timezone.utc)
    query_timestamp = response_timestamp - timedelta(milliseconds=rtt_ms)

    response = {
        "query_name": qname.rstrip(".").lower(),
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "timestamp": response_timestamp,
    }
    query = {"timestamp": query_timestamp}
    return response, query


def load_domains(domains_path: Path):
    return [
        line.strip().rstrip(".").lower()
        for line in domains_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main():
    parser = argparse.ArgumentParser(description="Generate DNS features for IForest training")
    parser.add_argument("--resolver", required=True, help="Resolver IP address")
    parser.add_argument(
        "--domains",
        default="detector/training/data/tranco_top4k_train.txt",
        help="Path to domain list (one per line)",
    )
    parser.add_argument("--output", required=True, help="Output parquet path")
    parser.add_argument("--passes", type=int, default=2, help="Times to iterate the domain list")
    parser.add_argument("--rate", type=float, default=10.0, help="Target queries per second")
    args = parser.parse_args()

    domains = load_domains(Path(args.domains))
    print(f"loaded {len(domains)} domains")

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [args.resolver]
    resolver.timeout = 3
    resolver.lifetime = 3

    interval = 1.0 / args.rate
    rows: list[object] = []
    total_queries = 0
    error_count = 0

    for pass_num in range(args.passes):
        random.shuffle(domains)
        for domain in domains:
            query_type = random.choices(["A", "A", "A", "AAAA"], k=1)[0]
            started_at = time.perf_counter()
            answer = resolver.resolve(domain, query_type)
            rtt_ms = (time.perf_counter() - started_at) * 1000.0
            response_dict, query_dict = response_to_dicts(answer, domain, rtt_ms)
            rows.append(extract_features(response_dict, query_dict))

            total_queries += 1
            if total_queries % 500 == 0:
                print(
                    f"pass {pass_num + 1}/{args.passes}: "
                    f"{total_queries} queries, {error_count} errors, {len(rows)} rows"
                )
            time.sleep(interval * random.uniform(0.5, 1.5))

    print(f"\nfinished {total_queries} queries, {error_count} errors, {len(rows)} rows")
    if not rows:
        print("no features collected")
        return

    dataframe = pd.DataFrame(rows, columns=FEATURE_NAMES)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataframe.to_parquet(output_path, index=False)
    print(f"saved {len(dataframe)} rows to {output_path}")
    print(dataframe.describe().to_string())


if __name__ == "__main__":
    main()
