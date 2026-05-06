from __future__ import annotations

import argparse
import random
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DOMAINS_PATH = REPO_ROOT / "detector" / "training" / "data" / "tranco_top5k.txt"
TRAIN_DOMAINS_PATH = REPO_ROOT / "detector" / "training" / "data" / "tranco_top4k_train.txt"
TEST_DOMAINS_PATH = REPO_ROOT / "detector" / "training" / "data" / "tranco_top1k_test.txt"


def load_domains(source_path: Path):
    seen_domains: set[str] = set()
    domains: list[str] = []
    for line in source_path.read_text(encoding="utf-8").splitlines():
        domain = line.strip().rstrip(".").lower()
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        domains.append(domain)
    return domains


def write_domains(output_path: Path, domains: list[str]):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(domains) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Split top domains into train and held-out test sets")
    parser.add_argument("--input", default=str(SOURCE_DOMAINS_PATH), help="Source domain list")
    parser.add_argument("--train-output", default=str(TRAIN_DOMAINS_PATH), help="Training domain output path")
    parser.add_argument("--test-output", default=str(TEST_DOMAINS_PATH), help="Held-out test domain output path")
    parser.add_argument("--train-count", type=int, default=4000, help="Number of domains to reserve for training")
    parser.add_argument("--seed", type=int, default=42, help="Shuffle seed for deterministic splitting")
    args = parser.parse_args()

    domains = load_domains(Path(args.input))
    if args.train_count <= 0:
        raise ValueError("--train-count must be > 0")
    if args.train_count >= len(domains):
        raise ValueError("--train-count must be smaller than the number of source domains")

    shuffled_domains = list(domains)
    random.Random(args.seed).shuffle(shuffled_domains)
    train_domains = shuffled_domains[: args.train_count]
    test_domains = shuffled_domains[args.train_count :]

    write_domains(Path(args.train_output), train_domains)
    write_domains(Path(args.test_output), test_domains)

    print(f"loaded {len(domains)} domains from {args.input}")
    print(f"wrote {len(train_domains)} training domains to {args.train_output}")
    print(f"wrote {len(test_domains)} held-out test domains to {args.test_output}")


if __name__ == "__main__":
    main()
