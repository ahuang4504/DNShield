from __future__ import annotations

import json
import time
from pathlib import Path


ATTACK_TXID_FILENAME = "attack_txid.json"


def clear_attack_query_txid(coordination_dir: Path):
    target_path = coordination_dir / ATTACK_TXID_FILENAME
    if target_path.exists():
        target_path.unlink()


def wait_for_attack_query_txid(
    coordination_dir: Path,
    expected_query_name: str,
    timeout_seconds: float,
):
    deadline = time.monotonic() + timeout_seconds
    target_path = coordination_dir / ATTACK_TXID_FILENAME

    while time.monotonic() < deadline:
        if target_path.exists():
            payload = json.loads(target_path.read_text(encoding="ascii"))
            if payload.get("query_name") == expected_query_name:
                return int(payload["transaction_id"])

        time.sleep(0.01)

    raise RuntimeError(f"timed out waiting for attack txid seed for {expected_query_name}")
