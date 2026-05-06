from __future__ import annotations

import json
from pathlib import Path


ATTACK_TXID_FILENAME = "attack_txid.json"


def publish_attack_query_txid(coordination_dir: Path, query_name: str, transaction_id: int):
    coordination_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "query_name": query_name,
        "transaction_id": transaction_id,
    }
    target_path = coordination_dir / ATTACK_TXID_FILENAME
    temporary_path = coordination_dir / f"{ATTACK_TXID_FILENAME}.tmp"
    temporary_path.write_text(json.dumps(payload), encoding="ascii")
    temporary_path.replace(target_path)
