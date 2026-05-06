from __future__ import annotations

import math
from collections import Counter

import numpy as np


FEATURE_NAMES = [
    "ttl_seconds",
    "n_answer_records",
    "n_authority_records",
    "n_additional_records",
    "label_entropy",
    "domain_length",
    "resolution_time_ms",
]


def extract_features(response: dict[str, object], query: dict[str, object] | None = None):
    answers = response.get("answers") or []
    authority = response.get("authority") or []
    additional = response.get("additional") or []
    qname = str(response.get("query_name") or "").rstrip(".").lower()

    ttl = int(answers[0][2]) if answers else 0

    labels = qname.split(".") if qname else []
    leftmost = labels[0] if labels else ""

    if query is not None:
        rtt = (response["timestamp"] - query["timestamp"]).total_seconds() * 1000
    else:
        rtt = -1.0

    return np.array(
        [
            float(ttl),
            float(len(answers)),
            float(len(authority)),
            float(len(additional)),
            shannon_entropy(leftmost),
            float(len(qname)),
            float(rtt),
        ],
        dtype=np.float32,
    )


def shannon_entropy(s: str):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))
