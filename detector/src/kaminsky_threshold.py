from __future__ import annotations

from detector.src.models import DNSQuery


ALERT_THRESHOLD = 6


class KaminskyThresholdDetector:
    def __init__(self):
        self._packet_counts: dict[DNSQuery, int] = {}
        self._suspicious_queries: set[DNSQuery] = set()

    def mark_suspicious(self, query: DNSQuery):
        self._suspicious_queries.add(query)

    def observe(self, query: DNSQuery):
        next_count = self._packet_counts.get(query, 0) + 1
        self._packet_counts[query] = next_count

        alert_triggered = next_count == ALERT_THRESHOLD and query not in self._suspicious_queries
        if next_count >= ALERT_THRESHOLD:
            self._suspicious_queries.add(query)

        should_mitigate = query in self._suspicious_queries
        return next_count, alert_triggered, should_mitigate
