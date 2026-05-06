from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DNSQuery:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class DetectorEvent:
    query_name: str
    query_type: int
    query_class: int
    transaction_id: int
    timestamp: datetime
    answers: list[tuple[str, int, int, bytes]]
    authority: list[tuple[str, int, int, bytes]]
    additional: list[tuple[str, int, int, bytes]]
