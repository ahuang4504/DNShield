from __future__ import annotations

import json

from detector.src.models import DNSQuery


def response_contains_ipv4_answer(response_event: object, answer_ip: bytes):
    answers = getattr(response_event, "answers", [])
    for _, rr_type, _, rdata in answers:
        if rr_type == 1 and rdata == answer_ip:
            return True
    return False


def attack_query_response_label(
    response_event: object,
    *,
    attack_query_name: str | None,
    forged_answer_ip: bytes,
    authoritative_answer_ip: bytes,
):
    if attack_query_name is None or getattr(response_event, "query_name", None) != attack_query_name:
        return None
    if response_contains_ipv4_answer(response_event, forged_answer_ip):
        return "forged"
    if response_contains_ipv4_answer(response_event, authoritative_answer_ip):
        return "authoritative"
    return "other"


def emit_kaminsky_alert(query: DNSQuery, packets_seen_for_query: int):
    print(
        json.dumps(
            {
                "event": "kaminsky_alert",
                "query_name": query.name,
                "query_type": query.qtype,
                "query_class": query.qclass,
                "packets_seen_for_query": packets_seen_for_query,
            }
        ),
        flush=True,
    )


def emit_iforest_alert(alert: dict[str, object]):
    print(json.dumps({"event": "iforest_alert", **alert}), flush=True)


def emit_detector_summary(
    *,
    attack_forged_responses_observed: int,
    attack_forged_iforest_observed: int,
    attack_authoritative_iforest_observed: int,
    attack_forged_iforest_alerts: int,
    attack_authoritative_iforest_alerts: int,
    attack_responses_forwarded_unmodified: int,
    responses_forwarded_unmodified: int,
    synthetic_client_attack_queries_scored: int,
    synthetic_client_attack_iforest_alerts: int,
    iforest_real_score_calls: int,
    iforest_real_score_total_ms: float,
):
    print(
        json.dumps(
            {
                "event": "detector_summary",
                "attack_forged_responses_observed": attack_forged_responses_observed,
                "attack_forged_iforest_observed": attack_forged_iforest_observed,
                "attack_authoritative_iforest_observed": attack_authoritative_iforest_observed,
                "attack_forged_iforest_alerts": attack_forged_iforest_alerts,
                "attack_authoritative_iforest_alerts": attack_authoritative_iforest_alerts,
                "attack_responses_forwarded_unmodified": attack_responses_forwarded_unmodified,
                "responses_forwarded_unmodified": responses_forwarded_unmodified,
                "synthetic_client_attack_queries_scored": synthetic_client_attack_queries_scored,
                "synthetic_client_attack_iforest_alerts": synthetic_client_attack_iforest_alerts,
                "iforest_real_score_calls": iforest_real_score_calls,
                "iforest_real_score_total_ms": iforest_real_score_total_ms,
            }
        ),
        flush=True,
    )
