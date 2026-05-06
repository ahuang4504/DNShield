from __future__ import annotations

import json


def extract_json_events(log_output: str):
    events: list[dict[str, object]] = []
    for line in log_output.splitlines():
        json_start = line.find("{")
        if json_start == -1:
            continue
        events.append(json.loads(line[json_start:]))
    return events


def parse_client_latency_summary(log_output: str):
    for event in extract_json_events(log_output):
        if event.get("event") != "client_latency_summary":
            continue

        return {
            "queries_sent": int(event["queries_sent"]),
            "queries_satisfied": int(event["queries_satisfied"]),
            "latency_samples": int(event["latency_samples"]),
            "latency_avg_ms": None if event["latency_avg_ms"] is None else float(event["latency_avg_ms"]),
        }

    return None


def parse_attacker_summary(log_output: str):
    for event in extract_json_events(log_output):
        if event.get("event") != "attacker_summary":
            continue

        return {
            "spoofed_packets_sent": int(event["spoofed_packets_sent"]),
        }

    return None


def parse_client_query_names(log_output: str):
    query_names: set[str] = set()
    for event in extract_json_events(log_output):
        if event.get("event") != "client_query_sent":
            continue
        query_name = str(event.get("query_name") or "").rstrip(".")
        if query_name:
            query_names.add(query_name)
    return query_names


def parse_detector_summary(log_output: str):
    for event in extract_json_events(log_output):
        if event.get("event") != "detector_summary":
            continue

        return {
            "attack_forged_responses_observed": int(event.get("attack_forged_responses_observed", 0)),
            "synthetic_client_attack_queries_scored": int(event.get("synthetic_client_attack_queries_scored", 0)),
            "synthetic_client_attack_iforest_alerts": int(event.get("synthetic_client_attack_iforest_alerts", 0)),
            "iforest_real_score_calls": int(event.get("iforest_real_score_calls", 0)),
            "iforest_real_score_total_ms": float(event.get("iforest_real_score_total_ms", 0.0)),
        }

    return {
        "attack_forged_responses_observed": 0,
        "synthetic_client_attack_queries_scored": 0,
        "synthetic_client_attack_iforest_alerts": 0,
        "iforest_real_score_calls": 0,
        "iforest_real_score_total_ms": 0.0,
    }


def alert_query_name(event: dict[str, object]):
    event_name = event.get("event")
    if event_name == "iforest_alert":
        return str(event.get("domain") or "")
    if event_name == "kaminsky_alert":
        return str(event.get("query_name") or "")
    return ""


def summarize_detector_alerts(
    log_output: str,
    *,
    attack_query_name: str | None,
    client_query_names: set[str],
):
    summary = {
        "attack_iforest_alert": 0,
        "attack_kaminsky_alerts": 0,
        "client_iforest_alerts": 0,
        "client_kaminsky_alerts": 0,
        "client_alerted_queries": 0,
    }
    client_alerted_query_names: set[str] = set()

    for event in extract_json_events(log_output):
        event_name = event.get("event")
        if event_name not in {"iforest_alert", "kaminsky_alert"}:
            continue

        query_name = alert_query_name(event)
        if event_name == "iforest_alert":
            if attack_query_name is not None and query_name == attack_query_name:
                summary["attack_iforest_alert"] = 1
            if query_name in client_query_names:
                summary["client_iforest_alerts"] += 1
                client_alerted_query_names.add(query_name)
        else:
            if attack_query_name is not None and query_name == attack_query_name:
                summary["attack_kaminsky_alerts"] += 1
            if query_name in client_query_names:
                summary["client_kaminsky_alerts"] += 1
                client_alerted_query_names.add(query_name)

    summary["client_alerted_queries"] = len(client_alerted_query_names)
    return summary


def print_benchmark_header(
    *,
    benchmark_duration_seconds: float,
    detector_enabled: bool,
    attacker_enabled: bool,
    client_enabled: bool,
):
    print(f"benchmark duration seconds: {benchmark_duration_seconds:.3f}")
    print(f"detector enabled: {int(detector_enabled)}")
    print(f"attacker enabled: {int(attacker_enabled)}")
    print(f"client enabled: {int(client_enabled)}")


def print_attack_summary(
    *,
    alert_summary: dict[str, int],
    detector_summary: dict[str, int],
    attacker_summary: dict[str, int | float | None] | None,
    cached_resolver_answer: str | None,
):
    print(f"iforest alert: {int(alert_summary['attack_iforest_alert'] > 0)}")
    print(f"kaminsky alert: {int(alert_summary['attack_kaminsky_alerts'] > 0)}")
    print(f"attacker packets viewed by detector: {detector_summary['attack_forged_responses_observed']}")
    if attacker_summary is not None:
        print(f"spoofed packets sent: {attacker_summary['spoofed_packets_sent']}")
    print(f"cached resolver answer: {cached_resolver_answer}")


def print_client_summary(
    *,
    detector_enabled: bool,
    client_queries_sent: int,
    client_queries_satisfied: int,
    client_iforest_alerts: int,
    client_kaminsky_alerts: int,
    client_alerts_total: int,
    client_false_positive_ratio: float,
    client_latency_summary: dict[str, int | float | None],
    detector_summary: dict[str, int],
):
    print(f"client queries sent: {client_queries_sent}")
    print(f"client queries satisfied: {client_queries_satisfied}")
    if detector_enabled:
        print(f"client iforest alert: {int(client_iforest_alerts > 0)}")
        print(f"client kaminsky alert: {int(client_kaminsky_alerts > 0)}")
        print(f"client alerts observed: {client_alerts_total}")
        print(f"client false positive ratio: {client_false_positive_ratio:.6f}")
        synthetic_client_attack_queries_scored = detector_summary["synthetic_client_attack_queries_scored"]
        if synthetic_client_attack_queries_scored > 0:
            synthetic_client_attack_iforest_alerts = detector_summary["synthetic_client_attack_iforest_alerts"]
            synthetic_true_positive_ratio = (
                synthetic_client_attack_iforest_alerts / synthetic_client_attack_queries_scored
            )
            print(f"client synthetic attack detections: {synthetic_client_attack_iforest_alerts}")
            print(f"client synthetic attack true positive ratio: {synthetic_true_positive_ratio:.6f}")
        if detector_summary["iforest_real_score_calls"] > 0:
            client_iforest_scoring_avg_ms = (
                detector_summary["iforest_real_score_total_ms"] / detector_summary["iforest_real_score_calls"]
            )
            print(f"client iforest scoring avg ms: {client_iforest_scoring_avg_ms:.6f}")
    print(
        "client end-to-end latency avg ms: "
        f"{client_latency_summary['latency_avg_ms'] if client_latency_summary['latency_avg_ms'] is not None else 'None'}"
    )
