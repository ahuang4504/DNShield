from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from netfilterqueue import NetfilterQueue

from attacker.attack_utils import build_nsd_template_forged_a_response_builder
from attacker.attack_utils import build_real_shaped_forged_a_response_builder
from detector.src.kaminsky_threshold import KaminskyThresholdDetector
from detector.src.logging_utils import attack_query_response_label
from detector.src.logging_utils import emit_detector_summary
from detector.src.logging_utils import emit_iforest_alert
from detector.src.logging_utils import emit_kaminsky_alert
from detector.src.scorer import IForestScorer
from detector.src.parser import parse_dns_query_to_authoritative
from detector.src.parser import parse_dns_response_event
from detector.src.query_tracker import MAX_VALID_RESPONSES
from detector.src.query_tracker import lookup_episode_key
from detector.src.query_tracker import OutstandingQueryTracker
from detector.src.query_tracker import ResponseMatch
from detector.src.tcp_mitigation import build_ipv4_udp_packet
from detector.src.tcp_mitigation import build_truncated_response
from detector.src.txid_seed import publish_attack_query_txid


QUEUE_NUMBER = 0
READINESS_QUERY_NAME = "ns1.lab.dnshield"


def stop(signum, frame):
    raise SystemExit


def score_first_valid_response(
    *,
    response_match: ResponseMatch | None,
    scorer: IForestScorer | None,
):
    if response_match is None or scorer is None:
        return None, None, None

    scoring_started_at = time.perf_counter()
    details = scorer.score_response_details(response_match.response_event, response_match.query_event)
    scoring_elapsed_ms = (time.perf_counter() - scoring_started_at) * 1000.0
    decision_score = float(details["decision_score"])
    if decision_score >= scorer.threshold:
        return None, scoring_elapsed_ms, details

    alert = {
        "alert_type": "iforest_anomaly",
        "severity": "HIGH",
        "domain": details["domain"],
        "transaction_id": details["transaction_id"],
        "response_index": None,
        "anomaly_score": round(-decision_score, 4),
        "decision_score": round(decision_score, 4),
        "raw_score": round(float(details["raw_score"]), 4),
        "threshold": details["threshold"],
        "feature_vector": details["feature_vector"],
        "feature_names": details["feature_names"],
        "timestamp": details["timestamp"],
    }
    alert["response_index"] = response_match.response_index
    alert["valid_txid_window_size"] = MAX_VALID_RESPONSES
    return alert, scoring_elapsed_ms, details


def build_synthetic_forged_response_event(
    *,
    query_event,
    resolver_ip: bytes,
    authoritative_ip_text: str,
    authoritative_ip_bytes: bytes,
    forged_answer_ip_text: str,
):
    query_name = getattr(query_event, "query_name", "")
    build_response = (
        build_nsd_template_forged_a_response_builder(query_name, forged_answer_ip_text)
        if query_name == "app.lab.dnshield"
        else build_real_shaped_forged_a_response_builder(
            query_name,
            ".",
            authoritative_ip_text,
            forged_answer_ip_text,
        )
    )
    response_payload = build_response(getattr(query_event, "transaction_id", 0))
    response_packet = build_ipv4_udp_packet(
        authoritative_ip_bytes,
        resolver_ip,
        53,
        33333,
        response_payload,
    )
    observed_at = getattr(query_event, "timestamp") + timedelta(milliseconds=1)
    parsed_response = parse_dns_response_event(response_packet, resolver_ip, observed_at)
    if parsed_response is None:
        return None

    _, response_event, _, _, _ = parsed_response
    return response_event


def load_domain_corpus(corpus_path_text: str | None):
    if not corpus_path_text:
        return set()

    domains: set[str] = set()
    with open(corpus_path_text, "r", encoding="utf-8") as corpus_file:
        for line in corpus_file:
            domain = line.strip().rstrip(".").lower()
            if domain:
                domains.add(domain)
    return domains


def is_actual_client_query_name(
    query_name: str,
    *,
    client_query_prefix: str,
    client_target_zone: str,
    client_exact_query_name: str | None,
    client_domain_corpus: set[str],
):
    normalized_query_name = query_name.rstrip(".").lower()
    if client_exact_query_name is not None:
        return normalized_query_name == client_exact_query_name
    if client_domain_corpus:
        return normalized_query_name in client_domain_corpus
    return normalized_query_name.startswith(f"{client_query_prefix.lower()}-") and normalized_query_name.endswith(
        f".{client_target_zone.lower()}"
    )


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    detector_enabled = os.environ.get("DETECTOR_ENABLED", "1") == "1"
    resolver_ip = bytes(int(part) for part in os.environ["RESOLVER_IP"].split("."))
    authoritative_ip = bytes(int(part) for part in os.environ["AUTHORITATIVE_IP"].split("."))
    forged_answer_ip = socket.inet_aton(os.environ["FORGED_ANSWER_IP"])
    forged_answer_ip_text = os.environ["FORGED_ANSWER_IP"]
    authoritative_ip_text = os.environ["AUTHORITATIVE_IP"]
    authoritative_answer_ip = socket.inet_aton(os.environ["AUTHORITATIVE_ANSWER_IP"])
    iforest_threshold = float(os.environ["IFOREST_THRESHOLD"])
    iforest_model_path = Path(os.environ["IFOREST_MODEL_PATH"])
    attack_query_name = os.environ.get("ATTACK_QUERY_NAME") or None
    attack_txid_coordination_dir = Path(os.environ["ATTACK_TXID_COORDINATION_DIR"])
    client_query_prefix = os.environ.get("CLIENT_QUERY_PREFIX", "client")
    client_target_zone = os.environ.get("CLIENT_TARGET_ZONE", "lab.dnshield")
    client_exact_query_name = (os.environ.get("CLIENT_EXACT_QUERY_NAME") or "").rstrip(".").lower() or None
    client_domain_corpus = load_domain_corpus(os.environ.get("CLIENT_DOMAIN_CORPUS_PATH") or None)
    synthetic_client_attack_eval = os.environ.get("CLIENT_SYNTHETIC_ATTACK_EVAL", "0") == "1"

    threshold_detector = None if not detector_enabled else KaminskyThresholdDetector()
    outstanding_query_tracker = None if not detector_enabled else OutstandingQueryTracker(closed_lookup_ttl=None)
    iforest_scorer = None if not detector_enabled else IForestScorer(iforest_model_path, iforest_threshold)
    nfqueue = NetfilterQueue()
    inject_socket = None
    attack_forged_responses_observed = 0
    attack_forged_iforest_observed = 0
    attack_authoritative_iforest_observed = 0
    attack_forged_iforest_alerts = 0
    attack_authoritative_iforest_alerts = 0
    attack_responses_forwarded_unmodified = 0
    responses_forwarded_unmodified = 0
    synthetic_client_attack_queries_scored = 0
    synthetic_client_attack_iforest_alerts = 0
    synthetic_client_scored_lookups: set[tuple[str, int, int]] = set()
    iforest_real_score_calls = 0
    iforest_real_score_total_ms = 0.0
    if detector_enabled:
        inject_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        inject_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("detector ready", flush=True)
    if detector_enabled:
        print("mode: active", flush=True)
        print("kaminsky + iforest enabled", flush=True)
    else:
        print("mode: pass-through", flush=True)

    def process_packet(packet):
        payload = packet.get_payload()
        observed_at = datetime.now(timezone.utc)

        parsed_outgoing_query = parse_dns_query_to_authoritative(payload, authoritative_ip, observed_at)
        if parsed_outgoing_query is not None:
            outgoing_query, _ = parsed_outgoing_query
            if outgoing_query.query_name.rstrip(".").lower() == READINESS_QUERY_NAME:
                packet.accept()
                return
            if outstanding_query_tracker is not None:
                outstanding_query_tracker.register_query(outgoing_query)
            if attack_query_name is not None and outgoing_query.query_name == attack_query_name:
                publish_attack_query_txid(
                    attack_txid_coordination_dir,
                    outgoing_query.query_name,
                    outgoing_query.transaction_id,
                )
            is_client_query = is_actual_client_query_name(
                outgoing_query.query_name,
                client_query_prefix=client_query_prefix,
                client_target_zone=client_target_zone,
                client_exact_query_name=client_exact_query_name,
                client_domain_corpus=client_domain_corpus,
            )
            client_lookup_key = lookup_episode_key(outgoing_query)
            should_score_synthetic_client_query = (
                synthetic_client_attack_eval
                and iforest_scorer is not None
                and is_client_query
                and client_lookup_key not in synthetic_client_scored_lookups
            )
            if should_score_synthetic_client_query:
                synthetic_response_event = build_synthetic_forged_response_event(
                    query_event=outgoing_query,
                    resolver_ip=resolver_ip,
                    authoritative_ip_text=authoritative_ip_text,
                    authoritative_ip_bytes=authoritative_ip,
                    forged_answer_ip_text=forged_answer_ip_text,
                )
                if synthetic_response_event is not None:
                    nonlocal synthetic_client_attack_queries_scored
                    nonlocal synthetic_client_attack_iforest_alerts
                    synthetic_client_scored_lookups.add(client_lookup_key)
                    synthetic_client_attack_queries_scored += 1
                    synthetic_details = iforest_scorer.score_response_details(
                        synthetic_response_event,
                        outgoing_query,
                    )
                    synthetic_alert = None
                    if float(synthetic_details["decision_score"]) < iforest_scorer.threshold:
                        synthetic_alert = {
                            "alert_type": "iforest_anomaly",
                            "severity": "HIGH",
                            "domain": synthetic_details["domain"],
                            "transaction_id": synthetic_details["transaction_id"],
                            "response_index": None,
                            "anomaly_score": round(-float(synthetic_details["decision_score"]), 4),
                            "decision_score": round(float(synthetic_details["decision_score"]), 4),
                            "raw_score": round(float(synthetic_details["raw_score"]), 4),
                            "threshold": synthetic_details["threshold"],
                            "feature_vector": synthetic_details["feature_vector"],
                            "feature_names": synthetic_details["feature_names"],
                            "timestamp": synthetic_details["timestamp"],
                        }
                    if synthetic_alert is not None:
                        synthetic_client_attack_iforest_alerts += 1

        parsed_response = parse_dns_response_event(payload, resolver_ip, observed_at)
        if parsed_response is None:
            packet.accept()
            return

        query, response_event, udp_offset, dns_offset, question_end = parsed_response
        if response_event.query_name.rstrip(".").lower() == READINESS_QUERY_NAME:
            packet.accept()
            return
        nonlocal attack_forged_iforest_observed
        nonlocal attack_authoritative_iforest_observed
        nonlocal attack_forged_iforest_alerts
        nonlocal attack_authoritative_iforest_alerts
        nonlocal attack_responses_forwarded_unmodified
        nonlocal responses_forwarded_unmodified
        nonlocal attack_forged_responses_observed
        nonlocal iforest_real_score_calls
        nonlocal iforest_real_score_total_ms
        attack_response_label = attack_query_response_label(
            response_event,
            attack_query_name=attack_query_name,
            forged_answer_ip=forged_answer_ip,
            authoritative_answer_ip=authoritative_answer_ip,
        )
        if attack_response_label == "forged":
            attack_forged_responses_observed += 1
        was_modified = False
        if detector_enabled:
            if threshold_detector is None:
                raise RuntimeError("threshold detector is unavailable while detector mode is active")
            next_count, alert_triggered, was_modified = threshold_detector.observe(query)
            if alert_triggered:
                emit_kaminsky_alert(query, next_count)

            if not alert_triggered and not was_modified:
                response_match = None
                if outstanding_query_tracker is not None:
                    response_match = outstanding_query_tracker.match_response(response_event)
                if response_match is not None and attack_response_label == "forged":
                    attack_forged_iforest_observed += 1
                elif response_match is not None and attack_response_label == "authoritative":
                    attack_authoritative_iforest_observed += 1
                is_client_response = (
                    response_match is not None
                    and is_actual_client_query_name(
                        response_match.query_event.query_name,
                        client_query_prefix=client_query_prefix,
                        client_target_zone=client_target_zone,
                        client_exact_query_name=client_exact_query_name,
                        client_domain_corpus=client_domain_corpus,
                    )
                )
                iforest_alert, scoring_elapsed_ms, iforest_details = score_first_valid_response(
                    response_match=response_match,
                    scorer=iforest_scorer,
                )
                if scoring_elapsed_ms is not None and is_client_response:
                    iforest_real_score_calls += 1
                    iforest_real_score_total_ms += scoring_elapsed_ms
                if iforest_alert is not None:
                    if attack_response_label is not None:
                        iforest_alert["benchmark_label"] = attack_response_label
                    if attack_response_label == "forged":
                        attack_forged_iforest_alerts += 1
                    elif attack_response_label == "authoritative":
                        attack_authoritative_iforest_alerts += 1
                    emit_iforest_alert(iforest_alert)
                    threshold_detector.mark_suspicious(query)
                    was_modified = True

        if was_modified:
            if inject_socket is None:
                raise RuntimeError("mitigation requested while detector is in pass-through mode")
            replacement_packet = build_truncated_response(
                payload,
                udp_offset,
                dns_offset,
                question_end,
            )
            inject_socket.sendto(replacement_packet, (socket.inet_ntoa(payload[16:20]), 0))
            packet.drop()
            return

        if attack_response_label is not None:
            attack_responses_forwarded_unmodified += 1
        responses_forwarded_unmodified += 1
        packet.accept()

    nfqueue.bind(QUEUE_NUMBER, process_packet)
    try:
        nfqueue.run()
    finally:
        nfqueue.unbind()
        if inject_socket is not None:
            inject_socket.close()
        emit_detector_summary(
            attack_forged_responses_observed=attack_forged_responses_observed,
            attack_forged_iforest_observed=attack_forged_iforest_observed,
            attack_authoritative_iforest_observed=attack_authoritative_iforest_observed,
            attack_forged_iforest_alerts=attack_forged_iforest_alerts,
            attack_authoritative_iforest_alerts=attack_authoritative_iforest_alerts,
            attack_responses_forwarded_unmodified=attack_responses_forwarded_unmodified,
            responses_forwarded_unmodified=responses_forwarded_unmodified,
            synthetic_client_attack_queries_scored=synthetic_client_attack_queries_scored,
            synthetic_client_attack_iforest_alerts=synthetic_client_attack_iforest_alerts,
            iforest_real_score_calls=iforest_real_score_calls,
            iforest_real_score_total_ms=iforest_real_score_total_ms,
        )
        print("detector stopping", flush=True)


if __name__ == "__main__":
    main()
