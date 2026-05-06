from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scripts.evaluation_logging import parse_attacker_summary
from scripts.evaluation_logging import parse_client_latency_summary
from scripts.evaluation_logging import parse_client_query_names
from scripts.evaluation_logging import parse_detector_summary
from scripts.evaluation_logging import print_attack_summary
from scripts.evaluation_logging import print_benchmark_header
from scripts.evaluation_logging import print_client_summary
from scripts.evaluation_logging import summarize_detector_alerts


REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_SPOOFED_PACKETS = 1 << 16
MAX_CLIENT_WAIT_SECONDS = 180.0
READINESS_PROBE_EXPECTED_IP = "172.30.0.10"
MAX_RESOLVER_READY_WAIT_SECONDS = 30.0


def run_command(
    args: list[str],
    capture_output: bool = False,
    check: bool = True,
    env: dict[str, str] | None = None,
):
    command_env = os.environ.copy() if env is None else env.copy()
    if shutil.which(args[0], path=command_env.get("PATH")) is None:
        raise RuntimeError(f"required command not found on PATH: {args[0]}")
    return subprocess.run(
        args,
        cwd=REPO_ROOT,
        check=check,
        text=True,
        capture_output=capture_output,
        env=command_env,
    )


def print_process_output(result: subprocess.CompletedProcess[str]):
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)


def run_compose_up(env: dict[str, str]):
    build_command = [
        "docker",
        "compose",
        "build",
        "detector",
        "resolver",
        "authoritative",
    ]
    if env.get("EVALUATION_ENABLE_CLIENT") == "1":
        build_command.append("client")
    if env.get("ATTACK_EXIT_AFTER_RUN") == "1":
        build_command.append("attacker")

    build_result = run_command(build_command, capture_output=True, env=env)
    print_process_output(build_result)

    up_command = [
        "docker",
        "compose",
        "up",
        "-d",
        "detector",
        "resolver",
        "authoritative",
    ]

    up_result = run_command(up_command, capture_output=True, env=env)
    print_process_output(up_result)


def dump_resolver_cache():
    return run_command(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "resolver",
            "unbound-control",
            "-c",
            "/etc/unbound/unbound.conf",
            "dump_cache",
        ],
        capture_output=True,
    ).stdout


def extract_cached_resolver_answer(cache_dump: str, query_name: str):
    cache_query_name = f"{query_name}."
    for line in cache_dump.splitlines():
        if cache_query_name not in line:
            continue
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        if match is not None:
            return match.group(0)
    return None


def cleanup_stale_attacker_containers():
    result = run_command(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            "label=com.docker.compose.service=attacker",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return

    stale_container_names = [
        name
        for name in result.stdout.splitlines()
        if name != "dnshield-attacker"
    ]
    if not stale_container_names:
        return

    run_command(["docker", "rm", "-f", *stale_container_names], check=False)


def wait_for_client_logs_until_summary():
    deadline = time.monotonic() + MAX_CLIENT_WAIT_SECONDS
    latest_client_logs = ""

    while time.monotonic() < deadline:
        latest_client_logs = run_command(
            ["docker", "compose", "logs", "--no-color", "client"],
            capture_output=True,
            check=False,
        ).stdout
        if parse_client_latency_summary(latest_client_logs) is not None:
            return latest_client_logs
        time.sleep(1)

    return latest_client_logs


def wait_for_resolver_ready():
    deadline = time.monotonic() + MAX_RESOLVER_READY_WAIT_SECONDS

    while time.monotonic() < deadline:
        probe_result = run_command(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "detector",
                "uv",
                "run",
                "python",
                "scripts/check_resolver_ready.py",
            ],
            capture_output=True,
            check=False,
        )
        if probe_result.returncode == 0:
            probe_output = json.loads(probe_result.stdout.strip() or "{}")
            if probe_output.get("answer_ip") == READINESS_PROBE_EXPECTED_IP:
                return
        time.sleep(1)

    raise RuntimeError("resolver did not become ready before evaluation started")


def build_parser():
    parser = argparse.ArgumentParser(description="Run the DNSHield evaluation benchmark")
    parser.add_argument("--detector", choices=["on", "off"], default="on")
    parser.add_argument("--client", choices=["on", "off"], default="on")
    parser.add_argument("--attacker", choices=["on", "off"], default="on")
    parser.add_argument("--attack-query-name", default=None)
    parser.add_argument("--client-exact-query-name", default=None)
    parser.add_argument("--client-domain-corpus", choices=["on", "off"], default="off")
    parser.add_argument(
        "--client-domain-corpus-source",
        choices=["test", "train"],
        default="test",
    )
    parser.add_argument("--warmup-seconds", type=float, default=2.0)
    return parser


def main():
    args = build_parser().parse_args()
    detector_enabled = args.detector == "on"
    client_enabled = args.client == "on"
    attacker_enabled = args.attacker == "on"
    benchmark_start = time.perf_counter()

    query_name = None
    if attacker_enabled:
        query_name = args.attack_query_name or f"eval-{uuid.uuid4().hex}.lab.dnshield"

    detector_logs = ""
    attacker_logs = ""
    client_logs = ""
    cached_resolver_answer: str | None = None

    compose_env = os.environ.copy()
    compose_env["DETECTOR_ENABLED"] = "1" if detector_enabled else "0"
    compose_env["EVALUATION_ENABLE_CLIENT"] = "1" if client_enabled else "0"
    compose_env["ATTACK_EXIT_AFTER_RUN"] = "1"
    compose_env["CLIENT_EXIT_AFTER_RUN"] = "1"
    compose_env["CLIENT_SYNTHETIC_ATTACK_EVAL"] = "1" if client_enabled and detector_enabled else "0"
    compose_env.setdefault("CLIENT_QUERY_PREFIX", "client")
    if query_name is not None:
        compose_env["ATTACK_QUERY_NAME"] = query_name
    if args.client_exact_query_name is not None:
        compose_env["CLIENT_EXACT_QUERY_NAME"] = args.client_exact_query_name
    if args.client_domain_corpus == "on":
        if args.client_domain_corpus_source == "train":
            compose_env["CLIENT_DOMAIN_CORPUS_PATH"] = "/app/detector/training/data/tranco_top4k_train.txt"
        else:
            compose_env["CLIENT_DOMAIN_CORPUS_PATH"] = "/app/detector/training/data/tranco_top1k_test.txt"

    try:
        run_command(["docker", "compose", "down", "--remove-orphans"], check=False)
        cleanup_stale_attacker_containers()
        run_compose_up(compose_env)
        time.sleep(args.warmup_seconds)
        wait_for_resolver_ready()

        if attacker_enabled:
            run_command(
                [
                    "docker",
                    "compose",
                    "up",
                    "--no-build",
                    "--no-deps",
                    "attacker",
                ],
                env=compose_env,
            )
            time.sleep(2)
        elif client_enabled:
            run_command(
                [
                    "docker",
                    "compose",
                    "up",
                    "-d",
                    "--no-build",
                    "--no-deps",
                    "client",
                ],
                env=compose_env,
            )
            client_logs = wait_for_client_logs_until_summary()

        run_command(["docker", "compose", "stop", "detector"])
        detector_logs = run_command(
            ["docker", "compose", "logs", "--no-color", "detector"],
            capture_output=True,
        ).stdout
        if attacker_enabled:
            attacker_logs = run_command(
                ["docker", "compose", "logs", "--no-color", "attacker"],
                capture_output=True,
            ).stdout
        if client_enabled:
            if not client_logs:
                client_logs = run_command(
                    ["docker", "compose", "logs", "--no-color", "client"],
                    capture_output=True,
                ).stdout

        cache_dump = dump_resolver_cache()
        if attacker_enabled:
            cached_resolver_answer = extract_cached_resolver_answer(cache_dump, query_name)
    finally:
        run_command(["docker", "compose", "down", "--remove-orphans"], check=False)

    attacker_summary = parse_attacker_summary(attacker_logs)
    client_latency_summary = parse_client_latency_summary(client_logs)
    client_query_names = parse_client_query_names(client_logs)
    detector_summary = parse_detector_summary(detector_logs)
    alert_summary = summarize_detector_alerts(
        detector_logs,
        attack_query_name=query_name,
        client_query_names=client_query_names,
    )
    if client_enabled and client_latency_summary is None:
        raise RuntimeError("did not find client latency summary")

    client_alerts_total = (
        alert_summary["client_iforest_alerts"] + alert_summary["client_kaminsky_alerts"]
    )
    client_queries_sent = 0 if client_latency_summary is None else int(client_latency_summary["queries_sent"])
    client_queries_satisfied = (
        0 if client_latency_summary is None else int(client_latency_summary["queries_satisfied"])
    )
    client_false_positive_ratio = (
        alert_summary["client_alerted_queries"] / client_queries_sent if client_queries_sent else 0.0
    )
    benchmark_duration_seconds = time.perf_counter() - benchmark_start

    print_benchmark_header(
        benchmark_duration_seconds=benchmark_duration_seconds,
        detector_enabled=detector_enabled,
        attacker_enabled=attacker_enabled,
        client_enabled=client_enabled,
    )

    if attacker_enabled:
        print_attack_summary(
            alert_summary=alert_summary,
            detector_summary=detector_summary,
            attacker_summary=attacker_summary,
            cached_resolver_answer=cached_resolver_answer,
        )

    if client_enabled and client_latency_summary is not None:
        print_client_summary(
            detector_enabled=detector_enabled,
            client_queries_sent=client_queries_sent,
            client_queries_satisfied=client_queries_satisfied,
            client_iforest_alerts=alert_summary["client_iforest_alerts"],
            client_kaminsky_alerts=alert_summary["client_kaminsky_alerts"],
            client_alerts_total=client_alerts_total,
            client_false_positive_ratio=client_false_positive_ratio,
            client_latency_summary=client_latency_summary,
            detector_summary=detector_summary,
        )


if __name__ == "__main__":
    main()
