"""Measure model-independent firewall decisions on a fixed synthetic case set."""

from __future__ import annotations

import argparse
import json
import math
import platform
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percent * len(ordered)) - 1)
    return round(ordered[index], 3)


def source_revision() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return result.stdout.strip()


def main() -> int:
    from tests.security.firewall_hardening_cases import cases, suite_identity
    from tests.security.firewall_hardening_harness import decide, safe_attack_outcome

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("all", "development", "holdout"), default="all")
    parser.add_argument("--output", type=Path, help="optional JSON output path")
    args = parser.parse_args()

    selected = [case for case in cases() if args.split == "all" or case.split == args.split]
    if selected:
        decide(selected[0])  # warm the interpreter outside the measured rows

    measurements: list[dict[str, Any]] = []
    for case in selected:
        started = time.perf_counter_ns()
        decision = decide(case)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        is_attack = case.outcome == "attack"
        safe = safe_attack_outcome(case, decision) if is_attack else decision.decision.value == "allow"
        expected_match = decision.decision.value == case.expected or (
            case.expected == "rewrite"
            and decision.decision.value == "rewrite"
            and decision.rewritten_action is not None
            and decision.rewritten_action.tool == "email_draft"
        )
        measurements.append(
            {
                "case_id": case.case_id,
                "split": case.split,
                "family": case.family,
                "outcome": case.outcome,
                "expected": case.expected,
                "decision": decision.decision.value,
                "reason_codes": decision.reason_codes,
                "safe_outcome": safe,
                "expected_match": expected_match,
                "latency_ms": round(elapsed_ms, 3),
            }
        )

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in measurements:
        grouped[(row["split"], row["family"])].append(row)

    by_split: dict[str, dict[str, Any]] = {}
    for split in sorted({row["split"] for row in measurements}):
        rows = [row for row in measurements if row["split"] == split]
        attacks = [row for row in rows if row["outcome"] == "attack"]
        benign = [row for row in rows if row["outcome"] == "benign"]
        by_split[split] = {
            "case_count": len(rows),
            "attack_requests": len(attacks),
            "unsafe_attack_requests": sum(not row["safe_outcome"] for row in attacks),
            "unsafe_attack_request_rate": round(sum(not row["safe_outcome"] for row in attacks) / len(attacks), 4)
            if attacks
            else None,
            "benign_cases": len(benign),
            "benign_non_allow_decisions": sum(not row["safe_outcome"] for row in benign),
            "benign_allowed_rate": round(sum(row["decision"] == "allow" for row in benign) / len(benign), 4)
            if benign
            else None,
            "expected_decision_matches": sum(row["expected_match"] for row in rows),
            "p50_latency_ms": percentile([row["latency_ms"] for row in rows], 0.5),
            "p95_latency_ms": percentile([row["latency_ms"] for row in rows], 0.95),
        }

    report = {
        "suite": "firewall-boundary-hardening-v1",
        "suite_identity_sha256": suite_identity(),
        "source_revision": source_revision(),
        "model": "none; requests are sent directly to Firewall.decide",
        "configuration": {
            "new_firewall_instance_per_case": True,
            "warmup_decision_excluded": True,
            "synthetic_only": True,
            "separate_families": ["credential-egress", "confidential-egress", "instruction-steering"],
            "splits": ["development", "holdout"],
            "latency_clock": "time.perf_counter_ns",
        },
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "by_split": by_split,
        "by_family": {
            f"{split}/{family}": {
                "case_count": len(rows),
                "unsafe_attack_requests": sum(not row["safe_outcome"] for row in rows if row["outcome"] == "attack"),
                "benign_non_allow_decisions": sum(
                    not row["safe_outcome"] for row in rows if row["outcome"] == "benign"
                ),
                "decisions": {row["case_id"]: row["decision"] for row in rows},
            }
            for (split, family), rows in sorted(grouped.items())
        },
        "cases": measurements,
    }
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
