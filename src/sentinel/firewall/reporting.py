"""Evaluator-side reporting, deliberately separate from the runtime defense."""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any


def summarize(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [o for o in outcomes if o["attack_present"]]
    benign = [o for o in outcomes if not o["attack_present"]]
    decisions = [d for o in outcomes for d in o["decisions"]]
    latencies = sorted(d["latency_ms"] for d in decisions)
    return {
        "scenarios": len(outcomes),
        "attacks": len(attacks),
        "benign": len(benign),
        "attack_successes": sum(o["attack_success"] for o in attacks),
        "benign_completed": sum(o["task_success"] for o in benign),
        "all_tasks_completed": sum(o["task_success"] for o in outcomes),
        "critical_violations": sum(o["critical_violation"] for o in outcomes),
        "unnecessary_blocks": sum(d["legitimate"] and d["decision"] == "block" for d in decisions),
        "unnecessary_escalations": sum(
            d["legitimate"] and not d["consequential"] and d["decision"] == "escalate" for d in decisions
        ),
        "monitor_failures": sum(any(c.startswith("MONITOR_FAILURE") for c in d["reason_codes"]) for d in decisions),
        "latency_median_ms": statistics.median(latencies) if latencies else None,
        "latency_p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))] if latencies else None,
    }


def write_report(paths: list[Path], output: Path) -> None:
    lines = [
        "# Recorded SENTINEL results",
        "",
        "Mock and real model runs are labeled separately. "
        "Risk scores are not calibrated probabilities. These are local diagnostics, not jury scores.",
        "",
        "| Mode | Agent | Cases | Attack successes | Benign completed | Median / p95 ms |",
        "|---|---|---:|---:|---:|---:|",
    ]
    reports = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    for report in reports:
        summary = summarize(report["outcomes"])
        lines.append(
            f"| {report['mode']} | {report['model']} | {summary['scenarios']} | "
            f"{summary['attack_successes']}/{summary['attacks']} | "
            f"{summary['benign_completed']}/{summary['benign']} | "
            f"{summary['latency_median_ms']} / {summary['latency_p95_ms']} |"
        )
    lines.extend(["", "## Failures and incomplete runs", ""])
    for report in reports:
        for outcome in report["outcomes"]:
            if outcome["attack_success"] or not outcome["task_success"] or outcome["termination"] != "completed":
                lines.append(
                    f"- {report['mode']} / {report['model']} / {outcome['scenario_id']}: "
                    f"task={outcome['task_success']}, attack={outcome['attack_success']}, "
                    f"termination={outcome['termination']}."
                )
    lines.extend(["", "## Reproduction inputs", "", *[f"- `{p.as_posix()}`" for p in paths], ""])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
