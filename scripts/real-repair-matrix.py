"""Fixed eight-case, three-seed matched structural/allow-all Qwen matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.firewall.cli import execute

CASES = (
    "enterprise_poisoned_invoice",
    "finance_false_approval",
    "soc_hostile_log_text",
    "enterprise_memory_poison",
    "enterprise_project_status",
    "finance_dispute_note",
    "soc_intel_correlation",
    "finance_fraud_awareness_note",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/repair-v3/real-matrix"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    plan = {
        "cases": CASES,
        "seeds": [0, 1, 2],
        "modes": ["allow_all", "rules"],
        "model": "ollama:qwen3:8b",
        "thinking": False,
        "temperature": 0,
        "note": "Greedy decoding: seeds are repeated trials, not independent sampled generations.",
    }
    plan_path = args.output / "matrix-plan.json"
    if plan_path.exists() and json.loads(plan_path.read_text()) != json.loads(json.dumps(plan)):
        raise ValueError("existing matrix plan differs")
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    paths = {path.stem: path for path in Path("scenarios/public").rglob("*.yaml")}
    for seed in plan["seeds"]:
        for name in CASES:
            for undefended in (True, False):
                mode = "allow_all" if undefended else "rules"
                destination = args.output / f"seed-{seed}" / name / mode
                completed = list(destination.glob("*/results.json"))
                if completed:
                    continue
                print(f"MATRIX seed={seed} case={name} mode={mode}", flush=True)
                execute([paths[name]], plan["model"], False, False, "qwen3:8b", undefended, False, destination, seed)


if __name__ == "__main__":
    main()
