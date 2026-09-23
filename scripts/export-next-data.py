"""Export redacted, measured traces for the Next.js observatory."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.firewall.dashboard import snapshot

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "artifacts/phase-final"
OUT = ROOT / "frontend/data"

RUNS = [
    ("rules", "Structural defense", "final-rules"),
    ("allow", "Allow all", "final-allow"),
    ("adaptive", "Adaptive schedule", "final-adaptive"),
    ("enterprise", "Enterprise · benign", "real/benign-enterprise"),
    ("finance", "Finance · benign", "real/benign-finance"),
    ("soc", "SOC · benign", "real/benign-soc"),
    ("invoice-allow", "Poisoned invoice · allow all", "real/poisoned-invoice-allow"),
    ("invoice-rules", "Poisoned invoice · defended", "real/poisoned-invoice-rules"),
    ("recovery-allow", "Recovery retry · allow all", "real/recovery-v2-allow"),
    ("recovery-rules", "Recovery retry · defended", "real/recovery-v2-rules"),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    index = []
    for ident, title, location in RUNS:
        candidates = sorted((BASE / location).glob("*/events.live.jsonl"))
        if not candidates:
            raise FileNotFoundError(f"No completed trace for {location}")
        trace = candidates[-1]
        item = snapshot(trace)
        metadata = item["metadata"]
        if not metadata.get("outcomes"):
            raise ValueError(f"No measured outcomes for {location}")
        (OUT / f"{ident}.json").write_text(json.dumps(item, ensure_ascii=False), encoding="utf-8")
        index.append(
            {
                "id": ident,
                "title": title,
                "mode": metadata["mode"],
                "model": metadata["model"],
                "attackMode": metadata["attack_mode"],
                "runs": len(metadata["outcomes"]),
                "attacks": sum(bool(o["attack_present"]) for o in metadata["outcomes"]),
                "attackSuccesses": sum(bool(o["attack_success"]) for o in metadata["outcomes"]),
                "tasksCompleted": sum(bool(o["task_success"]) for o in metadata["outcomes"]),
            }
        )
    (OUT / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Exported {len(index)} redacted trace groups to {OUT}")


if __name__ == "__main__":
    main()
