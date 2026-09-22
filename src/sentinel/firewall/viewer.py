"""A terminal evidence viewer. Raw synthetic artifacts remain unchanged."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, cast

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinel.firewall.state import LABELED_SECRET, OPAQUE, SECRET_KEY, variants


def read_live(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    events = []
    for i, line in enumerate(lines):
        try:
            events.append(json.loads(line))
        except ValueError:
            if i != len(lines) - 1 or line.endswith("\n"):
                raise ValueError(f"Corrupt trace at line {i + 1}") from None
    return events


def redact(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values: set[str] = set()

    def collect(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for k, child in value.items():
                collect(child, k)
        elif isinstance(value, list):
            for child in value:
                collect(child, key)
        elif isinstance(value, str):
            if SECRET_KEY.search(key) and 8 <= len(value) <= 512 and len(value.split()) == 1:
                values.add(value)
            values.update(m.group(1) for m in LABELED_SECRET.finditer(value))
            if key not in {"event_id", "run_id", "id", "action_digest"}:
                values.update(m.group() for m in OPAQUE.finditer(value))

    collect(events)
    patterns = [
        re.compile(r"\s*".join(re.escape(c) for c in encoded), re.I if kind == "hex" else 0)
        for value in values
        for kind, encoded in variants(value).items()
    ]

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            for pattern in patterns:
                value = pattern.sub("[redacted]", value)
        return value

    return cast(list[dict[str, Any]], clean(events))


def render(
    events: list[dict[str, Any]],
    *,
    step: int | None = None,
    kind: str | None = None,
    decision: str | None = None,
    last: int | None = None,
) -> Group:
    events = redact(events)
    selected_steps = {
        (e.get("run_id"), e.get("step_id"))
        for e in events
        if e.get("type") == "defense_decision" and e.get("payload", {}).get("decision") == decision
    }
    rows = [
        e
        for e in events
        if (step is None or e.get("step_id") == step)
        and (kind is None or e.get("type") == kind)
        and (decision is None or (e.get("run_id"), e.get("step_id")) in selected_steps)
    ]
    if last:
        rows = rows[-last:]
    table = Table("step", "event / actor", "evidence and outcome", expand=True)
    colors = {"allow": "green", "block": "red", "escalate": "yellow", "rewrite": "cyan"}
    for event in rows:
        payload = event.get("payload", {})
        label = event.get("type", "unknown")
        if label == "defense_decision":
            choice = payload.get("decision", "unknown")
            content = Text(
                f"{choice.upper()}  risk={payload.get('risk_score')}  confidence={payload.get('confidence')}\n",
                style=colors.get(choice, "white"),
            )
            content.append("candidate: " + json.dumps(payload.get("action"), ensure_ascii=False) + "\n")
            content.append(", ".join(payload.get("reason_codes", [])) + "\n" + str(payload.get("explanation", "")))
            if payload.get("rewritten_action"):
                content.append("\nreplacement: " + json.dumps(payload["rewritten_action"], ensure_ascii=False))
            if payload.get("metadata"):
                content.append("\nevidence: " + json.dumps(payload["metadata"], ensure_ascii=False))
        else:
            content = Text(json.dumps(payload, ensure_ascii=False))
        table.add_row(str(event.get("step_id")), label + "\n" + str(event.get("actor", "")), content)
    heading = Panel(
        Text("sentiel | action firewall\nUncalibrated risk indicators · synthetic data · simulated human approvals")
    )
    return Group(heading, table)


def view(
    path: Path,
    *,
    follow: bool = False,
    step: int | None = None,
    kind: str | None = None,
    decision: str | None = None,
    export_html: Path | None = None,
) -> None:
    console = Console(record=export_html is not None)
    if follow:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                live.update(render(read_live(path), step=step, kind=kind, decision=decision, last=12))
                time.sleep(0.5)
    else:
        console.print(render(read_live(path), step=step, kind=kind, decision=decision))
    if export_html:
        export_html.parent.mkdir(parents=True, exist_ok=True)
        console.save_html(str(export_html))
