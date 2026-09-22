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
    events: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        try:
            event = json.loads(line)
        except ValueError:
            if i != len(lines) - 1 or line.endswith("\n"):
                raise ValueError(f"Corrupt trace at line {i + 1}") from None
            continue
        if not isinstance(event, dict):
            raise ValueError(f"Trace event at line {i + 1} is not an object")
        events.append(event)
    return events


def redact(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values: set[str] = set()

    def collect(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for k, child in value.items():
                collect(k)
                collect(child, str(k))
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

    def clean_string(value: str) -> str:
        for pattern in patterns:
            value = pattern.sub("[redacted]", value)
        return value

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {clean_string(str(k)): clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            return clean_string(value)
        return value

    return cast(list[dict[str, Any]], clean(events))


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload")
    return payload if isinstance(payload, dict) else {"value": payload}


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _decision_content(payload: dict[str, Any]) -> Text:
    choice = str(payload.get("decision", "unknown"))
    colors = {"allow": "green", "block": "red", "escalate": "yellow", "rewrite": "cyan"}
    content = Text(
        f"{choice.upper()}  risk={payload.get('risk_score')}  confidence={payload.get('confidence')}\n",
        style=colors.get(choice, "white"),
    )
    content.append("candidate action: " + _json(payload.get("action")) + "\n")
    reason_codes = payload.get("reason_codes", [])
    if isinstance(reason_codes, list):
        content.append("reason: " + ", ".join(str(code) for code in reason_codes))
    else:
        content.append("reason: " + str(reason_codes))
    explanation = payload.get("explanation")
    if explanation:
        content.append("\n" + str(explanation))
    if payload.get("rewritten_action") is not None:
        content.append("\neffective action (rewrite): " + _json(payload["rewritten_action"]))
    if payload.get("metadata"):
        content.append("\nevidence / metadata: " + _json(payload["metadata"]))
    if payload.get("defense_error"):
        content.append("\ndefense error: " + str(payload["defense_error"]), style="bold red")
    return content


def _outcome_content(label: str, payload: dict[str, Any]) -> Text:
    if label in {"tool_result", "retrieval_result"}:
        succeeded = payload.get("succeeded") is True
        content = Text("SUCCEEDED" if succeeded else "FAILED", style="green" if succeeded else "red")
        content.append("  tool=" + str(payload.get("tool", "unknown")))
        if payload.get("effects"):
            content.append("\neffects: " + _json(payload["effects"]))
        content.append("\nresult: " + _json(payload.get("result")))
        if payload.get("error"):
            content.append("\nerror: " + str(payload["error"]), style="bold red")
        return content
    if label == "human_confirmation":
        approved = payload.get("approved") is True
        content = Text("APPROVED" if approved else "DENIED", style="green" if approved else "red")
        content.append("  tool=" + str(payload.get("tool", "unknown")))
        content.append("\naction digest: " + str(payload.get("action_digest", "unknown")))
        return content
    if label in {"task_success", "task_failure"}:
        succeeded = label == "task_success"
        content = Text("TASK SUCCESS" if succeeded else "TASK FAILURE", style="green" if succeeded else "red")
        if payload.get("summary"):
            content.append("\n" + str(payload["summary"]))
        if payload.get("termination"):
            content.append("\ntermination: " + str(payload["termination"]))
        return content
    return Text(_json(payload))


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
        if e.get("type") == "defense_decision" and _payload(e).get("decision") == decision
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
    for event in rows:
        payload = _payload(event)
        label = str(event.get("type", "unknown"))
        content = _decision_content(payload) if label == "defense_decision" else _outcome_content(label, payload)
        event_label = Text(label + "\n" + str(event.get("actor", "")))
        table.add_row(str(event.get("step_id")), event_label, content)
    heading = Panel(
        Text("sentiel | action firewall\nUncalibrated risk indicators | synthetic data | simulated human approvals")
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
