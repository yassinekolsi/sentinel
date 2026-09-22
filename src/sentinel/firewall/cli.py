"""Commands for local execution, evidence, and the bounded thinking experiment."""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path
from typing import Any

import httpx
import typer

from sentinel.cli import _model_factory
from sentinel.config import find_root, load_competition
from sentinel.core.events import Event, event_to_json
from sentinel.core.scenario import load_scenario
from sentinel.defenses.baselines import AllowAllDefense
from sentinel.evaluator.runner import AttackMode, RunConfig, run_scenario
from sentinel.firewall.engine import Firewall
from sentinel.firewall.semantic import LocalMonitor
from sentinel.storage.runs import ArtifactStore

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)


@app.command()
def serve(semantic: bool = False, cascade: bool = False, model: str = "qwen3:8b", port: int = 8080) -> None:
    """Serve the defense on loopback. Cascade is opt-in after the thinking experiment."""
    import uvicorn

    from sentinel.firewall.app import create_app

    uvicorn.run(create_app(semantic=semantic, cascade=cascade, model=model), host="127.0.0.1", port=port)


@app.command()
def doctor() -> None:
    """Inspect the local runtime without downloading or invoking models."""
    status: dict[str, Any] = {"python": platform.python_version(), "platform": platform.platform(), "ollama": None}
    try:
        with httpx.Client(trust_env=False, timeout=5) as client:
            response = client.get("http://127.0.0.1:11434/api/tags")
            response.raise_for_status()
            status["ollama"] = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        status["ollama"] = {"error": type(exc).__name__}
    typer.echo(json.dumps(status, indent=2))


@app.command()
def run(
    scenario: Path,
    model: str = "mock",
    semantic: bool = False,
    cascade: bool = False,
    monitor_model: str = "qwen3:8b",
    undefended: bool = False,
    adaptive: bool = False,
    artifacts: Path = Path("artifacts"),
) -> None:
    """Run one scenario, writing both a live stream and immutable final evidence."""
    execute([scenario], model, semantic, cascade, monitor_model, undefended, adaptive, artifacts)


@app.command()
def evaluate(
    scenarios: Path = Path("scenarios"),
    model: str = "mock",
    semantic: bool = False,
    cascade: bool = False,
    monitor_model: str = "qwen3:8b",
    undefended: bool = False,
    adaptive: bool = False,
    artifacts: Path = Path("artifacts"),
) -> None:
    """Evaluate a suite. Labels are used only after decisions, never by the defense."""
    from sentinel.core.scenario import discover_scenarios

    paths = discover_scenarios(scenarios)
    if not paths:
        raise typer.BadParameter("no scenarios found")
    execute(paths, model, semantic, cascade, monitor_model, undefended, adaptive, artifacts)


def execute(
    paths: list[Path],
    model: str,
    semantic: bool,
    cascade: bool,
    monitor_model: str,
    undefended: bool,
    adaptive: bool,
    artifacts: Path,
) -> None:
    from sentinel.firewall.reporting import summarize

    store = ArtifactStore(artifacts)
    mode = "allow_all" if undefended else "hybrid" if semantic else "rules"
    group = store.unique_group(f"{mode}-{model.replace(':', '-')}-{time.strftime('%Y%m%d-%H%M%S')}")
    directory = artifacts / group
    directory.mkdir(parents=True)
    live_path = directory / "events.live.jsonl"
    typer.echo(f"live trace: {live_path}")
    outcomes = []
    exposure = {}
    competition = load_competition(find_root() / "configs/local.yaml")

    def append_event(event: Event) -> None:
        with live_path.open("a", encoding="utf-8") as handle:
            handle.write(event_to_json(event) + "\n")

    config = RunConfig(
        root=find_root(),
        competition=competition,
        attack_mode=AttackMode.ADAPTIVE if adaptive else AttackMode.STATIC,
        model_factory=_model_factory(model),
        include_reference_plan=(model == "mock"),
        artifacts=store,
        artifact_group=group,
        event_sink=append_event,
    )
    for path in paths:
        scenario = load_scenario(path)
        defense = (
            AllowAllDefense()
            if undefended
            else Firewall(
                LocalMonitor(monitor_model) if semantic else None, cascade=cascade, audit_dir=directory / "defense"
            )
        )
        try:
            result = run_scenario(scenario, defense, config)
            outcomes.append(result.outcome.model_dump(mode="json"))
            # Evaluator-side exposure measurement. Never supplied to the defense.
            observed = [e for e in result.log.events if e.type.value in {"retrieval_result", "tool_result"}]
            payloads = [p.text for p in scenario.attack.payloads if p.text]
            exposure[scenario.id] = {
                "exact_payload_observed": any(
                    p in json.dumps(e.payload, ensure_ascii=False) for p in payloads for e in observed
                ),
                "measurement": "exact payload match; false may mean transformed/partial payload, not absence",
                "non_reference_action_proposed": any(not d.legitimate for d in result.outcome.decisions),
            }
            typer.echo(
                f"{scenario.id}: task={result.outcome.task_success} attack={result.outcome.attack_success} "
                f"termination={result.outcome.termination}"
            )
        finally:
            defense.close()
        report = {
            "model": model,
            "monitor_model": monitor_model if semantic else None,
            "mode": mode,
            "cascade": cascade,
            "attack_mode": config.attack_mode.value,
            "outcomes": outcomes,
            "exposure": exposure,
            "summary": summarize(outcomes),
        }
        (directory / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    typer.echo(json.dumps(report["summary"], indent=2))
    typer.echo(f"results: {directory / 'results.json'}")


@app.command()
def view(
    artifact: Path,
    follow: bool = False,
    step: int | None = None,
    kind: str | None = None,
    decision: str | None = None,
    export_html: Path | None = None,
) -> None:
    """Inspect/filter live or recorded evidence; presentation is redacted."""
    from sentinel.firewall.viewer import view as show

    show(artifact, follow=follow, step=step, kind=kind, decision=decision, export_html=export_html)


@app.command()
def thinking(
    cases: Path = Path("experiments/semantic-cases.json"),
    model: str = "qwen3:8b",
    output: Path = Path("artifacts/thinking.json"),
) -> None:
    """Run the predeclared paired ten-case reasoning experiment."""
    from sentinel.firewall.experiment import experiment

    experiment(cases, model, output)


@app.command()
def report(results: list[Path], output: Path = Path("reports/results.md")) -> None:
    """Compare saved runs without sending evaluation labels to the defense."""
    from sentinel.firewall.reporting import write_report

    write_report(results, output)


if __name__ == "__main__":
    app()
