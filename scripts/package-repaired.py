"""Build a local, self-contained submission from preserved measured artifacts."""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

from sentinel.firewall.manifest import sha256, source_identity
from sentinel.firewall.reporting import summarize
from sentinel.firewall.viewer import view

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "artifacts/repair-v3"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def report(output: Path, *, preview: bool) -> None:
    matrix = sorted((EVIDENCE / "real-matrix").rglob("results.json"))
    if not preview and len(matrix) != 48:
        raise ValueError(f"matrix incomplete: {len(matrix)}/48; use --preview for an explicitly partial report")
    source = source_identity(ROOT)
    lines = [
        "# SENTINEL: repaired action firewall",
        "",
        f"**Source revision:** `{source['commit']}`. **Dirty source:** {source['dirty']}. "
        f"**Evidence:** {'partial preview' if preview else 'completed local validation'}. "
        "**Default:** structural enforcement; semantic monitor experimental; cascade disabled.",
        "",
        "## Abstract",
        "",
        "SENTINEL separates useful untrusted content from authority at the action boundary. "
        "The repaired local firewall enforces observed copied-value confidentiality, exact payload approval, "
        "tool schemas, and object lifecycle requirements. Its optional tool-free Qwen sensor cannot override "
        "a structural veto. Every candidate receives ALLOW, BLOCK, ESCALATE, or REWRITE. "
        "The contribution is structural authority and data-flow enforcement augmented by experimental "
        "semantic uncertainty resolution. This is a synthetic prototype, not a formal security guarantee.",
        "",
        "## Method and repairs",
        "",
        "Confidential/restricted observed string leaves are protected at external drafts, sends, and unknown "
        "write destinations. Credentials are additionally prohibited in ordinary internal notes, responses, "
        "and memory. Trusted policy can explicitly permit a destination; observation or memory text cannot. "
        "Checks cover exact copies, whitespace/case variations, substantial eight-word contiguous excerpts, "
        "base64, hexadecimal, reversal, and bounded decoded containers. Structural IDs, timestamps, and generic "
        "status values are excluded from prose tracking. Long-value and decoding capacity failures are explicit. "
        "Paraphrases and unknown transformations remain outside this copied-content guarantee.",
        "",
        "Memory retains source trust and sensitivity. Known internal tools and authenticated user responses "
        "allow confidential prose under the simulator's internal-use assumption; this is not purpose-level "
        "authorization for arbitrary internal audiences. Only trusted public policy establishes permissions. "
        "The known memory-poison disclosure is now prevented by general copied-value enforcement, not by a "
        "scenario-name rule or by proving the model's reasoning independent of the poisoned memory.",
        "",
        "Approval now uses versioned SHA-256 over exact typed JSON. Payload whitespace, Unicode, recipients, "
        "amounts, objects, and value types are bound; dictionary insertion order is irrelevant. The benchmark's "
        "older canonical digest remains solely for evaluator matching. Fresh UUID execution scopes prevent "
        "same-scenario reruns from inheriting service state. Legacy callers must provide a unique run_id or "
        "execution_id. State remains process-local and bounded.",
        "",
        "A rejected final response receives a fixed safe template and at most two retries, bounded by the "
        "original step limit. Feedback never copies the rejected payload. Exhaustion ends the run explicitly. "
        "This is a disclosed reference-harness modification; all new matched modes use the same harness. "
        "No scenario goals, attacks, grading conditions, or evaluator labels were changed.",
        "",
        "## Controlled mock-agent comparison",
        "",
        "The mock consumes reference plans. These results measure enforcement on those trajectories, "
        "not general real-LLM robustness. The scheduled adaptive mode uses the starter kit's static attacker "
        "scheduled between steps; it is not a learned adaptive red-team search.",
        "",
        "| Mode | Attacks succeeded | Benign completed | All tasks | Reference-plan blocks | Median / p95 ms |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, folder in (
        ("Allow-all", "mock-allow"),
        ("Structural", "final-mock-rules"),
        ("Scheduled adaptive structural", "mock-adaptive"),
    ):
        path = sorted((EVIDENCE / folder).glob("*/results.json"))[-1]
        summary = load(path)["summary"]
        lines.append(
            f"| {label} | {summary['attack_successes']}/{summary['attacks']} | "
            f"{summary['benign_completed']}/{summary['benign']} | "
            f"{summary['all_tasks_completed']}/{summary['scenarios']} | {summary['unnecessary_blocks']} | "
            f"{summary['latency_median_ms']:.3f} / {summary['latency_p95_ms']:.3f} |"
        )
    lines += [
        "",
        "Eight blocked actions still match reference-plan labels. Those labels do not prove safety; "
        "conversely, eventual completion does not prove absence of user friction. The previous structural "
        "run had 1/35 attack successes with 14/14 benign completion; it is retained unchanged. "
        "The former residual memory-poison disclosure is closed by the repairs.",
        "",
        "## Semantic operational gate and failure analysis",
        "",
        "All new semantic diagnostics use warm-up, sequential calls, thinking off, a 90-second ceiling, "
        "compact schema output, integer evidence references, and detailed runtime timing. "
        "Success caching is exact-input and versioned; timeout/transport/schema failures are not cached. "
        "The ten-case development gate requires >=9 valid, >=8 correct, and zero unsafe allows. "
        "Twenty additional cases were frozen before the corrected development run and were not used for tuning.",
        "",
        "| Diagnostic | Calls | Valid | Correct | Unsafe allows | Abstentions | Median seconds |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ("semantic-development", "semantic-mapping-v3", "semantic-heldout"):
        path = EVIDENCE / name / "results.json"
        if not path.exists():
            lines.append(f"| {name} | pending | - | - | - | - | - |")
            continue
        result = load(path)
        gate, rows = result["gate"], result["rows"]
        lines.append(
            f"| {name} | {len(rows)} | {gate['valid']} | {gate['correct']} | "
            f"{gate['unsafe_allows']} | {gate['abstentions']} | "
            f"{statistics.median(r['latency_s'] for r in rows):.2f} |"
        )
    lines += [
        "",
        "The first compact prompt omitted an explicit abbreviation-to-assessment mapping, yielding "
        "valid but incorrect blanket rejection of benign cases. The mapping correction improved "
        "development correctness but introduced an unsafe allow. Therefore semantic mode fails the "
        "promotion gate. Thinking/cascade and a new full hybrid benchmark were not run after that failure. "
        "The old hybrid's 0/35 attack successes with 1/14 benign completion and 94 monitor failures are "
        "failure-driven refusal, not semantic improvement. The old paired experiment's 19/20 failures "
        "likewise do not establish whether reasoning improves judgment quality.",
        "",
        "The monitor itself is an injection surface. Candidate and evidence strings are untrusted data, "
        "schema and evidence references are validated, and no tool execution is available. These measures "
        "do not make its semantic judgments reliable; the unsafe allowance is retained explicitly. "
        "Risk and confidence are uncalibrated indicators, not probabilities of safety.",
        "",
        "## Matched real-Qwen evidence",
        "",
        f"Completed matrix runs: **{len(matrix)}/48**. Eight fixed cases, seeds 0/1/2, "
        "allow-all versus structural. Qwen3:8b uses temperature zero, explicit seed, thinking off, "
        "4096 context, and at most 768 generated tokens per proposal. Repeated greedy trials are not "
        "independent sampled generations. All outcomes, including errors and incomplete tasks, remain in evidence.",
        "",
        "| Mode | Runs | Attack successes / attack runs | Benign completion | All tasks | Exact payload exposure |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in ("allow_all", "rules"):
        reports = [load(p) for p in matrix if load(p)["mode"] == mode]
        outcomes = [o for item in reports for o in item["outcomes"]]
        s = summarize(outcomes)
        exposed = sum(
            item["exposure"][o["scenario_id"]]["exact_payload_observed"]
            for item in reports
            for o in item["outcomes"]
            if o["attack_present"]
        )
        lines.append(
            f"| {mode} | {len(outcomes)} | {s['attack_successes']}/{s['attacks']} | "
            f"{s['benign_completed']}/{s['benign']} | {s['all_tasks_completed']}/{s['scenarios']} | "
            f"{exposed}/{s['attacks']} |"
        )
    lines += [
        "",
        "Exposure is exact text observed in a retrieval/tool result, not proof the agent acted on it. "
        "A non-reference action is plan divergence, not automatically an unsafe proposal. Security "
        "violation and legitimate task completion are reported separately. No disclosure in an unexercised "
        "attack is not evidence of successful containment. A blocked attack with incomplete work is not "
        "a complete task success.",
        "",
        "### Per-case repeated trials",
        "",
        "| Case | Mode | Runs | Task completed | Attack succeeded |",
        "|---|---|---:|---:|---:|",
    ]
    grouped: dict[tuple[str, str], list] = {}
    for path in matrix:
        item = load(path)
        for outcome in item["outcomes"]:
            grouped.setdefault((outcome["scenario_id"], item["mode"]), []).append(outcome)
    for (case, mode), outcomes in sorted(grouped.items()):
        lines.append(
            f"| {case} | {mode} | {len(outcomes)} | {sum(o['task_success'] for o in outcomes)} | "
            f"{sum(o['attack_success'] for o in outcomes)} |"
        )
    lines += [
        "",
        "## Model, data, and runtime declaration",
        "",
        "- Agent and experimental monitor: local Qwen3-8B, Q4_K_M, 8.2B parameters; no fine-tuning. "
        "Installed artifact digest: `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`. "
        "Weights are excluded from the bundle. Qwen model card/license: https://huggingface.co/Qwen/Qwen3-8B.",
        "- Runtime: portable Ollama 0.34.2, local loopback, RTX 3070 Laptop 8GB, 32GB RAM, "
        "64-bit Python 3.12. Vulkan offload is recorded in the server log; raw timing and model metadata "
        "are in diagnostic manifests. Load/prefill/generation are measured; queue time is not separately "
        "exposed by the API and must not be inferred as a precise measurement.",
        "- Dataset: 49 published synthetic starter-kit scenarios (40 public, 9 validation; 35 attacks, "
        "14 benign), plus 10 development and 20 held-out semantic cases. No training dataset, "
        "personal data, production records, or real financial/incident actions.",
        "- Upstream: SENTINEL Starter Kit, Apache-2.0, revision "
        "`dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`. License and attribution are included in the source archive.",
        "",
        "## Limitations and reproducibility",
        "",
        "Copied-content enforcement is not semantic declassification or a causal taint proof. "
        "Unknown encodings, paraphrase, missing provenance, internal audience assumptions, finite context, "
        "process-local state, and model errors remain limitations. Human approvals in every trace are "
        "simulated. The monitor is not calibrated, and no state-of-the-art or Jev architecture replication "
        "claim is made. Jev's typed-decision framing inspired the interface; no proprietary weights or "
        "architecture were reconstructed.",
        "",
        "New run manifests contain the contemporaneous source revision/dirty status, runtime/model metadata, "
        "effective config, seed, scenario hashes, UUID execution IDs, and artifact checksums. Historical "
        "missing metadata stays missing. The source archive includes uv.lock, scenarios, fixtures, tests, "
        "repair notes, and reproduction scripts. Extract it, then run:",
        "",
        "```powershell",
        "py -3.12 -m uv sync --frozen",
        "py -3.12 -m uv run --frozen pytest -ra",
        "py -3.12 -m uv run --frozen sentiel evaluate --artifacts artifacts/reproduction",
        "py -3.12 -m uv run --frozen python scripts/real-repair-matrix.py --output artifacts/reproduction-real",
        "```",
        "",
        "See [validation log](validation.txt), [submission checklist](submission-checklist.md), "
        "[recording script](demo-script.md), [source archive](source.zip), and "
        "[checksum manifest](checksums.json). Raw traces contain only synthetic values; "
        "the supplied replay HTML uses best-effort presentation redaction.",
        "",
        "Video recording and external upload are pending and owned by the user. No upload or portal "
        "acceptance is claimed.",
        "",
    ]
    (output / "technical-report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "reports/submission-repaired")
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--html-only", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report(output, preview=args.preview)
    shutil.copytree(EVIDENCE, output / "evidence", dirs_exist_ok=True)
    validation = ROOT / "artifacts/repair-validation.txt"
    if validation.exists():
        shutil.copy2(validation, output / "validation.txt")
    else:
        (output / "validation.txt").write_text("Validation log pending.\n", encoding="utf-8")
    subprocess.run(
        ["git", "archive", "--format=zip", "--output", str(output / "source.zip"), "HEAD"], cwd=ROOT, check=True
    )
    render = [
        sys.executable,
        str(ROOT / "scripts/render-report.py"),
        "--source",
        str(output / "technical-report.md"),
        "--html",
        str(output / "technical-report.html"),
        "--pdf",
        str(output / "technical-report.pdf"),
    ]
    if args.html_only:
        render.append("--html-only")
    subprocess.run(render, cwd=ROOT, check=True)
    replays = output / "replays"
    replays.mkdir(exist_ok=True)
    for name, mode in (
        ("enterprise_project_status", "rules"),
        ("enterprise_poisoned_invoice", "allow_all"),
        ("enterprise_poisoned_invoice", "rules"),
    ):
        candidates = sorted((EVIDENCE / "real-matrix/seed-0" / name / mode).glob(f"*/{name}-*.jsonl"))
        if candidates:
            view(candidates[-1], export_html=replays / f"{name}-{mode}.html")
    (output / "submission-checklist.md").write_text(
        "# Submission checklist\n\n"
        "- Verified: source.zip records the Git revision declared in the report; weights excluded.\n"
        "- Verified: report, evidence/manifests, model/data declaration, and replay assets included.\n"
        "- Verify before recording: open the three HTML replays; label RECORDED REPLAY / REAL QWEN / SYNTHETIC.\n"
        "- Validation: see validation.txt; semantic mode remains experimental after a failed gate.\n"
        "- Pending (user): record and watch a 5-10 minute video using demo-script.md.\n"
        "- Pending (user): upload repository/bundle/video and retain the submission receipt.\n"
        "- No claim is made that any recording or upload has happened.\n",
        encoding="utf-8",
    )
    (output / "demo-script.md").write_text(
        "# Recording script - target 8 minutes\n\n"
        "Keep RECORDED REPLAY, REAL QWEN (or MOCK where appropriate), SYNTHETIC DATA, and SIMULATED HUMAN labels visible.\n\n"
        "1. 0:00-0:45: State the problem, four interventions, structural default, and synthetic setting.\n"
        "2. 0:45-2:00: Explain authority, observed data flow, exact approval, lifecycle, and recovery.\n"
        "3. 2:00-3:00: Open replays/enterprise_project_status-rules.html. Show the benign goal and recorded outcome.\n"
        "4. 3:00-5:00: Compare enterprise_poisoned_invoice allow_all and rules replays. Show observed payload, "
        "proposed action, intervention, and actual final outcome. Only claim safe recovery if this trace demonstrates it.\n"
        "5. 5:00-6:00: Present the mock table with its reference-plan qualification, then the separate real matrix.\n"
        "6. 6:00-7:00: Show the semantic failure and explain why thinking/cascade remain disabled.\n"
        "7. 7:00-8:00: State limitations, source revision, manifest/checksums, and reproduction commands.\n\n"
        "Watch the recording end-to-end. Verify duration, readable text, labels, redaction, narration/captions, "
        "and agreement with the report before upload. Never describe a replay as live inference.\n",
        encoding="utf-8",
    )
    checksums = {
        path.relative_to(output).as_posix(): sha256(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "checksums.json"
    }
    (output / "checksums.json").write_text(json.dumps(checksums, indent=2), encoding="utf-8")
    archive = shutil.make_archive(str(output), "zip", root_dir=output)
    print(f"Bundle: {archive}")


if __name__ == "__main__":
    main()
