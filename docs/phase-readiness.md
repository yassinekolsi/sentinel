# Phase audit — 23 September 2026

Scope: finish the defense, observability, reproducibility, and code/evidence package. The user
explicitly excluded video and technical-report work. No report/video was produced or updated in this
phase, and no external publication or portal submission is claimed.

The supplied specification awards 40 points to video/observability, 25 to the technical report,
15 to creativity/novelty, and 20 to engineering/responsible AI. These are jury assessments, not a
computed benchmark score. The PDF's published-set count is 19; this pinned starter-kit revision
actually contains 40 public and 9 validation scenarios. Evaluation uses the checked-in 49-case set.

| Requirement | Implementation / evidence | Status and limits |
| --- | --- | --- |
| Four legal interventions | `firewall/engine.py`; full mock trace exercises all four | Implemented |
| No scenario-specific decisions | Request-only policy/provenance/state; information-boundary tests | No scenario ID, filename, or expected outcome used by firewall |
| Live useful observability | `sentiel dashboard`; run/decision/search filters; linked action, decision, outcome; source classifications | Browser-tested on desktop/mobile; live file polling is labeled honestly |
| Risk, confidence, reasons | Decision cards, metadata, source trust/sensitivity, raw step details | Explicitly uncalibrated |
| Keep legitimate work useful | All 14 mock benign tasks; fresh Qwen benign task per domain | 3/3 real benign probes completed with no interventions; small sample |
| Real attack reaches defense | Two fresh matched Qwen poisoned-invoice pairs | Payload observed and credential proposal blocked; legitimate draft remains incomplete |
| Beyond keyword filtering | Stateful lifecycle enforcement, exact-action approval, copied-data flow, trust retained through memory, rechecked rewrites | Not a causal taint proof or complete semantic authorization |
| Ablation evidence | Matched allow-all vs structural, all 49 mock cases; historical semantic diagnostics | No full hybrid rerun after failed semantic safety gate |
| Adaptive/multi-step evidence | Full scheduled adaptive mock run and published multi-step/memory cases | Scheduled payloads, not a learned adaptive adversary |
| Reproducibility | Frozen dependencies, manifests, source/config/model hashes, tests, source archive | Historical missing metadata remains missing; greedy repeats are not independent samples |
| Portable evidence | `sentiel bundle` and `verify-bundle`; redacted offline replays, exact source snapshot, checksums | Report/video excluded; original manifests refer to original raw files |
| Responsible-AI declaration | README model/data declaration and safety boundaries | Simulated human, no production claims, known utility failure disclosed |
| Video / technical report | User-excluded deliverables | Not changed; user owns these separately |
| GitHub publication / submission | Local working tree and bundle prepared | No new commit, push, upload, or receipt claimed |

## Changes completed in this phase

- Added the browser observatory with offline interactive replay and a read-only loopback live endpoint.
  Attacker text is rendered as text, embedded JSON escapes script delimiters, and all presentation
  content is redacted before delivery. New event provenance exposes the source trust/sensitivity
  already visible to the defense. Historical omissions display as unknown.
- Added explicit, secret-free safety-feedback events. Generic blocked-final recovery now tells the
  model that no tool ran and that completion claims require successful tool results. The existing
  two-retry and scenario-step bounds remain. A fresh matched pair measured the change; draft
  completion still failed and that evidence is retained.
- Closed the agent runtime's remote-endpoint escape hatch and routed malformed Ollama envelopes
  into existing bounded model-error recovery. No base-agent system prompt or task grader was changed.
- Extended presentation redaction to explicit short and multiword credentials.
- Added source/file identity, archive-based evaluation, portable code/evidence packaging, raw-input
  checksum validation, and bundle tamper verification. The source ZIP contains working files, not
  only the last commit. Bundles reject unfinished traces and preserve historical source differences.
- Replaced stale README claims and historical handoff directions with current measured outcomes.

## Evidence and checks

`artifacts/phase-final/` preserves the new runs, including both failed-recovery pairs, and the generated
code/evidence bundle. Original `artifacts/repair-v3/` semantic development and frozen holdout evidence
is unchanged. Source and results are distinct; evaluator outcomes are never passed into the defense.

Main suite: 318 passed, one skipped because this Windows account cannot create symlinks. Starter
kits: 10 and 2 passed. Ruff lint/format and mypy are the source checks. Browser verification covers
run/decision filters, search, previous/next, replay controls, model/task/attack labels, provenance,
mobile overflow, and JavaScript errors. Screenshots and local browser scripts are in `.runtime/`.

## Remaining research limits

The optional monitor failed its development safety gate despite improved runtime validity. Keep it
experimental. Real Qwen can omit required tool work even after a safe retry. Broader matched tests,
paraphrase/encoding coverage, calibrated uncertainty, durable state, and the optional independent
AgentDojo evaluation would be future research. No finite checklist establishes maximum jury points.

The previously planned 48-run Qwen matrix is not complete. This phase deliberately records a smaller
measured sample: two matched attack pairs and three benign probes. It does not relabel that sample
as the full matrix or silently exclude failed tasks.
