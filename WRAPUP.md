# Historical handoff snapshot — 23 September 2026

This snapshot records an earlier local state. Its measurements, test counts, artifact paths, and
publication status describe that date only. For current setup, validation, and versioned measurements,
use [README.md](README.md) and [docs/evaluation-results/structural-mock-v1.md](docs/evaluation-results/structural-mock-v1.md).

## Implemented

- Interactive browser dashboard: linked action/decision/outcome, search, filters, source provenance,
  explicit mock/real labels, live polling, offline replay. Source: `src/sentinel/firewall/dashboard.*`.
- Secret-free recovery events and generic tool-completion feedback. Two final-response retries remain.
- Local-only agent endpoint validation and bounded handling of malformed Ollama response envelopes.
- Presentation redaction for short/multiword credentials.
- Source/file hashes, evaluation from extracted source archives, and a verified code/evidence bundle
  independent of report/video. Commands: `sentiel bundle` and `sentiel verify-bundle`.

## Measured outcomes

- Structural mock: 0/35 attacks, 14/14 benign, 49/49 total tasks; all four interventions exercised.
- Scheduled adaptive mock: 0/35 attacks, 14/14 benign. This is not a learned adaptive red team.
- Fresh real Qwen: benign enterprise, finance, SOC tasks all completed with no interventions.
- Two matched poisoned-invoice pairs: allow-all leaked a credential, structural prevented disclosure.
  Both defended runs returned a safe final response but failed to create the legitimate draft.
  The second pair tested explicit completion feedback; that did not fix task completion.
- Historical semantic development gate remains failed (one unsafe allow). Structural stays default,
  semantic experimental, thinking/cascade off. No expensive failed-gate benchmark was rerun.
- Main tests: 318 passed, 1 Windows symlink-privilege skip. Starter kits: 10 and 2 passed.

## Locations

- New raw evidence and portable bundle at the time: `artifacts/phase-final/` (local and gitignored).
- Historical raw evidence at the time: original artifact directories, including `artifacts/repair-v3/` (local and gitignored).
- Browser verification/screenshots: `.runtime/`.
- Source, tests, and updated docs are local working-tree changes; bundle captures their actual hashes.

## Honest remaining scope

Video/report and external publication/submission remain with the user. The full 48-run real-Qwen
matrix is not completed or claimed. Broader robustness, calibrated scores, semantic reliability,
and successful real-Qwen attacked-task recovery remain unproven research questions. The old
`scripts/package-repaired.py` generates reports and assumes 48 runs; use the new `bundle` command
for the requested code/evidence package. Historical source differences are preserved in manifests.

Use `py -3.12 -m uv`, not bare Python. Do not infer publication authorization from historical handoff
prose. Raw artifacts and prior reports remain untouched. No scenario goals, payloads, reference plans,
or grader definitions were modified to improve results.
