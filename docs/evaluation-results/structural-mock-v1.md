# Structural mock result record — v1

This is a compact, tracked record of one mock evaluation. It is regression evidence, not an official
score, and does not measure live-model robustness.

## Run identity

| Field | Value |
| --- | --- |
| Recorded | 2026-09-23 20:55:57 UTC |
| Source commit | `445529301bd017a719a0eb8d28ba1461939496b2` (clean) |
| Source tree SHA-256 | `94cce0e87173ea44ad6c10bc434b7e9ba08fc317bb8a9b4add9c7b57ad8c881a` |
| Environment | CPython 3.12.3; Linux 6.8.0-124-generic, x86_64, glibc 2.39; uv 0.11.19 |
| Model and mode | `mock`, structural rules, static attacks, no semantic monitor or cascade |
| Seed | `0` |
| Scenarios | 49 total: 35 attack and 14 benign, from `scenarios/` |
| Scenario-set SHA-256 | `1577901616d3378edfb7174e69b0aea76948220bae3134799a06707f7e243817` |
| Effective-config SHA-256 | `6bfb62075cf2a8b67b99912f6a0c7e77531af61362fb4f8ea54a79a5ab931934` |
| Results SHA-256 | `5a406581e35fde0fb1d62e0d6b1971d60e65bd98dae3bc20af5af9b7bcd2abef` |
| Manifest SHA-256 | `83d2fb7e245fcab95a028387089abd7aa91c7369518dfa80ebfd03b690cb0fa2` |

The scenario-set digest is SHA-256 over the compact, key-sorted JSON array of `{path, sha256}` records,
sorted by scenario path. The effective-config digest uses SHA-256 over compact, key-sorted JSON of the
manifest's `effective_config`. The full manifest records each scenario hash, effective configuration,
source-file hash, run identity, and artifact checksum.

## Outcomes

| Measurement | Result |
| --- | ---: |
| Attack successes | 0 / 35 |
| Benign tasks completed | 14 / 14 |
| All tasks completed | 49 / 49 |
| Critical violations | 0 |
| Blocks on reference-plan-labeled legitimate actions | 8 |
| Median / p95 decision latency | 0.289 / 0.803 ms |

These eight blocks matched actions labeled legitimate by the evaluator because they matched a reference
plan. This is a false-block proxy, not proof those actions should have been allowed in attack context.
The mock follows the published plans and the scenario set is public; these results do not show how a live
model will behave.
Latency is specific to the recorded machine and run.

## Regeneration

From the repository root, with Python 3.12 and `uv` installed:

```sh
uv sync --frozen --python 3.12
uv run --frozen sentinel-firewall evaluate --scenarios scenarios --model mock --seed 0 --artifacts artifacts/reproductions
```

The CLI creates a new timestamped directory and avoids overwriting existing groups. The original raw
run was `artifacts/phase4-repo-readiness/rules-mock-20260923-215557/`; it contains `results.json`,
`manifest.json`, and event traces, and is excluded from Git by `.gitignore`. The hashes above identify
that local run. Re-running produces a new artifact identity and machine-specific latency measurements.
Future measurements should be recorded as a new version; keep this record and its hashes unchanged.
