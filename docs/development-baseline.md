# Historical development baseline

Recorded on 2026-09-23 after introducing the shared `make check` gate.

This checkpoint is tied to source commit `2f0cae2e2127fc689fda5180e574246acfcb1f2a`; its test counts
and latency are not the current baseline. For the latest tracked-code mock result, see
[structural-mock-v1](evaluation-results/structural-mock-v1.md). This older record is retained so its
original environment, source identity, and measurements are not overwritten.

## Environment and source

- Source commit: `2f0cae2e2127fc689fda5180e574246acfcb1f2a`
- Source manifest: clean Git working tree; tree SHA-256 `632d7e8f04bcd7d9370044c6a7bc17278a1b8987bc24b33f8b78fe6b8829cc3b`
- OS: Linux 6.8.0-124-generic, x86_64
- Python: CPython 3.12.3
- Local uv: 0.11.19
- Dependencies: committed `uv.lock`, installed with frozen resolution

## Local check gate

Commands:

```sh
uv sync --frozen --python 3.12
make check
```

Recorded results:

- Ruff: all checks passed; 140 files already formatted.
- Mypy: no issues in 78 source files.
- Main suite: 319 passed.
- Python-defense starter kit: 10 passed.
- Learned-monitor starter kit: 2 passed.
- Scenario validation: 49/49 passed.

Each starter-kit test run emitted two dependency deprecation warnings from Starlette and AnyIO. The
tests passed; the warnings are recorded here so a later dependency update can address them explicitly.

## Structural/mock evaluation

Command:

```sh
uv run --frozen sentiel evaluate --artifacts artifacts/phase1-baseline
```

The recorded run is in the ignored local artifact directory
`artifacts/phase1-baseline/rules-mock-20260923-210613/`. Its manifest identifies source commit
`2f0cae2e2127fc689fda5180e574246acfcb1f2a`, records a clean source tree, and uses the `mock` model,
structural rules mode, and seed 0.

| Measurement | Result |
| --- | ---: |
| Scenarios | 49 |
| Attack scenarios | 35 |
| Attack successes | 0/35 |
| Benign tasks completed | 14/14 |
| All tasks completed | 49/49 |
| Critical violations | 0 |
| Legitimate actions blocked | 8 |
| Median / p95 decision latency | 0.561 / 1.611 ms |

The full `results.json`, event traces, and manifest are generated locally and are not committed. This
is a repeatable regression baseline, not evidence of live-model robustness: the mock follows
reference plans and the scenario set is public. The README’s real-model evidence and limitations
remain separate.

## CI status

The GitHub Actions workflow runs the same `make check` gate on pushes, pull requests, and manual
dispatch. Hosted run [35913958694](https://github.com/yassinekolsi/sentinel/actions/runs/35913958694)
passed on commit `b65f65e` in 40 seconds, including dependency installation and `make check`. GitHub
reported an informational `ubuntu-latest` migration annotation; it did not fail the run.
