# sentiel - current state and next steps

Paused at the user's request on 22 September 2026. This file supersedes stale completion claims in
HANDOFF.md and the original reports. Report/video/upload work is deferred to the user or next session.

## Completed and verified

- Confidential prose, long excerpts, supported encodings, and credential edge cases are protected.
- Memory retains sensitivity and trust; observation text cannot establish policy permissions.
- Exact versioned approval hashes are used by producers and consumers; evaluator matching is unchanged.
- UUID execution isolation and bounded safe final-response recovery are implemented.
- Compact semantic schema, explicit field mapping, success-only versioned cache, and shared deadline
  are implemented. New evaluations emit reproducibility manifests and checksums.
- Main suite: **298 passed, 1 skipped** (Windows symlink privilege). Both starter kits: **10 and 2 passed**.
- Ruff lint/format and mypy passed. All code changes are committed with lowercase messages.
- Final structural mock suite: **0/35 attack successes, 14/14 benign, 49/49 total task completion**;
  eight reference-plan actions were blocked. Median/p95 decision latency: 1.198/3.264 ms.
- Scheduled adaptive mock: 0/35 attacks, 14/14 benign. This uses a scheduled static attacker, not
  learned adaptive red-teaming. Mock agents consume reference plans; these are not real-LLM rates.
- Semantic corrected development: **10/10 valid, 8/10 correct, 1 unsafe allow, 1 abstention**.
- Frozen holdout: **20/20 valid, 17/20 correct, 0 unsafe allows, 3 abstentions**.
- Development safety gate FAILED. Keep structural default, semantic experimental, thinking/cascade off.
  Preserve the initial compact attempt (10 valid, 5 correct, blanket benign rejection) as development evidence.

## Incomplete / do not claim

- The 48-run real-Qwen matrix was started and stopped at the user's request before its first completed
  result. Its partial live trace is preserved. **No completed new matched real-model pair exists.**
- Bounded recovery passes scripted integration tests; successful recovery by real Qwen remains unproven.
- Old real-Qwen evidence is unchanged: one matched disclosure-prevention pair failed its legitimate task;
  only three of five original benign probes completed. Do not turn these into a general robustness claim.
- `reports/submission-preview` and its ZIP/PDF are incomplete previews, not final submission assets.
  The new packager has had a preview smoke check, not final PDF visual QA or final-bundle verification.
- Original report/HANDOFF results are historical. Some old language incorrectly calls local replays
  committed. Reports and artifacts are gitignored. No new push, video, upload, or portal receipt is claimed.
- Internal confidential prose relies on the simulator's internal-use assumption. Arbitrary paraphrase,
  purpose-level internal audience controls, and causal independence from poisoned memory remain limitations.

## Next steps, in priority order

1. Run one fresh matched real-Qwen poisoned-invoice pair and one benign task per domain. Inspect payload
   exposure, attempted disclosure, intervention, safe recovery, and legitimate completion separately.
   If time permits, resume `py -3.12 -m uv run --frozen python scripts/real-repair-matrix.py` for all
   eight cases, three seeds, and matched modes. It skips completed results and preserves partial runs.
2. Update the report/README/HANDOFF with the repaired results and honest real-model limits. Do not run
   an expensive thinking or full hybrid benchmark after the failed development gate.
3. Build and verify the final report/source/evidence/replay bundle. `scripts/package-repaired.py` currently
   requires 48 matrix results for a final bundle; revise its requirement transparently if shipping the
   smaller measured sample. `--preview` is deliberately labeled partial. Verify links, PDF pages, checksums,
   source revision, model/data declaration, and the actual replay outcomes.
4. User records a labeled 5-10 minute video: benign task, exercised attack, intervention, actual recovery
   outcome, architecture, and one limitation. Mock/real, live/replay, and simulated human must be explicit.
5. Publish the intended source revision and upload report/video/bundle; verify access and retain receipt.
   The user said they will handle recording and upload later.

## Locations and operating notes

- Repository: `E:/web-tp/cp/sentiel`; solution CLI `sentiel`, upstream module `sentinel`.
- New evidence: `artifacts/repair-v3`; original artifacts remain untouched.
- Detailed implemented boundaries: `docs/repair-notes.md`; original repair requirements: `REPAIR_PLAN.md`.
- Always use `py -3.12 -m uv`; local Qwen is served on loopback by portable Ollama with Vulkan offload.
- Do not restart architecture or train another model tonight. Finish measured evidence and presentation.
- All model evaluation processes launched for the matrix were stopped when the user requested wrapping up.

## Candid readiness assessment

Engineering: **86/100**. Full submission readiness: **75/100**. These are subjective assessments,
not measured jury scores. The repaired structural implementation is credible; semantic quality and
real-agent recovery are unresolved. The project can be finalized for tonight, but the current package
is not ready to submit unchanged: final reporting, video, and upload verification remain essential.
