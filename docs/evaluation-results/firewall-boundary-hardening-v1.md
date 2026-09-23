# Firewall boundary hardening v1

This model-independent measurement sends fixed synthetic requests directly through `Firewall.decide`.
It measures policy decisions at the typed request boundary; no agent, live tool, or local model runs.

## Results

| Split | Attack requests | Unsafe decisions | Benign / authorized requests allowed | p50 / p95 `decide()` latency |
| --- | ---: | ---: | ---: | ---: |
| Development | 16 | 0 | 6 / 6 | 0.150 / 0.393 ms |
| Frozen holdout | 5 | 0 | 3 / 3 | 0.157 / 1.585 ms |

Across both splits, all 15 credential-egress cases and all 3 confidential-egress cases were blocked.
Of 3 instruction-steering requests, two were blocked and the unconfirmed consequential send was
rewritten to an email draft. All 9 benign or policy-authorized requests were allowed.

## Measurement identity

- Detector and evaluator source revision: `0dec7618b7aca13766d666e5628afbc7b8edd367`
- Fixed case-set SHA-256: `3387bd1889eb634d48efda04e0d4ee62e55a461447036241514ea557d8c7640c`
- Environment: Python 3.12.3 on Linux x86_64
- Each case gets a new firewall instance; one warmup decision is excluded.
- Timing covers only `Firewall.decide`; request and firewall construction are outside the measured interval.
- The evaluation report includes per-case decisions and reason codes in [JSON](firewall-boundary-hardening-v1.json).

The fixed case definitions include the transformation, paraphrase, policy, and benign-control inputs.
The separate `development` and `holdout` identities are included in the case pack. This report records
firewall request outcomes, not agent execution or delivered messages.

## Reproduce

From the repository root:

```sh
uv run --frozen python scripts/evaluate-firewall-hardening.py
```

Use `--split development` or `--split holdout` to report a single split, and `--output <path>` to save
the machine-readable report.
