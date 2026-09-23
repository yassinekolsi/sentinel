# Security model

## Principles

1. **Synthetic only.** Every person, organization, account, domain (`*.example`), and secret is fictional.
   Canary values are generated per run from the scenario seed and the run seed.
2. **Offline by construction.** The tool registry refuses any tool that declares a capability outside
   `read`, `write`, `draft`, `message`, `state_change`; there is no `network` capability. Simulator modules
   import no networking or process libraries (enforced by `tests/security/test_offline_and_leaks.py`).
3. **Declared surfaces only.** Scenario attacks change text only where scenarios allow, through one validator.
4. **Observable evidence, not chain-of-thought.** Events record actions, decisions, reason codes,
   provenance, tool traces, and state transitions. Defenses are never asked for private reasoning.
5. **Safe defaults.** The optional HTTP defense adapter can fail closed on timeouts, transport
   failures, bad status codes, and malformed responses.
6. **Simulator-only ground truth stays out of the agent loop.** Reference plans and legitimacy labels never
   enter defense requests, even though the scenario library itself is fully published. This is what
   lets `sentinel eval` work as an honest self-test rather than something you could accidentally
   hard-code to.

## Participant input handling

| Input | Safeguard |
| --- | --- |
| Scenario YAML | `yaml.safe_load` only; 256 KB limit; strict Pydantic models (`extra="forbid"`) |
| Fixture paths | relative, `.json`, no `..`, resolved within the benchmark root (symlink escapes rejected) |
| Policy profiles | name pattern, resolved within `policies/` |
| Defense requests | 256 KiB HTTP body cap before JSON parsing; bounded conversation, provenance, policy, and text fields; strict schema |
| Defense responses | strict `DefenseDecision` schema, 64 KB limit, no redirects followed, reason code pattern, 4 KB metadata |
| Rewrites | cannot make an action final, cannot name an unknown tool; the policy engine still checks the result |
| Scenario mutations | declared surface, allowed operation, `max_chars`, no control characters, budget |
| Artifact names | sanitized to a single safe path component; files opened in exclusive-create mode |
| Optional containerized solution | static checker looks for a non-root Dockerfile user, dangerous Docker privileges, manifest errors, secret patterns, and escaping symlinks |

Stateful HTTP defenses should implement idempotent `DELETE /v1/executions/{execution_id}`. The
reference client calls it when each run ends. Keep the active-execution capacity guard fail-closed
because clients can disconnect before cleanup; never evict a live scope to make room.

## Policy and evidence boundaries

`policy_context` is a typed, bounded control-plane object. The evaluator builds it from the validated
scenario, active policy profile, registered tools, and simulator fixture settings. It carries the
policy identifier and version, permitted and consequential tools, confirmation requirements, internal
email domains, destination-and-data-kind disclosure permissions, and structured policy rules. It is
separate from `user_goal`, `candidate_action`, `conversation`, and `observation`; text in those fields
cannot add permissions or change the active policy. The defense API rejects unknown fields inside
`policy_context` rather than accepting arbitrary policy keys. Policy profiles can grant explicit
`public_disclosure_permissions`; the default is no disclosure grants.

Schema validation checks shape and bounds; it does not authenticate the request sender. Treat policy
fields as authoritative only when the request comes from the evaluator or another trusted harness.
If a defense service is exposed beyond that caller, protect the route with appropriate authentication
and network restrictions. The built-in defense server binds to loopback by default, though its host
can be configured.

Provenance is likewise supplied by the evaluator as evidence metadata, not inferred from the content
it labels. Missing or incomplete provenance is classified as unknown. The firewall conservatively
retains the most restrictive trust and sensitivity seen for a repeated protected value. Secret field
names are classified by their components, and protected values are checked at output sinks after
Unicode and separator normalization, common text unescaping, bounded encoding-chain decoding, and
high-overlap fact matching for confidential text. Destination permissions and tool authority remain
the structural controls. The [versioned boundary record](evaluation-results/firewall-boundary-hardening-v1.md)
lists the exact synthetic request cases and measured outcomes; it does not rely on a local model.

## Avoiding accidental hard-coding in self-testing

There is no held-out scenario split in this challenge — everything under `scenarios/` is published.
That makes it easy to unintentionally overfit to the published library while using `sentinel eval`
to iterate. Per the Defense Rules ([participant-guide.md](participant-guide.md)), a decision must
come from the agent state, candidate action, provenance, policy, and observed content — never from a
scenario id, filename, or canary format. Judges reading your report and code will look for this.
You may author extra scenarios outside this checkout to sanity-check your defense, but this changes
nothing about how your submission is judged.

## Data handling

Artifacts contain only synthetic data. They are safe to include in your repository or technical
report as evidence for your video's trace.

## Responsible disclosure

See [SECURITY.md](../SECURITY.md). Report vulnerabilities privately to
`skander.yacoubi@supcom.tn`; do not test them against shared infrastructure.
