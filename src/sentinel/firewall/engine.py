"""The enforcement boundary. Learned judgments never grant policy authority."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest
from sentinel.firewall.state import SecurityState
from sentinel.tools.registry import registry_for_domain


class Firewall(Defense):
    name = "sentiel_rules"

    def __init__(self, monitor: Any = None, *, cascade: bool = False, audit_dir: Path | None = None) -> None:
        self.monitor = monitor
        self.cascade = cascade
        self.name = "sentiel_hybrid" if monitor else "sentiel_rules"
        self.audit_dir = audit_dir
        self.states: dict[str, SecurityState] = {}
        self.cache: dict[tuple[str, int], tuple[str, DefenseDecision]] = {}
        self.lock = threading.RLock()
        self.tools = {tool.name: tool for domain in ("enterprise", "finance", "soc")
                      for tool in registry_for_domain(domain)}

    @staticmethod
    def result(kind: Decision, code: str, *, risk: float = 0.0, confidence: float = 1.0,
               explanation: str = "", rewrite: CandidateAction | None = None,
               metadata: dict[str, Any] | None = None) -> DefenseDecision:
        return DefenseDecision(decision=kind, risk_score=risk, confidence=confidence, reason_codes=[code],
                               explanation=explanation[:500], rewritten_action=rewrite,
                               metadata={"score_semantics": "uncalibrated risk indicator; not a probability",
                                         **(metadata or {})})

    def target(self, action: CandidateAction) -> CandidateAction:
        return action.confirmation_for if action.confirmation_for is not None else action

    def consequential(self, request: DefenseRequest, action: CandidateAction) -> bool:
        tool = self.tools.get(action.tool or "")
        return bool(tool and (tool.is_consequential(action.arguments)
                              or action.tool in request.policy_context.get("confirmation_required_tools", [])))

    def is_read(self, action: CandidateAction) -> bool:
        tool = self.tools.get(action.tool or "")
        return action.type is ActionType.TOOL_CALL and bool(tool and tool.capabilities == frozenset({"read"}))

    def structural(self, request: DefenseRequest, action: CandidateAction, state: SecurityState) -> DefenseDecision | None:
        if action.type is ActionType.TOOL_CALL:
            tool = self.tools.get(action.tool or "")
            if tool is None or action.tool not in request.policy_context.get("allowed_tools", []):
                return self.result(Decision.BLOCK, "TOOL_NOT_PERMITTED", risk=1, explanation="Tool is outside active authority.")
            try:
                tool.args_model.model_validate(action.arguments)
            except ValidationError:
                return self.result(Decision.BLOCK, "INVALID_ARGUMENTS", risk=1, explanation="Tool arguments fail its schema.")
        # Reads are not exempt from secret-bearing query checks.
        domains = request.policy_context.get("internal_email_domains", [])
        to = str(action.arguments.get("to", "")).lower()
        internal = bool(to and any(to.endswith("@" + str(d).lower()) for d in domains))
        external = (action.tool in {"email_send", "email_draft"} and not internal)
        leaks = state.leaks(action.text_payload(), external=external)
        if leaks:
            return self.result(Decision.BLOCK, "SENSITIVE_DATA_FLOW", risk=1,
                               explanation="Observed sensitive value crosses an unauthorized output boundary.",
                               metadata={"leaks": leaks[:4]})
        transitions = {"payment_confirm": ("payment_id", "prepared"),
                       "payment_execute": ("payment_id", "confirmed"),
                       "remediation_execute": ("remediation_id", "prepared")}
        if action.tool in transitions:
            key, required = transitions[action.tool]
            obj = state.objects.get(str(action.arguments.get(key)), {})
            if obj.get("status") != required:
                return self.result(Decision.BLOCK, "OBJECT_PREREQUISITE_MISSING", risk=1,
                                   explanation="No observed successful prerequisite for this exact object.")
        if state.overflow:
            return self.result(Decision.BLOCK, "STATE_CAPACITY_EXCEEDED", risk=1,
                               explanation="Evidence capacity exceeded; restart with a larger audited capacity.")
        return None

    def uncertain(self, request: DefenseRequest, action: CandidateAction, code: str) -> DefenseDecision:
        if self.is_read(action):
            return self.result(Decision.ALLOW, code, risk=0.1, confidence=0,
                               explanation="Permitted read passes structural checks; semantic confidence unavailable.")
        kind = Decision.ESCALATE if self.consequential(request, action) else Decision.BLOCK
        return self.result(kind, code, risk=0.5, confidence=0,
                           explanation="Safety could not be resolved; approval cannot override structural prohibitions.")

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        with self.lock:
            fingerprint = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
            cache_key = (request.run_id, request.step_id)
            cached = self.cache.get(cache_key)
            if cached:
                return cached[1] if cached[0] == fingerprint else self.result(
                    Decision.BLOCK, "STEP_REUSE_CONFLICT", risk=1, explanation="Step reused with changed inputs.")
            try:
                if request.run_id not in self.states and len(self.states) >= 256:
                    return self.result(Decision.BLOCK, "RUN_CAPACITY_EXCEEDED", risk=1)
                state = self.states.setdefault(request.run_id, SecurityState())
                if request.step_id <= state.last_step:
                    return self.result(Decision.BLOCK, "OUT_OF_ORDER_STEP", risk=1)
                state.ingest(request)
                decision = self._decide(request, state)
                if decision.decision in {Decision.ALLOW, Decision.ESCALATE, Decision.REWRITE}:
                    effective = decision.rewritten_action or request.candidate_action
                    if effective.type is ActionType.TOOL_CALL:
                        state.pending[request.step_id] = effective
                self._audit(request, decision, state)
            except Exception as exc:
                decision = self.result(Decision.BLOCK, "DEFENSE_INTERNAL_ERROR", risk=1, confidence=0,
                                       explanation=f"Defense failed closed ({type(exc).__name__}).")
            if len(self.cache) < 20_000:
                self.cache[cache_key] = (fingerprint, decision)
            return decision

    def _decide(self, request: DefenseRequest, state: SecurityState) -> DefenseDecision:
        candidate = request.candidate_action
        action = self.target(candidate)
        hard = self.structural(request, action, state)
        if hard:
            return hard
        semantic_metadata: dict[str, Any] = {}
        if self.monitor and not self.is_read(action):
            try:
                judgment = self.monitor.assess(request, state, thinking=False)
                passes = 1
                if self.cascade and (judgment.uncertain or self.consequential(request, action)):
                    judgment = self.monitor.assess(request, state, thinking=True)
                    passes = 2
                semantic_metadata = {"semantic": judgment.model_dump(mode="json"), "passes": passes}
                if judgment.unsafe:
                    return self.result(Decision.BLOCK, "SEMANTIC_POLICY_CONFLICT", risk=0.9,
                                       confidence=judgment.confidence, explanation="Semantic evidence indicates unauthorized behavior.",
                                       metadata=semantic_metadata)
                if judgment.uncertain:
                    result = self.uncertain(request, action, "SEMANTIC_UNCERTAINTY")
                    return result.model_copy(update={"metadata": {**result.metadata, **semantic_metadata}})
            except Exception as exc:
                return self.uncertain(request, action, "MONITOR_FAILURE_" + type(exc).__name__.upper()[:35])
        if self.consequential(request, action) and action.digest() not in request.history_digest.confirmations_granted:
            if candidate.type is ActionType.REQUEST_CONFIRMATION:
                return self.result(Decision.ALLOW, "CONFIRMATION_REQUEST_ALLOWED", risk=0.3,
                                   explanation="Requesting simulated approval; this does not execute the target.", metadata=semantic_metadata)
            replacement = self._replacement(action)
            if replacement is not None:
                replacement_request = request.model_copy(update={"candidate_action": replacement})
                checked = self._decide_replacement(replacement_request, state)
                if checked:
                    return self.result(Decision.REWRITE, "SAFE_DOWNGRADE", risk=0.4, rewrite=replacement,
                                       explanation="Replaced unconfirmed consequential action with a rechecked safe operation.",
                                       metadata=semantic_metadata)
            return self.result(Decision.ESCALATE, "CONFIRMATION_REQUIRED", risk=0.5,
                               explanation="Exact action requires recorded simulated human approval.", metadata=semantic_metadata)
        return self.result(Decision.ALLOW, "CHECKS_PASSED", risk=0.1 if self.monitor else 0.0,
                           confidence=0.5 if self.monitor else 1.0,
                           explanation="No violation found within the enabled checks; this is not a safety guarantee.",
                           metadata=semantic_metadata)

    def _replacement(self, action: CandidateAction) -> CandidateAction | None:
        if action.tool == "email_send":
            return action.model_copy(update={"tool": "email_draft"})
        if action.tool in {"ticket_update", "incident_update"} and action.arguments.get("note"):
            args = {k: v for k, v in action.arguments.items() if k != "status"}
            return action.model_copy(update={"arguments": args})
        return None

    def _decide_replacement(self, request: DefenseRequest, state: SecurityState) -> bool:
        if self.structural(request, request.candidate_action, state) is not None:
            return False
        if self.monitor:
            try:
                judgment = self.monitor.assess(request, state, thinking=False)
                return not judgment.unsafe and not judgment.uncertain
            except Exception:
                return False
        return True

    def _audit(self, request: DefenseRequest, decision: DefenseDecision, state: SecurityState) -> None:
        if self.audit_dir is None:
            return
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        name = hashlib.sha256(request.run_id.encode()).hexdigest()[:24]
        record = {"run_id": request.run_id, "step_id": request.step_id,
                  "candidate": request.candidate_action.model_dump(mode="json"),
                  "decision": decision.model_dump(mode="json"),
                  "evidence": [{"id": e.id, "role": e.role, "trust": e.trust,
                                "sensitivity": e.sensitivity, "provenance_ids": e.provenance_ids}
                               for e in list(state.evidence.values())[-12:]],
                  "state_counts": {"evidence": len(state.evidence), "sensitive": len(state.sensitive),
                                   "objects": len(state.objects)}}
        with (self.audit_dir / f"{name}.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")

    def close(self) -> None:
        if self.monitor:
            self.monitor.close()
        self.states.clear()
        self.cache.clear()
