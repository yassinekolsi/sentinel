"""Bounded, request-visible evidence. No evaluator or fixture access."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.actions import CandidateAction
from sentinel.defenses.interface import DefenseRequest

SECRET_KEY = re.compile(r"password|secret|token|credential|api[_ -]?key|recovery[_ -]?key", re.I)
IDENTIFIER_KEY = re.compile(r"iban|account_number|national_id", re.I)
LABELED_SECRET = re.compile(
    r"(?:password|token|secret|credential|api[_ -]?key)\s*(?:is|:|=)\s*['\"]?([\w+/.=\-]{8,})", re.I
)
OPAQUE = re.compile(r"\b(?=[A-Za-z0-9_+/=-]{16,}\b)(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]+\b")


def variants(value: str) -> dict[str, str]:
    raw = value.encode()
    return {"plain": value, "base64": base64.b64encode(raw).decode(), "hex": raw.hex(), "reversed": value[::-1]}


def match_encoding(value: str, payload: str) -> str | None:
    compact = "".join(payload.split())
    for encoding, encoded in variants(value).items():
        if encoded in payload:
            return encoding
        if "".join(encoded.split()) in compact:
            return "spaced_" + encoding
        if encoding == "hex" and encoded.lower() in compact.lower():
            return "hex"
    return None


@dataclass
class Evidence:
    id: str
    role: str
    content: str
    trust: str
    sensitivity: str
    provenance_ids: list[str]


@dataclass
class SensitiveValue:
    value: str
    credential: bool
    evidence_ids: set[str] = field(default_factory=set)


@dataclass
class SecurityState:
    evidence: dict[str, Evidence] = field(default_factory=dict)
    sensitive: dict[str, SensitiveValue] = field(default_factory=dict)
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    pending: dict[int, CandidateAction] = field(default_factory=dict)
    processed_results: set[int] = field(default_factory=set)
    last_step: int = 0
    overflow: bool = False

    def ingest(self, request: DefenseRequest) -> None:
        records = {r.id: r.provenance for r in request.provenance}
        for item in request.conversation:
            key = hashlib.sha256(json.dumps([item.role, item.content, item.provenance_ids]).encode()).hexdigest()[:16]
            if key in self.evidence:
                continue
            if len(self.evidence) >= 1000:
                self.overflow = True
                continue
            provs = [records[p] for p in item.provenance_ids if p in records]
            complete = bool(provs) and len(provs) == len(item.provenance_ids)
            trust = max(provs, key=lambda p: p.trust_level.rank).trust_level.value if complete else "unknown"
            sensitivity = max(provs, key=lambda p: p.sensitivity.rank).sensitivity.value if provs else "unknown"
            evidence = Evidence(key, item.role, item.content, trust, sensitivity, item.provenance_ids)
            self.evidence[key] = evidence
            if sensitivity in {"confidential", "restricted"}:
                self._extract(evidence)
        # Only an observed successful tool execution can advance lifecycle state.
        if request.observation and request.history_digest.tool_calls:
            call = request.history_digest.tool_calls[-1]
            action = self.pending.get(call.step_id)
            if (
                call.succeeded is True
                and call.step_id not in self.processed_results
                and action is not None
                and request.observation.kind == "tool_result"
            ):
                self.processed_results.add(call.step_id)
                try:
                    result = json.loads(request.observation.content)
                except (ValueError, TypeError):
                    result = {}
                if isinstance(result, dict) and "error" not in result:
                    object_id = result.get("payment_id") or result.get("remediation_id")
                    if isinstance(object_id, str) and action.tool in {
                        "payment_prepare",
                        "payment_confirm",
                        "payment_execute",
                        "remediation_prepare",
                        "remediation_execute",
                    }:
                        expected_id = action.arguments.get("payment_id") or action.arguments.get("remediation_id")
                        if expected_id is None or object_id == expected_id:
                            previous = self.objects.get(object_id, {})
                            self.objects[object_id] = {**previous, **action.arguments, **result, "tool": action.tool}
        self.last_step = request.step_id

    def _extract(self, evidence: Evidence) -> None:
        def remember(value: str, credential: bool) -> None:
            if len(value) < 8 or len(value) > 512:
                return
            if len(self.sensitive) >= 1000 and value not in self.sensitive:
                self.overflow = True
                return
            entry = self.sensitive.setdefault(value, SensitiveValue(value, credential))
            entry.credential |= credential
            entry.evidence_ids.add(evidence.id)

        def walk(value: Any, key: str = "") -> None:
            if isinstance(value, dict):
                for name, child in value.items():
                    walk(child, name)
            elif isinstance(value, list):
                for child in value:
                    walk(child, key)
            elif isinstance(value, str):
                if SECRET_KEY.search(key) and len(value.split()) == 1:
                    remember(value, True)
                elif IDENTIFIER_KEY.search(key):
                    remember(value, False)
                for match in LABELED_SECRET.finditer(value):
                    remember(match.group(1), True)
                if evidence.sensitivity == "restricted":
                    for match in OPAQUE.finditer(value):
                        remember(match.group(), True)

        try:
            walk(json.loads(evidence.content))
        except ValueError:
            walk(evidence.content)

    def leaks(self, payload: str, external: bool) -> list[dict[str, Any]]:
        findings = []
        for entry in self.sensitive.values():
            encoding = match_encoding(entry.value, payload)
            if encoding and (entry.credential or external):
                findings.append(
                    {
                        "encoding": encoding,
                        "evidence_ids": sorted(entry.evidence_ids),
                        "kind": "credential" if entry.credential else "identifier",
                    }
                )
        return findings
