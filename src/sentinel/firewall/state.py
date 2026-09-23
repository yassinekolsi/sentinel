"""Bounded, request-visible evidence. No evaluator or fixture access."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.actions import CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import DefenseRequest

SECRET_KEY = re.compile(r"password|secret|token|credential|api[_ -]?key|recovery[_ -]?key", re.I)
IDENTIFIER_KEY = re.compile(r"iban|account_number|national_id", re.I)
STRUCTURAL_KEY = re.compile(r"(^id$|_id$|timestamp|created_at|updated_at|date$|time$)", re.I)
LABELED_SECRET = re.compile(
    r"(?:password|token|secret|credential|api[_ -]?key)\s*(?:is|:|=)\s*['\"]?([\w+/.=\-]{8,})", re.I
)
OPAQUE = re.compile(r"\b(?=[A-Za-z0-9_+/=-]{16,}\b)(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]+\b")
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
MAX_DECODE_TOKENS = 128
MAX_DECODED_CHARS = 262_144
GENERIC_ENUMS = {
    "active",
    "approved",
    "closed",
    "complete",
    "completed",
    "confirmed",
    "disabled",
    "enabled",
    "executed",
    "failed",
    "false",
    "open",
    "pending",
    "prepared",
    "resolved",
    "true",
}
_TRUST_RANK = {level.value: level.rank for level in TrustLevel} | {"unknown": len(TrustLevel)}
_SENSITIVITY_RANK = {level.value: level.rank for level in Sensitivity} | {"unknown": len(Sensitivity)}


def normalized_text(value: str) -> str:
    """Normalize copied prose without changing its words or order."""
    return " ".join(unicodedata.normalize("NFC", value).casefold().split())


def protected_candidates(value: str) -> list[tuple[str, str]]:
    """Return full text plus bounded eight-word spans for copied-excerpt checks."""
    normalized = normalized_text(value)
    words = normalized.split()
    candidates = [("plain", value)]
    if normalized != value:
        candidates.append(("normalized", normalized))
    if len(words) >= 8:
        candidates.extend(("excerpt", " ".join(words[index : index + 8])) for index in range(len(words) - 7))
    # Preserve order while bounding duplicate work.
    return list(dict.fromkeys(candidates))


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


def decoded_payloads(payload: str) -> tuple[list[tuple[str, str]], bool]:
    """Decode bounded text containers without relying on evaluator canary data."""
    decoded: list[tuple[str, str]] = []
    seen_tokens: set[tuple[str, str]] = set()
    used = 0
    exhausted = False
    sources = [payload]
    sources.extend("".join(line.split()) for line in payload.splitlines() if any(char.isspace() for char in line))
    for source in sources:
        for encoding, pattern in (("base64_container", BASE64_TOKEN), ("hex_container", HEX_TOKEN)):
            for match in pattern.finditer(source):
                token = match.group()
                identity = (encoding, token)
                if identity in seen_tokens:
                    continue
                seen_tokens.add(identity)
                if len(seen_tokens) > MAX_DECODE_TOKENS:
                    exhausted = True
                    break
                try:
                    raw = (
                        bytes.fromhex(token)
                        if encoding == "hex_container"
                        else base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
                    )
                    text = raw.decode("utf-8", "ignore")
                except (binascii.Error, ValueError):
                    continue
                if not text:
                    continue
                used += len(text)
                if used > MAX_DECODED_CHARS:
                    exhausted = True
                    break
                decoded.append((encoding, text))
            if exhausted:
                break
        if exhausted:
            break
    return decoded, exhausted


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
    sensitivity: str = "confidential"
    source_trust: str = "unknown"
    field_paths: set[str] = field(default_factory=set)


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
            sensitivity = max(provs, key=lambda p: p.sensitivity.rank).sensitivity.value if complete else "unknown"
            evidence = Evidence(key, item.role, item.content, trust, sensitivity, item.provenance_ids)
            self.evidence[key] = evidence
            self._extract(evidence)
        # Only an observed successful tool execution can advance lifecycle state.
        if request.observation and request.history_digest.tool_calls:
            call = request.history_digest.tool_calls[-1]
            action = self.pending.get(call.step_id)
            if (
                call.succeeded is True
                and call.step_id not in self.processed_results
                and action is not None
                and call.tool == action.tool
                and request.observation.kind == "tool_result"
            ):
                self.processed_results.add(call.step_id)
                try:
                    result = json.loads(request.observation.content)
                except (ValueError, TypeError):
                    result = {}
                expected_status = {
                    "payment_prepare": "prepared",
                    "payment_confirm": "confirmed",
                    "payment_execute": "executed",
                    "remediation_prepare": "prepared",
                    "remediation_execute": "executed",
                }.get(action.tool or "")
                if isinstance(result, dict) and "error" not in result and result.get("status") == expected_status:
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
        def remember(value: str, credential: bool, path: str) -> None:
            value = value.strip()
            if not value or (not credential and (len(value) < 4 or normalized_text(value) in GENERIC_ENUMS)):
                return
            if len(value) > 16_000:
                self.overflow = True
                return
            if len(self.sensitive) >= 1000 and value not in self.sensitive:
                self.overflow = True
                return
            entry = self.sensitive.setdefault(
                value,
                SensitiveValue(
                    value,
                    credential,
                    sensitivity=evidence.sensitivity,
                    source_trust=evidence.trust,
                ),
            )
            entry.credential |= credential
            if _SENSITIVITY_RANK[evidence.sensitivity] > _SENSITIVITY_RANK[entry.sensitivity]:
                entry.sensitivity = evidence.sensitivity
            if _TRUST_RANK[evidence.trust] > _TRUST_RANK[entry.source_trust]:
                entry.source_trust = evidence.trust
            entry.field_paths.add(path or "$")
            entry.evidence_ids.add(evidence.id)

        def walk(value: Any, key: str = "", path: str = "$") -> None:
            if isinstance(value, dict):
                for name, child in value.items():
                    walk(child, name, f"{path}.{name}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, key, f"{path}[{index}]")
            elif isinstance(value, str):
                if SECRET_KEY.search(key):
                    remember(value, True, path)
                elif IDENTIFIER_KEY.search(key) and evidence.sensitivity in {"confidential", "restricted", "unknown"}:
                    remember(value, False, path)
                elif evidence.sensitivity in {"confidential", "restricted"} and not STRUCTURAL_KEY.search(key):
                    # Field names are retained only as diagnostics; sensitivity and
                    # observed provenance, not names, establish protection.
                    remember(value, False, path)
                for match in LABELED_SECRET.finditer(value):
                    remember(match.group(1), True, path)
                if evidence.sensitivity == "restricted":
                    for match in OPAQUE.finditer(value):
                        remember(match.group(), True, path)

        try:
            walk(json.loads(evidence.content))
        except ValueError:
            walk(evidence.content)

    def leaks(
        self,
        payload: str,
        external: bool,
        *,
        allow_confidential: bool = False,
        allow_credentials: bool = False,
    ) -> list[dict[str, Any]]:
        findings = []
        decoded, exhausted = decoded_payloads(payload)
        for entry in self.sensitive.values():
            encoding = None
            for candidate_kind, candidate in protected_candidates(entry.value):
                if not entry.credential and normalized_text(candidate) in normalized_text(payload):
                    encoding = "normalized:" + candidate_kind
                    break
                direct = match_encoding(candidate, payload)
                if direct:
                    encoding = direct if candidate_kind == "plain" else f"{candidate_kind}:{direct}"
                    break
                for container_encoding, content in decoded:
                    inner_encoding = match_encoding(candidate, content)
                    if inner_encoding:
                        encoding = f"{container_encoding}:{candidate_kind}:{inner_encoding}"
                        break
                if encoding:
                    break
            prohibited = (entry.credential and not allow_credentials) or (
                not entry.credential and external and not allow_confidential
            )
            if encoding and prohibited:
                evidence_ids = sorted(entry.evidence_ids)
                findings.append(
                    {
                        "encoding": encoding,
                        "evidence_ids": evidence_ids[:8],
                        "evidence_ids_omitted": max(0, len(evidence_ids) - 8),
                        "kind": "credential" if entry.credential else "protected_value",
                        "sensitivity": entry.sensitivity,
                        "source_trust": entry.source_trust,
                        "field_paths": sorted(entry.field_paths)[:8],
                    }
                )
        if exhausted and self.sensitive:
            findings.append(
                {
                    "encoding": "decode_budget_exceeded",
                    "evidence_ids": [],
                    "evidence_ids_omitted": 0,
                    "kind": "analysis_capacity",
                }
            )
        return findings
