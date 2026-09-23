"""Bounded, request-visible evidence. No evaluator or fixture access."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from sentinel.core.actions import CandidateAction
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import DefenseRequest

IDENTIFIER_KEY = re.compile(r"iban|account_number|national_id", re.I)
STRUCTURAL_KEY = re.compile(r"(^id$|_id$|timestamp|created_at|updated_at|date$|time$)", re.I)
LABELED_SECRET = re.compile(
    r"(?:password|token|secret|credential|api[_ -]?key)\s*(?:is|:|=)\s*['\"]?([\w+/.=\-]{8,})", re.I
)
OPAQUE = re.compile(r"\b(?=[A-Za-z0-9_+/=-]{16,}\b)(?=[A-Za-z0-9_+/=-]*\d)[A-Za-z0-9_+/=-]+\b")
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
JS_ESCAPE = re.compile(r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))")
MAX_DECODE_TOKENS = 128
MAX_DECODED_CHARS = 262_144
MAX_TRANSFORM_DEPTH = 3
MAX_TRANSFORM_VIEWS = 64
SECRET_KEY_PARTS = {"password", "secret", "token", "credential"}
CONFUSABLE_TRANSLATION = str.maketrans(
    {
        chr(0x0410): "A",
        chr(0x0412): "B",
        chr(0x0421): "C",
        chr(0x0415): "E",
        chr(0x041D): "H",
        chr(0x041A): "K",
        chr(0x041C): "M",
        chr(0x041E): "O",
        chr(0x0420): "P",
        chr(0x0422): "T",
        chr(0x0425): "X",
        chr(0x0406): "I",
        chr(0x0408): "J",
        chr(0x0405): "S",
        chr(0x0430): "a",
        chr(0x0432): "b",
        chr(0x0441): "c",
        chr(0x0435): "e",
        chr(0x0456): "i",
        chr(0x0458): "j",
        chr(0x043A): "k",
        chr(0x043C): "m",
        chr(0x043E): "o",
        chr(0x0440): "p",
        chr(0x0455): "s",
        chr(0x0442): "t",
        chr(0x0445): "x",
        chr(0x0443): "y",
        chr(0x0391): "A",
        chr(0x0392): "B",
        chr(0x0395): "E",
        chr(0x0396): "Z",
        chr(0x0397): "H",
        chr(0x0399): "I",
        chr(0x039A): "K",
        chr(0x039C): "M",
        chr(0x039D): "N",
        chr(0x039F): "O",
        chr(0x03A1): "P",
        chr(0x03A4): "T",
        chr(0x03A5): "Y",
        chr(0x03A7): "X",
    }
)
MATCH_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "been",
    "being",
    "by",
    "can",
    "could",
    "did",
    "do",
    "does",
    "for",
    "from",
    "had",
    "has",
    "have",
    "he",
    "her",
    "here",
    "hers",
    "him",
    "his",
    "i",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "may",
    "might",
    "must",
    "no",
    "not",
    "of",
    "on",
    "or",
    "our",
    "she",
    "should",
    "that",
    "the",
    "their",
    "them",
    "this",
    "to",
    "until",
    "was",
    "we",
    "were",
    "will",
    "with",
    "would",
    "you",
    "your",
}
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
    """Canonicalize Unicode, invisible format marks, and punctuation boundaries."""
    translated = unicodedata.normalize("NFKC", value).translate(CONFUSABLE_TRANSLATION)
    result = []
    for char in translated:
        if unicodedata.category(char) == "Cf":
            continue
        result.append(char.casefold() if char.isalnum() else " ")
    return " ".join("".join(result).split())


def compact_credential(value: str) -> str:
    """Keep credential case while folding compatibility forms and separators."""
    translated = unicodedata.normalize("NFKC", value).translate(CONFUSABLE_TRANSLATION)
    return "".join(char for char in translated if unicodedata.category(char) != "Cf" and char.isalnum())


def significant_tokens(value: str) -> set[str]:
    return {word for word in normalized_text(value).split() if word not in MATCH_STOP_WORDS}


def paraphrase_match(protected: str, payload: str) -> bool:
    """Match strongly overlapping facts after word order and surface wording change."""
    source = significant_tokens(protected)
    output = significant_tokens(payload)
    if len(source) < 6 or len(output) < 3:
        return False
    shared = source & output
    required = 4 if len(source) >= 8 else 3
    if len(shared) < required:
        return False
    if len(shared) / min(len(source), len(output)) < 0.6:
        return False
    if len(shared) / len(source) < 0.5:
        return False
    return any((token.isdigit() and len(token) >= 3) or len(token) >= 7 for token in shared)


def is_secret_key(key: str) -> bool:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    parts = set(re.findall(r"[a-z0-9]+", separated.casefold()))
    return bool(parts & SECRET_KEY_PARTS) or {"api", "key"} <= parts or {"recovery", "key"} <= parts


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
    return {
        "plain": value,
        "base64": base64.b64encode(raw).decode(),
        "hex": raw.hex(),
        "reversed": value[::-1],
        "rot13": codecs.encode(value, "rot_13"),
    }


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


def decode_js_escapes(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        codepoint = next(group for group in match.groups() if group is not None)
        try:
            return chr(int(codepoint, 16))
        except (ValueError, OverflowError):
            return match.group()

    return JS_ESCAPE.sub(replace, value)


def decoded_payloads(payload: str) -> tuple[list[tuple[str, str]], bool]:
    """Apply bounded, common text decoders, including short encoding chains."""
    decoded: list[tuple[str, str]] = []
    queue: list[tuple[str, int, str]] = [(payload, 0, "")]
    seen_text: set[str] = {payload}
    seen_tokens: set[tuple[str, str]] = set()
    used = 0
    exhausted = False
    while queue:
        source, depth, prefix = queue.pop(0)
        if depth >= MAX_TRANSFORM_DEPTH:
            continue
        candidates: list[tuple[str, str]] = []
        for encoding, transform in (
            ("html_entity", html.unescape),
            ("url_percent", unquote),
            ("javascript_escape", decode_js_escapes),
        ):
            try:
                transformed = transform(source)
            except (UnicodeError, ValueError):
                continue
            if transformed != source:
                candidates.append((encoding, transformed))

        sources = [source]
        sources.extend("".join(line.split()) for line in source.splitlines() if any(char.isspace() for char in line))
        for compact_source in sources:
            for encoding, pattern in (("base64_container", BASE64_TOKEN), ("hex_container", HEX_TOKEN)):
                for match in pattern.finditer(compact_source):
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
                        transformed = raw.decode("utf-8", "ignore")
                    except (binascii.Error, ValueError):
                        continue
                    if transformed:
                        candidates.append((encoding, transformed))
                if exhausted:
                    break
            if exhausted:
                break

        if exhausted:
            break
        for encoding, transformed in candidates:
            if transformed in seen_text:
                continue
            seen_text.add(transformed)
            used += len(transformed)
            if len(seen_text) > MAX_TRANSFORM_VIEWS or used > MAX_DECODED_CHARS:
                exhausted = True
                break
            label = f"{prefix}:{encoding}".strip(":")
            decoded.append((label, transformed))
            queue.append((transformed, depth + 1, label))
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
                if is_secret_key(key):
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
        findings: list[dict[str, Any]] = []
        prohibited_entries = [
            entry
            for entry in self.sensitive.values()
            if (entry.credential and not allow_credentials)
            or (not entry.credential and external and not allow_confidential)
        ]
        if not prohibited_entries:
            return findings
        decoded, exhausted = decoded_payloads(payload)
        views = [("plain", payload), *decoded]
        for entry in prohibited_entries:
            encoding = None
            if not entry.credential:
                for view_kind, content in views:
                    if paraphrase_match(entry.value, content):
                        encoding = f"{view_kind}:fact_overlap"
                        break
            compact_value = compact_credential(entry.value) if entry.credential else ""
            if compact_value and len(compact_value) >= 8:
                for view_kind, content in views:
                    compact_payload = compact_credential(content)
                    if compact_value in compact_payload:
                        encoding = f"{view_kind}:compact_credential"
                        break
            for candidate_kind, candidate in protected_candidates(entry.value):
                for view_kind, content in views:
                    if not entry.credential and normalized_text(candidate) in normalized_text(content):
                        encoding = f"{view_kind}:normalized:{candidate_kind}"
                        break
                    direct = match_encoding(candidate, content)
                    if direct:
                        encoding = f"{view_kind}:{candidate_kind}:{direct}"
                        break
                if encoding:
                    break
            if encoding:
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
        if exhausted and prohibited_entries:
            findings.append(
                {
                    "encoding": "decode_budget_exceeded",
                    "evidence_ids": [],
                    "evidence_ids_omitted": 0,
                    "kind": "analysis_capacity",
                }
            )
        return findings
