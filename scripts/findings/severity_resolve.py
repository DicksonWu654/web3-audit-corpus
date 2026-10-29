"""Standalone publisher severity resolver (standard library only).

Importing this file does not read files, change sys.path/cwd, or import repository
modules. Pass ``policy_path`` to use an exported schema/severity_map.json outside
the repository; the default is the reviewed YAML source beside this repository.
``severity_mapping`` returns a receipt; ``severity`` returns just its bucket.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import logging
from pathlib import Path
import re
import unicodedata

SEVERITIES = ("critical", "high", "medium", "low", "info", "gas", "unknown")
RESOLVER_VERSION = "severity-canon-v1"
LOGGER = logging.getLogger("findings.severity")


def _literal_key(value):
    return re.sub(r"\s+", "", unicodedata.normalize("NFKC", value).casefold())


@lru_cache(maxsize=8192)
def canonicalize_label(value):
    """Return a matching key without changing the source label.

    Only presentation is removed. Qualifiers such as 'potentially', combinations
    of risk classes, and priority codes remain distinct. Abbreviations are NOT
    guessed here: they must be defined in the selected publisher/era's labels.
    """
    text = unicodedata.normalize("NFKC", value).casefold().strip()
    # Rejoin PDF line-end hyphenation, including In-\nformative.
    text = re.sub(r"(?<=\w)-\s*\n\s*(?=\w)", "", text)
    # Markdown/bullets, parenthesized counts and hierarchical numbering can nest.
    while text:
        before = text
        text = re.sub(r"^[\W_]+", "", text)
        text = re.sub(r"^\d+(?:\.\d+)*(?:[\s.)\]:\-–—]+|$)", "", text)
        # '[L] Risk' is a punctuated severity code, not alphabetic numbering.
        text = re.sub(r"^(?:[ivxlcdm]+|[a-z])[.)\]:]\s+(?=\S)"
                      r"(?!(?:risk|severity|issues?|findings?)\b)", "", text)
        if text == before:
            break
    text = re.sub(r"[\[(]\s*\d+\s*[\])]\s*[\W_]*$", "", text)
    # Compact after removing numbering, so PDF letter spacing behaves like words.
    key = re.sub(r"[\W_]+", "", text)
    while key:
        before = key
        # A final plural belongs to the last word; 'gas' itself is singular.
        if len(key) > 3 and key.endswith("s") and not key.endswith(("ss", "us", "is")):
            key = key[:-1]
        key = re.sub(r"(?:risk|severity|issue|finding)$", "", key)
        if key == before:
            break
    # Keep explicit punctuation-only placeholders separate from empty labels.
    return key or _literal_key(value)


severity_key = canonicalize_label


def _label_index(publisher, entries):
    """Index both policy and inputs identically, with native base labels first.

    Old presentation-specific rows (e.g. '0 Minor') may disagree with their
    undecorated definition. The latter defines the class after canonicalization.
    Conflicting definitions of a base class still fail closed.
    """
    grouped = {}
    # Exported JSON sorts object keys. Tie-breaking must not depend on row order.
    for label, mapping in sorted(entries.items()):
        if mapping["normalized"] not in SEVERITIES or not mapping["rationale"]:
            raise ValueError(f"Invalid severity mapping: {publisher}: {label!r}")
        key = canonicalize_label(label)
        grouped.setdefault(key, []).append((label, mapping))
    labels = {}
    for key, aliases in grouped.items():
        native = [(label, m) for label, m in aliases if _literal_key(label) == key]
        choices = native or aliases
        if len({m["normalized"] for _, m in choices}) != 1:
            raise ValueError(f"Conflicting severity aliases: {publisher}: {key!r}")
        label, mapping = choices[0]
        labels[key] = {**mapping, "original_label": label}
    return labels


@lru_cache(maxsize=4)
def severity_policy(path=None):
    # JSON is the dependency-free YAML 1.2 subset used by the reviewed source.
    path = Path(path) if path else Path(__file__).resolve().parents[2] / "schema/severity_map.yaml"
    payload = path.read_bytes()
    policy = json.loads(payload)
    index = {publisher: [(era, _label_index(publisher, era["labels"])) for era in entry["eras"]]
             for publisher, entry in policy["publishers"].items()}
    return policy, index, hashlib.sha256(payload).hexdigest()


def definition_text(text):
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[\u200b\ufeff\u202a-\u202e\u2066-\u2069]", "", text)
    text = re.sub(r"(?<=\w)-\s*\n\s*(?=\w)", "", text)
    return re.sub(r"\s+", " ", text)


def select_severity_era(publisher, *, sha256=None, date=None, report_text=None, policy_path=None):
    _, index, _ = severity_policy(policy_path)
    eras = index.get(publisher, [])
    if report_text is not None and any(e.get("definition_regex") for e, _ in eras):
        text = definition_text(report_text)
        selected = [e["id"] for e, _ in eras if e.get("definition_regex") and re.search(e["definition_regex"], text, re.I)]
        if selected:
            return selected[0] if len(selected) == 1 else "<ambiguous>"
    selected = [e["id"] for e, _ in eras if sha256 and sha256 in e.get("document_sha256s", [])]
    if not selected and date:
        selected = [e["id"] for e, _ in eras if e.get("date_range") and
                    (not e["date_range"].get("from") or date >= e["date_range"]["from"]) and
                    (not e["date_range"].get("to") or date <= e["date_range"]["to"])]
    if not selected:
        selected = [e["id"] for e, _ in eras if e.get("default")]
    return selected[0] if len(selected) == 1 else "<ambiguous>"


@lru_cache(maxsize=4096)
def _log_unmapped(publisher, value, reason):
    LOGGER.warning("Unmapped severity publisher=%s label=%r reason=%s", publisher, value, reason)


def severity_mapping(value, publisher=None, *, sha256=None, date=None, kind=None, era=None,
                     report_text=None, log=True, policy_path=None):
    """Resolve a label using only its publisher/era; retain its verbatim input.

    Date selectors require a source-supported date. Collection/filename hints
    never select an era. This function never opens reports or their text caches.
    """
    policy, index, policy_sha = severity_policy(policy_path)
    key = canonicalize_label(value) if isinstance(value, str) else None
    receipt = {"policy": policy["policy"], "map_sha256": policy_sha,
               "resolver": RESOLVER_VERSION, "canonical_label": key,
               "publisher": publisher, "era": None, "input": value, "raw": value,
               "normalized": "unknown", "mapped": False}
    eras = index.get(publisher, [])
    if era is None:
        era = select_severity_era(publisher, sha256=sha256, date=date, report_text=report_text, policy_path=policy_path)
    selected = [(e, labels) for e, labels in eras if e["id"] == era]
    reason = "publisher_not_in_crosswalk" if not eras else "era_not_resolved"
    if len(selected) == 1:
        entry, labels = selected[0]
        receipt["era"] = entry["id"]
        if value is None:
            kind = (kind or "issues").casefold()
            kind = "suggestions" if kind in {"suggestion", "suggestions"} else "recommendations" if kind in {"recommendation", "recommendations"} else kind
            overrides = entry.get("unrated", {})
            if kind not in overrides and kind not in policy["unrated"]:
                kind = "issues"
            mapping = overrides.get(kind) or policy["unrated"][kind]
            return receipt | {**mapping, "mapped": True, "rule": "unrated_" + kind}
        mapping = labels.get(key)
        if mapping:
            return receipt | mapping | {"mapped": True}
        reason = "label_not_in_publisher_era"
    elif len(selected) > 1:
        reason = "ambiguous_era"
    # Unscoped helpers accept the full schema vocabulary, never publisher codes.
    if publisher is None and isinstance(value, str):
        labels = {canonicalize_label(label): bucket for label, bucket in policy["unscoped_labels"].items()
                  if len(label) > 2}
        if key in labels:
            return receipt | {"normalized": labels[key], "mapped": True, "rule": "unscoped_schema_vocabulary"}
    if log:
        _log_unmapped(publisher, value, reason)
    return receipt | {"reason": reason}


def severity(value, publisher=None, **kwargs):
    return severity_mapping(value, publisher, **kwargs)["normalized"]


resolve_severity = severity
