"""MoveBit's numbered (2022–23) and component-ID (2023+) report eras."""
import re

from core import Candidate, clean, field_severity, severity
from layout_support import STATUS, bounded, status_value, visible
from summary_counts import printed_counts as common_printed_counts
from variants import Fingerprint, Variant

DESCRIPTION = "MoveBit numbered sections and component-ID cards, native statuses and resolution receipts"

COMPONENT_ID = r"[A-Z][A-Z0-9_]{0,20}-\d{1,3}"
SECTION_ID = r"\d+\.\d+"
COMPONENT_SIGNATURE = (r"^[ \t]*" + COMPONENT_ID + r"[ \t]+[^\n]+\n"
                       r"(?:[^\n]*\n){0,8}[ \t]*Severity[ \t]*:")
NUMBERED_SIGNATURE = (r"^[ \t]*" + SECTION_ID + r"[ \t]+[^\n]+\n"
                      r"(?:[^\n]*\n){0,8}[ \t]*Severity[ \t]*:")
NATIVE_STATUS = r"(?:Partially Fixed|Confirmed|" + STATUS + r")"
STOP = r"(?:\d+[. ]+)?(?:Appendix(?:\s+\d+)?|Disclaimer|Formal Verification|Risk (?:Level|Rating)|Severity Classification)"


def _cards(report, identifiers, method):
    """Recognize metadata-bearing detail cards; aligned overview rows have no colon."""
    out = []
    heading = re.compile(r"^(" + identifiers + r")\s+(.+)")
    any_heading = re.compile(r"^(?:" + COMPONENT_ID + "|" + SECTION_ID + r")\s+")
    for i, line in enumerate(report.lines):
        m = heading.match(visible(line.content))
        if not m or line.code or re.search(r"(?:\.\s*){4,}", line.content):
            continue
        following = report.lines[i + 1:i + 15]
        stop = next((j for j, l in enumerate(following)
                     if any_heading.match(visible(l.content))), len(following))
        following = following[:stop]
        metadata = "\n".join(visible(l.content) for l in following)
        raw = field_severity(metadata)
        if not raw:
            continue
        title = [m[2]]
        for l in following:
            value = visible(l.content)
            if not value:
                continue
            if re.match(r"^(?:Severity|Status|Descriptions?|Code Location|Suggestion|Resolution)\s*:", value, re.I):
                break
            if l.page != line.page or re.fullmatch(r"\d+", value):
                break
            title.append(value)
        out.append(Candidate(line.start, clean(" ".join(title)), raw, m[1],
                             method=method, confidence=.96,
                             evidence={"severity_basis": "explicit_field",
                                       "parser_revision": "phase4e-group4-v1"}))
    return bounded(report, out, STOP)


def numbered(report):
    return _cards(report, SECTION_ID, "movebit-numbered-fields")


def component_cards(report):
    return _cards(report, COMPONENT_ID, "movebit-component-fields")


def _claim(report, raw, start, end, basis):
    return {"raw": raw, "start": start, "end": end,
            "text": report.text[start:end], "basis": basis, "profile": report.firm}


def _normal_status(report, raw, candidate):
    if raw.casefold() == "confirmed":
        # This older label means accepted as designed, rather than repaired.
        definition = re.search(r"Confirmed\s*:\s*The issue has been acknowledged by the code owner[^\n]*(?:\n[^\n]*)?", report.text, re.I)
        if definition:
            candidate.evidence["status_definition_evidence"] = _claim(
                report, "Confirmed", definition.start(), definition.end(), "publisher_status_definition")
            return "acknowledged"
    return status_value(raw, report.firm)


def _resolution(report, candidate):
    body = report.text[candidate.start:candidate.end]
    m = re.search(r"(?:^|[\n\f])[ \t]*(?:Resolution|Fix Review|Retest)\s*:\s*", body, re.I)
    if not m:
        return None
    end = re.search(r"(?m)^\s*(?:Appendix\b|\d+\s+(?:Disclaimer|Formal Verification)\b)", body[m.end():], re.I)
    stop = m.end() + end.start() if end else len(body)
    candidate.resolution = body[m.end():stop].strip()
    text = body[m.end():stop]
    # Completed remediation inside a labelled resolution is evidence;
    # a recommendation, negation or future promise is not.
    for pattern, normalized in (
        (r"\b(partially (?:fixed|resolved))\s+(?:this|the)\s+issue\b", "partial"),
        (r"\b(decid(?:es|ed)\s+not\s+to\s+fix)\b", "acknowledged"),
        (r"\b(plans?\s+to\s+fix)\b", "open"),
        (r"\b(fixed|resolved)\s+(?:this|the)\s+issue\b", "resolved"),
    ):
        found = re.search(pattern, text, re.I)
        if not found:
            continue
        before = text[max(0, found.start() - 45):found.start()]
        if normalized in {"resolved", "partial"} and re.search(r"\b(?:not|never|should|would|will|could|can|partially)\b[^.!?]*$", before, re.I):
            continue
        start = candidate.start + m.end() + found.start(1)
        if normalized == "resolved":
            normalized = status_value(found[1], report.firm)
        return _claim(report, found[1], start, start + len(found[1]), "explicit_resolution_assertion"), normalized
    return None


def _statuses(report, candidates, identifiers):
    indices = {}
    for line in report.lines:
        # Only ID-linked aligned table rows or labelled fix-review entries.
        m = re.match(r"^\s*(" + identifiers + r")(?:\s{2,}|\s*[|:]\s*)", line.text)
        if not m:
            continue
        # The status is the final table cell. Words such as Open inside a title
        # must not be mistaken for the remediation value.
        found = re.search(r"(?:^|[ \t]{2,}|\|)[ \t]*(" + NATIVE_STATUS + r")[ \t]*\|?[ \t]*$", line.text[m.end():], re.I)
        if found:
            start = line.start + m.end() + found.start(1)
            indices.setdefault(m[1], []).append(_claim(report, found[1], start, start + len(found[1]), "printed_id_status_table"))
    for candidate in candidates:
        candidate.status_raw = None
        candidate.normalized_status = None
        body = report.text[candidate.start:candidate.end]
        resolution = _resolution(report, candidate)
        fields = list(re.finditer(r"(?:^|[\n\f])[ \t]*(?:Status|Resolution Status)\s*:\s*(" + NATIVE_STATUS + r")\b", body, re.I))
        if fields:
            m = fields[-1]
            start = candidate.start + m.start(1)
            claim = _claim(report, m[1], start, candidate.start + m.end(1), "labelled_status_field")
            normalized = _normal_status(report, m[1], candidate)
        elif resolution:
            claim, normalized = resolution
        else:
            claims = indices.get(candidate.printed_id, [])
            norms = {_normal_status(report, claim["raw"], candidate) for claim in claims}
            if len(norms) != 1:
                if claims:
                    candidate.evidence["status_conflict"] = True
                    candidate.evidence["status_claims"] = claims
                continue
            claim = claims[-1]
            normalized = norms.pop()
        candidate.status_raw = claim["raw"]
        candidate.normalized_status = normalized
        candidate.evidence["status_evidence"] = claim


def numbered_status(report, candidates):
    return _statuses(report, candidates, SECTION_ID)


def component_status(report, candidates):
    return _statuses(report, candidates, COMPONENT_ID)


def printed_counts(report):
    """Read the independent numeric Count/Total column, retaining disagreements."""
    start = next((i for i, l in enumerate(report.lines)
                  if re.search(r"Issue Statistic|Audit Summary|Issues Statistic", l.content, re.I)), None)
    if start is not None:
        values, proof = {}, []
        for line in report.lines[start + 1:start + 38]:
            m = re.match(r"^(Informational|Minor|Medium|Major|Critical)\s+(\d+)\b", line.content, re.I)
            if m:
                values[m[1].casefold()] = int(m[2])
                proof.append({"page": line.page, "start": line.start, "end": line.end, "text": line.text})
        if values:
            normalized = {}
            for raw, count in values.items():
                bucket = severity(raw, report.firm)
                normalized[bucket] = normalized.get(bucket, 0) + count
            return {"counts": normalized, "basis": "printed_issue_statistic_total_column", "evidence": proof}
    return common_printed_counts(report)


def parse(report):
    """Compatibility entry point; the adapter dispatches the declared variants."""
    return component_cards(report) + numbered(report)


VARIANTS = (
    Variant("movebit/v2023_component_cards", Fingerprint((
        ("component_detail_field", COMPONENT_SIGNATURE, 8),
        ("publisher_methodology", r"MoveBit Audit BreakDown", 2)), ("2023", None)),
        component_cards, ("movebit_component", "movebit_component_modern"), component_status, printed_counts,
        "Component IDs, explicit Severity/Status fields and labelled resolution responses; global ordinals can cross component prefixes."),
    Variant("movebit/v2022_numbered_fields", Fingerprint((
        ("numbered_detail_field", NUMBERED_SIGNATURE, 8),
        ("native_status_legend", r"1\.4 Issue Status", 2)), ("2022", "2023"),
        reject_signatures=(COMPONENT_SIGNATURE,)),
        numbered, ("movebit_numbered",), numbered_status, printed_counts,
        "Numbered 5.x/6.x findings; Confirmed is acknowledged only with the publisher's explicit definition."),
)
