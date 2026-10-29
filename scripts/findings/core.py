"""Parser primitives: evidence spans, conservative heading detection and native labels."""
from __future__ import annotations
from dataclasses import dataclass, field
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Mapping
import re
import unicodedata
from severity_resolve import (definition_text, severity_key, severity_policy,
                              select_severity_era, severity_mapping as _severity_mapping)
from status_resolve import status_mapping as _status_mapping, select_status_era
from text_patterns import index_line

SEV = r"(?:Critical|High|Medium|Low|Informational|Information|Info|Gas(?:[ -]Optimization)?|Major|Minor|Undetermined|Unknown|Suggestion|Weakness|Recommendation|Best[ -]Practice|Nitpick)"
SPACED_SEV = "(?:" + "|".join(r"\s*".join(word) for word in ("Informational", "Critical", "Medium", "High", "Low", "Info", "Gas")) + ")"
_REPORT = ContextVar("severity_report", default=None)


@contextmanager
def severity_context(report):
    token = _REPORT.set(report)
    try:
        yield
    finally:
        _REPORT.reset(token)


def severity_mapping(value, publisher=None, *, sha256=None, date=None, kind=None, era=None, report_text=None, log=True):
    """Add parser report context to the standalone canonical severity resolver."""
    report = _REPORT.get()
    if publisher is None and report is not None:
        publisher = report.firm
    if report is not None:
        sha256 = sha256 or report.meta.get("sha256")
    if era is None and report is not None and publisher == report.firm:
        if not hasattr(report, "_severity_era"):
            report._severity_era = select_severity_era(publisher, sha256=sha256, report_text=report.text)
        era = report._severity_era
    return _severity_mapping(value, publisher, sha256=sha256, date=date, kind=kind,
                             era=era, report_text=report_text, log=log)


def severity(value, publisher=None, **kwargs):
    return severity_mapping(value, publisher, **kwargs)["normalized"]


class SeverityLookup(Mapping):
    """A parser's lexical vocabulary, with all bucket decisions in the YAML.

    Retains mapping-shaped syntax for legacy grammars without retaining a
    second normalization table. The active report supplies the era.
    """
    def __init__(self, publisher, labels):
        self.publisher, self.labels = publisher, tuple(labels)

    def __iter__(self):
        return iter(self.labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, label):
        if label not in self.labels:
            raise KeyError(label)
        return severity(label, self.publisher)


SHORT = SeverityLookup(None, ("C", "H", "M", "L", "I", "N", "G", "QA", "NC"))


def candidate_severity(report, candidate, *, sha256=None):
    kind = candidate.evidence.get("kind") or candidate.record_kind
    parent = candidate.evidence.get("source_section") or candidate.evidence.get("parent_title") or ""
    if parent.casefold().startswith("recommendation"):
        kind = "recommendation"
    if not hasattr(report, "_severity_era"):
        report._severity_era = select_severity_era(report.firm, sha256=sha256 or report.meta.get("sha256"), report_text=report.text)
    return severity_mapping(candidate.severity_raw, report.firm, sha256=sha256 or report.meta.get("sha256"), kind=kind, era=report._severity_era)


def status(value):
    if not value:
        return None
    key = re.sub(r"[\s_-]+", " ", unicodedata.normalize("NFKC", value).strip().lower().rstrip("."))
    if key == "resolved*":
        key = "resolved"
    if key.replace(" ", "") in {"resolved", "acknowledged", "fixed", "unresolved"}:
        key = key.replace(" ", "")
    if re.match(r"^fixed (?:in|at)\s+\S", key):
        key = "fixed"
    return {"fixed":"fixed", "implemented":"fixed", "fixed before report":"fixed", "acknowledged":"acknowledged",
            "acked":"acknowledged",
            "unresolved":"open", "open":"open", "pending":"open", "wip":"open", "not implemented":"open",
            "not resolved":"open", "in progress":"open",
            "partially fixed":"partial", "partially implemented":"partial", "partially resolved":"partial",
            "closed":"resolved", "resolved":"resolved", "patched":"fixed", "patched without reaudit":"fixed",
            "risk accepted":"acknowledged", "invalid":"invalid",
            "info":"info", "informational":"info"}.get(key, "other")


def candidate_status(report, candidate, *, sha256=None):
    """Resolve raw publisher labels centrally; parser guesses never override policy."""
    if not hasattr(report, '_status_era'):
        report._status_era = select_status_era(report.firm,
            sha256=sha256 or report.meta.get('sha256'), report_text=report.text)
    return _status_mapping(candidate.status_raw, report.firm, era=report._status_era,
                           sha256=sha256 or report.meta.get('sha256'))


def set_status_claim(report, candidate, match, offset=0, basis='labelled_status_field', group=1):
    """Store an exact source span selected by a publisher's structural reader."""
    start, end = offset + match.start(group), offset + match.end(group)
    raw = report.text[start:end]
    candidate.status_raw = raw
    candidate.normalized_status = status(raw)  # Legacy parser API; writer uses candidate_status.
    candidate.evidence['status_evidence'] = dict(raw=raw, text=raw, start=start, end=end,
                                               basis=basis, profile=report.firm)


def clean(value):
    return re.sub(r"\s+", " ", value.replace("\u200b", "").replace("\ufeff", "")).strip()


@dataclass
class Line:
    text: str
    start: int
    end: int
    page: int
    heading: int = 0
    content: str = ""
    code: bool = False
    excluded: bool = False


@dataclass
class Candidate:
    start: int
    title: str
    severity_raw: str | None = None
    printed_id: str | None = None
    normalized: str | None = None
    end: int | None = None
    status_raw: str | None = None
    method: str = "heading"
    confidence: float = .7
    record_kind: str = "formal_finding"
    evidence: dict = field(default_factory=dict)
    recommendation: str | None = None
    resolution: str | None = None
    normalized_status: str | None = None
    finding_phase: str | None = None


class Report:
    def __init__(self, text, meta, firm):
        self.text, self.meta, self.firm = text, meta, firm
        self.native = meta.get("structured")
        self.lines = []
        self.offsets = []
        fence = False
        for page in meta["pages"]:
            offset = page["start"]
            # Whole-page PDF TOCs and finding-index tables can wrap a title over
            # multiple rows, leaving individual rows that resemble detail headings.
            pdf = meta.get("file_format") == "pdf"
            excluded = pdf and bool(re.search(r"^\s*(?:Table\s+of\s+Contents|Contents)\s*$",page["text"],re.I|re.M)
                                    or re.search(r"\bID\s+(?:Title|Description)\s+[^\n]{0,90}(?:Severity|Risk)\b",page["text"],re.I)
                                    or re.search(r"^\s*ID\s+Severity\s+[^\n]{0,60}(?:Status|Description)\b",page["text"],re.I|re.M))
            for value in page["text"].splitlines(keepends=True):
                raw = value.rstrip("\r\n")
                stripped = raw.strip()
                if stripped.startswith(("```", "~~~")):
                    fence = not fence
                match = re.match(r"^(#{1,6})\s+(.*)", stripped)
                content = match[2] if match else stripped
                self.lines.append(Line(raw, offset, offset + len(raw), page["page"],
                                       len(match[1]) if match else 0, content, fence, excluded))
                offset += len(value)

    def near(self, i, n=9):
        return "\n".join(l.text for l in self.lines[i:i+n])


def is_toc(line):
    return bool(index_line(line.text, padded=False) or
                re.match(r"^\s*(?:[-*] |\|)", line.text) or line.code or line.excluded)


def field_severity(text, key="Severity"):
    match = re.search(r"\b" + key + r"\s*(?:\*\*)?\s*[:|]\s*(?:\*\*)?(" + SEV + r")\b", text, re.I)
    return match[1] if match else None


def explicit_status(text):
    match = re.search(r"\b(?:Status|Update)\s*(?:\*\*)?\s*:\s*(?:\*\*)?(Partially (?:Fixed|Implemented)|Fixed before report|Not Implemented|Acknowledged|Unresolved|Resolved|Fixed|Open|Pending|Implemented|Invalid|Accepted|Mitigated|Won.t Fix|WIP)\b", text, re.I)
    return match[1] if match else None


def bracket_findings(report):
    """C4/Pashov and related ID-bearing detail headings, excluding TOCs/tables."""
    out = []
    pattern = re.compile(r"^(?:Issue\s+)?\[{0,2}(?P<id>(?P<code>C|H|M|L|I|G|NC|QA)[- ]\d+)\]?(?:\s*[:.)|–-]\s*|\s+)(?P<title>.+)", re.I)
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        if report.meta.get("file_format") in {"md", "html"} and not line.heading:
            continue
        m = pattern.match(line.content)
        if not m:
            continue
        if not line.heading and re.search(r"\s{2,}\d+\s*$", m["title"]):
            continue
        # Multi-column ID/title/status rows are summary entries, not detailed findings.
        if not line.heading and re.search(r"\s{3,}(?:Resolved|Fixed|Acknowledged|Open|" + SEV + r")\b", m["title"], re.I):
            continue
        title = re.sub(r"\s+#+\s*$", "", m["title"])
        if line.content.startswith("[["):
            title=re.sub(r"\]\(https?://.*\)\s*$","",title)
        code = m["code"].upper()
        raw = m["code"]  # Preserve the printed source code, not an invented spelled-out label.
        out.append(Candidate(line.start, title, raw, m["id"], severity(raw, report.firm),
                             method="severity-coded-heading", confidence=.9 if line.heading else .8,
                             evidence={"severity_basis": "printed_id_prefix", "label_is_code": True}))
    return out


def numbered_metadata(report, *, levels=(2,), prefixes=None, severity_key="Severity", inherit=False, chain=False):
    """Numbered detail sections with explicit nearby risk fields or severity parents."""
    out, current = [], None
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        m = re.match(r"^(\d+(?:\.\d+)+)\.?\s+(.+)", line.content)
        if not m:
            continue
        number, title = m.groups()
        section = re.fullmatch(r"(" + SEV + r"|Gas Savings)(?:\s+(?:Risk|Findings|Issues))?", title, re.I)
        if section:
            current = section[1]
            continue
        if len(number.split(".")) not in levels or (prefixes and not any(number.startswith(p) for p in prefixes)):
            continue
        nearby = report.near(i, 10)
        raw = field_severity(nearby, severity_key)
        if chain:
            match = re.search(r"(?:^|\n)\s*(?:[^\n]{0,60}?\s+)?(" + SEV + r")\s+Version\s+\d+", nearby, re.I)
            raw = match[1] if match else raw
        if raw is None and inherit:
            raw = current
        if raw is None:
            continue
        pid = re.search(r"\bID:\s*([A-Z][A-Z0-9]*-\d+)\b", nearby)
        out.append(Candidate(line.start, title, raw, pid[1] if pid else number, normalized=severity(raw, report.firm),
                             method="numbered-metadata" if not inherit else "numbered-severity-section", confidence=.9,
                             evidence={"section": number, "severity_basis": "explicit_field" if field_severity(nearby, severity_key) else "section_or_classification"}))
    return out


def numbered_severity_fields(report):
    """A numbered title followed by an explicit severity field (Oak/Trail of Bits)."""
    out = []
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        m = re.match(r"^(\d{1,3})[.)]\s*[\u200b]?\s*(.+)", line.content)
        if not m:
            continue
        nearby = report.near(i, 7)
        raw = field_severity(nearby)
        if raw:
            out.append(Candidate(line.start, m[2], raw, m[1], method="numbered-severity-field", confidence=.88))
    return out


def finish(report, candidates):
    """Bound spans and remove repeated TOC/detail IDs without merging semantic titles."""
    ordered = sorted(candidates, key=lambda c: c.start)
    result = []
    for i, c in enumerate(ordered):
        if result and result[-1].start == c.start:
            continue
        explicit_end = c.end is not None
        c.end = c.end if explicit_end else (ordered[i+1].start if i+1 < len(ordered) else len(report.text))
        # End before a clearly labelled appendix or footer section, not in arbitrary prose.
        tail = report.text[c.start:c.end]
        stop = re.search(r"\n\s*(?:#{1,3}\s+)?(?:(?:\d+\s+)?Appendix(?:\s+[A-Z])?\s*[:.—-]|(?:\d+\s+)?Disclaimers?\s*\n|(?:\d+\s+)?Conclusion\s*\n|(?:\d+\s+)?Audit Scope\s*\n|(?:Automated Analysis|Code Coverage|Test Results|Low Risk and Non-Critical Issues|Gas Optimizations)\s*\n)", tail, re.I)
        if not explicit_end and stop and stop.start() > 100:
            c.end = c.start + stop.start()
        # Explicit listing excerpts can be shorter than a detailed finding card.
        # Keep their exact bounds instead of padding them with the next entry.
        short_excerpt = (explicit_end and c.record_kind == "summary_excerpt" and bool(c.title)
                         and bool(report.text[c.start:c.end].strip()))
        short_native_detail = (explicit_end and c.record_kind == "formal_finding" and bool(c.title)
                               and c.evidence.get("publisher_explicit_short_detail") is True
                               and bool(report.text[c.start:c.end].strip()))
        if len(report.text[c.start:c.end].strip()) < 45 and not (short_excerpt or short_native_detail):
            continue
        # A variant may reject generic matches (for example inside code samples).
        if c.status_raw is None and not c.evidence.get('status_reader_complete'):
            c.status_raw = explicit_status(report.text[c.start:c.end])
        result.append(c)
    # Repeated printed IDs on distinct detail sections are retained (e.g. Guardian rounds).
    from prior_findings import exclude_prior_findings
    result = exclude_prior_findings(report, result)
    for candidate in result:
        candidate.normalized = candidate_severity(report, candidate)["normalized"]
    return result
