"""Fallback: severity-coded headings, explicit severity metadata, then summary table candidates."""
import re
from core import Candidate, SEV, bracket_findings, numbered_metadata, numbered_severity_fields, field_severity, is_toc

DESCRIPTION = "Severity-coded headings, numbered detail metadata, and explicitly labelled summary-table excerpts"


def parse(report):
    entries = bracket_findings(report)
    occupied = {c.start for c in entries}
    for c in numbered_metadata(report, levels=(2, 3, 4)) + numbered_severity_fields(report):
        if c.start not in occupied:
            c.method = "generic-" + c.method
            c.confidence = min(c.confidence, .65)
            entries.append(c)
            occupied.add(c.start)
    if entries:
        return entries
    # Table-only rows stay summary excerpts; they never masquerade as detailed findings.
    for i, line in enumerate(report.lines):
        if line.code:
            continue
        cells = [x.strip() for x in re.split(r"\s{2,}|\|", line.text) if x.strip()]
        if len(cells) < 3 or not re.fullmatch(r"(?:[A-Z]{1,8}[-_])?\d{1,3}", cells[0]):
            continue
        severity_cell = next((x for x in cells[1:] if re.fullmatch(SEV, x, re.I)), None)
        titles = [x for x in cells[1:] if len(x) > 10 and x != severity_cell and not re.fullmatch(r"Resolved|Acknowledged|Fixed|Open|Pending", x, re.I)]
        if severity_cell and titles:
            entries.append(Candidate(line.start, titles[0], severity_cell, cells[0], end=line.end,
                                     method="generic-summary-table", confidence=.4, record_kind="summary_excerpt"))
    return entries
