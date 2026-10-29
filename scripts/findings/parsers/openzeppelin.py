"""OpenZeppelin web reports group level-three finding headings under severity sections."""
from core import severity, Candidate, SEV, bracket_findings, is_toc
import re
DESCRIPTION = "Web heading hierarchy under severity sections, including Notes & Additional Information"


def parse(report):
    out, current, level = [], None, 0
    for line in report.lines:
        if line.code or not line.heading:
            continue
        title = line.content.strip()
        m = re.fullmatch(r"(" + SEV + r")(?:\s+Severity)?(?:\s+Issues)?", title, re.I)
        if m or re.fullmatch(r"Notes?\s*(?:&|and)\s*Additional Information", title, re.I):
            current = m[1] if m else title
            level = line.heading
            continue
        if current and line.heading <= level:
            current = None
        if current and line.heading == level + 1:
            out.append(Candidate(line.start, title, current, method="openzeppelin-severity-section", confidence=.88,
                                 normalized=severity(current, report.firm),
                                 evidence={"severity_basis":"publisher_section", "section":current}))
    return out or bracket_findings(report)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('openzeppelin', parse),)
