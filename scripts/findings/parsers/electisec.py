"""Electisec/yAudit reports have '1. High - title' headings and MD [H-n] entries."""
from core import severity, Candidate, SEV, bracket_findings, is_toc, numbered_metadata
import re
DESCRIPTION = "Numbered explicit severity-title headings and legacy yAudit severity-ID headings"


def parse(report):
    out = bracket_findings(report)
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        m = re.match(r"^(\d+)\.\s+(" + SEV + r"|Gas savings)\s*[-–:]\s*(.+)", line.content, re.I)
        if m:
            out.append(Candidate(line.start, m[3], m[2], m[2] + "-" + m[1],
                                 normalized=severity(m[2], report.firm),
                                 method="electisec-severity-title", confidence=.9))
    return out or numbered_metadata(report,levels=(3,),inherit=True)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('electisec', parse),)
