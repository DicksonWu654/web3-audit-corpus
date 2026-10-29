"""CODESPECT detail status fields and terminal overview status cells."""
import re
from parsers.generic import parse, DESCRIPTION
from core import set_status_claim
from layout_support import bounded
from variants import Variant, Fingerprint

STATE = r'Partially (?:Fixed|Resolved)|Not Fixed|Unresolved|Fixed|Acknowledged|Resolved|Open'


def read_status(report, candidates):
    bounded(report, candidates)
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        body = report.text[c.start:c.end]
        hits = list(re.finditer(r'(?mi)^[ \t]*Status\s*:\s*('+STATE+r')\b', body))
        if c.record_kind == 'summary_excerpt':
            hits += list(re.finditer(r'(?:[ \t]{2,}|\|[ \t]*)('+STATE+r')[ \t|.]*$', body, re.I))
        if hits:
            set_status_claim(report, c, hits[-1], c.start, 'codespect_detail_field' if c.record_kind != 'summary_excerpt' else 'codespect_overview_cell')


VARIANTS = (Variant('codespect/v2024_status_cards', Fingerprint((
    ('publisher', r'CODESPECT', 6), ('overview', r'Findings Overview', 2))),
    parse, ('codespect_status',), read_status),)
