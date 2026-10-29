"""Zellic Detailed Findings use numbered headings; article risk follows Impact."""
import re
from core import Candidate, SEV, is_toc, numbered_metadata
from core import set_status_claim
from layout_support import bounded
DESCRIPTION = "Detailed numbered findings with explicit Impact (or legacy Severity) risk metadata"


def parse(report):
    # Zellic describes its published risk buckets as impact ratings, not likelihood.
    out = []
    for i,line in enumerate(report.lines):
        if is_toc(line):
            continue
        m = re.search(r"(?<![\d.])(\d+\.\d+)\.?\s+(.+)",line.content)
        if not m:
            continue
        context = report.near(i,12)
        if not re.search(r"\b(?:Target|Category)\b",context):
            continue
        raw = None
        for key in ("Impact", "Severity"):
            value = re.search(r"\b"+key+r"\s*(?::\s*|\s{2,})("+SEV+r")\b",context,re.I)
            if value:
                raw = value[1]
                break
        if raw:
            start = line.start + line.text.find(m[1])
            out.append(Candidate(start,m[2],raw,m[1],method="zellic-column-metadata",confidence=.92,
                                 evidence={"severity_basis":"publisher_impact_rating"}))
    return out or numbered_metadata(report, levels=(2,), severity_key="Impact") or numbered_metadata(report, levels=(2,))


def read_status(report, candidates):
    bounded(report, candidates)
    state = r'Partially (?:fixed|resolved|addressed)|Not (?:fixed|resolved)|Acknowledged and fixed|Acknowledged|Fixed|Resolved|Remediated|Addressed|Mitigated|Unresolved|Open'
    table={};active=False
    for line in report.lines:
        if re.search(r'\bFinding\s+Status\b',line.text,re.I):active=True;continue
        if not active:continue
        m=re.match(r'^\s*(\d+\.\d+)\s{2,}('+state+r')\s*$',line.text,re.I)
        if m:table.setdefault(m[1],[]).append((m,line.start))
        elif re.match(r'^\s*(?:\d+\.\s+|Detailed Findings|Executive Summary)',line.content,re.I):active=False
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        c.status_raw=c.normalized_status=None
        body = report.text[c.start:c.end]
        claims = []
        for section in re.finditer(r'(?mi)^[ \t\f]*(?:#{1,6}\s*)?(?:Remediation|Resolution|Fix Review)\s*:?\s*\n', body):
            response = body[section.end():]
            for m in re.finditer(r'\b('+state+r')\b', response, re.I):
                prefix = response[max(0,m.start()-90):m.start()]
                if re.search(r'\b(?:should|could|would|will|to be|not yet|not been|if|unless|recommend)\b',prefix,re.I): continue
                claims.append((m, section.end()))
        if claims:
            m, offset = claims[-1]
            set_status_claim(report,c,m,c.start+offset,'zellic_remediation_assertion')
        elif table.get(c.printed_id):
            linked=table[c.printed_id]
            if len({m[2].casefold() for m,_ in linked})==1:
                m,offset=linked[-1]
                set_status_claim(report,c,m,offset,'zellic_finding_status_table',group=2)
            else:c.evidence['status_conflict']=True


from variants import Variant, Fingerprint
VARIANTS = (
    Variant('zellic/v2022_remediation', Fingerprint((('remediation',r'^\s*Remediation\s*$',8),)), parse, ('zellic_remediation',), read_status),
    Variant('zellic/legacy', Fingerprint(legacy=True), parse, ('legacy_contract',), read_status),
)
