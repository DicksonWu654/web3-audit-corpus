"""Trail of Bits numeric finding titles and Severity/Difficulty/Type blocks."""
from core import numbered_severity_fields
from core import set_status_claim
from layout_support import bounded
import re
DESCRIPTION = "Numbered detail titles with Severity/Difficulty blocks; summary and TOC rows excluded"


def parse(report):
    from trail_of_bits_unrated import PROFILES, parse as unrated
    if report.meta.get('sha256') in PROFILES:
        return unrated(report)
    return numbered_severity_fields(report)


STATE = r'Partially\s+(?:Fixed|Resolved|Addressed)|Not\s+(?:Fixed|Resolved)|Risk Accepted|Unresolved|Resolved|Fixed|Acknowledged|Unaddressed|Addressed|Undetermined'


def read_status(report,candidates):
    bounded(report,candidates)
    claims={}; active=False
    for line in report.lines:
        if re.search(r'(?:Fix (?:Log|Status|Review)|Remediation (?:Status|Review)|Detailed Fix Log|Vulnerability Status|Finding Status)',line.content,re.I):
            active=True
        if not active or line.code:continue
        pid=re.match(r'^[ \t]*(TOB-[A-Z0-9-]+|\d{1,3})\b',line.text)
        # Commit/PR annotations wrap independently from the verdict column;
        # an open '(PR' on this line is still a complete Resolved assertion.
        verdict=re.search(r'(?:[ \t]{2,}|\|[ \t]*)('+STATE+r')(?:[ \t]+\([^\n]*)?[ \t|]*$',line.text,re.I)
        if pid and verdict:claims.setdefault(pid[1],[]).append((verdict,line.start))
    # Modern appendices give a separate TOB-ID heading and a leading verdict
    # paragraph. This also avoids joining noncontiguous wrapped table cells.
    for i,line in enumerate(report.lines):
        pid=re.match(r'^\s*(TOB-[A-Z0-9-]+)\s*:',line.text)
        if not pid:continue
        for following in report.lines[i+1:i+8]:
            if re.match(r'^\s*TOB-[A-Z0-9-]+\s*:',following.text):break
            verdict=re.match(r'^\s*('+STATE+r')(?:\b|[.:])',following.text,re.I)
            if verdict:
                claims.setdefault(pid[1],[]).append((verdict,following.start));break
    for c in candidates:
        if c.method == 'unrated-narrative-detail':
            continue  # Reviewed exact heading claims are already attached.
        c.evidence['status_reader_complete']=True
        body=report.text[c.start:c.end]
        # A native TOB ID is stronger than the ordinal used by old detail titles.
        native=re.search(r'\b(?:ID|Finding ID)(?:\s*:\s*|\s{2,})(TOB-[A-Z0-9-]+)',body[:1800],re.I)
        linked=claims.get(native[1],[]) if native else []
        if not linked:linked=claims.get(c.printed_id,[])
        if linked:
            if len({re.sub(r'\s+',' ',m[1].casefold()) for m,_ in linked})==1:
                m,offset=linked[-1];set_status_claim(report,c,m,offset,'trail_of_bits_fix_log_table')
            else:c.evidence['status_conflict']=True
            continue
        m=re.search(r'(?mi)^[ \t]*(?:Status|Fix Status)\s*:\s*('+STATE+r')\b',body)
        if m:set_status_claim(report,c,m,c.start,'trail_of_bits_status_field')


from variants import Variant, Fingerprint
VARIANTS=(
    Variant('trail-of-bits/v2020_fix_log',Fingerprint((('fix_log',r'Fix (?:Log|Status)|Detailed Fix Log',8),)),parse,('tob_fix_log',),read_status),
    Variant('trail-of-bits/legacy',Fingerprint(legacy=True),parse,('legacy_contract',),read_status),
)
