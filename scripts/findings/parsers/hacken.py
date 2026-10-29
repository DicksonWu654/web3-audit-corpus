"""Hacken's numbered Audit overview entries under printed severity buckets."""
import re
from core import Candidate, clean
from variants import Variant, Fingerprint

DESCRIPTION='Numbered detailed findings within the Audit overview severity sections; no issue summaries converted to findings'


def parse_legacy(report):
    text=report.text
    starts=list(re.finditer(r'(?im)^\s*(?:(?:Audit|Issues)\s+overview|Findings)\s*:?[ \t]*$',text))
    if not starts: return []
    start=starts[-1].end()
    stop=re.search(r'(?im)^\s*(?:Recommendations|Conclusion|Disclaimers)\s*$',text[start:])
    end=start+stop.start() if stop else len(text)
    section=text[start:end]
    headings=list(re.finditer(r'(?im)^\s*(Critical|High|Medium|Low|Informational)\s*$',section))
    output=[]
    for i,h in enumerate(headings):
        lo=start+h.end();hi=start+(headings[i+1].start() if i+1<len(headings) else len(section))
        items=list(re.finditer(r'(?m)^[ \t]*(\d{1,3})\.[ \t]+([^\n]+)',text[lo:hi]))
        for j,m in enumerate(items):
            a=lo+m.start();z=lo+items[j+1].start() if j+1<len(items) else hi
            body=text[a:z]
            status=re.search(r'(?im)^[ \t\f]*Status[ \t]*:[ \t]*(?:\r?\n[ \t]*)?(\S[^\r\n.]*)',body)
            if status and status[1].strip().casefold()=='www' and body[status.end(1):].lower().startswith('.hacken.io'):
                # A blank field above the running footer supplies no claim.
                status=None
            c=Candidate(a,clean(m[2]),h[1],h[1]+'-'+m[1],end=z,method='hacken-audit-overview',confidence=.9)
            c.evidence['publisher_explicit_short_detail']=True
            c.evidence['severity_label_span']=dict(start=start+h.start(1),end=start+h.end(1),text=h[1],basis='printed_parent_heading')
            if status:
                c.status_raw=status[1]
                c.evidence['status_evidence']=dict(start=a+status.start(1),end=a+status.end(1),text=status[1],raw=status[1],basis='explicit_status_field')
            output.append(c)
    return output


def initial_counts(report):
    """Read only the initial conclusion, including singular 'issue'."""
    m = re.search(r'(?is)As a result of the audit,?\s*security engineers found\s+(.{0,350}?(?:issues?|vulnerabilit(?:y|ies)))\.', report.text)
    if not m:
        m = re.search(r'(?is)Upon auditing,?\s*the code was found to contain\s+(.{0,350}?(?:issues?|vulnerabilit(?:y|ies)))[,.]', report.text)
    if not m:
        table = re.search(r'(?im)^\s*Review date[ \t]+Low[ \t]+Medium[ \t]+High[ \t]+Critical[ \t]*\n'
                          r'[^\n]*?\d{4}[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]*$', report.text)
        if table:
            return dict(counts=dict(zip(('low','medium','high','critical'),map(int,table.groups()))),
                        ambiguous=False,basis='first_printed_review_date_table_row',
                        evidence=[dict(start=table.start(),end=table.end(),text=table[0])])
        return None
    counts = {x[2].lower(): int(x[1]) for x in re.finditer(r'(\d+)\s+(critical|high|medium|low)', m[1], re.I)}
    if not counts and re.fullmatch(r'no\s+(?:severity\s+)?issues?', m[1].strip(), re.I):
        counts = dict.fromkeys(('critical', 'high', 'medium', 'low'), 0)
    return dict(counts=counts, ambiguous=False, basis='explicit_initial_audit_conclusion',
                evidence=[dict(start=m.start(), end=m.end(), text=m[0])]) if counts else None

def parse(report):
    """Extend the existing per-firm parser for a single unnumbered detail.

    A printed initial count of exactly one in that severity must independently
    confirm the cardinality. Never turn 'no issues', conclusions, checklists or
    API issue summaries into finding body text.
    """
    from core import Candidate, clean
    modern = parse_modern(report)
    if modern is not None:
        return modern
    result = parse_legacy(report)
    summary = initial_counts(report)
    if not summary:
        return result
    t = report.text
    starts = list(re.finditer(r'(?im)^\s*(?:(?:Audit|Issues)\s+overview|Findings)\s*:?[ \t]*$', t))
    if not starts:
        return result
    start = starts[-1].end()
    stop = re.search(r'(?im)^\s*(?:Recommendations|Conclusion|Disclaimers)\s*$', t[start:])
    end = start + stop.start() if stop else len(t)
    heads = list(re.finditer(r'(?im)^\s*(Critical|High|Medium|Low|Informational)\s*$', t[start:end]))
    for i, h in enumerate(heads):
        lo = start + h.end()
        hi = start + (heads[i + 1].start() if i + 1 < len(heads) else end - start)
        if summary['counts'].get(h[1].lower()) != 1 or any(lo <= c.start < hi for c in result):
            continue
        block = t[lo:hi]
        # Strip the running footer only at the end; preserve source coordinates.
        footer = re.search(r'(?im)^[ \t]*(?:www\.)?hacken\.io\s*\f?\s*$', block)
        if footer:
            hi = lo + footer.start()
            block = t[lo:hi]
        content = list(re.finditer(r'(?m)^([^\S\n]*)(\S[^\n]*)$', block))
        if not content:
            continue
        first = content[0]
        if re.match(r'(?:No\b|None\b|Not (?:found|applicable)|\d+\.)', first[2], re.I):
            continue
        if len(block.strip()) < 20 or re.search(r'(?m)^\s*(?:[2-9]\.|[•●])\s+', block):
            continue
        # Title is a verbatim first source line. A wrapped prose title remains
        # short; the exact full content is retained in the body span.
        a = lo + first.start(2)
        c = Candidate(a, clean(first[2]), h[1], '', end=hi,
                      method='hacken-unnumbered-detail', confidence=.9)
        c.evidence.update(publisher_explicit_short_detail=True,
            severity_label_span=dict(start=start+h.start(1), end=start+h.end(1), text=h[1], basis='printed_parent_heading'),
            unnumbered_cardinality_evidence=summary,
            publisher_finding_id_absent=True)
        result.append(c)
    return sorted(result, key=lambda c: c.start)

def parse_modern(report):
    """2023 C01/H01 cards and F-YYYY-ID cards, bounded to actual detail pages."""
    from core import Candidate, clean
    t=report.text
    starts=list(re.finditer(r'(?im)^\s*Findings\s*$',t))
    if not starts:
        return None
    start=starts[-1].end()
    stop=re.search(r'(?im)^\s*(?:Disclaimers|Appendix\s+\d+\..*)\s*$',t[start:])
    end=start+stop.start() if stop else len(t)
    section=t[start:end]
    codes=list(re.finditer(r'(?m)^[ \t\f]*(?P<id>[CHMLI]\d{2,3})\.[ \t]+(?P<title>[^\n]+)',section))
    cards=list(re.finditer(r'(?m)^[ \t\f]*(?P<id>F-\d{4}-\d+)[ \t]+-[ \t]+(?P<title>[^\n]+?)[ \t]+-[ \t]+(?P<sev>Critical|High|Medium|Low|Info(?:rmational)?)[ \t]*$',section))
    heads=list(re.finditer(r'(?im)^\s*(Critical|High|Medium|Low|Informational|Observation Details)\s*$',section))
    output=[]
    if cards:
        for i,m in enumerate(cards):
            a=start+m.start(); z=start+(cards[i+1].start() if i+1<len(cards) else len(section))
            parent=re.search(r'(?im)^\s*Observation Details\s*$',t[a:z])
            if parent:
                z=a+parent.start()
            if not re.search(r'(?im)^[ \t]*Description:',t[a:min(z,a+400)]):
                continue
            c=Candidate(a,clean(m['title']),m['sev'],m['id'],end=z,
                method='hacken-f-id-detail',confidence=.95)
            c.evidence.update(publisher_explicit_short_detail=True,
                severity_label_span=dict(start=start+m.start('sev'),end=start+m.end('sev'),text=m['sev'],basis='printed_heading_label'),
                source_section='Observation Details' if m['sev'].lower().startswith('info') else 'Vulnerability Details')
            output.append(c)
    elif codes:
        for i,m in enumerate(codes):
            a=start+m.start(); z=start+(codes[i+1].start() if i+1<len(codes) else len(section))
            parents=[h for h in heads if h.start()<m.start()]
            parent=parents[-1] if parents else None
            if not parent or not parent[1].upper().startswith(m['id'][0]):
                continue
            next_parent=next((h for h in heads if m.end()<h.start()<z-start),None)
            if next_parent:
                z=start+next_parent.start()
            c=Candidate(a,clean(m['title']),parent[1],m['id'],end=z,
                method='hacken-letter-id-detail',confidence=.95)
            c.evidence.update(publisher_explicit_short_detail=True,
                severity_label_span=dict(start=start+parent.start(1),end=start+parent.end(1),text=parent[1],basis='printed_parent_heading'))
            output.append(c)
    return output if cards or codes else None


def printed_counts(report):
    return initial_counts(report)


VARIANTS=(Variant('hacken/v2020_audit_overview',Fingerprint((
    ('audit_overview',r'^\s*(?:(?:Audit|Issues)\s+overview|Findings)\s*:?[ \t]*$',6),
    ('printed_severity_bucket',r'^\s*(?:Critical|High|Medium|Low)\s*$',2))),
    parse,('hacken_audit_overview',),printed_counts=printed_counts,
    notes='Detailed numbered entries within printed severity buckets; unfamiliar layouts remain flagged.'),)


# Prefer explicit modern finding IDs over embedded numbered recommendation steps.
VARIANTS = (Variant('hacken/gapfill_modern_v1', Fingerprint((
    ('modern_detail_id', r'^\s*(?:[CHMLI]\d{2,3}\.|F-\d{4}-\d+\s+-)', 5),
    ('findings_section', r'^\s*Findings\s*$', 4))), parse,
    ('hacken_gapfill_letter_cards', 'hacken_gapfill_f_cards'), printed_counts=printed_counts),) + VARIANTS
