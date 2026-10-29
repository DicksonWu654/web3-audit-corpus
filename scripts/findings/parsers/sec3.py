"""Soteria/Sec3 ID headings inside Findings in Detail, including multi-program IDs."""
from __future__ import annotations
from core import severity, Candidate, SHORT, clean
from collections import Counter, defaultdict
import re
DESCRIPTION = 'Sec3/Soteria finding IDs confined to detailed findings; overview statuses, compound IDs and unlabeled team issues retained'
ID=re.compile(r'^\s*\[(?P<id>(?:(?:P\d+-)?[A-Z]-)?\d+(?:-\d+)*)\]\s+(?P<title>.+)$')


def overview(report):
    """Independently read source overview rows; never create detailed findings from them."""
    active=False;rows=[]
    for line in report.lines:
        v=line.content
        if re.fullmatch(r'Result Overview',v,re.I): active=True;continue
        if active and re.fullmatch(r'(?:Findings in Detail|Appendix.*|DISCLAIMER)',v,re.I): break
        if not active: continue
        m=ID.match(line.text)
        if not m: continue
        cells=re.split(r'\s{2,}',m['title'])
        # Last columns are printed impact and status. Some reports omit impact.
        state=cells[-1] if len(cells)>1 else None
        risk=cells[-2] if len(cells)>2 else None
        rows.append({'id':m['id'],'title':cells[0],'risk':risk,'status':state,'page':line.page,'start':line.start,'end':line.end,'text':line.text})
    return rows


def parse(report, era=None):
    active=False;out=[];lookup=defaultdict(list)
    for row in overview(report):lookup[row['id']].append(row)
    stop=len(report.text)
    for i,line in enumerate(report.lines):
        v=line.content
        if re.fullmatch(r'Findings in Detail',v,re.I): active=True;continue
        if active and re.fullmatch(r'(?:Appendix.*|DISCLAIMER|ABOUT)',v,re.I):stop=line.start;break
        if not active: continue
        m=ID.match(line.text)
        if not m or re.search(r'\.{4}',line.text):continue
        if era == 'program' and not m['id'].startswith('P'):continue
        if era == 'plain' and m['id'].startswith('P'):continue
        if m['id'].isdigit() and (len(m['id'])<2 or m['id'] not in lookup):continue
        source=lookup.get(m['id'],[])
        source=source[0] if len(source)==1 else None
        title=m['title'];j=i+1
        # Some PDF paragraphs directly follow the heading without a blank line.
        # Extend only when the independently printed overview confirms a continuation.
        key=lambda value: re.sub(r'[^a-z0-9]','',value.lower())
        reference=key(source['title']) if source else ''
        while j<len(report.lines) and report.lines[j].content and report.lines[j].page==line.page:
            nxt=report.lines[j].content
            if not reference.startswith(key(title+' '+nxt)):
                break
            title+=' '+nxt;j+=1
        code=re.search(r'(?:^|-)([A-Z])-\d',m['id'])
        prefix=code[1] if code else ''
        raw=source['risk'] if source and source['risk'] else prefix if prefix in SHORT else None
        normalized=None if source and source['risk'] else SHORT.get(prefix,'unknown')
        start=line.start
        for previous in reversed(report.lines[max(0,i-3):i]):
            if not previous.content:continue
            if re.match(r'^IMPACT\s*[–—-]',previous.content):start=previous.start
            break
        out.append(Candidate(start,clean(title),raw,m['id'],normalized=severity(raw, report.firm),
                   status_raw=source['status'] if source else None,method='detailed-id-heading',confidence=.97,
                   evidence={'severity_basis':'printed_overview_impact' if source and source['risk'] else 'printed_id_prefix' if prefix in SHORT else 'unlabeled_publisher_finding',
                             'overview_row':source} ))
    for i,c in enumerate(out):c.end=out[i+1].start if i+1<len(out) else stop
    return out


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, fields


def parse_single_digit(report):
    return parse(report,'plain')


def parse_padded(report):
    return parse(report,'plain')


def parse_program(report):
    # Compound P1/P2 namespaces are independent finding sequences.
    return parse(report,'program')


def parse_clean_review(report):
    return []


def status_overview(report,candidates):
    fields(report,candidates,(FIELD,))


def status_padded(report,candidates):
    status_overview(report,candidates)


def status_program(report,candidates):
    status_overview(report,candidates)


def status_clean_review(report,candidates):
    fields(report,candidates,(),preserve=False)


VARIANTS=(
    Variant('sec3/v2022_program_ids',Fingerprint((('program_id',r'^\s*\[P\d+-[A-Z]-\d+(?:-\d+)*\]',10),),('2022','2024')),parse_program,('sec3_program',),status_program),
    Variant('sec3/v2024_padded_ids',Fingerprint((('padded_id',r'^\s*\[[A-Z]-0\d+\]',8),('detail_chapter',r'^\s*Findings in Detail\s*$',2)),('2024','2026')),parse_padded,('sec3_padded',),status_padded),
    Variant('sec3/v2022_overview_ids',Fingerprint((('detail_chapter',r'^\s*Findings in Detail\s*$',6),('overview',r'^\s*Result Overview\s*$',2)),('2022','2024')),parse_single_digit,('sec3_overview',),status_overview),
    Variant('sec3/v2023_clean_review',Fingerprint((('overview',r'^\s*Result Overview\s*$',4),('clean_statement',r'no (?:security )?(?:issues?|vulnerabilities|findings)|no (?:high|critical)[^\n]*issues',3)),('2023','2026')),parse_clean_review,('sec3_clean',),status_clean_review),
)
