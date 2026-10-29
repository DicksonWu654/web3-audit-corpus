"""Shieldify Markdown and PDF detail cards, including details sharing an index page."""
from core import severity, Candidate, SHORT, clean
import re

DESCRIPTION = 'Severity-ID detail cards, wrapped titles and standalone risk metadata in Markdown/PDF'
LABEL = r'Critical|High|Medium|Low|Informational|Information|Info|Gas(?: Optimization)?'


def bounded(report, candidates):
    """Group 3 source receipts and explicit chapter/appendix boundaries."""
    ordered=sorted(candidates,key=lambda c:c.start)
    for i,c in enumerate(ordered):
        c.evidence['parser_revision']='phase4b-group3-v1'
        key=re.sub(r'[\s_]+','',(c.status_raw or '')).lower()
        native_status={'solved':'fixed','riskaccepted':'acknowledged','partiallyresolved':'partial',
                       'partiallyfixed':'partial','partiallysolved':'partial','noissue':'invalid','new':'open','reported':'open'}
        if key in native_status and hasattr(c,'normalized_status'):
            c.normalized_status=native_status[key]
        end=ordered[i+1].start if i+1<len(ordered) else len(report.text)
        tail=report.text[c.start:end]
        stop=re.search(r'^\s*(?:#{1,3}\s+)?(?:(?:\d{1,2}[.)]?|[A-D])\s+)?(?:APPENDIX(?:\s+[A-Z])?\s*(?:[:—.–-].*)?|CONCLUSION|DISCLAIMER|Vulnerability Severity Rating|About Neodyme|Scope of the Audit)\s*$',tail,re.I|re.M)
        if c.end is None and stop and stop.start()>100:
            c.end=c.start+stop.start()
    return ordered


def cards(report, *, description=False):
    out=[]
    for i,line in enumerate(report.lines):
        explicit_header=report.firm=='shieldify' and bool(re.match(r'^FINDING\s+',line.content,re.I))
        value=re.sub(r'^FINDING\s+','',line.content,flags=re.I) if explicit_header else line.content
        id_pattern=r'(?:C|H|M|L|I|G|NC|QA)-\d+' if not explicit_header else r'[CHMLIG1]-[0-9O]+'
        m=re.match(r'^\[?('+id_pattern+r')\]?\s*[:.)–-]?\s*(.*)',value,re.I)
        if not m or (line.code and report.meta.get('file_format')!='pdf') or re.search(r'(?:\.\s*){3,}\s*\d+\s*$',line.content):
            continue
        if report.meta.get('file_format') in {'md','html'} and not line.heading:
            continue
        if re.search(r'\s{3,}(?:'+LABEL+r'|Fixed|Resolved|Acknowledged|Open)\b',m[2],re.I):
            continue
        title=[m[2]]
        card_start=line.start
        raw=None
        found=False
        prior=next((l for l in reversed(report.lines[max(0,i-4):i]) if l.content),None)
        priorlabel=re.fullmatch(r'('+LABEL+r')(?:\s{2,}(Fixed|Resolved|Acknowledged|Open|Pending))?',prior.content,re.I) if prior else None
        following=next((l for l in report.lines[i+1:i+5] if l.content),None)
        if (explicit_header and not m[2] and following and following.content=='Description'
                and prior and prior.page==line.page and not priorlabel):
            title=[prior.content]
            card_start=prior.start
        for j,nxt in enumerate(report.lines[i+1:i+18],i+1):
            if re.match(r'^\[?[CHMLIG]-\d+',nxt.content,re.I):
                break
            field=re.match(r'^\*{0,2}Severity\*{0,2}\s*:?',nxt.content,re.I)
            if field:
                tail=nxt.content[field.end():].strip(' *:')
                if not tail:
                    tail=next((l.content for l in report.lines[j+1:j+5] if l.content),'').strip('*')
                sm=re.match(r'('+LABEL+r')(?: Risk)?\b',tail,re.I)
                if sm:
                    raw=sm[0]
                    found=True
                break
            if re.fullmatch(r'Description|Summary',nxt.content,re.I):
                found=description or bool(line.heading) or bool(priorlabel) or explicit_header
                if priorlabel:
                    raw=priorlabel[1]
                break
            if re.fullmatch(r'Location of Affected Code|Recommendation|Team Response',nxt.content,re.I):
                break
            if description and re.match(r'(?:Initial|Post-fix) diff review',nxt.content,re.I):
                continue
            if nxt.heading:
                break
            if nxt.content:
                if re.search(r'SMART CONTRACT SECURITY ASSESSMENT|S\s+H\s+I\s+E\s+L\s+D\s+I\s+F\s+Y',nxt.content,re.I):
                    continue
                if re.fullmatch(r'\d+',nxt.content):
                    following=next((l for l in report.lines[j+1:j+6] if l.content),None)
                    if not (following and re.match(r'^Severity\b',following.content,re.I)):
                        if following and following.page!=nxt.page:
                            continue
                        break
                title.append(nxt.content)
        if not found and line.heading and report.meta.get('file_format') in {'md','html'}:
            found=True
            title=[m[2]]
        if not found:
            continue
        id_code=m[1].split('-')[0].upper()
        source_risk=raw or (m[1].split('-')[0] if id_code in SHORT else None)
        out.append(Candidate(card_start,clean(' '.join(title)),source_risk,m[1],severity(source_risk, report.firm),
                             status_raw=priorlabel[2] if priorlabel else None,
                             method='severity-id-detail-card',confidence=.96,
                             evidence={'severity_basis':'explicit_field' if raw else 'printed_id_prefix' if source_risk else 'unrecognized_ocr_id_prefix'}))
        if explicit_header and (m[1].startswith('1-') or 'O' in m[1]):
            out[-1].evidence['ocr_id_uncertain']=True
    for j,c in enumerate(out):
        body=report.text[c.start:out[j+1].start if j+1<len(out) else len(report.text)]
        st=re.search(r'\b(?:Status|Remediation)\s*:?\s*(?:\n\s*)?(Partially (?:Fixed|Resolved)|Fixed|Resolved|Acknowledged|Open|Won.t Fix|Mitigated|Accepted)\b',body,re.I)
        if not st:
            st=re.search(r'(?:^|\n)\s*(?:#{1,4}\s*)?(?:Resolution|Remediation)\s*\n\s*(Fixed|Resolved|Acknowledged|Open)\b',body,re.I)
        if st:
            c.status_raw=st[1]
    statuses={}
    for line in report.lines:
        sm=re.match(r'^\|?\s*\[?([CHMLIG]-\d+)\]?\s*(?:\||\s{2,}).*?(Fixed|Resolved|Acknowledged|Open|Pending|Partially Fixed)\s*\|?\s*$',line.content,re.I)
        if sm:
            statuses.setdefault(sm[1],[]).append((sm[2],line.start,line.end))
    for c in out:
        entries=statuses.get(c.printed_id,[])
        if c.status_raw is None and entries and len({v[0].lower() for v in entries})==1:
            c.status_raw=entries[0][0]
            c.evidence['status_summary_span']={'start':entries[0][1],'end':entries[0][2]}
    return bounded(report,out)


def parse(report):
    return cards(report)


from variants import Variant, Fingerprint
from layout_support import STATUS, status_value


def markdown_cards(report):
    """2023–26 Markdown headings and pipe-table remediation index."""
    return cards(report)


def pdf_risk_cards(report):
    """2023–26 bracketed ID/title, then a separate Severity/High Risk field."""
    return cards(report)


def pdf_badge_cards(report):
    """2026 redesign: risk/status badges above ID/title or FINDING identifier."""
    return cards(report,description=True)


SHIELDIFY_STATUS=(r'(?:Acknowledged\s+and\s+(?:partially\s+)?fixed|Partially (?:Addressed|Solved|Mitigated)|'
                  r'No (?:Issue|Fix Required)|Not (?:yet )?(?:Fixed|Resolved)|Solved|Risk Accepted|'+STATUS+r')')


def _claim(text):
    # A response may say "Acknowledged and fixed"; its last action determines
    # remediation. Arbitrary recommendations containing "fixed" never match.
    return re.match(r'\s*(?:\*\*|\{|\[)?\s*('+SHIELDIFY_STATUS+r')\b',text,re.I)


def _status_normalized(raw):
    key=clean(raw).casefold()
    return {'acknowledged and fixed':'fixed','acknowledged and partially fixed':'partial',
            'partially addressed':'partial','partially solved':'partial','partially mitigated':'partial',
            'no issue':'invalid','no fix required':'acknowledged','not yet fixed':'open','not yet resolved':'open',
            'solved':'fixed'}.get(key) or status_value(raw,'shieldify')


def _attach_status(report,candidates,*,badges=False):
    indices={}
    for line in report.lines:
        m=re.match(r'^\s*\|?\s*\[?([CHMLIG]-\d+)\]?\s*(?:\||\s{2,})',line.text,re.I)
        if not m:continue
        tail=re.search(r'\b('+SHIELDIFY_STATUS+r')\s*\.?\s*\|?\s*$',line.text,re.I)
        if tail:indices.setdefault(m[1].casefold(),[]).append((tail[1],line.start+tail.start(1),line.start+tail.end(1),'printed_id_status_table'))
    for c in candidates:
        c.evidence['status_reader_complete']=True
        c.status_raw=None;c.normalized_status=None
        body=report.text[c.start:c.end]
        claims=[]
        # Restrict to labelled publisher response fields, never exploit code.
        for i,line in enumerate(report.lines):
            if not c.start<=line.start<c.end or line.code:continue
            header=re.match(r'^\*{0,2}(Team Response|Status|Resolution|Remediation|Fix Review)\*{0,2}\s*:?\s*(.*)$',line.content,re.I)
            if not header:continue
            tail=header[2]
            value=line; m=_claim(tail)
            if m:
                col=line.text.find(tail)+m.start(1)
            else:
                value=next((n for n in report.lines[i+1:i+7] if n.content and n.start<c.end and not n.code),None)
                if value is None or value.heading:continue
                m=_claim(value.content)
                if not m:continue
                col=value.text.find(value.content)+m.start(1)
            claims.append((m[1],value.start+col,value.start+col+len(m[1]),
                           'publisher_team_response' if header[1].casefold()=='team response' else 'labelled_resolution_field'))
        if not claims and badges:
            first=next((i for i,l in enumerate(report.lines) if l.start>=c.start),0)
            for line in report.lines[max(0,first-5):first+2]:
                badge=re.fullmatch(r'\s*('+LABEL+r')\s{2,}('+SHIELDIFY_STATUS+r')\s*',line.text,re.I)
                if badge:
                    claims.append((badge[2],line.start+badge.start(2),line.start+badge.end(2),'printed_risk_status_badge'))
        if not claims:
            table=indices.get((c.printed_id or '').casefold(),[])
            if len({_status_normalized(x[0]) for x in table})==1:claims=table[-1:]
            elif table:c.evidence['status_conflict']=True
        if claims:
            raw,start,end,basis=claims[-1]
            c.status_raw=raw;c.normalized_status=_status_normalized(raw)
            c.evidence['status_evidence']={'raw':raw,'start':start,'end':end,'text':report.text[start:end],
                                          'basis':basis,'profile':'shieldify'}


def status_markdown(report,candidates):return _attach_status(report,candidates)
def status_pdf_risk(report,candidates):return _attach_status(report,candidates)
def status_pdf_badges(report,candidates):return _attach_status(report,candidates,badges=True)


VARIANTS=(
    Variant('shieldify/v2023_markdown_cards',Fingerprint((
        ('markdown_finding',r'^\s*#{1,4}\s+\[?[CHMLIG]-\d+\]?\s+\S',8),
        ('findings_chapter',r'^\s*#{1,3}\s+(?:\d+\.\s*)?Findings\s*$',6),
        ('publisher_chapter',r'^\s*#{1,3}\s+\d+\.\s+About Shieldify\s*$',6),
    ),('2023','2026'),formats=('md','html')),markdown_cards,('shieldify_markdown_card',),status_markdown,
            notes='Markdown detail headings plus ID-linked status table and Team Response.'),
    Variant('shieldify/v2026_pdf_badge_cards',Fingerprint((
        ('finding_identifier',r'^\s*FINDING\s+[CHMLIG1]-[0-9O]+',14),
        ('risk_status_badge',r'^\s*(?:'+LABEL+r')\s{2,}(?:'+SHIELDIFY_STATUS+r')\s*$',12),
        ('risk_badge_without_status',r'^\s*(?:'+LABEL+r')\s*$',12),
        ('bare_identifier',r'^\s*[CHMLIG]-\d+\s+\S',2),
    ),('2026','2026'),formats=('pdf',)),pdf_badge_cards,('shieldify_pdf_badge','shieldify_pdf_finding'),status_pdf_badges,
            notes='2026 redesign with risk/status badges and title above/beside FINDING IDs; OCR uncertainty preserved.'),
    Variant('shieldify/v2023_pdf_risk_cards',Fingerprint((
        ('severity_field',r'^\s*Severity\s*$',7),
        ('findings_chapter',r'^\s*(?:\d+\.\s*)?Findings(?: Summary)?\s*$',6),
        ('report_footer',r'Your smart contracts, our shielding',6),
    ),('2023','2026'),formats=('pdf',)),pdf_risk_cards,('shieldify_pdf_risk_card','shieldify_pdf_zero_findings'),status_pdf_risk,
            notes='Bracketed ID/title with separate Risk label and publisher response; explicit clean reviews retain zero rows.'),
)
