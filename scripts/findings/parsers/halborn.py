"""Halborn's numbered HAL detail sections, before and after numeric risk scores."""
from core import severity, Candidate, clean
import re
from parsers.shieldify import bounded

DESCRIPTION = 'HAL detail sections with wrapped titles, printed risk labels and remediation status'
LABEL = r'CRITICAL|HIGH|MEDIUM|VERY LOW|LOW|INFORMATIONAL|INFORMATION|INFO'
RISK = r'\s*[-–—−]\s*('+LABEL+r')(?:\s*\([\d.]+\))?(?:\s+(?:'+LABEL+r')?\s*(?:RISK ACCEPTED|ACKNOWLEDGED|SOLVED))?\s*[}]*$'


def parse(report, era=None):
    out = []
    toc_pages={p['page'] for p in report.meta['pages'] if re.search(r'^[ \t]*(?:Description|Risk Level|Remediation Plan)[ \t]{2,}\d+[ \t]*$',p['text'],re.M)}
    for i, line in enumerate(report.lines):
        m = re.match(r'^(\d+(?:\.\d+)+)\.?\s+(?:\((HAL-\d+)\)\s*)?(.*)', line.content, re.I)
        hal = re.match(r'^\((HAL-\d+)\)\s+(.+)',line.content,re.I) if line.heading else None
        if not (m or hal) or line.page < 5 or line.page in toc_pages:
            continue
        if era == 'sections' and ((m and m[2]) or hal):
            continue
        if era == 'hal' and not ((m and m[2]) or hal):
            continue
        if era == 'pentest':
            continue
        if re.search(r'\s{3,}\d+\s*$', line.text):
            continue
        if m and re.match(r'(?:Remediation|Recommendation|Description|Risk Level)\b',m[3],re.I):
            continue
        if m and not m[2] and (not m[1].startswith('3.') or not re.search(r'\bDescription\b',report.near(i,15),re.I)):
            continue
        first=m[3] if m else hal[2]
        parts = [first]
        # Wrapped PDF headings end before the description metadata.
        for nxt in ([] if re.search(RISK,first,re.I) else report.lines[i+1:i+20]):
            if not nxt.content:
                continue
            if re.fullmatch(r'FINDINGS & TECH DETAILS|\d+',nxt.content,re.I):
                continue
            if re.match(r'\d+(?:\.\d+)+\.?\s+\(HAL-\d+\)',nxt.content,re.I):
                break
            if re.match(r'(?:Description\b|Details:|Risk Level|Score\b|BVSS|Exploitability\b|Impact\b|Code Location)', nxt.content, re.I):
                break
            parts.append(nxt.content)
            if re.search(RISK,clean(' '.join(parts)),re.I):
                break
        heading = clean(' '.join(parts)).rstrip(' }')
        risk = re.search(RISK, heading, re.I)
        if not risk:
            risk = re.search(r'\b(' + LABEL + r')\s*\([\d.]+\)\s*$', heading, re.I)
        if risk:
            out.append(Candidate(line.start, heading[:risk.start()].rstrip(' -–'), risk[1], (m[2] or m[1]) if m else hal[1],
                                 normalized=severity(risk[1], report.firm),
                                 method='halborn-hal-detail', confidence=.96))
    # The first wallet pentest era has unnumbered risk-suffixed headings.
    # Repeated headers followed only by remediation are continuation pages.
    if not out and era in {None, 'pentest'}:
        for i,line in enumerate(report.lines):
            risk=re.search(RISK,line.content,re.I)
            if not risk or line.page<5 or line.page in toc_pages:
                continue
            if re.search(r'\s{3,}\d+\s*$',line.text):
                continue
            near=report.near(i+1,7)
            page=next(p['text'] for p in report.meta['pages'] if p['page']==line.page)
            if not (re.search(r'\bDescription\s*:',near,re.I) or 'FINDINGS & TECH DETAILS' in page):
                continue
            title=[line.content[:risk.start()]]
            start=line.start
            for prev in reversed(report.lines[max(0,i-2):i]):
                if not prev.content or prev.page!=line.page or re.search(r'DETAILS|[.;:]$',prev.content):
                    break
                title.insert(0,prev.content)
                start=prev.start
            out.append(Candidate(start,clean(' '.join(title)),risk[1],None,
                                 method='halborn-legacy-pentest-heading',confidence=.92))
    for j,c in enumerate(out):
        end = out[j+1].start if j+1 < len(out) else len(report.text)
        body = report.text[c.start:end]
        st = re.search(r'\b(?:Remediation (?:Plan|Status)|Status)\s*:?\s*(PARTIALLY (?:SOLVED|FIXED|RESOLVED)|SOLVED|RESOLVED|FIXED|ACKNOWLEDGED|RISK ACCEPTED|NOT APPLICABLE|UNRESOLVED|ACCEPTED)\b', body, re.I)
        if not st:
            st=re.search(r'\b(RISK ACCEPTED|ACKNOWLEDGED|PARTIALLY SOLVED|SOLVED)\s*$',body[:300],re.I|re.M)
        if st:
            c.status_raw = st[1]
    return bounded(report,out)


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields, claim


def counts_sections(report):
    from summary_counts import printed_counts
    from collections import Counter
    result=printed_counts(report)
    if not result:return None
    tally=Counter();proof=[]
    for page in report.meta['pages']:
        ls=page['text'].splitlines(keepends=True);offset=page['start'];column=None
        for value in ls:
            header=re.search(r'SECURITY ANALYSIS\s+(RISK LEVEL)',value,re.I)
            if header:column=header.start(1)
            elif column is not None:
                # Only the original RISK LEVEL column, not the remediation
                # date/right-hand regrading column on old overview tables.
                for m in re.finditer(r'\b('+LABEL+r')\b',value,re.I):
                    if column-8 <= m.start() <= column+8:
                        tally[severity(m[1],report.firm)]+=1
                        proof.append({'start':offset+m.start(1),'end':offset+m.end(1),'text':m[1]})
                        break
            offset+=len(value)
    if proof and any(tally[k]!=v for k,v in result['counts'].items()):
        result=result|{'ambiguous':True,'ambiguity_reason':'Aggregate totals conflict with the independently printed original risk-level table; old reports mix remediation and original snapshots.',
                       'original_risk_table_counts':dict(tally),'original_risk_table_evidence':proof}
    return result


def parse_pentest(report):
    return parse(report, 'pentest')


def parse_sections(report):
    return parse(report, 'sections')


def parse_hal(report):
    return parse(report, 'hal')


def parse_bvss(report):
    # BVSS changes the heading suffix and risk metadata; HAL remains the ID.
    return parse(report, 'hal')


def parse_slash_cards(report):
    out=[]
    for i,line in enumerate(report.lines):
        value=re.sub(r'H[ \t]*A[ \t]*L[ \t]*-[ \t]*([0-9][0-9 \t]*)',lambda m:'HAL-'+re.sub(r'\s','',m[1]),line.content)
        value=re.sub(r'\([ \t]*(HAL-\d+)[ \t]*\)',r'(\1)',value)
        m=re.match(r'^(\d+[ \t]*\.[ \t]*\d+)\.?\s+(?:\((HAL-\d+)\)\s*)?(.+)',value,re.I)
        if not m or re.search(r'\.{4}|\s{3,}\d+\s*$',line.text):continue
        title=[m[3]];raw=None
        for nxt in report.lines[i+1:i+15]:
            grade=re.fullmatch(r'//\s*('+LABEL+r')\s*',nxt.content,re.I)
            if grade:raw=grade[1];break
            if re.match(r'Description\b|\d+\s*\.\s*\d+\s+\(',nxt.content,re.I):break
            if nxt.content:title.append(nxt.content)
        if raw:
            section=re.sub(r'\s','',m[1])
            out.append(Candidate(line.start,clean(' '.join(title)),raw,m[2] or section,method='halborn-slash-risk-card',confidence=.98,
                                 evidence={'severity_basis':'explicit_slash_risk_badge','section_id':section}))
    for i,c in enumerate(out):c.end=out[i+1].start if i+1<len(out) else len(report.text)
    return out


def status_pentest(report, candidates):
    status_hal(report,candidates)


def status_hal(report, candidates):
    fields(report,candidates,(FIELD,
        ('remediation_plan',r'\bRemediation (?:Plan|Status)\s*:*\s*('+STATE+r')\b'),
        # Banners/page breaks often separate the plan heading and verdict.
        ('remediation_verdict',r'^[ \t]*('+STATE+r')[ \t]*:[ \t]+')))


def status_bvss(report, candidates):
    status_hal(report,candidates)


def status_slash_cards(report,candidates):
    tables={};active=False;pending=None
    for line in report.lines:
        if re.search(r'SECURITY ANALYSIS\s+RISK LEVEL',line.text,re.I):active=True;continue
        if not active:continue
        if re.match(r'^\d+\.\s*FINDINGS',line.content,re.I):active=False;continue
        m=re.match(r'^\s*(HAL-\d+)\s*-',line.text,re.I)
        if m:pending=m[1]
        state=re.search(r'\s{2,}('+STATE+r')\s*$',line.text,re.I)
        if state and pending:
            tables.setdefault(pending,[]).append(claim(report,state,line.start,'hal_id_overview_remediation_cell'))
            pending=None
    fields(report,candidates,(FIELD,('remediation_section',r'^[ \t]*Remediation(?: (?:Plan|Status))?\s*:?\s*('+STATE+r')\b')),tables=tables,preserve=False)


WEBSITE_MARKER = '## Halborn Website Finding Records'


def parse_website(report):
    """Read public Flight records rendered into the canonical text, once each.

    The visible page repeats mobile/desktop overview tables. Detail records in
    the source payload have stable HAL IDs and include rich HTML that the
    server-rendered skeleton omits. Neither overview rows nor totals create
    additional findings.
    """
    marker = report.text.find(WEBSITE_MARKER)
    if marker < 0:
        return []
    headings = list(re.finditer(r'^### (HAL-\d+) (.+)$', report.text[marker:], re.M))
    out = []
    for i, heading in enumerate(headings):
        start = marker + heading.start()
        end = marker + headings[i+1].start() if i+1 < len(headings) else len(report.text)
        body = report.text[start:end]
        label = re.search(r'^Severity:[ \t]*([^\n]+)', body, re.M)
        if not label:
            raise ValueError('Halborn website record lacks its publisher severity: '+heading[1])
        c = Candidate(start, heading[2], label[1], heading[1], end=end,
                      method='halborn-website-record', confidence=.99,
                      evidence={'severity_basis':'publisher_website_finding_record',
                                'severity_label_span':{'start':start+label.start(1),
                                                       'end':start+label.end(1),'text':label[1]},
                                'status_reader_complete':True})
        out.append(c)
    return out


def status_website(report, candidates):
    # An exact field, including previously unseen native labels; no prose scan.
    fields(report,candidates,(('website_record_status',r'^Status:[ \t]*([^\n]+)'),),preserve=False)


def counts_website(report):
    """Independent on-page severity chart, never the finding-record array."""
    marker = report.text.find(WEBSITE_MARKER)
    text = report.text[:marker] if marker >= 0 else report.text
    charts = []
    for chart in re.finditer(r'^Severity Breakdown\s*\n', text, re.M):
        tail = text[chart.end():]
        stop = re.search(r'^(?:Actions|## |About this report)', tail, re.M)
        tail = tail[:stop.start()] if stop else tail
        values, proof = {}, []
        for m in re.finditer(r'^(Critical|High|Medium|Low|Informational)[ \t]*(\d+)\s*$', tail, re.M|re.I):
            values[severity(m[1],report.firm)] = int(m[2])
            begin = chart.end()+m.start()
            proof.append({'start':begin,'end':chart.end()+m.end(),'text':m[0]})
        if len(values) == 5:
            charts.append((values,proof))
    if not charts:
        return None
    values, proof = charts[0]
    return {'counts':values,'basis':'halborn_website_severity_breakdown','evidence':proof,
            'ambiguous':any(v != values for v,_ in charts[1:])}


VARIANTS = (
    Variant('halborn/v2025_website', Fingerprint((('website_records',r'^## Halborn Website Finding Records$',30),),formats=('html',)),parse_website,('halborn_website',),status_website,counts_website),
    Variant('halborn/v2024_slash_cards', Fingerprint((('slash_risk_badge',r'^\s*//\s*(?:'+LABEL+r')\s*$',9),('bvss',r'\bBVSS\b',3)),('2024','2026')),parse_slash_cards,('halborn_slash',),status_slash_cards),
    Variant('halborn/v2023_bvss', Fingerprint((('bvss',r'\bBVSS\b|SEVERITY COEFFICIENT',7),('hal_id',r'\(HAL-\d+\)',3)),('2023','2026')),parse_bvss,('halborn_bvss',),status_bvss),
    Variant('halborn/v2021_hal', Fingerprint((('hal_id',r'\(HAL-\d+\)',8),),('2021','2023')),parse_hal,('halborn_hal',),status_hal),
    Variant('halborn/v2020_sections', Fingerprint((('detail_chapter',r'FINDINGS\s*&\s*(?:TECHNICAL|TECH)\s*DETAILS',6),('numbered_risk',r'^\s*3\.\d+\.?\s+.+[-–]\s*(?:Critical|High|Medium|Low|Informational)\s*$',2)),('2020','2021')),parse_sections,('halborn_sections',),status_hal,counts_sections),
    Variant('halborn/v2020_pentest', Fingerprint((('pentest',r'\b(?:PENETRATION TEST|PENTEST|WALLET SECURITY)',1),('risk_suffix',r'^\s*[A-Za-z][^\n]+[-–]\s*(?:'+LABEL+r')\s*$',3),('description',r'\bDescription\s*:',3)),('2020','2021'),reject_signatures=(r'\(HAL-\d+\)',)),parse_pentest,('halborn_pentest',),status_pentest),
)
