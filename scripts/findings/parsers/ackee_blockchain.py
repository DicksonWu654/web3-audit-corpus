"""Ackee colon-ID headings and explicit '<label> severity issue' detail cards."""
from core import severity, Candidate, SHORT, clean
import re
from parsers.shieldify import bounded

DESCRIPTION = 'Ackee letter-number detail headings with explicit severity and revision-aware status'


def parse(report, era=None):
    out = []
    legacy_report=not re.search(r'\bImpact:',report.text)
    for i,line in enumerate(report.lines):
        m = re.match(r'^(?:\d+\.\d+\.\s+)?([CHMLIWN]\d+F?)\s*(?::|\s+-)\s*(.*)',line.content)
        numbered = re.match(r'^(\d+\.\d+)\.\s+(.+)',line.content)
        if era != 'colon' and not m and numbered and 'Appendix' not in numbered[2]:
            near = report.near(i, 7)
            impact=re.search(r'\bImpact:\s*(Informational|Info|Warning|High|Medium|Low)\b',near,re.I)
            if impact and re.search(r'\bTarget:',near):
                raw=impact[1] if impact[1].lower() in {'informational','info','warning'} else None
                out.append(Candidate(line.start,numbered[2],raw,numbered[1],method='ackee-legacy-numbered-card',confidence=.9,
                                     evidence={'severity_basis':'explicit_nonexploitable_impact_label' if raw else 'no_scalar_risk_label',
                                               'impact_raw':impact[1]}))
        if era == 'numbered' or not m or line.page < 4 or re.search(r'(?:\.\s*){4,}',line.text):
            continue
        if re.search(r'\s{3,}(?:Info|Warning|Critical|High|Medium|Low|Fixed|Acknowledged|\d\.\d)\b',m[2]):
            continue
        neighborhood=[]
        for nxt in report.lines[i+1:i+12]:
            if nxt.page!=line.page or re.match(r'^[CHMLIWN]\d+F?\s*:',nxt.content):
                break
            neighborhood.append(nxt)
        near='\n'.join(l.text for l in neighborhood)
        sev = re.search(r'^\s*(Critical|High|Medium|Low|Info(?:rmational)?|Warning)\s+severity\s+(?:issue|finding)\s*$',near,re.I|re.M)
        first='\n'.join(l.content for l in neighborhood if l.content)
        metadata=bool(re.search(r'\bImpact:\s*\S','\n'.join(first.splitlines()[:5])) and re.search(r'\bTarget:',near))
        legacy=legacy_report and bool(line.page>=8 and re.search(r'(?:^|\n)\s*\d+\. Findings\s*(?:\n|$)',report.text[:line.start]))
        if not sev and not metadata and not legacy:
            continue
        title = [m[2]]
        for nxt in neighborhood:
            if re.search(r'\bseverity\s+(?:issue|finding)|\bImpact:',nxt.content,re.I):
                break
            if legacy and not metadata and not sev:
                break
            if nxt.content:
                title.append(nxt.content)
        raw=sev[1] if sev else m[1][0]
        out.append(Candidate(line.start,clean(' '.join(title)),raw,m[1],severity(raw, report.firm),
                             method='ackee-detail-card',confidence=.96,
                             evidence={'severity_basis':'explicit_field' if sev else 'printed_id_prefix'}))
    # Status is explicitly printed in the findings overview, often absent from
    # the detail's narrative fix discussion. Never infer it from that discussion.
    statuses={}
    for line in report.lines:
        m=re.match(r'^([CHMLIWN]\d+)\s*:\s*.*\s{2,}(Partially fixed|Fixed|Acknowledged|Open)\s*$',line.content,re.I)
        if m:
            statuses[m[1]]=(m[2],line.start,line.end)
    for j,c in enumerate(out):
        end = out[j+1].start if j+1<len(out) else len(report.text)
        body = report.text[c.start:end]
        st = re.search(r'\bStatus\s*[:–-]\s*([^\n]+)',body,re.I)
        if not st:
            st = re.search(r'^(?:\s*)(Fixed|Acknowledged|Partially fixed|Resolved|Open|No action taken)\s*$',body,re.I|re.M)
        if st:
            c.status_raw=st[1].strip()
        elif c.printed_id in statuses:
            c.status_raw,start,stop=statuses[c.printed_id]
            c.evidence['status_summary_span']={'start':start,'end':stop}
    return bounded(report,out)


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields, claim
from core import set_status_claim


def solution_status(report,candidates):
    """Latest revision's Solution section supersedes the early overview."""
    for c in candidates:
        c.evidence['status_reader_complete']=True
        body=report.text[c.start:c.end]
        # Fix-log cards state the disposition under Description, with no
        # separate Status field. This is an assertion about this issue only.
        m=re.search(r'\b(This issue\s+(?:was|has been)\s+(?:partially\s+)?(?:acknowledged|fixed|resolved|addressed)\s+by the client[^.\n]*\.)',body,re.I)
        if m:
            set_status_claim(report,c,m,c.start,'ackee_fix_log_assertion')
        for section in re.finditer(r'(?mi)^[ \t]*Solution(?:\s*\(Revision[^\n]*\))?\s*:?\s*\n',body):
            tail=body[section.end():]
            end=re.search(r'(?mi)^\s*(?:Solution|Recommendation|Go back to|Client[’\x27]s (?:comment|response))\b',tail)
            response=tail[:end.start() if end else len(tail)]
            m=re.search(r'\b(Partially\s+fixed|Not fixed|Acknowledged|Fixed|Resolved|Unresolved|Invalidated)\b',response,re.I)
            if not m:
                m=re.search(r'(?m)^\s*(Functions(?: [^\n]+)? have been renamed[^.]+\.|Functions [\s\S]{0,180}?are now used in the\s+code\.)',response)
            if m and not re.search(r'\b(?:should|could|will|to be|not yet)\b',response[:m.start()],re.I):
                set_status_claim(report,c,m,c.start+section.end(),'ackee_revision_solution')
                if m[1].casefold()=='fixed' and re.search(r'\bfixed only\b',response,re.I):
                    # Keep the full qualifying assertion for central resolution.
                    full=re.search(r'([^\n]*fixed only[^.]*\.)',response,re.I)
                    if full:set_status_claim(report,c,full,c.start+section.end(),'ackee_partial_revision_solution')


def parse_colon(report):
    return parse(report,'colon')


def parse_numbered(report):
    out=parse(report,'numbered')
    overview=_numbered_overview(report)
    key=lambda s:re.sub(r'[^a-z0-9]','',s.casefold())
    for c in out:
        title=key(c.title)
        matches=[row for row in overview if len(title)>=12 and len(key(row['title']))>=12 and (key(row['title']).startswith(title) or title.startswith(key(row['title'])))]
        if len(matches)==1:
            row=matches[0]
            c.evidence['section_id']=c.printed_id
            c.printed_id=row['id']
            c.evidence['id_basis']='unique_native_overview_title_join'
            c.evidence['native_overview_id_span']=row['id_span']
    return out


def _numbered_overview(report):
    rows=[];column=None;header=0
    for i,line in enumerate(report.lines):
        if re.search(r'\bId\s+.*?\bType\b.*\bImpact\b.*\bStatus\b',line.text,re.I):
            column=re.search(r'\bType\b',line.text,re.I).start();header=i;continue
        if column is None:continue
        m=re.match(r'^\s*([CHMLIWN]\d+F?)\b(?!:)',line.text)
        if not m:continue
        first=last=i
        while first>header+1 and report.lines[first-1].page==line.page and report.lines[first-1].content:first-=1
        while last+1<len(report.lines) and report.lines[last+1].page==line.page and report.lines[last+1].content:last+=1
        pieces=[];claims=[]
        for part in report.lines[first:last+1]:
            pieces.append(re.sub(r'^\s*'+re.escape(m[1])+r'\b','',part.text[:column]).strip())
            state=re.search(r'\b('+STATE+r')\s*$',part.text,re.I)
            if state:claims.append(claim(report,state,part.start,'native_overview_status_cell'))
        rows.append({'id':m[1],'title':clean(' '.join(pieces)),'claims':claims,
                     'id_span':{'start':line.start+m.start(1),'end':line.start+m.end(1),'text':m[1]}})
    return rows


def parse_dash_metadata(report):
    return parse(report,'metadata')


def parse_severity(report):
    return parse(report,'metadata')


def parse_revision(report):
    return parse(report,'metadata')


def status_colon(report,candidates):
    fields(report,candidates,(FIELD,),tables=_id_status_tables(report),preserve=False)
    solution_status(report,candidates)


def status_numbered(report,candidates):
    tables={row['id']:row['claims'] for row in _numbered_overview(report)}
    fields(report,candidates,(FIELD,),tables=tables)
    solution_status(report,candidates)


def status_dash_metadata(report,candidates):
    fields(report,candidates,(FIELD,('client_response',r'^[ \t]*Client[’\x27]s response[ \t]*:?\s*('+STATE+r')\b')))
    solution_status(report,candidates)


def _id_status_tables(report):
    tables={}
    for line in report.lines:
        m=re.match(r'^[ \t]*([CHMLIWN]\d+F?)(?:[ \t]*:|[ \t]{2,})',line.text)
        st=re.search(r'\s{2,}('+STATE+r')[.!]?\s*$',line.text,re.I)
        if m and st:
            tables.setdefault(m[1],[]).append(claim(report,st,line.start,'id_linked_revision_table'))
    return tables


def status_revision(report,candidates):
    # ID-linked final overview is preferred to unlabelled prose in details.
    fields(report,candidates,(FIELD,),tables=_id_status_tables(report),preserve=False)
    solution_status(report,candidates)


VARIANTS=(
    Variant('ackee-blockchain/v2021_dash_metadata',Fingerprint((('dash_id',r'^\s*[CHMLIWN]\d+F?\s+-\s+\S',7),('impact',r'\bImpact:',3)),('2021','2022')),parse_dash_metadata,('ackee_dash',),status_dash_metadata),
    Variant('ackee-blockchain/v2023_status_overview',Fingerprint((('revision_status_header',r'\bSeverity\s+(?:Version|Found in)\s+Status\b',9),('revision_table_row',r'^\s*[CHMLIWN]\d+:.*\s{2,}\d+\.\d+\s{2,}(?:Fixed|Acknowledged|Reported|Partially fixed)',9)),('2023','2026')),parse_revision,('ackee_revision',),status_revision),
    Variant('ackee-blockchain/v2022_severity_cards',Fingerprint((('severity_card',r'^\s*(?:Critical|High|Medium|Low|Info(?:rmational)?|Warning)\s+severity\s+(?:issue|finding)\s*$',7),('id_impact',r'^\s*[CHMLIWN]\d+F?\s*:',6),('impact',r'\bImpact:',3)),('2022','2026')),parse_severity,('ackee_severity',),status_revision),
    Variant('ackee-blockchain/v2021_numbered_impact',Fingerprint((('numbered',r'^\s*\d+\.\d+\.\s+\S',2),('impact',r'\bImpact:',3),('target',r'\bTarget:',3)),('2021','2022'),reject_signatures=(r'^\s*[CHMLIWN]\d+F?\s*(?::|\s+-)',)),parse_numbered,('ackee_numbered','ackee_numbered_summary'),status_numbered),
    Variant('ackee-blockchain/v2021_colon_titles',Fingerprint((('colon_id',r'^\s*[CHMLIWN]\d+\s*:',6),('findings_chapter',r'^\s*\d+\. Findings\s*$',2)),('2021','2022'),reject_signatures=(r'\bImpact:',)),parse_colon,('ackee_colon',),status_colon),
)
