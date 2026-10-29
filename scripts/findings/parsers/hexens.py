"""Hexens numbered remediation cards, symbolic fields and risk-matrix badges."""
import re
from core import Candidate, clean, status
from variants import Variant, Fingerprint, dispatch
from summary_counts import printed_counts as generic_counts

DESCRIPTION = 'Hexens numbered, symbolic-field and pipe/badge cards, with verbatim status receipts'
ID = r'[A-Za-z][A-Za-z0-9_-]*-\d+'
RISK = r'(Critical|High|Medium|Low|Informational|Info)'
STATUS = r'(?:[Pp]artially\s+(?:fixed|ﬁxed|resolved)|Not\s+(?:fixed|ﬁxed|resolved)|Fixed|ﬁxed|Acknowledged|Resolved|Open|Pending|Mitigated|Accepted|Unresolved)'


def _cards(report, heading, method):
    entries=[]
    for i,line in enumerate(report.lines):
        if line.code or line.excluded:continue
        m=re.fullmatch(heading,line.content)
        if not m:continue
        ident=m[1]; initial=m[2] or ''
        following=[]
        # Limit by page and by the next publisher card, not arbitrary blank-line
        # count: some PDFs double-space the metadata block.
        for l in report.lines[i+1:i+100]:
            if l.page!=line.page:break
            if re.fullmatch(heading,l.content):break
            following.append(l)
            if re.match(r'^DESCRIPTION\s*:',l.content,re.I):break
        field=next((l for l in following if re.search(r'\bSEVERITY\s*:',l.content,re.I)),None)
        if field is None:continue
        sev=re.search(r'\bSEVERITY\s*:\s*'+RISK+r'\b',field.content,re.I)
        if not sev:continue
        title=[initial] if initial else []
        for l in following:
            if l.start>=field.start:break
            if l.content:title.append(l.content)
        for k,t in enumerate(title):
            badge=re.search(r'\s{3,}('+STATUS+r')\s*$',t,re.I)
            if badge:title[k]=t[:badge.start()]
        entries.append(Candidate(line.start,clean(' '.join(title)),sev[1],ident,
                                 method=method,confidence=.98,
                                 evidence={'severity_basis':'explicit_publisher_label'}))
    for j,c in enumerate(entries):
        end=entries[j+1].start if j+1<len(entries) else len(report.text)
        for p in report.meta['pages']:
            if c.start<p['start']<end and (not p['text'].strip() or len(re.sub(r'\s','',p['text']))<8):end=p['start'];break
        c.end=end
    return entries


def numbered_cards(report):
    return _cards(report,r'(\d+)[.)]\s+(.+)','hexens-numbered-remediation')


def symbolic_dot_cards(report):
    return _cards(report,r'('+ID+r')\s*\.\s*(.*)','hexens-symbolic-dot-fields')


def symbolic_stacked_cards(report):
    return _cards(report,r'('+ID+r')\s*()','hexens-symbolic-stacked-fields')


def pipe_badge_cards(report):
    return _cards(report,r'('+ID+r')\s*\|\s*(.+)','hexens-pipe-risk-matrix')


def _attach_status(report,candidates,badges=False):
    tables={}
    for page in report.meta['pages']:
        if not re.search(r'(?im)^[^\n]*(?:ID|Finding|Code)[^\n]*Severity[^\n]*Status',page['text']):continue
        for line in report.lines:
            if line.page!=page['page']:continue
            pid=re.search(r'\b'+ID+r'\b',line.text)
            claim=re.search(r'(?:\s{2,}|\|)[ \t]*('+STATUS+r')[ \t|]*$',line.text,re.I)
            if pid and claim:
                tables.setdefault(pid[0],[]).append((line.start+claim.start(1),line.start+claim.end(1)))
    for c in candidates:
        body=report.text[c.start:c.end]
        claims=[]
        for m in re.finditer(r'(?im)^[ \t]*STATUS\s*:\s*('+STATUS+r')\b',body):
            claims.append((m.start(1),m.end(1),'labelled_status_field'))
        # A later labelled resolution/fix-review statement supersedes the card.
        for m in re.finditer(r'(?im)^[ \t]*(?:Resolution|Fix Review|Status Update)\s*[:.]?\s*\n?[ \t]*('+STATUS+r')\b',body):
            claims.append((m.start(1),m.end(1),'resolution_section'))
        if badges:
            header=body.split('Severity:',1)[0].split('SEVERITY:',1)[0]
            for m in re.finditer(r'(?im)[ \t]{3,}('+STATUS+r')[ \t]*$',header):
                claims.append((m.start(1),m.end(1),'title_status_badge'))
        # Only publisher-labelled claims count. Resolution imperatives in early
        # reports are recommendations and must leave remediation status null.
        c.status_raw=None;c.normalized_status=None
        if not claims:
            indexed=tables.get(c.printed_id,[])
            if len({status(report.text[s:e]) for s,e in indexed})==1:
                start,end=indexed[-1]
                claims=[(start-c.start,end-c.start,'printed_id_status_table')]
            else:
                if indexed:c.evidence['status_conflict']=True
                continue
        start,end,basis=max(claims,key=lambda claim:claim[0])
        start+=c.start;end+=c.start;raw=report.text[start:end]
        c.status_raw=raw
        c.normalized_status={'mitigated':'resolved','accepted':'acknowledged','not fixed':'open'}.get(raw.casefold()) or status(raw)
        c.evidence['status_evidence']={'raw':raw,'text':raw,'start':start,'end':end,'basis':basis,'profile':'hexens'}


def numbered_status(report,candidates):return _attach_status(report,candidates)
def symbolic_dot_status(report,candidates):return _attach_status(report,candidates)
def symbolic_stacked_status(report,candidates):return _attach_status(report,candidates)
def pipe_badge_status(report,candidates):return _attach_status(report,candidates,True)


def parse(report):return dispatch(report,VARIANTS)
def printed_counts(report):return generic_counts(report)

VARIANTS=(
 Variant('hexens/v2025_pipe_badges',Fingerprint((('pipe_card',r'^\s*'+ID+r'\s*\|\s*\S',10),('risk_matrix',r'Severity:\s*'+RISK+r'.*Probability:',2)),('2025','2026'),('pdf',)),pipe_badge_cards,('hexens_pipe_badge',),pipe_badge_status),
 Variant('hexens/v2023_symbolic_dot',Fingerprint((('symbolic_dot_card',r'^\s*'+ID+r'[ \t]*\.[^\n]*\n(?:[^\n]*\n){0,12}[ \t]*SEVERITY\s*:',8),('severity_field',r'^\s*SEVERITY\s*:',2)),('2022','2023'),('pdf',)),symbolic_dot_cards,('hexens_symbolic_dot',),symbolic_dot_status),
 Variant('hexens/v2023_symbolic_stacked',Fingerprint((('standalone_symbolic_card',r'^\s*'+ID+r'[ \t]*\n(?:[^\n]*\n){1,18}[ \t]*SEVERITY\s*:',8),('severity_field',r'^\s*SEVERITY\s*:',2)),('2023','2025'),('pdf',)),symbolic_stacked_cards,('hexens_symbolic_stacked',),symbolic_stacked_status),
 Variant('hexens/v2021_numbered',Fingerprint((('numbered_title',r'^\s*\d+[.)]\s+\S',4),('severity_field',r'^\s*SEVERITY\s*:\s*'+RISK,3)),('2021','2023'),('pdf',)),numbered_cards,('hexens_numbered',),numbered_status,notes='Includes an early source whose collector date is 2016; range is a hint only.'),
)
