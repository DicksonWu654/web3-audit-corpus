"""Kudelski labelled cards, KS identifiers, matrix cards and architecture reviews."""
import re
from core import Candidate, is_toc, clean
from layout_support import view, bounded, attach_status, RISK, STATUS
from variants import Variant, Fingerprint
DESCRIPTION='Kudelski numeric/KS cards, explicit risk matrices, supplementary observations and architecture review sections'
PID=r'KS(?:\s*[-–]\s*[A-Za-z0-9]+)*[-–]\d+'


def remediation_status(report,candidates):
    attach_status(report,candidates,'kudelski-security')
    for c in candidates:
        body=report.text[c.start:c.end]
        m=re.search(r'(?m)^\s*The referenced issue is already (fixed)\.',body,re.I)
        if not c.status_raw and m:
            raw=m[1];start=c.start+m.start(1);end=c.start+m.end(1)
            c.status_raw=raw;c.normalized_status='fixed'
            c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],basis='explicit_issue_resolution',profile='kudelski-security')
        if not c.status_raw:
            c.normalized_status='unknown'
            c.evidence['status_availability']=dict(status='unknown',reason='not_stated',checked='labelled card status, matrix status and ID-linked summary')


def retest(report):
    # The public Beluga release only rechecks the earlier audit. Do not turn
    # remediated earlier findings into newly discovered vulnerabilities.
    report.layout_disposition={'reason':'prior_audit_retest_only','basis':'Retest report heading and Severity/Resolved cards',
                               'status_claims':[{'start':m.start(1),'end':m.end(1),'text':m[1]} for m in re.finditer(r'Severity\s+(Resolved)\b',report.text,re.I)]}
    return []


def cards(report):
    r=view(report);out=[];active=False
    for i,l in enumerate(r.lines):
        if is_toc(l):continue
        if re.fullmatch(r'(?:\d+\.?\s+)?(?:TECHNICAL (?:FINDINGS|DETAILS)(?: OF SECURITY FINDINGS)?|OBSERVATIONS)',l.content,re.I):active=True
        if re.fullmatch(r'(?:\d+\.?\s+)?(?:METHODOLOGY|APPENDIX.*|DEFINITIONS.*)',l.content,re.I):active=False
        m=re.match(r'^(?:(\d+(?:\.\d+)+)\.?\s+)?('+PID+r')\s*[:–-]?\s*(.+)',l.content)
        num=re.match(r'^(\d+(?:\.\d+)+)\.?\s+(.+)',l.content)
        if not m and not (active and num):continue
        if num and re.match(r'(?:Severity|Impact|Likelihood|Kickoff|Ramp-up|Review|Reporting|Verify|Methodology)\b',num[2],re.I):continue
        title=m[3] if m else num[2];pid=m[2] if m else num[1]
        ahead=[]
        for q in r.lines[i+1:]:
            if re.match(r'^(?:\d+(?:\.\d+)+\.?\s+|'+PID+r')',q.content):break
            ahead.append(q)
            if len(ahead)>=18:break
        raw=None;status=None
        for j,q in enumerate(ahead):
            explicit=re.match(r'^(?:Overall )?Severity\s*:?\s*\[?('+RISK+r')\b',q.content,re.I)
            if explicit:raw=explicit[1];break
            if re.fullmatch(r'Severity\s+Impact\s+Likelihood(?:\s+Status)?',q.content,re.I):
                value=next((v for v in ahead[j+1:j+4] if v.content),None)
                fields=re.match(r'^('+RISK+r')\s+('+RISK+r')\s+('+RISK+r')(?:\s+('+STATUS+r'))?',value.content,re.I) if value else None
                if fields:raw=fields[1];status=fields[4];break
        observation=bool(m and '-O-' in pid)
        if raw is None and not observation:continue
        if raw is None and observation and not any(re.match(r'^(?:Description|Recommendation)\b',q.content,re.I) for q in ahead):continue
        out.append(Candidate(l.start,title,raw,pid,status_raw=status,method='kudelski-ks-card' if m else 'kudelski-numbered-card',
                             record_kind='observation' if observation else 'formal_finding',confidence=.94))
    # In the title-first template the native Finding ID belongs to the title
    # immediately above it, including unnumbered and wrapped title blocks.
    title_first=labelled_cards(report)
    for c in title_first:
        out=[old for old in out if not (c.start<=old.start<c.evidence['metadata_end'])]
    return bounded(report,out+title_first,r'(?:\d+\s+)?(?:METHODOLOGY|APPENDIX.*|CONCLUSION|ABOUT KUDELSKI.*)')


def labelled_cards(report):
    out=[];lines=report.lines
    for i,line in enumerate(lines):
        m=re.fullmatch(r'Finding ID\s*:\s*(\S+)',line.content,re.I)
        if not m or is_toc(line):continue
        block=[]
        for q in lines[i+1:i+12]:
            if q.page!=line.page or re.match(r'^(?:Description|Proof|Recommendation|Finding ID)\b',q.content,re.I):break
            block.append(q)
        risk=next((re.match(r'^(?:Overall )?Severity\s*:?\s*\[?('+RISK+r')\b',q.content,re.I) for q in block
                   if re.match(r'^(?:Overall )?Severity\b',q.content,re.I)),None)
        if not risk:continue
        title=[]
        for q in reversed(lines[max(0,i-7):i]):
            if q.page!=line.page:break
            if not q.content:
                if title:break
                continue
            if re.search(r'Assessment$|Review$|Technical Findings$|©|Page \d+|Security Findings$',q.content,re.I):break
            title.insert(0,q)
        if not title:continue
        value=clean(' '.join(q.content for q in title))
        value=re.sub(r'^\d+(?:\.\d+)+\.?\s+','',value)
        status=next((re.match(r'^Status\s*:?\s*\[?([^\]\n]+)',q.content,re.I) for q in block if re.match(r'^Status\b',q.content,re.I)),None)
        out.append(Candidate(title[0].start,value,risk[1],m[1],status_raw=status[1].strip() if status else None,
                             method='kudelski-title-before-id',confidence=.97,
                             evidence={'native_id_span':dict(start=line.start,end=line.end,text=line.text),
                                       'metadata_end':block[-1].end if block else line.end}))
    return out


def architecture(report):
    out=[];active=False
    for l in report.lines:
        if is_toc(l):continue
        if re.fullmatch(r'5\s+GENERAL FINDINGS AND CLAIMS',l.content,re.I):active=True;continue
        if active and re.match(r'^6\s+',l.content):break
        if not active:continue
        m=re.match(r'^(5\.\d+)\s+(.+)',l.content)
        if re.search(r'\.{3}|\s{3,}\d+\s*$',l.text):continue
        if m:out.append(Candidate(l.start,m[2],printed_id=m[1],record_kind='observation',method='kudelski-architecture-observation',confidence=.8))
    return bounded(report,out,r'6\s+.*|(?:\d+\s+)?APPENDIX.*')


def threat_model(report):
    # Threat potentials are hypothetical, not findings of an exploitable bug.
    return []


def parse(report):return cards(report)

VARIANTS=(
 Variant('kudelski-security/v2021_title_before_id',Fingerprint((('finding_id',r'^\s*Finding ID\s*:\s*\S+',10),('severity',r'^\s*Severity\s*:?\s*\[?'+RISK,2)),('2020','2024')),cards,('kudelski_title_before_id',),remediation_status),
 Variant('kudelski-security/v2025_risk_matrix',Fingerprint((('matrix',r'^\s*Severity\s+Impact\s+Likelihood\s+Status',8),('ks_id',PID,2)),('2024','2026')),cards,('kudelski_matrix',),remediation_status),
 Variant('kudelski-security/v2022_ks_fields',Fingerprint((('ks_id',PID,6),('field',r'(?:Overall )?Severity\s*:',2)),('2022','2026')),cards,('kudelski_ks',),remediation_status),
 Variant('kudelski-security/v2020_numbered_fields',Fingerprint((('fields',r'^\s*Severity\s*:',6),('technical',r'TECHNICAL (?:FINDINGS|DETAILS)',2)),('2020','2023')),cards,('kudelski_numbered',),remediation_status),
 Variant('kudelski-security/v2019_architecture',Fingerprint((('architecture',r'Architectural Security Review',5),('general_claims',r'GENERAL FINDINGS AND CLAIMS',3)),('2019','2020')),architecture,('kudelski_architecture',),remediation_status),
 Variant('kudelski-security/v2021_threat_model',Fingerprint((('threat_potential',r'Severity Potential',6),('threat',r'Threat Model',2)),('2021','2022')),threat_model,('kudelski_threat',),remediation_status),
)


def summary_only(report):
    # Some public releases intentionally contain only the finding inventory.
    # Retain those entries as excerpts, with no invented detailed narrative.
    out=[]
    for line in report.lines:
        m=re.match(r'^\s*('+PID+r')\s+('+RISK+r')\s+(.+?)\s{2,}('+STATUS+r')\s*$',line.text,re.I)
        if m:out.append(Candidate(line.start,m[3],m[2],m[1],end=line.end,status_raw=m[4],record_kind='summary_excerpt',method='kudelski-summary-only',confidence=.6))
    return out

VARIANTS=(Variant('kudelski-security/v2022_summary_only',Fingerprint((('overview_caption',r'Table 2:\s*Findings Overview',8),('technical_findings',r'Technical Findings',2)),('2021','2023'),reject_signatures=(r'^\s*(?:Overall )?Severity\s*:?\s*\[?'+RISK+r'\b',r'^\s*Severity\s+Impact\s+Likelihood')),summary_only,('kudelski_summary',),remediation_status),)+VARIANTS

VARIANTS=(Variant('kudelski-security/v2022_retest',Fingerprint((('retest',r'Retest',3),('resolved_card',r'^\s*Severity\s+Resolved\s*$',7))),retest,('kudelski_retest',)),)+VARIANTS
