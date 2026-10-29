"""Coinspect detail cards across inline Total Risk, legacy grids and modern Risk columns."""
from __future__ import annotations
import re
from core import Candidate, clean
DESCRIPTION = 'Coinspect risk-card metadata, preserving inline/column risk, wrapped titles and explicit resolution values'
ID=re.compile(r'^\s*([A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,3})(?:\s+(.*?))?\s*$')
RISK=re.compile(r'\b(Critical|High|Medium|Low|Informational|Info|None|Unknown|No Risk|Zero)\b',re.I)


def cell_below(lines,index,column,width=16):
    for line in lines[index+1:index+7]:
        value=line.text[max(0,column-3):column+width].strip()
        if value:
            return value,line
    return None,None


def parse(report, family=None):
    out=[]
    for i,line in enumerate(report.lines):
        m=ID.match(line.text.replace('\u200b',''))
        if not m:continue
        nearby=report.lines[i+1:i+35]
        # These metadata cards are absent from TOCs, summary rows and prose references.
        header=next(((j,l) for j,l in enumerate(nearby) if re.search(r'\bTotal Risk\b',l.text) or re.match(r'^\s*Status\s+Risk\s*$',l.text)),None)
        if not header or header[0]>10 or header[1].page!=line.page:continue
        if any(ID.match(l.text.replace('\u200b','')) for l in nearby[:header[0]]):continue
        j,riskline=header;raw=None;state=None;resolution=None
        legacy=re.search(r'\bTotal Risk\b',riskline.text)
        if family in {'inline','grid'} and not legacy:continue
        if family=='status_risk' and legacy:continue
        if legacy:
            after=riskline.text[legacy.end():].strip()
            inline=RISK.match(after)
            if family=='inline' and not inline:continue
            if family=='grid' and inline:continue
            if inline:raw=inline[1]
            else:
                # Risk may appear one row below Impact; keep the left Total Risk column.
                for l in nearby[j+1:j+6]:
                    left=l.text[:max(16,legacy.start()+14)].strip()
                    mm=RISK.fullmatch(left)
                    if mm:raw=mm[1];break
            # An explicit Status column takes priority over a legacy Fixed checkbox.
            for k,l in enumerate(nearby[:25]):
                sm=re.search(r'\bStatus\b',l.text)
                if sm:
                    state,sl=cell_below(nearby,k,sm.start(),20)
                    break
            # A printed checkmark under Fixed states fixed; ! remains unresolved/unknown.
            for k,l in enumerate(nearby[:25]):
                if not state and re.search(r'\bFixed\b',l.text):
                    value,vl=cell_below(nearby,k,l.text.index('Fixed'),12)
                    if value and re.match(r'^(?:✔|✓|√|Yes)\s*$',value,re.I):state='Fixed'
                    elif value and re.fullmatch(r'(?:No|Partially)',value,re.I):state=value
                    break
        else:
            riskcol=riskline.text.index('Risk')
            value,vl=cell_below(nearby,j,riskcol)
            mm=RISK.match(value or '')
            if mm:raw=mm[1]
            state,sl=cell_below(nearby,j,riskline.text.index('Status'),min(20,max(1,riskcol-riskline.text.index('Status')-3)))
            for k,l in enumerate(nearby[:30]):
                if re.search(r'\bResolution\b',l.text):
                    resolution,rl=cell_below(nearby,k,l.text.index('Resolution'),20);break
        if raw is None:
            continue
        # Card titles occupy all lines before the first metadata row (Category in 2016).
        title=[m[2]] if m[2] else []
        for l in nearby[:j]:
            if re.match(r'^\s*(?:Category|Impact|Location|Total Risk|Status|Resolution)\b',l.text):break
            if re.search(r'\S\s{2,}\S',l.text.strip()):break
            if l.content and not l.content.isdigit():title.append(l.content)
        if not title:continue
        out.append(Candidate(line.start,clean(' '.join(title)),raw,m[1],status_raw=state,
                  method='risk-metadata-card',confidence=.97,
                  evidence={'severity_basis':'explicit_total_risk' if legacy else 'explicit_risk_column',
                            'risk_header_span':{'start':riskline.start,'end':riskline.end},'resolution_raw':resolution}))
    for i,c in enumerate(out):
        end=out[i+1].start if i+1<len(out) else len(report.text)
        # Bound before publisher's appendix, conclusion, testing and disclaimer sections.
        tail=report.text[c.start:end]
        stop=re.search(r'(?im)^\s*(?:\d+\.\s*)?(?:Appendix\b[^\n]*|Disclaimer|(?:General )?Conclusion(?:s[^\n]*)?|Testing|Opportunity to fix Bitcoin[^\n]*)\s*$',tail)
        c.end=c.start+stop.start() if stop else end
    return out


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses
from core import set_status_claim


def resolution_status(report,candidates):
    """Read complete Resolution assertions, rather than clipped column cells."""
    for c in candidates:
        c.evidence['status_reader_complete']=True
        body=report.text[c.start:c.end]
        state=r'Partially\s+(?:fixed|resolved)|Not\s+fixed|Won[’\x27]t fix|Fixed|Resolved|Solved|Acknowledged|Mitigated|Open'
        for section in re.finditer(r'(?mi)^[ \t\f]*(?:Resolution|Status)\s*:?\s*\n',body):
            tail=body[section.end():]
            end=re.search(r'(?mi)^\s*(?:Description|Recommendations?|References?|Resources?|Contracts?|Resolution|Status)\s*:?\s*$',tail)
            response=tail[:end.start() if end else min(len(tail),1800)]
            m=re.search(r'^\s*('+state+r')\b',response,re.I)
            if not m:m=re.search(r'\b(?:This issue|The issue|It)\s+(?:has been|was|is)(?: considered)?\s+('+state+r')\b',response,re.I)
            if not m:m=re.search(r'\bCoinspect considers this issue\s+(partially addressed)\b',response,re.I)
            if not m:m=re.search(r'\b(decided not to address this issue|smart contract will not be modified)\b',response,re.I)
            if m:set_status_claim(report,c,m,c.start+section.end(),'coinspect_resolution_assertion')

def parse_inline(report):return parse(report,'inline')
def parse_grid(report):return parse(report,'grid')
def parse_status_risk(report):return parse(report,'status_risk')
def parse_clean_review(report):return []
def status_inline(report,candidates):
    statuses(report,candidates,headings=True,narrative=True,index_id=r'\b[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,3}\b')
    resolution_status(report,candidates)
def status_grid(report,candidates):
    statuses(report,candidates,headings=True,narrative=True,index_id=r'\b[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,3}\b')
    resolution_status(report,candidates)
def status_risk(report,candidates):
    statuses(report,candidates,headings=True,narrative=True,index_id=r'\b[A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,3}\b')
    resolution_status(report,candidates)
def status_clean_review(report,candidates):return None

VARIANTS=(
    Variant('coinspect/v2016_inline_risk',Fingerprint((('inline total risk',r'Total Risk[ \t]+(?:Low|Medium|High|Critical)[\u200b \t]*\|',15),),('2016','2018')),parse_inline,('coinspect_inline',),status_inline,notes='Early inline Total Risk/Impact/Likelihood cards; only explicit remediation is used, never Effort to Fix.'),
    Variant('coinspect/v2024_status_risk',Fingerprint((('status/risk header',r'^\s*Status\s+Risk\s*$',9),),('2024','2026')),parse_status_risk,('coinspect_status_risk',),status_risk,notes='Modern Status/Risk metadata columns plus Resolution sections; repeated audit IDs and deliberately skipped namespaces remain unchanged.'),
    Variant('coinspect/v2018_risk_grid',Fingerprint((('risk grid',r'\bTotal Risk\b',10),),('2018','2023')),parse_grid,('coinspect_grid',),status_grid,notes='Legacy Total Risk/Impact/Location grids and Fixed checkboxes; remediation sections and fix-review references are preserved.'),
    Variant('coinspect/v2020_clean_review',Fingerprint((('clean statement',r'no (?:security )?(?:issues|vulnerabilities)|No security\s+issues|did not (?:find|identify)|no significant',6),('audit structure',r'Executive Summary|Assessment and Scope',2)),('2020','2022')),parse_clean_review,('coinspect_clean',),status_clean_review,notes='Clean or narrative audit without numbered risk cards; no synthetic zero-severity findings.'),
)
